// SPDX-License-Identifier: GPL-3.0-or-later
//! Aggregate IPv4/IPv6 CIDR prefixes into their minimal covering set.
//!
//! Inputs are parsed with [`parse_entry`] and collected in an [`Aggregator`],
//! which merges overlapping and adjacent ranges and emits the smallest list
//! of CIDR blocks that covers exactly the same addresses.
//!
//! ```
//! use route_summarization::Aggregator;
//!
//! let mut agg = Aggregator::new();
//! for line in ["10.0.0.0/24", "10.0.1.0/24", "192.0.2.7", "2001:db8::/33", "2001:db8:8000::/33"] {
//!     agg.add_str(line, false).unwrap();
//! }
//! let out: Vec<String> = agg.summarize().iter().map(|p| p.to_string()).collect();
//! assert_eq!(out, ["10.0.0.0/23", "192.0.2.7", "2001:db8::/32"]);
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Address family of a prefix or range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// Address width in bits.
    pub const fn bits(self) -> u8 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    const fn max(self) -> u128 {
        match self {
            Family::V4 => u32::MAX as u128,
            Family::V6 => u128::MAX,
        }
    }
}

/// An inclusive address range within one family. Always valid: `start <= end`,
/// both within the family's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    family: Family,
    start: u128,
    end: u128,
}

impl Range {
    /// A range of numeric addresses; `None` unless `start <= end` and both fit
    /// the family (IPv4 values must be at most `u32::MAX`).
    pub fn new(family: Family, start: u128, end: u128) -> Option<Self> {
        (start <= end && end <= family.max()).then_some(Self { family, start, end })
    }

    /// The range between two addresses of the same family, in either order.
    pub fn from_ips(a: IpAddr, b: IpAddr) -> Option<Self> {
        let ((fa, a), (fb, b)) = (from_ip(a), from_ip(b));
        (fa == fb).then(|| Self {
            family: fa,
            start: a.min(b),
            end: a.max(b),
        })
    }

    pub fn family(&self) -> Family {
        self.family
    }

    /// First address, as an integer.
    pub fn start(&self) -> u128 {
        self.start
    }

    /// Last address (inclusive), as an integer.
    pub fn end(&self) -> u128 {
        self.end
    }
}

/// A CIDR prefix with no host bits set. Displays host routes (/32, /128) as a
/// bare address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Prefix {
    family: Family,
    addr: u128,
    len: u8,
}

impl Prefix {
    /// `None` if `len` exceeds the family's width, `addr` does not fit the
    /// family, or `addr` has bits set beyond the prefix length.
    pub fn new(family: Family, addr: u128, len: u8) -> Option<Self> {
        (len <= family.bits() && addr <= family.max() && addr & host_mask(family, len) == 0)
            .then_some(Self { family, addr, len })
    }

    pub fn family(&self) -> Family {
        self.family
    }

    /// The prefix's network address.
    pub fn network(&self) -> IpAddr {
        to_ip(self.family, self.addr)
    }

    /// Prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// True when the prefix covers a single address.
    pub fn is_host(&self) -> bool {
        self.len == self.family.bits()
    }

    /// The addresses the prefix covers.
    pub fn range(&self) -> Range {
        Range {
            family: self.family,
            start: self.addr,
            end: self.addr | host_mask(self.family, self.len),
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // std formats IPv6 per RFC 5952: lowercase, no leading zeros, `::` only
        // for the longest run of two or more zero groups.
        if self.is_host() {
            write!(f, "{}", self.network())
        } else {
            write!(f, "{}/{}", self.network(), self.len)
        }
    }
}

/// Why an input line was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Not an IPv4 or IPv6 address.
    InvalidAddress,
    /// Prefix length is not a plain decimal number within the family's width.
    InvalidPrefixLength,
    /// Range ends belong to different families, or start is after end.
    InvalidRange,
    /// SPF `ip4:` given an IPv6 value, or `ip6:` given an IPv4 value.
    SpfFamilyMismatch,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::InvalidAddress => "not a valid IPv4/IPv6 address",
            ParseError::InvalidPrefixLength => "invalid prefix length",
            ParseError::InvalidRange => "invalid address range",
            ParseError::SpfFamilyMismatch => "SPF mechanism does not match address family",
        })
    }
}

impl std::error::Error for ParseError {}

/// Parse one input entry into an address range.
///
/// Accepted forms, for both IPv4 and IPv6:
/// * `addr` — a single host
/// * `addr/len` — a prefix; host bits are masked off (`10.1.2.3/8` is `10.0.0.0/8`)
/// * `start-end` — an inclusive range, split into CIDRs on output
///
/// With `spf`, a leading `ip4:` or `ip6:` (any case) is stripped and must match
/// the address family.
///
/// Rejected: IPv4 octets with leading zeros (ambiguous octal), IPv6 zone IDs
/// (`fe80::1%eth0`, meaningless in a route), and prefix lengths with a sign or
/// leading zeros (`/032`).
pub fn parse_entry(input: &str, spf: bool) -> Result<Range, ParseError> {
    let mut s = input.trim();
    let mut want = None;
    if spf {
        if let Some(rest) = strip_prefix_ci(s, "ip4:") {
            want = Some(Family::V4);
            s = rest;
        } else if let Some(rest) = strip_prefix_ci(s, "ip6:") {
            want = Some(Family::V6);
            s = rest;
        }
    }

    let range = if let Some((a, b)) = s.split_once('-') {
        let (fa, start) = parse_addr(a.trim())?;
        let (fb, end) = parse_addr(b.trim())?;
        if fa != fb {
            return Err(ParseError::InvalidRange);
        }
        Range::new(fa, start, end).ok_or(ParseError::InvalidRange)?
    } else if let Some((a, len)) = s.split_once('/') {
        let (family, addr) = parse_addr(a)?;
        let len = parse_len(len, family)?;
        let host = host_mask(family, len);
        Range {
            family,
            start: addr & !host,
            end: (addr & !host) | host,
        }
    } else {
        let (family, addr) = parse_addr(s)?;
        Range {
            family,
            start: addr,
            end: addr,
        }
    };

    match want {
        Some(f) if f != range.family => Err(ParseError::SpfFamilyMismatch),
        _ => Ok(range),
    }
}

/// Collects ranges and produces the minimal covering prefix list.
///
/// Exclusions are subtracted address by address: the summary covers exactly
/// the added addresses minus the excluded ones, whatever the order of calls
/// and however the inputs overlap. A prefix that partly overlaps an exclusion
/// is split around it.
///
/// ```
/// use route_summarization::Aggregator;
///
/// let mut agg = Aggregator::new();
/// agg.add_str("192.0.2.0/24", false).unwrap();
/// agg.exclude_str("192.0.2.0/25", false).unwrap();
/// agg.exclude_str("192.0.2.255", false).unwrap();
/// let out: Vec<String> = agg.summarize().iter().map(|p| p.to_string()).collect();
/// assert_eq!(out, ["192.0.2.128/26", "192.0.2.192/27", "192.0.2.224/28",
///                  "192.0.2.240/29", "192.0.2.248/30", "192.0.2.252/31", "192.0.2.254"]);
/// ```
#[derive(Debug, Default, Clone)]
pub struct Aggregator {
    include: Ranges,
    exclude: Ranges,
}

#[derive(Debug, Default, Clone)]
struct Ranges {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

impl Ranges {
    fn push(&mut self, r: Range) {
        match r.family {
            Family::V4 => self.v4.push((r.start, r.end)),
            Family::V6 => self.v6.push((r.start, r.end)),
        }
    }

    fn get(&self, family: Family) -> &[(u128, u128)] {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, r: Range) {
        self.include.push(r);
    }

    /// Parse and add one entry; see [`parse_entry`].
    pub fn add_str(&mut self, input: &str, spf: bool) -> Result<(), ParseError> {
        self.add(parse_entry(input, spf)?);
        Ok(())
    }

    /// Remove these addresses from the summary, wherever they appear.
    pub fn exclude(&mut self, r: Range) {
        self.exclude.push(r);
    }

    /// Parse and exclude one entry; see [`parse_entry`].
    pub fn exclude_str(&mut self, input: &str, spf: bool) -> Result<(), ParseError> {
        self.exclude(parse_entry(input, spf)?);
        Ok(())
    }

    /// True when nothing has been added (exclusions alone don't count).
    pub fn is_empty(&self) -> bool {
        self.include.v4.is_empty() && self.include.v6.is_empty()
    }

    /// Minimal CIDR list: all IPv4 first, then IPv6, each in address order.
    pub fn summarize(&self) -> Vec<Prefix> {
        let mut out = Vec::new();
        for family in [Family::V4, Family::V6] {
            let include = merge(self.include.get(family));
            let exclude = merge(self.exclude.get(family));
            for (start, end) in subtract(&include, &exclude) {
                split(family, start, end, &mut out);
            }
        }
        out
    }
}

/// Sort and merge overlapping or adjacent ranges.
fn merge(ranges: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// `include` minus `exclude`; both sorted, merged and disjoint.
fn subtract(include: &[(u128, u128)], exclude: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut out = Vec::with_capacity(include.len());
    let mut first = 0; // first exclusion that can still overlap
    for &(mut start, end) in include {
        while first < exclude.len() && exclude[first].1 < start {
            first += 1;
        }
        let mut alive = true;
        for &(x_start, x_end) in exclude[first..].iter().take_while(|x| x.0 <= end) {
            if x_start > start {
                out.push((start, x_start - 1));
            }
            if x_end >= end {
                alive = false;
                break;
            }
            start = x_end + 1; // x_end < end, so no overflow
        }
        if alive {
            out.push((start, end));
        }
    }
    out
}

/// Append the fewest aligned CIDR blocks covering `start..=end`.
fn split(family: Family, mut start: u128, end: u128, out: &mut Vec<Prefix>) {
    let width = u32::from(family.bits());
    loop {
        let align = if start == 0 {
            width
        } else {
            start.trailing_zeros().min(width)
        };
        let span = end - start; // block size minus one
        let fit = if span == u128::MAX {
            128
        } else {
            127 - (span + 1).leading_zeros()
        };
        let block = align.min(fit);
        out.push(Prefix {
            family,
            addr: start,
            len: (width - block) as u8,
        });
        match 1u128
            .checked_shl(block)
            .and_then(|size| start.checked_add(size))
        {
            Some(next) if next <= end && next <= family.max() => start = next,
            _ => break,
        }
    }
}

fn parse_addr(s: &str) -> Result<(Family, u128), ParseError> {
    // std rejects IPv4 leading zeros and IPv6 zone IDs; accepts embedded IPv4
    // in IPv6 (`::ffff:192.0.2.1`).
    s.parse::<IpAddr>()
        .map(from_ip)
        .map_err(|_| ParseError::InvalidAddress)
}

fn from_ip(ip: IpAddr) -> (Family, u128) {
    match ip {
        IpAddr::V4(a) => (Family::V4, u128::from(u32::from(a))),
        IpAddr::V6(a) => (Family::V6, u128::from(a)),
    }
}

fn parse_len(s: &str, family: Family) -> Result<u8, ParseError> {
    let plain = !s.is_empty()
        && s.len() <= 3
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    match s.parse::<u8>() {
        Ok(n) if plain && n <= family.bits() => Ok(n),
        _ => Err(ParseError::InvalidPrefixLength),
    }
}

fn host_mask(family: Family, len: u8) -> u128 {
    let host_bits = u32::from(family.bits() - len);
    if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    }
}

fn to_ip(family: Family, v: u128) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::from(v as u32)),
        Family::V6 => IpAddr::V6(Ipv6Addr::from(v)),
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(lines: &[&str]) -> Vec<String> {
        let mut a = Aggregator::new();
        for l in lines {
            a.add_str(l, false).unwrap();
        }
        a.summarize().iter().map(ToString::to_string).collect()
    }

    fn rejects(s: &str) -> ParseError {
        parse_entry(s, false).unwrap_err()
    }

    #[test]
    fn merges_adjacent_and_contained() {
        assert_eq!(
            agg(&["10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25"]),
            ["10.0.0.0/23"]
        );
        assert_eq!(
            agg(&["10.0.0.0/24", "10.0.2.0/24"]),
            ["10.0.0.0/24", "10.0.2.0/24"]
        );
    }

    #[test]
    fn masks_host_bits() {
        assert_eq!(agg(&["10.1.2.3/8"]), ["10.0.0.0/8"]);
        assert_eq!(agg(&["2001:db8::1/32"]), ["2001:db8::/32"]);
    }

    #[test]
    fn host_routes_print_bare_in_both_families() {
        assert_eq!(agg(&["1.2.3.4", "1.2.3.4/32"]), ["1.2.3.4"]);
        assert_eq!(agg(&["2001:db8::1", "2001:db8::1/128"]), ["2001:db8::1"]);
    }

    #[test]
    fn full_address_spaces() {
        assert_eq!(agg(&["0.0.0.0/0", "10.0.0.0/8"]), ["0.0.0.0/0"]);
        assert_eq!(agg(&["::/0", "2001:db8::/32"]), ["::/0"]);
        assert_eq!(agg(&["::/1", "8000::/1"]), ["::/0"]);
        assert_eq!(
            agg(&["255.255.255.255", "255.255.255.254"]),
            ["255.255.255.254/31"]
        );
        assert_eq!(
            agg(&["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]),
            ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        );
    }

    #[test]
    fn ranges_in_both_families() {
        assert_eq!(agg(&["10.0.0.0-10.0.0.255"]), ["10.0.0.0/24"]);
        assert_eq!(
            agg(&["10.0.0.1 - 10.0.0.6"]),
            ["10.0.0.1", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6"]
        );
        assert_eq!(agg(&["2001:db8::-2001:db8::ffff"]), ["2001:db8::/112"]);
        assert_eq!(rejects("10.0.0.9-10.0.0.1"), ParseError::InvalidRange);
        assert_eq!(rejects("10.0.0.1-::1"), ParseError::InvalidRange);
    }

    #[test]
    fn rfc5952_output() {
        // The Perl/Net::CIDR::Lite version printed these as `0001::/16`,
        // `00ab::/16`, `2001:db8::1:1:1:1:1` and `...:28::/120`.
        assert_eq!(agg(&["1::/16"]), ["1::/16"]);
        assert_eq!(agg(&["ab::/16"]), ["ab::/16"]);
        assert_eq!(agg(&["2001:db8:0:1:1:1:1:1"]), ["2001:db8:0:1:1:1:1:1"]);
        assert_eq!(
            agg(&["2001:558:fe14:76:68:87:28:0/120"]),
            ["2001:558:fe14:76:68:87:28:0/120"]
        );
        assert_eq!(agg(&["2001:DB8::/32"]), ["2001:db8::/32"]);
        assert_eq!(agg(&["2001:0:0:1:0:0:0:1"]), ["2001:0:0:1::1"]);
        assert_eq!(agg(&["::ffff:1.2.3.0/120"]), ["::ffff:1.2.3.0/120"]);
    }

    #[test]
    fn rejects_ambiguous_input() {
        assert_eq!(rejects("010.1.2.3"), ParseError::InvalidAddress);
        assert_eq!(rejects("555.2.2.2/30"), ParseError::InvalidAddress);
        assert_eq!(rejects("fe80::1%eth0"), ParseError::InvalidAddress);
        assert_eq!(rejects("2001:db8::%1/64"), ParseError::InvalidAddress);
        assert_eq!(rejects("garbage:"), ParseError::InvalidAddress);
        assert_eq!(rejects("192.168.8.0/33"), ParseError::InvalidPrefixLength);
        assert_eq!(rejects("2001:db8::/129"), ParseError::InvalidPrefixLength);
        assert_eq!(rejects("10.0.0.0/01"), ParseError::InvalidPrefixLength);
        assert_eq!(rejects("2001:db8::/032"), ParseError::InvalidPrefixLength);
        assert_eq!(rejects("10.0.0.0/+8"), ParseError::InvalidPrefixLength);
        assert_eq!(rejects("10.0.0.0/"), ParseError::InvalidPrefixLength);
    }

    #[test]
    fn spf_prefixes() {
        assert!(parse_entry("ip4:192.0.2.0/24", true).is_ok());
        assert!(parse_entry("IP6:2001:db8::/32", true).is_ok());
        assert_eq!(
            parse_entry("ip4:2001:db8::/32", true),
            Err(ParseError::SpfFamilyMismatch)
        );
        assert_eq!(
            parse_entry("ip6:192.0.2.0/24", true),
            Err(ParseError::SpfFamilyMismatch)
        );
        // Without --spf the mechanism is not stripped.
        assert!(parse_entry("ip4:192.0.2.0/24", false).is_err());
    }

    #[test]
    fn output_is_minimal_and_exact() {
        // Brute-force check over a small IPv4 window: the summary must cover
        // exactly the input addresses, and no two output blocks may be mergeable.
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..500 {
            let mut a = Aggregator::new();
            let mut want = [false; 1024];
            for _ in 0..(rand() % 20 + 1) {
                let len = 22 + (rand() % 11) as u8;
                let addr = (rand() % 1024) as u128;
                let host = host_mask(Family::V4, len);
                let (s, e) = (addr & !host, addr | host);
                a.add(Range {
                    family: Family::V4,
                    start: s,
                    end: e,
                });
                want[s as usize..=e as usize]
                    .iter_mut()
                    .for_each(|w| *w = true);
            }
            let out = a.summarize();
            let mut got = [false; 1024];
            for p in &out {
                let e = p.addr | host_mask(Family::V4, p.len);
                got[p.addr as usize..=e as usize]
                    .iter_mut()
                    .for_each(|g| *g = true);
            }
            assert_eq!(want, got);
            for w in out.windows(2) {
                let (x, y) = (w[0], w[1]);
                let sibling = x.len == y.len && x.addr ^ y.addr == 1u128 << (32 - x.len);
                assert!(!sibling, "mergeable siblings {x} {y}");
            }
        }
    }

    #[test]
    fn constructors_reject_invalid_values() {
        assert!(Range::new(Family::V4, 0, u128::from(u32::MAX)).is_some());
        assert!(Range::new(Family::V4, 1 << 40, 1 << 40).is_none());
        assert!(Range::new(Family::V6, 10, 5).is_none());
        assert!(Range::new(Family::V6, 0, u128::MAX).is_some());

        let (a, b) = ("10.0.0.9".parse().unwrap(), "10.0.0.1".parse().unwrap());
        assert_eq!(
            Range::from_ips(a, b),
            Range::new(Family::V4, 0x0a00_0001, 0x0a00_0009)
        );
        assert!(Range::from_ips(a, "::1".parse().unwrap()).is_none());

        assert!(Prefix::new(Family::V4, 0x0a00_0000, 8).is_some());
        assert!(Prefix::new(Family::V4, 0x0a00_0001, 8).is_none()); // host bits
        assert!(Prefix::new(Family::V4, 0, 33).is_none());
        assert!(Prefix::new(Family::V4, 1 << 32, 32).is_none());
        assert!(Prefix::new(Family::V6, 0, 129).is_none());
        assert_eq!(
            Prefix::new(Family::V4, 0x0a00_0000, 24).unwrap().range(),
            Range::new(Family::V4, 0x0a00_0000, 0x0a00_00ff).unwrap()
        );
    }

    fn agg_excluding(include: &[&str], exclude: &[&str]) -> Vec<String> {
        let mut a = Aggregator::new();
        include.iter().for_each(|l| a.add_str(l, false).unwrap());
        exclude
            .iter()
            .for_each(|l| a.exclude_str(l, false).unwrap());
        a.summarize().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn exclusion_splits_overlapping_prefixes() {
        assert_eq!(
            agg_excluding(&["10.0.0.0/24"], &["10.0.0.0/25"]),
            ["10.0.0.128/25"]
        );
        assert_eq!(
            agg_excluding(&["10.0.0.0/30"], &["10.0.0.1"]),
            ["10.0.0.0", "10.0.0.2/31"]
        );
        // Merged first, then subtracted: the /31 from two hosts loses one.
        assert_eq!(
            agg_excluding(&["140.82.112.2", "140.82.112.3"], &["140.82.112.3"]),
            ["140.82.112.2"]
        );
        // One exclusion spanning several separate inputs.
        assert_eq!(
            agg_excluding(
                &["10.0.0.0/24", "10.0.2.0/24", "10.0.4.0/24"],
                &["10.0.0.128-10.0.4.127"]
            ),
            ["10.0.0.0/25", "10.0.4.128/25"]
        );
        // Several exclusions inside one input.
        assert_eq!(
            agg_excluding(&["10.0.0.0/29"], &["10.0.0.1", "10.0.0.6"]),
            ["10.0.0.0", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.7"]
        );
    }

    #[test]
    fn exclusion_boundaries() {
        // Adjacent but not overlapping: no effect.
        assert_eq!(
            agg_excluding(&["10.0.0.0/24"], &["10.0.1.0/24", "9.255.255.255"]),
            ["10.0.0.0/24"]
        );
        // Superset or equal: everything goes.
        assert!(agg_excluding(&["10.1.0.0/16"], &["10.0.0.0/8"]).is_empty());
        assert!(agg_excluding(&["10.0.0.0/8"], &["10.0.0.0/8"]).is_empty());
        // Exclusions alone produce nothing.
        assert!(agg_excluding(&[], &["10.0.0.0/8"]).is_empty());
        // Other family is untouched.
        assert_eq!(
            agg_excluding(&["2001:db8::/32"], &["0.0.0.0/0"]),
            ["2001:db8::/32"]
        );
        assert_eq!(agg_excluding(&["10.0.0.0/8"], &["::/0"]), ["10.0.0.0/8"]);
    }

    #[test]
    fn exclusion_at_address_space_edges() {
        let v4 = agg_excluding(&["0.0.0.0/0"], &["0.0.0.0", "255.255.255.255"]);
        assert_eq!(v4.first().unwrap(), "0.0.0.1");
        assert_eq!(v4.last().unwrap(), "255.255.255.254");
        assert_eq!(v4.len(), 62); // 31 blocks climbing up, 31 back down

        let v6 = agg_excluding(
            &["::/0"],
            &["::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
        );
        assert_eq!(v6.first().unwrap(), "::1");
        assert_eq!(
            v6.last().unwrap(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
        );
        assert_eq!(v6.len(), 254);

        assert_eq!(agg_excluding(&["::/0"], &["::/1"]), ["8000::/1"]);
        assert_eq!(agg_excluding(&["::/0"], &["8000::/1"]), ["::/1"]);
    }

    #[test]
    fn exclusion_is_order_independent() {
        let mut a = Aggregator::new();
        a.exclude_str("10.0.0.5", false).unwrap();
        a.add_str("10.0.0.0/29", false).unwrap();
        let mut b = Aggregator::new();
        b.add_str("10.0.0.0/29", false).unwrap();
        b.exclude_str("10.0.0.5", false).unwrap();
        assert_eq!(a.summarize(), b.summarize());
        assert!(!a.is_empty());
        let mut only_excludes = Aggregator::new();
        only_excludes.exclude_str("10.0.0.0/8", false).unwrap();
        assert!(only_excludes.is_empty());
    }
}
