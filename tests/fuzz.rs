// SPDX-License-Identifier: GPL-3.0-or-later
//! Randomized property tests against an independent oracle.
//!
//! Runs as part of `cargo test`. Tune with:
//!   FUZZ_ITERS=100000 cargo test --release --test fuzz
//!   FUZZ_SEED=1234 FUZZ_ITERS=1 cargo test --test fuzz   # replay a failure

mod common;

use common::{Rng, addr_text, host_mask, prefix_range, run_cases, union, v6_exploded};
use route_summarization::{Aggregator, Family, Prefix, Range, parse_entry};

/// A random range in `family`, biased toward clustered, overlapping and
/// adjacent inputs, with occasional huge prefixes and address-space edges.
fn random_family(rng: &mut Rng) -> Family {
    if rng.chance(50) {
        Family::V4
    } else {
        Family::V6
    }
}

fn random_range(rng: &mut Rng, family: Family, base: u128) -> Range {
    let bits = u64::from(family.bits());
    let max = if family == Family::V4 {
        u128::from(u32::MAX)
    } else {
        u128::MAX
    };
    // Cluster most addresses within a 2^12 window so they interact.
    let addr = match rng.below(10) {
        0 => rng.u128() & max,
        1 => max - u128::from(rng.below(8)),
        2 => u128::from(rng.below(8)),
        _ => (base | u128::from(rng.below(1 << 12))) & max,
    };
    if rng.chance(15) {
        let span_bits = rng.range(0, 14);
        let span = u128::from(rng.below(1 << span_bits));
        let end = addr.saturating_add(span).min(max);
        return Range {
            family,
            start: addr,
            end,
        };
    }
    let len = if rng.chance(3) {
        rng.range(0, bits)
    } else {
        rng.range(bits - 14, bits)
    } as u8;
    let host = host_mask(family, len);
    Range {
        family,
        start: addr & !host,
        end: (addr & !host) | host,
    }
}

/// Exact: output covers precisely the input addresses.
/// Minimal: blocks are sorted, disjoint and aligned, and no two are siblings.
/// (Any coverable parent block would contain a sibling pair at its deepest
/// split, so "no siblings" implies no merge is possible.)
fn check(family: Family, input: &[Range], out: &[Prefix]) {
    let want = union(input.iter().map(|r| (r.start, r.end)).collect());
    let got_blocks: Vec<Range> = out
        .iter()
        .filter(|p| p.family == family)
        .map(prefix_range)
        .collect();
    let got = union(got_blocks.iter().map(|r| (r.start, r.end)).collect());
    assert_eq!(want, got, "{family:?} coverage differs");

    let ps: Vec<&Prefix> = out.iter().filter(|p| p.family == family).collect();
    for p in &ps {
        assert!(p.len <= family.bits());
        assert_eq!(p.addr & host_mask(family, p.len), 0, "unaligned {p}");
    }
    for w in got_blocks.windows(2) {
        assert!(w[0].end < w[1].start, "unsorted or overlapping output");
    }
    for w in ps.windows(2) {
        let (a, b) = (w[0], w[1]);
        let sibling =
            a.len == b.len && a.len > 0 && a.addr ^ b.addr == 1u128 << (family.bits() - a.len);
        assert!(!sibling, "mergeable siblings {a} {b}");
    }
}

#[test]
fn aggregation_is_exact_and_minimal() {
    run_cases("aggregation_is_exact_and_minimal", 2000, |rng| {
        let base4 = u128::from(rng.next() as u32) & !0xfff;
        let base6 = rng.u128() & !0xfff;
        let mut agg = Aggregator::new();
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for _ in 0..rng.range(1, 200) {
            let r = if rng.chance(50) {
                let r = random_range(rng, Family::V4, base4);
                v4.push(r);
                r
            } else {
                let r = random_range(rng, Family::V6, base6);
                v6.push(r);
                r
            };
            agg.add(r);
        }
        let out = agg.summarize();
        // IPv4 strictly before IPv6.
        let first_v6 = out
            .iter()
            .position(|p| p.family == Family::V6)
            .unwrap_or(out.len());
        assert!(out[first_v6..].iter().all(|p| p.family == Family::V6));
        check(Family::V4, &v4, &out);
        check(Family::V6, &v6, &out);
    });
}

#[test]
fn input_order_does_not_matter() {
    run_cases("input_order_does_not_matter", 500, |rng| {
        let base = rng.u128() & !0xfff;
        let ranges: Vec<Range> = (0..rng.range(1, 60))
            .map(|_| {
                let family = random_family(rng);
                random_range(rng, family, base)
            })
            .collect();
        let mut fwd = Aggregator::new();
        let mut rev = Aggregator::new();
        ranges.iter().for_each(|r| fwd.add(*r));
        ranges.iter().rev().for_each(|r| rev.add(*r));
        assert_eq!(fwd.summarize(), rev.summarize());
    });
}

#[test]
fn summarizing_output_again_is_stable() {
    run_cases("summarizing_output_again_is_stable", 500, |rng| {
        let base = rng.u128() & !0xfff;
        let mut agg = Aggregator::new();
        for _ in 0..rng.range(1, 100) {
            let family = random_family(rng);
            agg.add(random_range(rng, family, base));
        }
        let once = agg.summarize();
        let mut again = Aggregator::new();
        for p in &once {
            again.add_str(&p.to_string(), false).unwrap();
        }
        assert_eq!(once, again.summarize());
    });
}

#[test]
fn display_round_trips_through_parse() {
    run_cases("display_round_trips_through_parse", 5000, |rng| {
        let family = if rng.chance(50) {
            Family::V4
        } else {
            Family::V6
        };
        let len = rng.range(0, u64::from(family.bits())) as u8;
        let max = if family == Family::V4 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        let addr = rng.u128() & max & !host_mask(family, len);
        let p = Prefix { family, addr, len };
        let text = p.to_string();
        assert_eq!(parse_entry(&text, false), Ok(prefix_range(&p)), "{text}");
        // SPF form round-trips too.
        let spf = format!(
            "{}:{text}",
            if family == Family::V4 { "ip4" } else { "ip6" }
        );
        assert_eq!(parse_entry(&spf, true), Ok(prefix_range(&p)), "{spf}");
        // RFC 5952: lowercase, and never a `::` standing in for one group.
        if family == Family::V6 {
            assert!(!text.bytes().any(|b| b.is_ascii_uppercase()), "{text}");
            let addr_part = text.split('/').next().unwrap();
            if let Some((l, r)) = addr_part.split_once("::") {
                let groups = |s: &str| {
                    if s.is_empty() {
                        0
                    } else {
                        s.split(':').count()
                    }
                };
                assert!(
                    groups(l) + groups(r) <= 6,
                    "`::` replaces one group: {text}"
                );
            }
            for g in addr_part.split(':').filter(|g| !g.is_empty()) {
                assert!(g.len() == 1 || !g.starts_with('0'), "leading zero: {text}");
            }
        }
    });
}

#[test]
fn equivalent_spellings_parse_identically() {
    run_cases("equivalent_spellings_parse_identically", 2000, |rng| {
        let v = rng.u128();
        let len = rng.range(0, 128) as u8;
        let canonical = parse_entry(&format!("{}/{len}", addr_text(Family::V6, v)), false).unwrap();
        for spelling in [
            format!("{}/{len}", v6_exploded(v)),
            format!("{}/{len}", v6_exploded(v).to_uppercase()),
            format!("  {}/{len}\t", addr_text(Family::V6, v)),
            format!("IP6:{}/{len}", v6_exploded(v)),
        ] {
            let spf = spelling.trim_start().starts_with("IP6:");
            assert_eq!(parse_entry(&spelling, spf), Ok(canonical), "{spelling}");
        }
    });
}

#[test]
fn arbitrary_input_never_panics() {
    const ALPHABET: &[u8] = b"0123456789abcdefABCDEF.:/-% ip46\t#x";
    run_cases("arbitrary_input_never_panics", 20000, |rng| {
        let len = rng.below(48) as usize;
        let mut s: String = (0..len)
            .map(|_| ALPHABET[rng.below(ALPHABET.len() as u64) as usize] as char)
            .collect();
        if rng.chance(10) {
            // Random bytes, including non-ASCII, to exercise slicing on char boundaries.
            let bytes: Vec<u8> = (0..rng.below(16)).map(|_| rng.next() as u8).collect();
            s.push_str(&String::from_utf8_lossy(&bytes));
        }
        for spf in [false, true] {
            if let Ok(r) = parse_entry(&s, spf) {
                assert!(r.start <= r.end, "{s:?}");
                if r.family == Family::V4 {
                    assert!(r.end <= u128::from(u32::MAX), "{s:?}");
                }
            }
        }
    });
}
