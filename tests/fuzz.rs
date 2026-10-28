// SPDX-License-Identifier: GPL-3.0-or-later
//! Randomized property tests against an independent oracle.
//!
//! Runs as part of `cargo test`. Tune with:
//!   FUZZ_ITERS=100000 cargo test --release --test fuzz
//!   FUZZ_SEED=1234 FUZZ_ITERS=1 cargo test --test fuzz   # replay a failure

mod common;

use common::{Rng, addr_text, host_mask, run_cases, union, v6_exploded};
use route_summarization::{Aggregator, Family, Prefix, Range, overlapping, parse_entry};

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
        return Range::new(family, addr, end).unwrap();
    }
    let len = if rng.chance(3) {
        rng.range(0, bits)
    } else {
        rng.range(bits - 14, bits)
    } as u8;
    let host = host_mask(family, len);
    Range::new(family, addr & !host, (addr & !host) | host).unwrap()
}

/// Exact: output covers precisely the input addresses.
/// Minimal: blocks are sorted, disjoint and aligned, and no two are siblings.
/// (Any coverable parent block would contain a sibling pair at its deepest
/// split, so "no siblings" implies no merge is possible.)
fn check(family: Family, input: &[Range], out: &[Prefix]) {
    check_against(family, union(intervals(input)), out);
}

fn intervals(rs: &[Range]) -> Vec<(u128, u128)> {
    rs.iter().map(|r| (r.start(), r.end())).collect()
}

/// Naive set difference, written independently of the library's sweep: chop
/// every exclusion out of every interval, one pair at a time.
fn naive_subtract(mut set: Vec<(u128, u128)>, exclude: &[(u128, u128)]) -> Vec<(u128, u128)> {
    for &(xs, xe) in exclude {
        let mut next = Vec::new();
        for (s, e) in set {
            if xe < s || xs > e {
                next.push((s, e));
                continue;
            }
            if s < xs {
                next.push((s, xs - 1));
            }
            if e > xe {
                next.push((xe + 1, e));
            }
        }
        set = next;
    }
    union(set)
}

fn check_against(family: Family, want: Vec<(u128, u128)>, out: &[Prefix]) {
    let got_blocks: Vec<Range> = out
        .iter()
        .filter(|p| p.family() == family)
        .map(Prefix::range)
        .collect();
    let got = union(got_blocks.iter().map(|r| (r.start(), r.end())).collect());
    assert_eq!(want, got, "{family:?} coverage differs");

    let ps: Vec<&Prefix> = out.iter().filter(|p| p.family() == family).collect();
    for p in &ps {
        let (addr, len) = (p.range().start(), p.prefix_len());
        assert!(len <= family.bits());
        assert_eq!(addr & host_mask(family, len), 0, "unaligned {p}");
    }
    for w in got_blocks.windows(2) {
        assert!(w[0].end() < w[1].start(), "unsorted or overlapping output");
    }
    for w in ps.windows(2) {
        let (a, b) = (w[0], w[1]);
        let (len, a_addr, b_addr) = (a.prefix_len(), a.range().start(), b.range().start());
        let sibling =
            len == b.prefix_len() && len > 0 && a_addr ^ b_addr == 1u128 << (family.bits() - len);
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
            .position(|p| p.family() == Family::V6)
            .unwrap_or(out.len());
        assert!(out[first_v6..].iter().all(|p| p.family() == Family::V6));
        check(Family::V4, &v4, &out);
        check(Family::V6, &v6, &out);
    });
}

#[test]
fn exclusion_is_exact_set_difference() {
    run_cases("exclusion_is_exact_set_difference", 2000, |rng| {
        let base4 = u128::from(rng.next() as u32) & !0xfff;
        let base6 = rng.u128() & !0xfff;
        let mut agg = Aggregator::new();
        let (mut inc4, mut inc6, mut exc4, mut exc6) = (vec![], vec![], vec![], vec![]);
        // Calls interleave in random order; the result must not depend on it.
        for _ in 0..rng.range(1, 150) {
            let family = random_family(rng);
            let base = if family == Family::V4 { base4 } else { base6 };
            let r = random_range(rng, family, base);
            let excluding = rng.chance(35);
            match (excluding, family) {
                (false, Family::V4) => inc4.push(r),
                (false, Family::V6) => inc6.push(r),
                (true, Family::V4) => exc4.push(r),
                (true, Family::V6) => exc6.push(r),
            }
            if excluding {
                agg.exclude(r);
            } else {
                agg.add(r);
            }
        }
        let out = agg.summarize();
        let want4 = naive_subtract(union(intervals(&inc4)), &intervals(&exc4));
        let want6 = naive_subtract(union(intervals(&inc6)), &intervals(&exc6));
        check_against(Family::V4, want4, &out);
        check_against(Family::V6, want6, &out);
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

/// A mixed-family list of clustered ranges, with some exact duplicates.
fn random_list(rng: &mut Rng, max: u64) -> Vec<Range> {
    let base4 = u128::from(rng.next() as u32) & !0xfff;
    let base6 = rng.u128() & !0xfff;
    let mut ranges: Vec<Range> = Vec::new();
    for _ in 0..rng.range(0, max) {
        if !ranges.is_empty() && rng.chance(5) {
            let dup = ranges[rng.below(ranges.len() as u64) as usize];
            ranges.push(dup);
            continue;
        }
        let family = random_family(rng);
        let base = if family == Family::V4 { base4 } else { base6 };
        ranges.push(random_range(rng, family, base));
    }
    ranges
}

fn shares_address(a: Range, b: Range) -> bool {
    a.family() == b.family() && a.start() <= b.end() && b.start() <= a.end()
}

#[test]
fn overlap_matches_pairwise_oracle() {
    run_cases("overlap_matches_pairwise_oracle", 2000, |rng| {
        let ranges = random_list(rng, 120);
        let got = overlapping(&ranges);

        // Exactly the entries that share an address with some other entry.
        let want: Vec<usize> = (0..ranges.len())
            .filter(|&i| (0..ranges.len()).any(|j| j != i && shares_address(ranges[i], ranges[j])))
            .collect();
        let mut sorted = got.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, want, "{ranges:?}");

        // Each index once, in (family, start, wider first) order.
        sorted.dedup();
        assert_eq!(sorted.len(), got.len(), "duplicate index");
        for w in got.windows(2) {
            let (a, b) = (ranges[w[0]], ranges[w[1]]);
            let key = |r: Range| (r.family(), r.start(), std::cmp::Reverse(r.end()));
            assert!(key(a) <= key(b), "out of order: {a:?} before {b:?}");
        }
    });
}

#[test]
fn overlap_does_not_depend_on_input_order() {
    run_cases("overlap_does_not_depend_on_input_order", 1000, |rng| {
        let ranges = random_list(rng, 80);
        let mut shuffled = ranges.clone();
        for i in (1..shuffled.len()).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            shuffled.swap(i, j);
        }
        let pick =
            |rs: &[Range]| -> Vec<Range> { overlapping(rs).into_iter().map(|i| rs[i]).collect() };
        // Equal entries may swap places, but the printed list is the same.
        assert_eq!(pick(&ranges), pick(&shuffled));
    });
}

/// Address count, or `None` for a whole IPv6 space (2^128).
fn size(r: Range) -> Option<u128> {
    (r.end() - r.start()).checked_add(1)
}

/// Total addresses in disjoint ranges, or `None` if it exceeds u128.
fn total(rs: impl Iterator<Item = Range>) -> Option<u128> {
    rs.into_iter()
        .try_fold(0u128, |acc, r| acc.checked_add(size(r)?))
}

#[test]
fn overlap_agrees_with_aggregation() {
    // Checked through the aggregator, independently of the sweep: the
    // unreported entries are pairwise disjoint (their union holds as many
    // addresses as their sizes add up to), and removing a reported entry
    // uncovers fewer addresses than it holds (it shares one with the rest).
    run_cases("overlap_agrees_with_aggregation", 1000, |rng| {
        let ranges = random_list(rng, 80);
        let hit = overlapping(&ranges);
        for family in [Family::V4, Family::V6] {
            let rest: Vec<(u128, u128)> = (0..ranges.len())
                .filter(|i| !hit.contains(i) && ranges[*i].family() == family)
                .map(|i| (ranges[i].start(), ranges[i].end()))
                .collect();
            let mut agg = Aggregator::new();
            rest.iter()
                .for_each(|&(s, e)| agg.add(Range::new(family, s, e).unwrap()));
            let covered = total(agg.summarize().iter().map(Prefix::range));
            let summed = rest.iter().try_fold(0u128, |acc, &(s, e)| {
                acc.checked_add(size(Range::new(family, s, e).unwrap())?)
            });
            // Skipped when a count exceeds u128 (only a whole ::/0 or more).
            if let (Some(a), Some(b)) = (summed, covered) {
                assert_eq!(a, b, "{family:?} unreported entries overlap");
            }
        }
        for &i in &hit {
            let mut others = Aggregator::new();
            let mut all = Aggregator::new();
            for (j, r) in ranges.iter().enumerate() {
                all.add(*r);
                if j != i {
                    others.add(*r);
                }
            }
            let family = ranges[i].family();
            let count = |a: &Aggregator| {
                total(
                    a.summarize()
                        .iter()
                        .filter(|p| p.family() == family)
                        .map(Prefix::range),
                )
            };
            if let (Some(with), Some(without)) = (count(&all), count(&others)) {
                // `end - start` is the size minus one: at least one address
                // of the entry is still covered by the others.
                let r = ranges[i];
                assert!(
                    with - without <= r.end() - r.start(),
                    "{r:?} shares nothing"
                );
            }
        }
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
        let p = Prefix::new(family, addr, len).unwrap();
        let text = p.to_string();
        assert_eq!(parse_entry(&text, false), Ok(p.range()), "{text}");
        // SPF form round-trips too.
        let spf = format!(
            "{}:{text}",
            if family == Family::V4 { "ip4" } else { "ip6" }
        );
        assert_eq!(parse_entry(&spf, true), Ok(p.range()), "{spf}");
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
                assert!(r.start() <= r.end(), "{s:?}");
                if r.family() == Family::V4 {
                    assert!(r.end() <= u128::from(u32::MAX), "{s:?}");
                }
            }
        }
    });
}
