// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared helpers for the randomized test harnesses.
#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use route_summarization::{Family, Prefix, Range};

/// xorshift64* — small, deterministic, dependency-free.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    pub fn u128(&mut self) -> u128 {
        (u128::from(self.next()) << 64) | u128::from(self.next())
    }

    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

/// Seed from `FUZZ_SEED`, else time-based so repeated runs explore new inputs.
pub fn seed() -> u64 {
    std::env::var("FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        })
}

/// Iteration count from `FUZZ_ITERS`, else `default`.
pub fn iters(default: usize) -> usize {
    std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Run `body` with a fresh seed per case; on panic, report how to replay it.
pub fn run_cases(name: &str, default_iters: usize, mut body: impl FnMut(&mut Rng)) {
    let base = seed();
    for i in 0..iters(default_iters) {
        let case_seed = base.wrapping_add(i as u64);
        let mut rng = Rng::new(case_seed);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mut rng)));
        if let Err(e) = result {
            eprintln!("{name}: failed at case {i}; replay with FUZZ_SEED={case_seed} FUZZ_ITERS=1");
            std::panic::resume_unwind(e);
        }
    }
}

pub fn host_mask(family: Family, len: u8) -> u128 {
    let host_bits = u32::from(family.bits() - len);
    if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    }
}

pub fn prefix_range(p: &Prefix) -> Range {
    Range {
        family: p.family,
        start: p.addr,
        end: p.addr | host_mask(p.family, p.len),
    }
}

/// Union of inclusive intervals, merged where they overlap or touch.
pub fn union(mut v: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    v.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::new();
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if last.1 == u128::MAX || s <= last.1 + 1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

pub fn addr_text(family: Family, v: u128) -> String {
    match family {
        Family::V4 => Ipv4Addr::from(v as u32).to_string(),
        Family::V6 => Ipv6Addr::from(v).to_string(),
    }
}

/// Fully expanded IPv6 (`2001:0db8:0000:...`), the form least like the output.
pub fn v6_exploded(v: u128) -> String {
    (0..8)
        .map(|i| format!("{:04x}", (v >> (112 - 16 * i)) as u16))
        .collect::<Vec<_>>()
        .join(":")
}
