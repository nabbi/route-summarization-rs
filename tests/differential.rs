// SPDX-License-Identifier: GPL-3.0-or-later
//! Differential fuzzing against the original Perl script.
//!
//! Ignored by default because it needs Perl and Net::CIDR::Lite:
//!   cargo test --test differential -- --ignored
//!   PERL_AGGREGATE=/path/to/aggregateCIDR.pl FUZZ_ITERS=5000 cargo test --release --test differential -- --ignored
//!
//! Inputs are limited to forms both versions accept identically (hosts and
//! prefixes, no ranges or SPF), and outputs are compared after normalizing
//! formatting, since the Rust version deliberately prints RFC 5952 IPv6 and
//! bare IPv6 host routes.

mod common;

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use common::{Rng, addr_text, run_cases, v6_exploded};
use route_summarization::Family;

fn perl_script() -> String {
    std::env::var("PERL_AGGREGATE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../route-summarization/aggregateCIDR.pl"
        )
        .into()
    })
}

fn run(cmd: &mut Command, input: &str) -> String {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{cmd:?} failed");
    String::from_utf8(out.stdout).unwrap()
}

/// Parse each output line to (address, length) so formatting differences vanish.
fn normalize(out: &str) -> Vec<(IpAddr, u8)> {
    out.lines()
        .map(|l| {
            let (a, len) = l.split_once('/').unwrap_or((l, ""));
            let ip: IpAddr = a
                .parse()
                .unwrap_or_else(|_| panic!("unparseable output {l:?}"));
            let len = if len.is_empty() {
                if ip.is_ipv4() { 32 } else { 128 }
            } else {
                len.parse().unwrap()
            };
            (ip, len)
        })
        .collect()
}

fn random_input(rng: &mut Rng) -> String {
    let base4 = rng.next() as u32 & 0xffff_0000;
    let base6 = rng.u128() & !0xf_ffff;
    let mut s = String::new();
    for _ in 0..rng.range(1, 300) {
        if rng.chance(50) {
            let a = u128::from(base4 | (rng.next() as u32 & 0xffff));
            if rng.chance(20) {
                s += &addr_text(Family::V4, a);
            } else {
                s += &format!("{}/{}", addr_text(Family::V4, a), rng.range(16, 32));
            }
        } else {
            let a = base6 | u128::from(rng.next() as u32 & 0xf_ffff);
            let text = if rng.chance(50) {
                addr_text(Family::V6, a)
            } else {
                v6_exploded(a)
            };
            if rng.chance(20) {
                s += &text;
            } else {
                s += &format!("{text}/{}", rng.range(108, 128));
            }
        }
        s.push('\n');
    }
    s
}

#[test]
#[ignore = "needs perl and Net::CIDR::Lite; run with --ignored"]
fn matches_perl_after_normalizing() {
    let script = perl_script();
    assert!(
        std::path::Path::new(&script).exists(),
        "Perl script not found at {script}; set PERL_AGGREGATE"
    );
    run_cases("matches_perl_after_normalizing", 300, |rng| {
        let input = random_input(rng);
        let perl = run(Command::new("perl").args([&script, "-q"]), &input);
        let rust = run(
            Command::new(env!("CARGO_BIN_EXE_aggregate-cidr")).arg("-q"),
            &input,
        );
        assert_eq!(normalize(&perl), normalize(&rust), "input:\n{input}");
    });
}
