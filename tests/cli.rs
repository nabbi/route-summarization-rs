// SPDX-License-Identifier: GPL-3.0-or-later
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aggregate-cidr"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The binary may exit before reading all of stdin (e.g. a fatal
    // --exclude error), so a broken pipe here is expected, not a failure.
    if let Err(e) = child.stdin.take().unwrap().write_all(input.as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    child.wait_with_output().unwrap()
}

fn stdout(args: &[&str], input: &str) -> String {
    String::from_utf8(run(args, input).stdout).unwrap()
}

#[test]
fn baseline_matches_expected() {
    let input = include_str!("networks");
    let expected = include_str!("networks.expected");
    assert_eq!(stdout(&["-q"], input), expected);
}

#[test]
fn stdout_holds_only_prefixes() {
    // Without -q, warnings go to stderr; stdout stays machine-readable.
    let out = run(&[], "10.0.0.0/24\nbogus\n");
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "10.0.0.0/24\n");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("<stdin>:2: ignoring 'bogus'"), "{err}");
    assert!(out.status.success());
}

#[test]
fn quiet_silences_stderr() {
    let out = run(&["--quiet"], "bogus\n");
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
}

#[test]
fn spf_round_trip() {
    let input =
        "ip4:10.0.0.0/25\nIP4:10.0.0.128/25\nip6:2001:db8::1\nip4:192.0.2.9\nip6:10.0.0.1\n";
    assert_eq!(
        stdout(&["--spf", "-q"], input),
        "ip4:10.0.0.0/24\nip4:192.0.2.9\nip6:2001:db8::1\n"
    );
}

#[test]
fn reads_files_and_stdin_dash() {
    let path = std::env::temp_dir().join(format!("aggregate-cidr-test-{}", std::process::id()));
    std::fs::write(&path, "10.0.0.0/24\n").unwrap();
    let out = stdout(&["-q", path.to_str().unwrap(), "-"], "10.0.1.0/24\n");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(out, "10.0.0.0/23\n");
}

#[test]
fn missing_file_fails() {
    let out = run(&["/nonexistent/aggregate-cidr"], "");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn unknown_option_is_usage_error() {
    let out = run(&["--bogus"], "");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn comments_are_stripped() {
    assert_eq!(
        stdout(&["-q"], "# header\n10.0.0.0/24  # office\n"),
        "10.0.0.0/24\n"
    );
}

#[test]
fn utf8_bom_is_ignored() {
    assert_eq!(stdout(&["-q"], "\u{feff}10.0.0.0/24\n"), "10.0.0.0/24\n");
}

#[test]
fn warnings_escape_control_characters_and_truncate() {
    let long = "x".repeat(500);
    let out = run(&[], &format!("bad\x1b[31mred\n{long}\n"));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(!err.contains('\x1b'), "{err:?}");
    assert!(err.contains(r"bad\u{1b}[31mred"), "{err:?}");
    let long_line = err.lines().find(|l| l.contains("xxx")).unwrap();
    assert!(
        long_line.len() < 200 && long_line.contains("..."),
        "{long_line}"
    );
}

#[test]
fn read_errors_name_the_file() {
    let out = run(&[env!("CARGO_MANIFEST_DIR")], "");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains(env!("CARGO_MANIFEST_DIR")), "{err}");
}

#[cfg(unix)]
#[test]
fn non_utf8_file_name_does_not_panic() {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::OsStr::from_bytes(b"/nonexistent/\xff");
    let out = Command::new(env!("CARGO_BIN_EXE_aggregate-cidr"))
        .arg(name)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn help_into_closed_pipe_does_not_panic() {
    // A pipe whose reader has already exited: writes fail with EPIPE every time.
    let mut sink = Command::new("true").stdin(Stdio::piped()).spawn().unwrap();
    let writer = sink.stdin.take().unwrap();
    sink.wait().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_aggregate-cidr"))
        .arg("--help")
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn fixture(name: &str) -> String {
    format!("{}/tests/exclude/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Total addresses covered by output lines (same family assumed).
fn address_count(out: &str) -> u128 {
    out.lines()
        .map(|l| {
            let r = route_summarization::parse_entry(l, false).unwrap();
            r.end() - r.start() + 1
        })
        .sum()
}

#[test]
fn exclude_fixes_tcl_ipset_bypass_cases() {
    // The cases where tcl-ipset's exact-string exclusion let addresses through.
    let excludes = std::env::temp_dir().join(format!("aggregate-cidr-ex-{}", std::process::id()));
    std::fs::write(&excludes, "140.82.112.3\n140.82.112.4\n").unwrap();
    let ex = excludes.to_str().unwrap();
    let rfc1918 = fixture("rfc1918.txt");
    let input =
        "140.82.112.2\n140.82.112.3\n140.82.112.0/24\n10.1.0.0/16\n10.0.0.0/8\n11.0.0.0/8\n";
    let out = stdout(&["-q", "-x", ex, "--exclude", &rfc1918], input);
    std::fs::remove_file(&excludes).unwrap();
    assert_eq!(
        out,
        "11.0.0.0/8\n140.82.112.0/31\n140.82.112.2\n140.82.112.5\n140.82.112.6/31\n\
         140.82.112.8/29\n140.82.112.16/28\n140.82.112.32/27\n140.82.112.64/26\n140.82.112.128/25\n"
    );
}

#[test]
fn exclude_rfc1918_fixture() {
    let input =
        "10.20.0.0/16\n172.31.255.255\n192.168.1.0/24\n8.8.8.8\n172.15.0.0/16\n172.32.0.0/16\n";
    let out = stdout(
        &["-q", &format!("--exclude={}", fixture("rfc1918.txt"))],
        input,
    );
    assert_eq!(out, "8.8.8.8\n172.15.0.0/16\n172.32.0.0/16\n");
}

#[test]
fn exclude_bogons_leaves_exact_public_space() {
    let out = stdout(&["-q", "-x", &fixture("bogons-ipv4.txt")], "0.0.0.0/0\n");
    let bogons = stdout(
        &["-q"],
        &std::fs::read_to_string(fixture("bogons-ipv4.txt")).unwrap(),
    );
    assert_eq!(address_count(&out) + address_count(&bogons), 1u128 << 32);
    for line in out.lines() {
        let r = route_summarization::parse_entry(line, false).unwrap();
        for b in bogons.lines() {
            let x = route_summarization::parse_entry(b, false).unwrap();
            assert!(
                r.end() < x.start() || r.start() > x.end(),
                "{line} overlaps {b}"
            );
        }
    }

    let out6 = stdout(
        &[
            "-q",
            "-x",
            &fixture("bogons-ipv6.txt"),
            "-x",
            &fixture("ipv6-local.txt"),
        ],
        "::/0\n",
    );
    let bogons6 = stdout(
        &["-q"],
        &std::fs::read_to_string(fixture("bogons-ipv6.txt")).unwrap(),
    );
    // ipv6-local.txt is a subset of bogons-ipv6.txt; 2^128 itself overflows u128.
    assert_eq!(
        address_count(&out6),
        u128::MAX - address_count(&bogons6) + 1
    );
}

#[test]
fn exclude_with_spf() {
    let ex = std::env::temp_dir().join(format!("aggregate-cidr-spf-{}", std::process::id()));
    std::fs::write(&ex, "ip4:192.0.2.128/25\nip6:2001:db8::1\n").unwrap();
    let out = stdout(
        &["-q", "--spf", "-x", ex.to_str().unwrap()],
        "ip4:192.0.2.0/24\nip6:2001:db8::/127\n",
    );
    std::fs::remove_file(&ex).unwrap();
    assert_eq!(out, "ip4:192.0.2.0/25\nip6:2001:db8::\n");
}

#[test]
fn invalid_exclusion_is_fatal_even_when_quiet() {
    let ex = std::env::temp_dir().join(format!("aggregate-cidr-bad-{}", std::process::id()));
    std::fs::write(&ex, "10.0.0.0/8\n10.0.0.0/33\n").unwrap();
    let out = run(&["-q", "-x", ex.to_str().unwrap()], "10.0.0.0/7\n");
    std::fs::remove_file(&ex).unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "must not write partial output");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains(":2: invalid exclusion '10.0.0.0/33'"), "{err}");
}

#[test]
fn exclude_usage_errors() {
    assert_eq!(run(&["-x"], "").status.code(), Some(2));
    assert_eq!(run(&["-x", "-"], "").status.code(), Some(2)); // stdin used twice
    assert_eq!(
        run(&["-x", "/nonexistent/aggregate-cidr"], "")
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn exclude_from_stdin_with_file_input() {
    let input = std::env::temp_dir().join(format!("aggregate-cidr-in-{}", std::process::id()));
    std::fs::write(&input, "10.0.0.0/30\n").unwrap();
    let out = stdout(&["-q", "-x", "-", input.to_str().unwrap()], "10.0.0.0\n");
    std::fs::remove_file(&input).unwrap();
    assert_eq!(out, "10.0.0.1\n10.0.0.2/31\n");
}
