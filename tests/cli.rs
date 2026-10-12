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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
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
