# Deployment

## Build

```bash
cargo build --release --locked
install -m 0755 target/release/aggregate-cidr /usr/local/bin/
```

Or `cargo install --locked --path .` to install into `~/.cargo/bin`.

The binary has no runtime dependencies beyond libc. For a fully static binary
to copy between Linux hosts:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

Requires Rust 1.85 or newer (the `rust-version` in `Cargo.toml`, checked in CI).

## Replacing the Perl version

The command-line options match `aggregateCIDR.pl`, so existing integrations
that look the tool up by name (for example
[postwhite](https://github.com/nabbi/postwhite) and
[tcl-ipset](https://github.com/nabbi/tcl-ipset), which run
`which aggregateCIDR.pl`) can switch with a symlink:

```bash
ln -sf /usr/local/bin/aggregate-cidr /usr/local/bin/aggregateCIDR.pl
```

Step-by-step switch-over and rollback:
[Migrating from the Perl version](perl-differences.md#switching-over).

Check these two changes before switching
([full list](perl-differences.md)):

- **IPv6 host routes print without `/128`** (`2001:db8::1`), as IPv4 hosts
  already print without `/32`. postwhite's example Postfix tables already
  contain bare IPv6 entries, and ipset `hash:net` sets accept them (ipset
  lists host entries without `/128` itself).
- **Non-prefix output goes to stderr.** Without `-q`, the Perl version printed
  `#` header lines to stdout; this version prints only prefixes to stdout.
  Callers using `-q`, as postwhite and tcl-ipset do, see no difference. Tcl's
  `exec` treats any stderr output as an error, so keep `-q` there.

### Exclusion lists in tcl-ipset

tcl-ipset's `exclude` list (used by `ipset-denylists.tcl` to keep GitHub and
RFC 1918 space out of the denylist) is matched as exact strings after
summarizing, so an excluded address inside a larger entry is still blocked.
Passing the list to `--exclude` instead removes it exactly; see
[Exclusions](usage.md#exclusions).

### Verified integrations

- **postwhite:** on its bundled data (`yahoo_static_hosts.txt` and the example
  CIDR tables), output with `--quiet --spf` is byte-identical to the Perl
  version.
- **tcl-ipset:** running its `main` end to end (in an isolated network
  namespace) on about 2,700 mixed entries gave identical IPv4 host and network
  sets. The IPv6 set gained 4 networks that the Perl version silently lost:
  Perl prints them as `2001:558:fe14:76:68:87:28::/120`, with `::` standing in
  for a single zero group, which tcllib's `ip::is 6` (1.5.1) rejects, so
  tcl-ipset skipped them. This version prints the RFC 5952 form
  (`...:28:0/120`), which tcllib accepts.

## Exit status

| Code | Meaning |
|---|---|
| 0 | success; invalid lines were skipped (warned on stderr unless `-q`) |
| 1 | an input file could not be opened or read, or output failed |
| 2 | unknown option |

A closed stdout (for example `| head`) exits 0.
