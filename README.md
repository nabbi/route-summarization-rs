# CIDR Route Summarization (Rust)

`aggregate-cidr` collapses IPv4 and IPv6 prefixes into their minimal covering
set, with optional SPF `ip4:` / `ip6:` input and output. No dependencies.

A Rust rewrite of [nabbi/route-summarization](https://github.com/nabbi/route-summarization)
(Perl), with that version's quirks fixed.

```console
$ printf '10.0.0.0/24\n10.0.1.0/24\n2001:db8::1\n' | aggregate-cidr
10.0.0.0/23
2001:db8::1
```

To replace the Perl version in place, symlink it:
`ln -sf /usr/local/bin/aggregate-cidr /usr/local/bin/aggregateCIDR.pl`
([details and rollback](docs/perl-differences.md#switching-over)).

Also used as a library by [spf-flatten](https://github.com/nabbi/spf-flatten),
which flattens SPF records within the RFC 7208 lookup limits and aggregates the
resulting ranges with this crate.

## Install

With Homebrew (macOS or Linux), from the
[oubliette tap](https://github.com/nabbi/homebrew-oubliette):

```bash
brew install nabbi/oubliette/route-summarization
```

Or with Cargo, or from a checkout:

```bash
cargo install --locked route-summarization
cargo build --release --locked     # target/release/aggregate-cidr
cargo test
```

Requires Rust 1.85 or newer.

## Docs

- [Usage](docs/usage.md): options, input formats, output, library API
- [Migrating from the Perl version](docs/perl-differences.md): symlink switch-over, rollback, what changed
- [Testing](docs/testing.md): fuzz harness and the differential test against Perl
- [Deployment](docs/deployment.md): installing, and replacing the Perl version

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE), which also covers
attribution for the original concept. The Perl version remains MIT.
