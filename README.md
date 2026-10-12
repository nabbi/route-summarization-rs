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

## Build

```bash
cargo build --release     # target/release/aggregate-cidr
cargo test
```

## Docs

- [Usage](docs/usage.md): options, input formats, output, library API
- [Migrating from the Perl version](docs/perl-differences.md): what changed and why
- [Testing](docs/testing.md): fuzz harness and the differential test against Perl

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE), which also covers
attribution for the original concept. The Perl version remains MIT.
