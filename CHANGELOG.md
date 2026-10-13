# Changelog

## 0.1.0 - 2026-10-12

First release: a Rust rewrite of
[route-summarization](https://github.com/nabbi/route-summarization) (Perl).
See [docs/perl-differences.md](docs/perl-differences.md) for behaviour changes.

- `--exclude FILE`: subtract addresses from the output, splitting prefixes
  that overlap them. Invalid exclusions are fatal.
- Example exclusion lists in `tests/exclude/` (RFC 1918, IPv6 local, bogons).
