# Migrating from the Perl version

Compared against [nabbi/route-summarization](https://github.com/nabbi/route-summarization):

| Behaviour | Perl | Rust |
|---|---|---|
| IPv6 with a first group below `1000` | `0001::/16` (Net::CIDR::Lite bug) | `1::/16` |
| A single zero group | compressed to `::` | written as `0` (RFC 5952 §4.2.2) |
| IPv6 host routes | `2001:db8::1/128` | `2001:db8::1` (matches IPv4) |
| Ranges (`a-b`) | IPv6 only, by accident | IPv4 and IPv6 |
| `ip4:` with an IPv6 value | accepted | rejected |
| `IP4:` uppercase SPF | not stripped | stripped (SPF is case-insensitive) |
| Hints and headers | stdout | stderr, and the hint only on a terminal |
| `#` comments | reported as invalid | ignored |
| File arguments | read (via Perl `<>`) | read, and `-` means stdin |

Zone IDs (`fe80::1%eth0`), IPv4 octets with leading zeros, and prefix lengths
with leading zeros (`/032`) are rejected, as in the Perl version.

Aggregation results are otherwise identical: randomized comparison
against the Perl script (`tests/differential.rs`) matches after normalizing
formatting.
On one million mixed prefixes, this version runs in about 0.25s; the Perl
version takes about 12.5s.
