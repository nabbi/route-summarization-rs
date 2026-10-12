# Usage

## Command line

```bash
aggregate-cidr < cidr.txt
aggregate-cidr --spf spf-a.txt spf-b.txt
cat list.txt | aggregate-cidr -q -        # `-` reads stdin
```

```text
-h, --help     print usage
-q, --quiet    suppress warnings and hints on stderr
-s, --spf      accept SPF ip4:/ip6: entries and print in SPF form
-V, --version  print version
```

Only prefixes go to stdout. Warnings name the file and line of each rejected
entry. Exit status: `0` success (invalid lines are skipped), `1` I/O error,
`2` bad option.

## Input

One entry per line; anything after `#` is a comment.

```text
192.0.2.1                    # host
192.0.2.0/24                 # prefix (host bits are masked: 10.1.2.3/8 -> 10.0.0.0/8)
198.51.100.10-198.51.100.20  # inclusive range, IPv4 or IPv6
2001:db8:10::/48
ip4:203.0.113.0/25           # with --spf (case-insensitive)
```

## Output

Minimal CIDR set, IPv4 first, then IPv6, each in address order. Host routes are
printed as bare addresses in both families. IPv6 is formatted per
[RFC 5952](https://www.rfc-editor.org/rfc/rfc5952).

## Library

```rust
use route_summarization::Aggregator;

let mut agg = Aggregator::new();
agg.add_str("10.0.0.0/24", false)?;
agg.add_str("10.0.1.0/24", false)?;
for prefix in agg.summarize() {
    println!("{prefix}"); // 10.0.0.0/23
}
```
