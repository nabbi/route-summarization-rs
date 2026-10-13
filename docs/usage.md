# Usage

## Command line

```bash
aggregate-cidr < cidr.txt
aggregate-cidr --spf spf-a.txt spf-b.txt
cat list.txt | aggregate-cidr -q -        # `-` reads stdin
aggregate-cidr -x tests/exclude/rfc1918.txt denylist.txt
```

```text
-x, --exclude FILE  remove the addresses listed in FILE from the output,
                    splitting any prefix that overlaps them; repeatable
-h, --help          print usage
-q, --quiet         suppress warnings and hints on stderr
-s, --spf           accept SPF ip4:/ip6: entries and print in SPF form
-V, --version       print version
```

Only prefixes go to stdout. Warnings name the file and line of each rejected
entry. Exit status: `0` success (invalid input lines are skipped), `1` I/O
error or invalid exclusion, `2` bad option.

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

## Exclusions

`--exclude FILE` removes addresses from the output. FILE uses the same format
as input (hosts, prefixes, ranges, comments, and `ip4:`/`ip6:` with `--spf`).
Give it more than once to combine lists, or `-` to read exclusions from stdin
when the input comes from files.

Exclusion is set subtraction on addresses: the output covers exactly the
input addresses minus the excluded ones, written as the fewest prefixes. It
doesn't depend on how entries are written, merged or ordered:

| Input | Exclude | Output |
|---|---|---|
| `140.82.112.2`, `140.82.112.3` | `140.82.112.3` | `140.82.112.2` |
| `140.82.112.0/24` | `140.82.112.3`, `140.82.112.4` | 9 prefixes: `.0/31`, `.2`, `.5`, `.6/31` ... `.128/25` |
| `10.0.0.0/8`, `11.0.0.0/8` | `10.0.0.0/8` | `11.0.0.0/8` |
| `10.1.0.0/16` | `10.0.0.0/8` | nothing |
| `10.0.0.0/24` | `10.0.1.0/24` (adjacent) | `10.0.0.0/24` |

### Why exclusions split prefixes

Matching exclusions against output strings, as tcl-ipset did before it
switched to `--exclude`, misses an excluded address whenever it is inside a
larger entry: `140.82.112.3` never equals `140.82.112.2/31` or
`140.82.112.0/24`, so it gets blocked anyway.
Summarizing makes this more likely, but it isn't the cause: a `/24` on the
input list has the same problem with no summarizing at all.

An entry that partly overlaps an exclusion leaves three choices: keep it
(the excluded address is still listed), drop it (every other address in it
is lost too), or split it. Only splitting is exact, so that is what this
tool does. Since an overlapping entry must be split anyway, there is no
separate "normalize without summarizing" mode; the split output is already
the minimal form.

### Invalid exclusions are errors

An invalid input line is skipped with a warning, but an invalid exclusion
stops the run with exit status `1` and no output, even with `-q`. An
exclusion list protects addresses that must never appear in the output, so
silently skipping a typo would put them back in.

### Example lists

`tests/exclude/` has ready-made lists, each entry commented with its RFC:

| File | Contents |
|---|---|
| `rfc1918.txt` | IPv4 private space: `10/8`, `172.16/12`, `192.168/16` |
| `ipv6-local.txt` | IPv6 loopback, link-local and unique local (`fc00::/7`) |
| `bogons-ipv4.txt` | IPv4 special-purpose, documentation, multicast and reserved space |
| `bogons-ipv6.txt` | IPv6 special-purpose, documentation, unique local, link-local and multicast |

The tests check that, for example, `0.0.0.0/0` minus `bogons-ipv4.txt`
covers exactly the remaining public space, with no overlap.

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

`parse_entry` turns one input line into a `Range`, and `Aggregator::add` takes
ranges directly. `Aggregator::exclude` and `exclude_str` subtract ranges, in
any order relative to `add`. `Range::new`, `Range::from_ips` and `Prefix::new` validate
their arguments and return `None` for values outside the address family, so
an invalid range or prefix cannot be constructed. `summarize` returns
`Prefix` values; use `network()`, `prefix_len()`, `family()` and `range()` to
inspect them, or `Display` for the formatted text.
