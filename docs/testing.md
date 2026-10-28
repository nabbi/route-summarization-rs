# Testing

| Suite | What it checks |
|---|---|
| `src/lib.rs` unit tests | parsing, formatting, edge cases, each fixed quirk |
| `tests/cli.rs` | CLI behaviour; `tests/networks` is the Perl repo's fixture; `tests/exclude/` lists |
| `tests/fuzz.rs` | randomized properties against an independent oracle |
| `tests/differential.rs` | randomized comparison with the Perl script (opt-in) |

The fuzz harness uses no dependencies and runs with every `cargo test`. Each
case checks that the output covers exactly the input addresses, is minimal
(sorted, aligned, disjoint, no mergeable siblings), doesn't depend on input
order, and is stable when fed back in. With exclusions, the output must equal a
naive pairwise set difference computed separately from the library's sweep. For
`overlapping`, the result must equal a naive check of every pair, come out in
address order whatever the input order, and agree with the aggregator: the
unreported entries hold as many addresses as their union, and dropping a
reported entry leaves at least one of its addresses still covered. It also checks that formatting
round-trips through the parser and follows RFC 5952, and that arbitrary input
never panics.

```bash
FUZZ_ITERS=100000 cargo test --release --test fuzz        # longer run
FUZZ_SEED=<seed> FUZZ_ITERS=1 cargo test --test fuzz      # replay a failure
```

Seeds are time-based unless `FUZZ_SEED` is set; a failure prints the seed to
replay it.

The differential test needs Perl and `Net::CIDR::Lite`, and expects a checkout
of [the Perl repo](https://github.com/nabbi/route-summarization) next to this
one (or set `PERL_AGGREGATE`):

```bash
cargo test --release --test differential -- --ignored
PERL_AGGREGATE=/path/to/aggregateCIDR.pl FUZZ_ITERS=5000 cargo test --release --test differential -- --ignored
```

## Doctests and `noexec` /tmp

rustdoc builds doctests in the temp directory and runs them from there, so
they fail where `/tmp` is mounted `noexec`. `.cargo/config.toml` points
`TMPDIR` at `target/` for cargo commands in this repo to avoid that.
