# Testing

| Suite | What it checks |
|---|---|
| `src/lib.rs` unit tests | parsing, formatting, edge cases, each fixed quirk |
| `tests/cli.rs` | CLI behaviour; `tests/networks` is the Perl repo's fixture |
| `tests/fuzz.rs` | randomized properties against an independent oracle |
| `tests/differential.rs` | randomized comparison with the Perl script (opt-in) |

The fuzz harness uses no dependencies and runs with every `cargo test`. Each
case checks that the output covers exactly the input addresses, is minimal
(sorted, aligned, disjoint, no mergeable siblings), doesn't depend on input
order, and is stable when fed back in. It also checks that formatting
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
