# Migrating from the Perl version

## Switching over

The command-line options match `aggregateCIDR.pl`, so anything that runs the
Perl script by name (postwhite and tcl-ipset use `which aggregateCIDR.pl`)
can switch with a symlink. No caller changes are needed.

1. Install the binary (see [Deployment](deployment.md)):

   ```bash
   cargo build --release --locked
   sudo install -m 0755 target/release/aggregate-cidr /usr/local/bin/
   ```

2. Check what `aggregateCIDR.pl` points to now, so you can roll back:

   ```bash
   ls -l "$(which aggregateCIDR.pl)"
   ```

3. Point the old name at the new binary:

   ```bash
   sudo ln -sf /usr/local/bin/aggregate-cidr /usr/local/bin/aggregateCIDR.pl
   ```

4. Confirm:

   ```bash
   printf 'ip4:10.0.0.0/25\nip4:10.0.0.128/25\n' | aggregateCIDR.pl --quiet --spf
   # ip4:10.0.0.0/24
   aggregateCIDR.pl --version
   # aggregate-cidr 0.1.0
   ```

To roll back, point the symlink at the Perl script again, using the target
from step 2. With the Perl repo's [INSTALL.md](https://github.com/nabbi/route-summarization/blob/master/INSTALL.md)
layout, that is:

```bash
sudo ln -sf /usr/local/bin/route-summarization/aggregateCIDR.pl /usr/local/bin/aggregateCIDR.pl
```

Review the behaviour changes below first. The two most likely to matter for
existing integrations are bare IPv6 host routes (no `/128`) and header lines
moving to stderr; see [Deployment](deployment.md#replacing-the-perl-version).

## Behaviour changes

Compared against [nabbi/route-summarization](https://github.com/nabbi/route-summarization):

| Behaviour | Perl | Rust |
|---|---|---|
| IPv6 with a first group below `1000` | `0001::/16` (Net::CIDR::Lite bug) | `1::/16` |
| A single zero group | compressed to `::`, which tcllib's `ip::is 6` rejects, so tcl-ipset drops the entry | written as `0` (RFC 5952 §4.2.2) |
| IPv6 host routes | `2001:db8::1/128` | `2001:db8::1` (matches IPv4) |
| Ranges (`a-b`) | IPv6 only, by accident | IPv4 and IPv6 |
| `ip4:` with an IPv6 value | accepted | rejected |
| `IP4:` uppercase SPF | not stripped | stripped (SPF is case-insensitive) |
| Hints and headers | stdout | stderr, and the hint only on a terminal |
| `#` comments | reported as invalid | ignored |
| File arguments | read (via Perl `<>`) | read, and `-` means stdin |
| Exclusions | not supported | `--exclude FILE`, exact set subtraction |

Zone IDs (`fe80::1%eth0`), IPv4 octets with leading zeros, and prefix lengths
with leading zeros (`/032`) are rejected, as in the Perl version.

Aggregation results are otherwise identical: randomized comparison
against the Perl script (`tests/differential.rs`) matches after normalizing
formatting.
On one million mixed prefixes, this version runs in about 0.25s; the Perl
version takes about 12.5s.
