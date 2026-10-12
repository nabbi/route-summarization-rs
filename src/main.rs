// SPDX-License-Identifier: GPL-3.0-or-later
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::process::ExitCode;

use route_summarization::{Aggregator, Family};

const USAGE: &str = "\
usage: aggregate-cidr [OPTIONS] [FILE...]

Aggregates IPv4/IPv6 CIDR prefixes into their minimal covering set.
Reads FILEs, or stdin when none are given (or for `-`).

Each line holds one entry: an address, a prefix (addr/len) or an
inclusive range (start-end). Text after `#` is a comment.

options:
  -h, --help     print usage
  -q, --quiet    suppress warnings and hints on stderr
  -s, --spf      accept SPF ip4:/ip6: entries and print in SPF form
  -V, --version  print version

Only prefixes are written to stdout; everything else goes to stderr.
";

struct Opts {
    quiet: bool,
    spf: bool,
    files: Vec<String>,
}

fn parse_args() -> Result<Option<Opts>, String> {
    let mut opts = Opts {
        quiet: false,
        spf: false,
        files: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("aggregate-cidr {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "-q" | "--quiet" => opts.quiet = true,
            "-s" | "--spf" => opts.spf = true,
            "--" => {
                opts.files.extend(args);
                break;
            }
            "-" => opts.files.push(arg),
            s if s.starts_with('-') => return Err(format!("unknown option: {s}")),
            _ => opts.files.push(arg),
        }
    }
    if opts.files.is_empty() {
        opts.files.push("-".into());
    }
    Ok(Some(opts))
}

fn read_into(
    agg: &mut Aggregator,
    name: &str,
    reader: impl BufRead,
    opts: &Opts,
) -> io::Result<()> {
    for (n, line) in reader.split(b'\n').enumerate() {
        let line = line?;
        let line = String::from_utf8_lossy(&line);
        let entry = line.split('#').next().unwrap_or_default().trim();
        if entry.is_empty() {
            continue;
        }
        if let Err(e) = agg.add_str(entry, opts.spf) {
            if !opts.quiet {
                eprintln!("{name}:{}: ignoring '{entry}': {e}", n + 1);
            }
        }
    }
    Ok(())
}

fn run(opts: &Opts) -> io::Result<()> {
    let mut agg = Aggregator::new();
    for name in &opts.files {
        if name == "-" {
            let stdin = io::stdin();
            if !opts.quiet && stdin.is_terminal() {
                eprintln!("# One IP/CIDR per line, e.g. 1.2.3.0/24 -- press CTRL+D when done.");
            }
            read_into(&mut agg, "<stdin>", stdin.lock(), opts)?;
        } else {
            let file =
                File::open(name).map_err(|e| io::Error::new(e.kind(), format!("{name}: {e}")))?;
            read_into(&mut agg, name, BufReader::new(file), opts)?;
        }
    }

    let mut out = io::BufWriter::new(io::stdout().lock());
    for p in agg.summarize() {
        if opts.spf {
            out.write_all(match p.family {
                Family::V4 => b"ip4:",
                Family::V6 => b"ip6:",
            })?;
        }
        writeln!(out, "{p}")?;
    }
    out.flush()
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(Some(o)) => o,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aggregate-cidr: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        // Downstream closed the pipe (e.g. `| head`); not an error.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aggregate-cidr: {e}");
            ExitCode::FAILURE
        }
    }
}
