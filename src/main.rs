// SPDX-License-Identifier: GPL-3.0-or-later
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use route_summarization::{Aggregator, Family, overlapping, parse_entry};

const USAGE: &str = "\
usage: aggregate-cidr [OPTIONS] [FILE...]

Aggregates IPv4/IPv6 CIDR prefixes into their minimal covering set.
Reads FILEs, or stdin when none are given (or for `-`).

Each line holds one entry: an address, a prefix (addr/len) or an
inclusive range (start-end). Text after `#` is a comment.

options:
  -x, --exclude FILE  remove the addresses listed in FILE from the output,
                      splitting any prefix that overlaps them; repeatable.
                      An invalid entry in FILE is an error, not skipped.
  -h, --help          print usage
  -o, --overlap       instead of summarizing, print only the input entries
                      that share an address with another entry (one inside
                      another, partial overlap, or a duplicate), as written,
                      in address order
  -q, --quiet         suppress warnings and hints on stderr
  -s, --spf           accept SPF ip4:/ip6: entries and print in SPF form
  -V, --version       print version

Only prefixes (or, with --overlap, entries) are written to stdout; everything else goes to stderr.
";

/// Longest slice of a rejected entry echoed in a warning.
const ECHO_MAX: usize = 80;

enum Action {
    Run(Opts),
    Print(String),
}

/// A file to read; `None` is stdin.
type Input = Option<PathBuf>;

struct Opts {
    quiet: bool,
    spf: bool,
    overlap: bool,
    inputs: Vec<Input>,
    excludes: Vec<Input>,
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Action, String> {
    let mut opts = Opts {
        quiet: false,
        spf: false,
        overlap: false,
        inputs: Vec::new(),
        excludes: Vec::new(),
    };
    let mut args = args.into_iter();
    let input = |a: OsString| (a != "-").then(|| PathBuf::from(a));
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(Action::Print(USAGE.into())),
            Some("-V" | "--version") => {
                let version = concat!("aggregate-cidr ", env!("CARGO_PKG_VERSION"), "\n");
                return Ok(Action::Print(version.into()));
            }
            Some("-o" | "--overlap") => opts.overlap = true,
            Some("-q" | "--quiet") => opts.quiet = true,
            Some("-s" | "--spf") => opts.spf = true,
            Some("-x" | "--exclude") => match args.next() {
                Some(file) => opts.excludes.push(input(file)),
                None => return Err("--exclude needs a FILE".into()),
            },
            Some(s) if s.starts_with("--exclude=") => {
                opts.excludes.push(input(s["--exclude=".len()..].into()));
            }
            Some("--") => {
                opts.inputs.extend(args.map(input));
                break;
            }
            Some(s) if s.starts_with('-') && s != "-" => {
                return Err(format!("unknown option: {s}"));
            }
            _ => opts.inputs.push(input(arg)),
        }
    }
    if opts.inputs.is_empty() {
        opts.inputs.push(None);
    }
    if opts.overlap && !opts.excludes.is_empty() {
        return Err("--overlap cannot be combined with --exclude".into());
    }
    if opts.inputs.contains(&None) && opts.excludes.contains(&None) {
        return Err("stdin cannot be both an input and an exclude list".into());
    }
    Ok(Action::Run(opts))
}

/// Quote an untrusted entry for a warning: escape control characters (no
/// terminal escape injection) and cap the length.
fn echo(entry: &str) -> String {
    let escaped: String = entry.escape_debug().collect();
    match escaped.char_indices().nth(ECHO_MAX) {
        Some((i, _)) => format!("{}...", &escaped[..i]),
        None => escaped,
    }
}

/// Call `f` with the 1-based line number and entry of each line that is not
/// blank or a comment.
fn for_each_entry(reader: impl BufRead, mut f: impl FnMut(usize, &str)) -> io::Result<()> {
    for (n, line) in reader.split(b'\n').enumerate() {
        let line = line?;
        let line = String::from_utf8_lossy(&line);
        let line = if n == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            &line
        };
        let entry = line.split('#').next().unwrap_or_default().trim();
        if !entry.is_empty() {
            f(n + 1, entry);
        }
    }
    Ok(())
}

fn with_name(name: &str) -> impl FnOnce(io::Error) -> io::Error + '_ {
    move |e| io::Error::new(e.kind(), format!("{name}: {e}"))
}

/// Open an input for reading, with the name to use in messages.
fn open(input: &Input, quiet: bool, what: &str) -> io::Result<(String, Box<dyn BufRead>)> {
    match input {
        None => {
            let stdin = io::stdin();
            if !quiet && stdin.is_terminal() {
                eprintln!(
                    "# {what}: one IP/CIDR per line, e.g. 1.2.3.0/24 -- press CTRL+D when done."
                );
            }
            Ok(("<stdin>".into(), Box::new(stdin.lock())))
        }
        Some(path) => {
            let name = path.display().to_string();
            let file = File::open(path).map_err(with_name(&name))?;
            Ok((name, Box::new(BufReader::new(file))))
        }
    }
}

/// Print the input entries that overlap another entry, as written.
fn run_overlap(opts: &Opts) -> io::Result<()> {
    let (mut ranges, mut entries) = (Vec::new(), Vec::new());
    for input in &opts.inputs {
        let (name, reader) = open(input, opts.quiet, "input")?;
        for_each_entry(reader, |n, entry| match parse_entry(entry, opts.spf) {
            Ok(r) => {
                ranges.push(r);
                entries.push(entry.to_owned());
            }
            Err(e) if !opts.quiet => eprintln!("{name}:{n}: ignoring '{}': {e}", echo(entry)),
            Err(_) => {}
        })
        .map_err(with_name(&name))?;
    }

    let mut out = io::BufWriter::new(io::stdout().lock());
    for i in overlapping(&ranges) {
        writeln!(out, "{}", entries[i])?;
    }
    out.flush()
}

fn run(opts: &Opts) -> io::Result<()> {
    if opts.overlap {
        return run_overlap(opts);
    }
    let mut agg = Aggregator::new();

    // Exclusions first, so a bad exclude list fails before any input is read.
    let mut bad_excludes = 0;
    for input in &opts.excludes {
        let (name, reader) = open(input, opts.quiet, "exclusions")?;
        for_each_entry(reader, |n, entry| {
            if let Err(e) = agg.exclude_str(entry, opts.spf) {
                // Always reported: skipping it would leave the address in the output.
                eprintln!("{name}:{n}: invalid exclusion '{}': {e}", echo(entry));
                bad_excludes += 1;
            }
        })
        .map_err(with_name(&name))?;
    }
    if bad_excludes > 0 {
        return Err(io::Error::other(format!(
            "{bad_excludes} invalid exclusion(s); no output written"
        )));
    }

    for input in &opts.inputs {
        let (name, reader) = open(input, opts.quiet, "input")?;
        for_each_entry(reader, |n, entry| {
            if let Err(e) = agg.add_str(entry, opts.spf) {
                if !opts.quiet {
                    eprintln!("{name}:{n}: ignoring '{}': {e}", echo(entry));
                }
            }
        })
        .map_err(with_name(&name))?;
    }

    let mut out = io::BufWriter::new(io::stdout().lock());
    for p in agg.summarize() {
        if opts.spf {
            out.write_all(match p.family() {
                Family::V4 => b"ip4:",
                Family::V6 => b"ip6:",
            })?;
        }
        writeln!(out, "{p}")?;
    }
    out.flush()
}

fn main() -> ExitCode {
    let result = match parse_args(std::env::args_os().skip(1)) {
        Ok(Action::Run(opts)) => run(&opts),
        Ok(Action::Print(text)) => io::stdout().lock().write_all(text.as_bytes()),
        Err(e) => {
            eprintln!("aggregate-cidr: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Downstream closed the pipe (e.g. `| head`); not an error.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aggregate-cidr: {e}");
            ExitCode::FAILURE
        }
    }
}
