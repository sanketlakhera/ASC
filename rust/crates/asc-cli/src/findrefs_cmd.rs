//! `asc findrefs`: `cli._handle_findrefs` and `ApkHandler.for_each_findrefs`.
//!
//! The order of checks is the oracle's, since it decides which error a bad
//! invocation reports: member query, `-o` file, APK file, central directory,
//! no entries (exit 0, even with `--threads 0`), worker count, then entries.

use crate::argparse::{Kind, Nargs, Opt, Outcome, Parser, Pos, Value, py_repr};
use asc_core::AscError;
use asc_core::apk::{EntryRefs, findrefs_entry, map_ordered};
use asc_core::findrefs::Query;
use asc_core::findrefs::format::to_output;
use asc_core::findrefs::member::MemberQuery;
use asc_core::zip::parse_cd_dex_entries;
use memmap2::Mmap;
use std::fs::File;
use std::io::{self, Write};
use std::time::Instant;

const KINDS: &[&str] = &["string", "type", "method", "field"];

fn findrefs_parser() -> Parser {
    Parser {
        prog: "asc findrefs",
        opts: vec![
            Opt {
                strings: &["-h", "--help"],
                dest: "help",
                kind: Kind::Help,
            },
            Opt {
                strings: &["--debug"],
                dest: "debug",
                kind: Kind::StoreTrue,
            },
            Opt {
                strings: &["--threads", "--thread"],
                dest: "threads",
                kind: Kind::Store { int: true },
            },
        ],
        pos: vec![
            Pos {
                dest: "apk_path",
                nargs: Nargs::One,
            },
            Pos {
                dest: "find_type",
                nargs: Nargs::Parser(KINDS),
            },
        ],
    }
}

fn leaf_parser(kind: &[u8]) -> Parser {
    let output = Opt {
        strings: &["-o", "--output"],
        dest: "output",
        kind: Kind::Store { int: false },
    };
    let help = Opt {
        strings: &["-h", "--help"],
        dest: "help",
        kind: Kind::Help,
    };
    if kind == b"string" || kind == b"type" {
        return Parser {
            prog: if kind == b"string" {
                "asc findrefs apk_path string"
            } else {
                "asc findrefs apk_path type"
            },
            opts: vec![help, output],
            pos: vec![Pos {
                dest: "value",
                nargs: Nargs::One,
            }],
        };
    }
    Parser {
        prog: if kind == b"method" {
            "asc findrefs apk_path method"
        } else {
            "asc findrefs apk_path field"
        },
        opts: vec![
            help,
            output,
            Opt {
                strings: &["--class"],
                dest: "class_name",
                kind: Kind::Store { int: false },
            },
            Opt {
                strings: &["--fuzzy-class"],
                dest: "fuzzy_class",
                kind: Kind::StoreTrue,
            },
        ],
        pos: vec![Pos {
            dest: "name",
            nargs: Nargs::Optional,
        }],
    }
}

/// The parsed command line.
struct Args {
    debug: bool,
    threads: i128,
    apk_path: Vec<u8>,
    kind: Vec<u8>,
    value: Option<Vec<u8>>,
    output: Option<Vec<u8>>,
    class_name: Option<Vec<u8>>,
    fuzzy_class: bool,
}

fn usage_error(prog: &str, msg: &str) -> i32 {
    eprintln!("usage: {prog} [-h] ...");
    eprintln!("{prog}: error: {msg}");
    2
}

fn parse_args(argv: &[Vec<u8>]) -> Result<Args, i32> {
    let outcome = |o: Outcome| match o {
        Outcome::Help(prog) => {
            println!("usage: {prog} [-h] ...");
            0
        }
        Outcome::Error(prog, msg) => usage_error(prog, &msg),
    };
    let top = findrefs_parser().parse_known(argv).map_err(outcome)?;
    let Some(Value::Sub(kind, rest)) = top.values.get("find_type").cloned() else {
        return Err(usage_error(
            "asc findrefs",
            "the following arguments are required: find_type",
        ));
    };
    let leaf = leaf_parser(&kind).parse_known(&rest).map_err(outcome)?;
    let mut extras = leaf.extras;
    extras.extend(top.extras);
    if !extras.is_empty() {
        let shown: Vec<String> = extras
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        return Err(usage_error(
            "asc",
            &format!("unrecognized arguments: {}", shown.join(" ")),
        ));
    }
    let s = |v: Option<&Value>| match v {
        Some(Value::Str(s)) => Some(s.clone()),
        _ => None,
    };
    Ok(Args {
        debug: matches!(top.values.get("debug"), Some(Value::Bool(true))),
        threads: match top.values.get("threads") {
            Some(Value::Int(n)) => *n,
            _ => 8,
        },
        apk_path: s(top.values.get("apk_path")).unwrap_or_default(),
        value: s(leaf.values.get("value")).or_else(|| s(leaf.values.get("name"))),
        output: s(leaf.values.get("output")),
        class_name: s(leaf.values.get("class_name")),
        fuzzy_class: matches!(leaf.values.get("fuzzy_class"), Some(Value::Bool(true))),
        kind,
    })
}

/// argv bytes as Python's `str` holds them on POSIX: UTF-8, every undecodable
/// byte as the lone surrogate U+DC80..U+DCFF (`surrogateescape`).
pub fn decode_arg(arg: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(arg.len());
    for chunk in arg.utf8_chunks() {
        units.extend(chunk.valid().encode_utf16());
        units.extend(chunk.invalid().iter().map(|&b| 0xdc00 | u16::from(b)));
    }
    units
}

/// `cli._format_class_name`.
fn format_class_name(name: &[u16]) -> Vec<u16> {
    let (l, semi, slash, dot) = (
        u16::from(b'L'),
        u16::from(b';'),
        u16::from(b'/'),
        u16::from(b'.'),
    );
    if name.first() == Some(&l) && name.last() == Some(&semi) && name.contains(&slash) {
        return name.to_vec();
    }
    let mut out: Vec<u16> = name
        .iter()
        .map(|&u| if u == dot { slash } else { u })
        .collect();
    if out.first() != Some(&l) {
        out.insert(0, l);
    }
    if out.last() != Some(&semi) {
        out.push(semi);
    }
    out
}

/// `cli._get_find_query`.
fn find_query(args: &Args) -> Result<Query, String> {
    let value = args.value.as_deref().map(decode_arg);
    match args.kind.as_slice() {
        b"string" => Ok(Query::String(value.unwrap_or_default())),
        b"type" => Ok(Query::Type(value.unwrap_or_default())),
        kind => {
            let key = if kind == b"method" { "method" } else { "field" };
            let class = args
                .class_name
                .as_deref()
                .map(decode_arg)
                .filter(|c| !c.is_empty());
            let name = value.filter(|n| !n.is_empty());
            if class.is_none() && name.is_none() {
                return Err(format!(
                    "{key} query needs at least one of class or {key} name"
                ));
            }
            let class = class.map(|c| {
                let (dot, slash) = (u16::from(b'.'), u16::from(b'/'));
                let c = if !args.fuzzy_class {
                    format_class_name(&c)
                } else if c.contains(&dot) && !c.contains(&slash) {
                    c.iter()
                        .map(|&u| if u == dot { slash } else { u })
                        .collect()
                } else {
                    c
                };
                (c, !args.fuzzy_class)
            });
            let q = MemberQuery { class, name };
            Ok(if key == "method" {
                Query::Method(q)
            } else {
                Query::Field(q)
            })
        }
    }
}

/// A path as Python shows it in messages: decoded like argv, lone
/// surrogates printed as `?`.
fn shown(path: &[u8]) -> String {
    to_output(&decode_arg(path))
}

/// `str(OSError)`: `[Errno N] strerror`, as Python prints a failed write.
fn errno_text(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => {
            let full = io::Error::from_raw_os_error(code).to_string();
            let strerror = full.split(" (os error").next().unwrap_or(&full);
            format!("[Errno {code}] {strerror}")
        }
        None => e.to_string(),
    }
}

/// `str(OSError)` for a failed open: `[Errno N] strerror: 'path'`.
fn os_error(e: &io::Error, path: &[u8]) -> String {
    format!("{}: {}", errno_text(e), py_repr(&shown(path)))
}

fn os_path(path: &[u8]) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path))
    }
    #[cfg(not(unix))]
    {
        std::path::PathBuf::from(String::from_utf8_lossy(path).into_owned())
    }
}

/// `ApkHandler._open_apk`.
fn open_apk(path: &[u8]) -> Result<Mmap, String> {
    let p = os_path(path);
    let Ok(meta) = std::fs::metadata(&p) else {
        return Err(format!("APK file not found: {}", shown(path)));
    };
    if meta.len() < 22 {
        return Err(AscError::EocdNotFound.to_string());
    }
    if meta.is_dir() {
        return Err(os_error(&io::Error::from_raw_os_error(21), path));
    }
    let file = File::open(&p).map_err(|e| os_error(&e, path))?;
    // SAFETY: the file is only read; a concurrent writer could change the
    // bytes under us, which the parsers tolerate (every read is bounds-checked).
    unsafe { Mmap::map(&file) }.map_err(|e| os_error(&e, path))
}

pub fn run(argv: &[Vec<u8>], t_start: Instant) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let result = execute(&args, &mut out, t_start);
    let _ = out.flush();
    match result {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("Error: {msg}");
            1
        }
    }
}

fn execute(args: &Args, out: &mut impl Write, t_start: Instant) -> Result<(), String> {
    let query = find_query(args)?;
    let mut output = match args.output.as_deref().filter(|o| !o.is_empty()) {
        Some(path) => Some(io::BufWriter::new(
            File::create(os_path(path)).map_err(|e| os_error(&e, path))?,
        )),
        None => None,
    };

    let t_scan = Instant::now();
    let apk = open_apk(&args.apk_path)?;
    let mut entries = parse_cd_dex_entries(&apk).map_err(|e| e.to_string())?;
    entries.sort_by_key(|e| e.comp_size);
    if !entries.is_empty() {
        if args.threads <= 0 {
            return Err("max_workers must be greater than 0".into());
        }
        let workers = usize::try_from(args.threads).unwrap_or(usize::MAX);
        let pid = std::process::id();
        let mut write_err = None;
        let out = std::cell::RefCell::new(&mut *out);
        let emitted = map_ordered(
            &entries,
            workers,
            |entry| findrefs_entry(&apk, entry, &query),
            |r: &EntryRefs| {
                if args.debug {
                    let _ = writeln!(
                        out.borrow_mut(),
                        "[APK] [P{pid}] '{}' inflate={:.2} us process={:.2} us",
                        r.name,
                        r.inflate_us,
                        r.process_us
                    );
                }
            },
            |r: EntryRefs| {
                if r.lines.is_empty() {
                    return Ok(());
                }
                let mut text = String::new();
                for line in &r.lines {
                    text.push_str(&to_output(line));
                    text.push('\n');
                }
                if let Err(e) = out.borrow_mut().write_all(text.as_bytes()) {
                    write_err.get_or_insert(errno_text(&e));
                }
                if let Some(f) = output.as_mut()
                    && let Err(e) = f.write_all(text.as_bytes())
                {
                    write_err.get_or_insert(errno_text(&e));
                }
                Ok(())
            },
        );
        // Whatever was written before an error stays in the -o file.
        if let Some(f) = output.as_mut() {
            let _ = f.flush();
        }
        emitted.map_err(|e| e.to_string())?;
        if let Some(e) = write_err {
            return Err(e);
        }
        if args.debug {
            let _ = writeln!(
                out.borrow_mut(),
                "[APK] for_each_findrefs total={:.2} us count={} workers={}",
                t_scan.elapsed().as_secs_f64() * 1e6,
                entries.len(),
                args.threads
            );
        }
    }
    if let Some(mut f) = output {
        f.flush().map_err(|e| e.to_string())?;
    }
    if args.debug {
        let _ = writeln!(
            out,
            "[DEBUG] Total Execution Time: {:.2} us",
            t_start.elapsed().as_secs_f64() * 1e6
        );
    }
    Ok(())
}
