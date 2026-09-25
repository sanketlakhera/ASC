//! The subset of Python 3.12's `argparse` the `findrefs` grammar uses, ported
//! from `ArgumentParser._parse_known_args` so the same command lines are
//! accepted and rejected: options and positionals interleave, `--opt=value`,
//! `-ovalue`, unambiguous long-option prefixes (`--thr` is ambiguous between
//! `--threads` and `--thread`), `-1` as a positional, `--` ending options, and
//! a sub-parser positional that takes every remaining argument.
//!
//! Help and usage text are M6; errors carry argparse's message and exit 2.

use std::collections::HashMap;

pub type Arg = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Help,
    StoreTrue,
    /// One value; `int` converts it with Python's `int()`.
    Store {
        int: bool,
    },
}

pub struct Opt {
    pub strings: &'static [&'static str],
    pub dest: &'static str,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nargs {
    One,
    Optional,
    /// A sub-command name followed by everything after it.
    Parser(&'static [&'static str]),
}

pub struct Pos {
    pub dest: &'static str,
    pub nargs: Nargs,
}

pub struct Parser {
    pub prog: &'static str,
    pub opts: Vec<Opt>,
    pub pos: Vec<Pos>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Int(i128),
    Str(Arg),
    /// A sub-command and its arguments.
    Sub(Arg, Vec<Arg>),
    None,
}

#[derive(Debug)]
pub enum Outcome {
    Help(&'static str),
    Error(&'static str, String),
}

pub struct Parsed {
    pub values: HashMap<&'static str, Value>,
    pub extras: Vec<Arg>,
}

/// One interpretation of an option-like argument: the option index (None for
/// an unknown option), the option string, and an explicit argument.
type OptTuple = (Option<usize>, String, Option<Arg>);

fn text(a: &[u8]) -> String {
    String::from_utf8_lossy(a).into_owned()
}

impl Parser {
    fn lookup(&self, s: &[u8]) -> Option<usize> {
        self.opts
            .iter()
            .position(|o| o.strings.iter().any(|os| os.as_bytes() == s))
    }

    /// All `(option index, option string)` pairs in declaration order.
    fn option_strings(&self) -> impl Iterator<Item = (usize, &'static str)> + '_ {
        self.opts
            .iter()
            .enumerate()
            .flat_map(|(i, o)| o.strings.iter().map(move |s| (i, *s)))
    }

    /// `_parse_optional`: `None` for a positional.
    fn parse_optional(&self, arg: &[u8]) -> Option<Vec<OptTuple>> {
        let first = *arg.first()?;
        if first != b'-' {
            return None;
        }
        if let Some(i) = self.lookup(arg) {
            return Some(vec![(Some(i), text(arg), None)]);
        }
        if arg.len() == 1 {
            return None;
        }
        if let Some(eq) = arg.iter().position(|&b| b == b'=') {
            let (name, value) = arg.split_at(eq);
            if let Some(i) = self.lookup(name) {
                return Some(vec![(
                    Some(i),
                    text(name),
                    Some(value.get(1..).unwrap_or_default().to_vec()),
                )]);
            }
        }
        let tuples = self.option_tuples(arg);
        if !tuples.is_empty() {
            return Some(tuples);
        }
        if is_negative_number(arg) {
            return None;
        }
        if arg.contains(&b' ') {
            return None;
        }
        Some(vec![(None, text(arg), None)])
    }

    /// `_get_option_tuples` (allow_abbrev is on).
    fn option_tuples(&self, arg: &[u8]) -> Vec<OptTuple> {
        let mut out = Vec::new();
        let (prefix, explicit) = match arg.iter().position(|&b| b == b'=') {
            Some(eq) => (
                arg.get(..eq).unwrap_or_default(),
                Some(arg.get(eq.saturating_add(1)..).unwrap_or_default().to_vec()),
            ),
            None => (arg, None),
        };
        if arg.get(1) == Some(&b'-') {
            for (i, s) in self.option_strings() {
                if s.as_bytes().starts_with(prefix) {
                    out.push((Some(i), s.to_string(), explicit.clone()));
                }
            }
        } else {
            let short = arg.get(..2).unwrap_or(arg);
            let short_explicit = arg.get(2..).unwrap_or_default().to_vec();
            for (i, s) in self.option_strings() {
                if s.as_bytes() == short {
                    out.push((Some(i), s.to_string(), Some(short_explicit.clone())));
                } else if s.as_bytes().starts_with(prefix) {
                    out.push((Some(i), s.to_string(), explicit.clone()));
                }
            }
        }
        out
    }

    /// `parse_known_args`.
    pub fn parse_known(&self, args: &[Arg]) -> Result<Parsed, Outcome> {
        let mut values: HashMap<&'static str, Value> = HashMap::new();
        for o in &self.opts {
            let default = match o.kind {
                Kind::Help => continue,
                Kind::StoreTrue => Value::Bool(false),
                Kind::Store { .. } => Value::None,
            };
            values.insert(o.dest, default);
        }
        for p in &self.pos {
            values.insert(p.dest, Value::None);
        }

        // classify: 'A' argument, 'O' option, '-' the first "--"
        let mut pattern = Vec::with_capacity(args.len());
        let mut options: HashMap<usize, Vec<OptTuple>> = HashMap::new();
        let mut rest_are_args = false;
        for (i, a) in args.iter().enumerate() {
            if rest_are_args {
                pattern.push(b'A');
            } else if a == b"--" {
                pattern.push(b'-');
                rest_are_args = true;
            } else if let Some(t) = self.parse_optional(a) {
                options.insert(i, t);
                pattern.push(b'O');
            } else {
                pattern.push(b'A');
            }
        }

        let mut state = State {
            parser: self,
            args,
            pattern: &pattern,
            values,
            seen: Vec::new(),
            extras: Vec::new(),
            positionals: (0..self.pos.len()).collect(),
        };
        let mut start = 0usize;
        let max_opt = options.keys().copied().max();
        while max_opt.is_some_and(|m| start <= m) {
            let Some(next_opt) = options.keys().copied().filter(|&i| i >= start).min() else {
                break;
            };
            if start != next_opt {
                let end = state.consume_positionals(start)?;
                if end > start {
                    start = end;
                    continue;
                }
                start = end;
            }
            if !options.contains_key(&start) {
                state.extras.extend(
                    args.get(start..next_opt)
                        .unwrap_or_default()
                        .iter()
                        .cloned(),
                );
                start = next_opt;
            }
            start = state.consume_optional(
                start,
                options.get(&start).map(Vec::as_slice).unwrap_or_default(),
            )?;
        }
        let stop = state.consume_positionals(start)?;
        state
            .extras
            .extend(args.get(stop..).unwrap_or_default().iter().cloned());

        let missing: Vec<&str> = self
            .pos
            .iter()
            .enumerate()
            .filter(|(i, p)| !state.seen.contains(i) && p.nargs != Nargs::Optional)
            .map(|(_, p)| p.dest)
            .collect();
        if !missing.is_empty() {
            return Err(Outcome::Error(
                self.prog,
                format!(
                    "the following arguments are required: {}",
                    missing.join(", ")
                ),
            ));
        }
        Ok(Parsed {
            values: state.values,
            extras: state.extras,
        })
    }
}

struct State<'a> {
    parser: &'a Parser,
    args: &'a [Arg],
    pattern: &'a [u8],
    values: HashMap<&'static str, Value>,
    /// Positionals already consumed.
    seen: Vec<usize>,
    extras: Vec<Arg>,
    positionals: Vec<usize>,
}

impl State<'_> {
    fn err(&self, msg: String) -> Outcome {
        Outcome::Error(self.parser.prog, msg)
    }

    fn consume_optional(&mut self, start: usize, tuples: &[OptTuple]) -> Result<usize, Outcome> {
        if tuples.len() > 1 {
            let names: Vec<&str> = tuples.iter().map(|t| t.1.as_str()).collect();
            let arg = text(self.args.get(start).map(Vec::as_slice).unwrap_or_default());
            return Err(self.err(format!(
                "ambiguous option: {arg} could match {}",
                names.join(", ")
            )));
        }
        let Some((action, option_string, explicit)) = tuples.first() else {
            return Ok(start.saturating_add(1));
        };
        let Some(action) = *action else {
            self.extras
                .push(self.args.get(start).cloned().unwrap_or_default());
            return Ok(start.saturating_add(1));
        };
        let Some(opt) = self.parser.opts.get(action) else {
            return Ok(start.saturating_add(1));
        };
        match (opt.kind, explicit) {
            (Kind::Help, None) => Err(Outcome::Help(self.parser.prog)),
            (Kind::StoreTrue, None) => {
                self.values.insert(opt.dest, Value::Bool(true));
                Ok(start.saturating_add(1))
            }
            (Kind::Help | Kind::StoreTrue, Some(explicit)) => {
                // Single-dash flags could combine (-xyz); none of ours do, and
                // every other case is argparse's "ignored explicit argument".
                Err(self.err(format!(
                    "argument {}: ignored explicit argument {}",
                    opt.strings.join("/"),
                    py_repr(&text(explicit))
                )))
            }
            (Kind::Store { int }, Some(explicit)) => {
                let v = convert(opt, int, explicit).map_err(|m| self.err(m))?;
                self.values.insert(opt.dest, v);
                Ok(start.saturating_add(1))
            }
            (Kind::Store { int }, None) => {
                let next = start.saturating_add(1);
                if self.pattern.get(next) != Some(&b'A') {
                    return Err(self.err(format!(
                        "argument {}: expected one argument",
                        opt.strings.join("/")
                    )));
                }
                let value = self.args.get(next).cloned().unwrap_or_default();
                let v = convert(opt, int, &value).map_err(|m| self.err(m))?;
                self.values.insert(opt.dest, v);
                let _ = option_string;
                Ok(next.saturating_add(1))
            }
        }
    }

    /// `consume_positionals` with `_match_arguments_partial`.
    fn consume_positionals(&mut self, mut start: usize) -> Result<usize, Outcome> {
        let pattern = self.pattern.get(start..).unwrap_or_default();
        let counts = match_partial(
            &self
                .positionals
                .iter()
                .filter_map(|&i| self.parser.pos.get(i).map(|p| p.nargs))
                .collect::<Vec<_>>(),
            pattern,
        );
        let taken = counts.len();
        let consumed: Vec<usize> = self.positionals.drain(..taken).collect();
        for (idx, count) in consumed.into_iter().zip(counts) {
            let end = start.saturating_add(count);
            let mut args: Vec<Arg> = self.args.get(start..end).unwrap_or_default().to_vec();
            let pat = self.pattern.get(start..end).unwrap_or_default();
            let Some(pos) = self.parser.pos.get(idx) else {
                continue;
            };
            // the first "--" of a positional's arguments is dropped
            match pos.nargs {
                Nargs::Parser(_) => {
                    if pat.first() == Some(&b'-') && !args.is_empty() {
                        args.remove(0);
                    }
                }
                _ => {
                    if pat.contains(&b'-')
                        && let Some(dd) = args.iter().position(|a| a == b"--")
                    {
                        args.remove(dd);
                    }
                }
            }
            start = end;
            self.seen.push(idx);
            let value = match pos.nargs {
                Nargs::Optional if args.is_empty() => Value::None,
                Nargs::One | Nargs::Optional => {
                    Value::Str(args.first().cloned().unwrap_or_default())
                }
                Nargs::Parser(choices) => {
                    let name = args.first().cloned().unwrap_or_default();
                    if !choices.iter().any(|c| c.as_bytes() == name.as_slice()) {
                        let list: Vec<String> = choices.iter().map(|c| format!("'{c}'")).collect();
                        return Err(self.err(format!(
                            "argument {}: invalid choice: {} (choose from {})",
                            pos.dest,
                            py_repr(&text(&name)),
                            list.join(", ")
                        )));
                    }
                    Value::Sub(name, args.get(1..).unwrap_or_default().to_vec())
                }
            };
            self.values.insert(pos.dest, value);
        }
        Ok(start)
    }
}

/// `_match_arguments_partial`: as many positionals as the pattern allows,
/// dropping trailing empty matches that stop right before an option.
fn match_partial(nargs: &[Nargs], pattern: &[u8]) -> Vec<usize> {
    for n in (1..=nargs.len()).rev() {
        if let Some((counts, end)) = match_seq(nargs.get(..n).unwrap_or_default(), pattern, 0) {
            let mut counts = counts;
            if pattern.get(end) == Some(&b'O') {
                while counts.last() == Some(&0) {
                    counts.pop();
                }
            }
            return counts;
        }
    }
    Vec::new()
}

/// `re.match` of the concatenated positional patterns `(-*A-*)`, `(-*A?-*)`
/// and `(-*A[-AO]*)` at `at`: each group's length and the end. Candidate
/// lengths are tried in the order the regex backtracks through them.
fn match_seq(nargs: &[Nargs], pattern: &[u8], at: usize) -> Option<(Vec<usize>, usize)> {
    let Some((&first, rest)) = nargs.split_first() else {
        return Some((Vec::new(), at));
    };
    let tail = pattern.get(at..).unwrap_or_default();
    // "-*" is greedy, and giving a dash back never lets an A match there, so
    // the leading dashes are always all of them.
    let d = tail.iter().take_while(|&&c| c == b'-').count();
    let has_a = tail.get(d) == Some(&b'A');
    let mut lengths: Vec<usize> = Vec::new();
    match first {
        Nargs::One | Nargs::Optional => {
            if has_a {
                let after = d.saturating_add(1);
                let trail = tail
                    .get(after..)
                    .unwrap_or_default()
                    .iter()
                    .take_while(|&&c| c == b'-')
                    .count();
                lengths.extend((0..=trail).rev().map(|t| after.saturating_add(t)));
            }
            if first == Nargs::Optional {
                // A? empty: the dashes alone, shorter and shorter
                lengths.extend((0..=d).rev());
            }
        }
        Nargs::Parser(_) => {
            if has_a {
                let min = d.saturating_add(1);
                let max = min.saturating_add(
                    tail.get(min..)
                        .unwrap_or_default()
                        .iter()
                        .take_while(|c| b"-AO".contains(c))
                        .count(),
                );
                lengths.extend((min..=max).rev());
            }
        }
    }
    for len in lengths {
        if let Some((mut counts, end)) = match_seq(rest, pattern, at.saturating_add(len)) {
            counts.insert(0, len);
            return Some((counts, end));
        }
    }
    None
}

fn is_negative_number(arg: &[u8]) -> bool {
    // ^-\d+$|^-\d*\.\d+$
    let Some(body) = arg.strip_prefix(b"-") else {
        return false;
    };
    if !body.is_empty() && body.iter().all(u8::is_ascii_digit) {
        return true;
    }
    match body.iter().position(|&b| b == b'.') {
        Some(dot) => {
            let (int, frac) = body.split_at(dot);
            let frac = frac.get(1..).unwrap_or_default();
            int.iter().all(u8::is_ascii_digit)
                && !frac.is_empty()
                && frac.iter().all(u8::is_ascii_digit)
        }
        None => false,
    }
}

fn convert(opt: &Opt, int: bool, value: &[u8]) -> Result<Value, String> {
    if !int {
        return Ok(Value::Str(value.to_vec()));
    }
    py_int(value).map(Value::Int).ok_or_else(|| {
        format!(
            "argument {}: invalid int value: {}",
            opt.strings.join("/"),
            py_repr(&text(value))
        )
    })
}

/// Python `int(str)` for ASCII text: surrounding whitespace, a sign, digits
/// with single underscores between them. Saturates past `i128`.
pub fn py_int(value: &[u8]) -> Option<i128> {
    let s = std::str::from_utf8(value).ok()?;
    let s = s.trim_matches(|c: char| c.is_whitespace());
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, s.get(1..)?),
        Some(b'+') => (false, s.get(1..)?),
        _ => (false, s),
    };
    let bytes = digits.as_bytes();
    if bytes.is_empty() || bytes.first() == Some(&b'_') || bytes.last() == Some(&b'_') {
        return None;
    }
    if bytes.windows(2).any(|w| w == b"__") {
        return None;
    }
    let mut v: i128 = 0;
    for &b in bytes {
        if b == b'_' {
            continue;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.saturating_mul(10).saturating_add(i128::from(b - b'0'));
    }
    Some(if neg { v.saturating_neg() } else { v })
}

/// `repr()` of a str.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
