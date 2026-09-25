//! Python `re` bytes patterns, compiled for `regex::bytes`.
//!
//! findrefs queries are Python 3.12 bytes regexes over MUTF-8 data. `regex::bytes`
//! reads several constructs differently (`\<` is a word boundary, `&&` inside a
//! class is an intersection, `a{` is an error, `\x{41}` and `(?<name>)` are
//! accepted), so a pattern is never handed over as text. Instead this module
//! ports CPython's `re._parser` (Tokenizer, `_parse_sub`, `_parse`, `_escape`,
//! `_class_escape`, `_parse_flags`) and emits an equivalent `regex` pattern from
//! the parsed items, every literal as a `\xNN` byte. Parse errors carry the text
//! and position `re.error` would print.
//!
//! What `regex` cannot express (lookaround, backreferences, conditionals, atomic
//! groups, possessive repeats, the `L` flag) is parsed to the end, as Python
//! does, and then refused with `unsupported pattern syntax`. A Python error
//! anywhere in the pattern still takes precedence, as it would in Python.
//!
//! One more class is refused: a pattern that can match the empty string and
//! prefers an empty option somewhere (a lazy repeat, or an alternative that can
//! match empty before another alternative). After an empty match at `p`,
//! CPython's `finditer` looks for a non-empty match at `p` (`must_advance`),
//! which `regex` cannot do: it moves on to `p + 1`. The two then attribute
//! matches to different strings, so such a pattern is not run at all.

use crate::error::AscError;
use regex::bytes::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::fmt::Write as _;

/// `_sre.MAXREPEAT` on 64-bit CPython.
const MAXREPEAT: u64 = 4_294_967_295;

/// Compiles a MUTF-8 encoded Python bytes pattern.
pub fn compile(pattern: &[u8]) -> Result<Regex, AscError> {
    let translated = translate(pattern)?;
    RegexBuilder::new(&translated)
        .unicode(false)
        .build()
        .map_err(|e| AscError::UnsupportedPattern(first_line(&e.to_string())))
}

/// The `regex` pattern equivalent to a Python bytes pattern.
pub fn translate(pattern: &[u8]) -> Result<String, AscError> {
    let mut parser = Parser {
        src: Tokenizer::new(pattern).map_err(|e| e.into_error(pattern))?,
        empty_preferring: false,
        repeats: Vec::new(),
        groups: 1,
        open_groups: Vec::new(),
        groupdict: HashMap::new(),
        grouprefpos: Vec::new(),
        lookbehind_groups: None,
        unsupported: None,
        global_flags: Flags::default(),
    };
    let body = parser.parse_top().map_err(|e| e.into_error(pattern))?;
    if let Some(what) = parser.unsupported {
        return Err(AscError::UnsupportedPattern(what.to_string()));
    }
    Ok(body)
}

fn first_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| l.starts_with("error:"))
        .map_or_else(
            || s.lines().next().unwrap_or_default().to_string(),
            |l| l.trim_start_matches("error:").trim().to_string(),
        )
}

/// A Python-side parse failure.
enum PyError {
    /// `re.error(msg, pattern, pos)`.
    At(String, usize),
    /// An exception without a position (`OverflowError`).
    Plain(String),
}

impl PyError {
    fn into_error(self, pattern: &[u8]) -> AscError {
        match self {
            // re.error: '%s at position %d', plus line and column when the
            // pattern has more than one line.
            Self::At(msg, pos) => {
                let mut text = format!("{msg} at position {pos}");
                if pattern.contains(&b'\n') {
                    let head = pattern.get(..pos).unwrap_or(pattern);
                    let lineno = head
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count()
                        .saturating_add(1);
                    let colno = match head.iter().rposition(|&b| b == b'\n') {
                        Some(nl) => pos.saturating_sub(nl),
                        None => pos.saturating_add(1),
                    };
                    let _ = write!(text, " (line {lineno}, column {colno})");
                }
                AscError::PatternError(text)
            }
            Self::Plain(msg) => AscError::PatternError(msg),
        }
    }
}

type PResult<T> = Result<T, PyError>;

/// A pattern character the way Python's Tokenizer yields it: one byte (the
/// pattern is decoded as latin-1), or a backslash and the byte after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Char(u8),
    Esc(u8),
}

impl Tok {
    fn len(self) -> usize {
        match self {
            Self::Char(_) => 1,
            Self::Esc(_) => 2,
        }
    }
    fn is(self, c: u8) -> bool {
        self == Self::Char(c)
    }
    fn char_in(self, set: &[u8]) -> bool {
        matches!(self, Self::Char(c) if set.contains(&c))
    }
    /// `repr`-ish text for messages, non-ASCII as `\xNN` (Python applies
    /// `backslashreplace` to bytes-pattern messages).
    fn text(self) -> String {
        match self {
            Self::Char(c) => byte_text(c),
            Self::Esc(c) => format!("\\{}", byte_text(c)),
        }
    }
}

fn byte_text(c: u8) -> String {
    if c.is_ascii() {
        char::from(c).to_string()
    } else {
        format!("\\x{c:02x}")
    }
}

fn bytes_text(bytes: &[u8]) -> String {
    bytes.iter().map(|&c| byte_text(c)).collect()
}

const DIGITS: &[u8] = b"0123456789";
const OCTDIGITS: &[u8] = b"01234567";
const HEXDIGITS: &[u8] = b"0123456789abcdefABCDEF";
const WHITESPACE: &[u8] = b" \t\n\r\x0b\x0c";
const SPECIAL_CHARS: &[u8] = b".\\[{()*+?^$|";
const REPEAT_CHARS: &[u8] = b"*+?{";

struct Tokenizer<'p> {
    s: &'p [u8],
    index: usize,
    next: Option<Tok>,
}

impl<'p> Tokenizer<'p> {
    fn new(s: &'p [u8]) -> PResult<Self> {
        let mut t = Self {
            s,
            index: 0,
            next: None,
        };
        t.advance()?;
        Ok(t)
    }

    fn advance(&mut self) -> PResult<()> {
        let Some(&c) = self.s.get(self.index) else {
            self.next = None;
            return Ok(());
        };
        if c == b'\\' {
            let Some(&e) = self.s.get(self.index.saturating_add(1)) else {
                return Err(PyError::At(
                    "bad escape (end of pattern)".into(),
                    self.s.len().saturating_sub(1),
                ));
            };
            self.next = Some(Tok::Esc(e));
            self.index = self.index.saturating_add(2);
        } else {
            self.next = Some(Tok::Char(c));
            self.index = self.index.saturating_add(1);
        }
        Ok(())
    }

    fn get(&mut self) -> PResult<Option<Tok>> {
        let this = self.next;
        self.advance()?;
        Ok(this)
    }

    fn matches(&mut self, c: u8) -> PResult<bool> {
        if self.next == Some(Tok::Char(c)) {
            self.advance()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn next_in(&self, set: &[u8]) -> bool {
        self.next.is_some_and(|t| t.char_in(set))
    }

    fn getwhile(&mut self, n: usize, set: &[u8]) -> PResult<Vec<u8>> {
        let mut out = Vec::new();
        for _ in 0..n {
            match self.next {
                Some(Tok::Char(c)) if set.contains(&c) => {
                    out.push(c);
                    self.advance()?;
                }
                _ => break,
            }
        }
        Ok(out)
    }

    /// `getuntil`: the characters before `terminator`, which is consumed.
    fn getuntil(&mut self, terminator: u8, name: &str) -> PResult<Vec<Tok>> {
        let mut out = Vec::new();
        loop {
            let c = self.next;
            self.advance()?;
            match c {
                None => {
                    if out.is_empty() {
                        return Err(self.error(format!("missing {name}"), 0));
                    }
                    let msg = format!("missing {}, unterminated name", char::from(terminator));
                    return Err(self.error(msg, out.iter().map(|t: &Tok| t.len()).sum()));
                }
                Some(t) if t.is(terminator) => {
                    if out.is_empty() {
                        return Err(self.error(format!("missing {name}"), 1));
                    }
                    return Ok(out);
                }
                Some(t) => out.push(t),
            }
        }
    }

    fn tell(&self) -> usize {
        self.index.saturating_sub(self.next.map_or(0, Tok::len))
    }

    fn seek(&mut self, index: usize) -> PResult<()> {
        self.index = index;
        self.advance()
    }

    fn error(&self, msg: impl Into<String>, offset: usize) -> PyError {
        PyError::At(msg.into(), self.tell().saturating_sub(offset))
    }
}

/// Inline flags that matter to the translation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Flags {
    i: bool,
    m: bool,
    s: bool,
    x: bool,
    a: bool,
    l: bool,
    t: bool,
}

impl Flags {
    fn set(&mut self, c: u8) {
        match c {
            b'i' => self.i = true,
            b'm' => self.m = true,
            b's' => self.s = true,
            b'x' => self.x = true,
            b'a' => self.a = true,
            b'L' => self.l = true,
            b't' => self.t = true,
            _ => {}
        }
    }
    fn intersects(self, other: Self) -> bool {
        (self.i && other.i)
            || (self.m && other.m)
            || (self.s && other.s)
            || (self.x && other.x)
            || (self.a && other.a)
            || (self.l && other.l)
            || (self.t && other.t)
    }
    /// The `regex` flag letters (`x`, `a` are handled here, not by `regex`).
    fn rust(self) -> String {
        let mut out = String::new();
        for (on, c) in [(self.i, 'i'), (self.m, 'm'), (self.s, 's')] {
            if on {
                out.push(c);
            }
        }
        out
    }
}

fn is_flag(c: u8) -> bool {
    b"iLmsxatu".contains(&c)
}

/// What the last item of a sequence is, for the repeat checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    /// `^ $ \A \Z \b \B`: "nothing to repeat".
    At,
    /// A repeat: "multiple repeat".
    Repeat,
    Other,
}

struct Parser<'p> {
    src: Tokenizer<'p>,
    /// A lazy repeat, or an alternative that can match empty before another.
    empty_preferring: bool,
    /// Every repeat as (start of its operand, sre opcode name), for the
    /// template flag's compile error.
    repeats: Vec<(usize, &'static str)>,
    /// `state.groups`: group 0 plus every opened group.
    groups: usize,
    /// Groups still open (their width is None in Python).
    open_groups: Vec<usize>,
    groupdict: HashMap<Vec<u8>, usize>,
    /// Conditional references to groups, checked after parsing.
    grouprefpos: Vec<(usize, usize)>,
    lookbehind_groups: Option<usize>,
    unsupported: Option<&'static str>,
    global_flags: Flags,
}

/// One parsed alternative: its `regex` text and item bookkeeping.
struct Seq {
    out: String,
    items: usize,
    last: Option<Item>,
    /// Where the last item started in the pattern.
    last_start: usize,
    /// Whether every item before the last can match the empty string.
    prefix_nullable: bool,
    last_nullable: bool,
}

impl Seq {
    fn new() -> Self {
        Self {
            out: String::new(),
            items: 0,
            last: None,
            last_start: 0,
            prefix_nullable: true,
            last_nullable: true,
        }
    }

    fn push(&mut self, text: &str, kind: Item, start: usize, nullable: bool) {
        self.prefix_nullable = self.nullable();
        self.out.push_str(text);
        self.items = self.items.saturating_add(1);
        self.last = Some(kind);
        self.last_start = start;
        self.last_nullable = nullable;
    }

    /// Whether the whole sequence can match the empty string.
    fn nullable(&self) -> bool {
        self.prefix_nullable && (self.items == 0 || self.last_nullable)
    }
}

fn lit(out: &mut String, c: u64) {
    let c = u8::try_from(c).unwrap_or(u8::MAX);
    if c.is_ascii_alphanumeric() {
        out.push(char::from(c));
    } else {
        let _ = write!(out, "\\x{c:02X}");
    }
}

/// A class member as `_class_escape` / the class loop produce it.
enum ClassCode {
    Literal(u64),
    Category(&'static str),
}

impl<'p> Parser<'p> {
    fn unsupported(&mut self, what: &'static str) {
        self.unsupported.get_or_insert(what);
    }

    fn checkgroup(&self, gid: usize) -> bool {
        gid < self.groups && !self.open_groups.contains(&gid)
    }

    fn checklookbehindgroup(&self, gid: usize) -> PResult<()> {
        if let Some(lb) = self.lookbehind_groups {
            if !self.checkgroup(gid) {
                return Err(self.src.error("cannot refer to an open group", 0));
            }
            if gid >= lb {
                return Err(self.src.error(
                    "cannot refer to group defined in the same lookbehind subpattern",
                    0,
                ));
            }
        }
        Ok(())
    }

    fn checkgroupname(&self, name: &[Tok], offset: usize) -> PResult<()> {
        let raw: Vec<u8> = name
            .iter()
            .flat_map(|t| match *t {
                Tok::Char(c) => vec![c],
                Tok::Esc(c) => vec![b'\\', c],
            })
            .collect();
        let len = raw.len().saturating_add(offset);
        if !raw.is_ascii() {
            // "%a" of the latin-1 decoded name
            let shown: String = raw
                .iter()
                .map(|&c| {
                    if c.is_ascii() {
                        char::from(c).to_string()
                    } else {
                        format!("\\x{c:02x}")
                    }
                })
                .collect();
            return Err(self
                .src
                .error(format!("bad character in group name '{shown}'"), len));
        }
        let ident = raw
            .first()
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
            && raw.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
        if !ident {
            let shown = String::from_utf8_lossy(&raw).into_owned();
            return Err(self.src.error(
                format!("bad character in group name {}", py_repr(&shown)),
                len,
            ));
        }
        Ok(())
    }

    fn parse_top(&mut self) -> PResult<String> {
        let (body, nullable) = self.parse_sub(false, 0)?;
        // fix_flags runs before the trailing-parenthesis check
        if self.global_flags.a && self.global_flags.l {
            return Err(PyError::Plain(
                "ASCII and LOCALE flags are incompatible".into(),
            ));
        }
        if self.src.next.is_some() {
            return Err(self.src.error("unbalanced parenthesis", 0));
        }
        for &(g, pos) in &self.grouprefpos {
            if g >= self.groups {
                return Err(PyError::At(format!("invalid group reference {g}"), pos));
            }
        }
        // sre_compile refuses every repeat under the template flag; the first
        // one met walking the parsed pattern is the one named.
        if self.global_flags.t
            && let Some(&(_, op)) = self.repeats.iter().min_by_key(|(at, _)| *at)
        {
            return Err(PyError::Plain(format!(
                "internal: unsupported template operator {op}"
            )));
        }
        if self.global_flags.l {
            self.unsupported("the L (locale) flag");
        }
        if nullable && self.empty_preferring {
            self.unsupported("a pattern that can match empty and prefers an empty option");
        }
        let flags = self.global_flags.rust();
        if flags.is_empty() {
            Ok(body)
        } else {
            Ok(format!("(?{flags}){body}"))
        }
    }

    /// `_parse_sub`: alternatives separated by `|`. The result is one atom when
    /// there is more than one alternative.
    fn parse_sub(&mut self, mut verbose: bool, nested: usize) -> PResult<(String, bool)> {
        let mut items = Vec::new();
        let mut nullable = false;
        loop {
            let first = nested == 0 && items.is_empty();
            let seq = self.parse(verbose, nested.saturating_add(1), first)?;
            if !self.src.matches(b'|')? {
                nullable |= seq.nullable();
                items.push(seq.out);
                break;
            }
            // an empty-capable alternative with another after it
            if seq.nullable() {
                self.empty_preferring = true;
            }
            nullable |= seq.nullable();
            items.push(seq.out);
            if nested == 0 {
                verbose = self.global_flags.x;
            }
        }
        if items.len() == 1 {
            return Ok((items.pop().unwrap_or_default(), nullable));
        }
        Ok((format!("(?:{})", items.join("|")), nullable))
    }

    /// `_parse`: one alternative.
    fn parse(&mut self, mut verbose: bool, nested: usize, first: bool) -> PResult<Seq> {
        let mut seq = Seq::new();
        while let Some(this) = self.src.next {
            if this.is(b'|') || this.is(b')') {
                break;
            }
            let at = self.src.tell();
            self.src.get()?;

            if verbose {
                if this.char_in(WHITESPACE) {
                    continue;
                }
                if this.is(b'#') {
                    loop {
                        match self.src.get()? {
                            None => break,
                            Some(t) if t.is(b'\n') => break,
                            Some(_) => {}
                        }
                    }
                    continue;
                }
            }

            match this {
                Tok::Esc(c) => {
                    let (text, kind, nullable) = self.escape(c)?;
                    seq.push(&text, kind, at, nullable);
                }
                Tok::Char(c) if !SPECIAL_CHARS.contains(&c) => {
                    let mut text = String::new();
                    lit(&mut text, u64::from(c));
                    seq.push(&text, Item::Other, at, false);
                }
                Tok::Char(b'[') => {
                    let text = self.class()?;
                    seq.push(&text, Item::Other, at, false);
                }
                Tok::Char(c) if REPEAT_CHARS.contains(&c) => {
                    let here = self.src.tell();
                    let (min, max) = match c {
                        b'?' => (0, Some(1)),
                        b'*' => (0, None),
                        b'+' => (1, None),
                        _ => {
                            // '{': a repeat only when well formed, otherwise a literal
                            if self.src.next.is_some_and(|t| t.is(b'}')) {
                                seq.push("\\x7B", Item::Other, at, false);
                                continue;
                            }
                            let lo = self.src.getwhile(usize::MAX, DIGITS)?;
                            let hi = if self.src.matches(b',')? {
                                Some(self.src.getwhile(usize::MAX, DIGITS)?)
                            } else {
                                None
                            };
                            if !self.src.matches(b'}')? {
                                seq.push("\\x7B", Item::Other, at, false);
                                self.src.seek(here)?;
                                continue;
                            }
                            let hi = hi.unwrap_or_else(|| lo.clone());
                            let mut min = 0;
                            let mut max = None;
                            if !lo.is_empty() {
                                min = repeat_count(&lo)?;
                            }
                            if !hi.is_empty() {
                                let m = repeat_count(&hi)?;
                                if m < min {
                                    return Err(self.src.error(
                                        "min repeat greater than max repeat",
                                        self.src.tell().saturating_sub(here),
                                    ));
                                }
                                max = Some(m);
                            }
                            (min, max)
                        }
                    };
                    let this_len = this.len();
                    match seq.last {
                        None | Some(Item::At) => {
                            return Err(self.src.error(
                                "nothing to repeat",
                                self.src
                                    .tell()
                                    .saturating_sub(here)
                                    .saturating_add(this_len),
                            ));
                        }
                        Some(Item::Repeat) => {
                            return Err(self.src.error(
                                "multiple repeat",
                                self.src
                                    .tell()
                                    .saturating_sub(here)
                                    .saturating_add(this_len),
                            ));
                        }
                        Some(Item::Other) => {}
                    }
                    let mut q = match (min, max) {
                        (0, None) => "*".to_string(),
                        (1, None) => "+".to_string(),
                        (0, Some(1)) => "?".to_string(),
                        (m, None) => format!("{{{m},}}"),
                        (m, Some(n)) if m == n => format!("{{{m}}}"),
                        (m, Some(n)) => format!("{{{m},{n}}}"),
                    };
                    let op = if self.src.matches(b'?')? {
                        q.push('?');
                        self.empty_preferring = true;
                        "MIN_REPEAT"
                    } else if self.src.matches(b'+')? {
                        self.unsupported("possessive repeat");
                        "POSSESSIVE_REPEAT"
                    } else {
                        "MAX_REPEAT"
                    };
                    self.repeats.push((seq.last_start, op));
                    seq.out.push_str(&q);
                    seq.last = Some(Item::Repeat);
                    seq.last_nullable = seq.last_nullable || min == 0;
                }
                Tok::Char(b'.') => seq.push(".", Item::Other, at, false),
                Tok::Char(b'(') => {
                    if let Some((text, kind, nullable)) =
                        self.group(&mut verbose, nested, first, &seq)?
                    {
                        seq.push(&text, kind, at, nullable);
                    }
                }
                Tok::Char(b'^') => seq.push("^", Item::At, at, true),
                Tok::Char(b'$') => seq.push("$", Item::At, at, true),
                Tok::Char(_) => {}
            }
        }
        Ok(seq)
    }

    /// A `(` construct; `None` when it adds no item (comment, global flags).
    fn group(
        &mut self,
        verbose: &mut bool,
        nested: usize,
        first: bool,
        seq: &Seq,
    ) -> PResult<Option<(String, Item, bool)>> {
        let start = self.src.tell().saturating_sub(1);
        let mut capture = true;
        let mut name: Option<Vec<Tok>> = None;
        let mut add = Flags::default();
        let mut del = Flags::default();
        let mut atomic = false;
        if self.src.matches(b'?')? {
            let Some(ch) = self.src.get()? else {
                return Err(self.src.error("unexpected end of pattern", 0));
            };
            match ch {
                Tok::Char(b'P') => {
                    if self.src.matches(b'<')? {
                        let n = self.src.getuntil(b'>', "group name")?;
                        self.checkgroupname(&n, 1)?;
                        name = Some(n);
                    } else if self.src.matches(b'=')? {
                        let n = self.src.getuntil(b')', "group name")?;
                        self.checkgroupname(&n, 1)?;
                        let key = tok_bytes(&n);
                        let Some(&gid) = self.groupdict.get(&key) else {
                            let shown = py_repr(&String::from_utf8_lossy(&key));
                            return Err(self.src.error(
                                format!("unknown group name {shown}"),
                                key.len().saturating_add(1),
                            ));
                        };
                        if !self.checkgroup(gid) {
                            return Err(self.src.error(
                                "cannot refer to an open group",
                                key.len().saturating_add(1),
                            ));
                        }
                        self.checklookbehindgroup(gid)?;
                        self.unsupported("backreference");
                        return Ok(Some(("(?:)".into(), Item::Other, true)));
                    } else {
                        let Some(c) = self.src.get()? else {
                            return Err(self.src.error("unexpected end of pattern", 0));
                        };
                        return Err(self.src.error(
                            format!("unknown extension ?P{}", c.text()),
                            c.len().saturating_add(2),
                        ));
                    }
                }
                Tok::Char(b':') => capture = false,
                Tok::Char(b'#') => {
                    loop {
                        if self.src.next.is_none() {
                            return Err(self.src.error(
                                "missing ), unterminated comment",
                                self.src.tell().saturating_sub(start),
                            ));
                        }
                        if self.src.get()?.is_some_and(|t| t.is(b')')) {
                            break;
                        }
                    }
                    return Ok(None);
                }
                Tok::Char(c @ (b'=' | b'!' | b'<')) => {
                    let mut lookbehind = false;
                    let mut saved = None;
                    if c == b'<' {
                        let Some(c2) = self.src.get()? else {
                            return Err(self.src.error("unexpected end of pattern", 0));
                        };
                        if !c2.char_in(b"=!") {
                            return Err(self.src.error(
                                format!("unknown extension ?<{}", c2.text()),
                                c2.len().saturating_add(2),
                            ));
                        }
                        lookbehind = true;
                        saved = Some(self.lookbehind_groups);
                        if self.lookbehind_groups.is_none() {
                            self.lookbehind_groups = Some(self.groups);
                        }
                    }
                    let _ = self.parse_sub(*verbose, nested.saturating_add(1))?;
                    if lookbehind && saved == Some(None) {
                        self.lookbehind_groups = None;
                    }
                    if !self.src.matches(b')')? {
                        return Err(self.src.error(
                            "missing ), unterminated subpattern",
                            self.src.tell().saturating_sub(start),
                        ));
                    }
                    self.unsupported(if lookbehind {
                        "lookbehind"
                    } else {
                        "lookahead"
                    });
                    return Ok(Some(("(?:)".into(), Item::Other, true)));
                }
                Tok::Char(b'(') => {
                    let condname = self.src.getuntil(b')', "group name")?;
                    let raw = tok_bytes(&condname);
                    let condgroup = if !raw.is_empty() && raw.iter().all(u8::is_ascii_digit) {
                        let g = std::str::from_utf8(&raw)
                            .ok()
                            .and_then(|s| s.parse::<usize>().ok())
                            .unwrap_or(usize::MAX);
                        if g == 0 {
                            return Err(self
                                .src
                                .error("bad group number", raw.len().saturating_add(1)));
                        }
                        // _sre.MAXGROUPS on 64-bit CPython
                        if g >= (1 << 30) - 1 {
                            return Err(self.src.error(
                                format!("invalid group reference {g}"),
                                raw.len().saturating_add(1),
                            ));
                        }
                        let pos = self.src.tell().saturating_sub(raw.len()).saturating_sub(1);
                        if !self.grouprefpos.iter().any(|&(x, _)| x == g) {
                            self.grouprefpos.push((g, pos));
                        }
                        g
                    } else {
                        self.checkgroupname(&condname, 1)?;
                        match self.groupdict.get(&raw) {
                            Some(&g) => g,
                            None => {
                                let shown = py_repr(&String::from_utf8_lossy(&raw));
                                return Err(self.src.error(
                                    format!("unknown group name {shown}"),
                                    raw.len().saturating_add(1),
                                ));
                            }
                        }
                    };
                    self.checklookbehindgroup(condgroup)?;
                    self.parse(*verbose, nested.saturating_add(1), false)?;
                    if self.src.matches(b'|')? {
                        self.parse(*verbose, nested.saturating_add(1), false)?;
                        if self.src.next.is_some_and(|t| t.is(b'|')) {
                            return Err(self
                                .src
                                .error("conditional backref with more than two branches", 0));
                        }
                    }
                    if !self.src.matches(b')')? {
                        return Err(self.src.error(
                            "missing ), unterminated subpattern",
                            self.src.tell().saturating_sub(start),
                        ));
                    }
                    self.unsupported("conditional group");
                    return Ok(Some(("(?:)".into(), Item::Other, true)));
                }
                Tok::Char(b'>') => {
                    capture = false;
                    atomic = true;
                }
                Tok::Char(c) if is_flag(c) || c == b'-' => match self.parse_flags(c)? {
                    None => {
                        if !first || seq.items > 0 {
                            return Err(self.src.error(
                                "global flags not at the start of the expression",
                                self.src.tell().saturating_sub(start),
                            ));
                        }
                        *verbose = self.global_flags.x;
                        return Ok(None);
                    }
                    Some((a, d)) => {
                        add = a;
                        del = d;
                        capture = false;
                    }
                },
                other => {
                    return Err(self.src.error(
                        format!("unknown extension ?{}", other.text()),
                        other.len().saturating_add(1),
                    ));
                }
            }
        }

        let group = if capture {
            let gid = self.groups;
            if let Some(n) = &name {
                let key = tok_bytes(n);
                if let Some(&ogid) = self.groupdict.get(&key) {
                    let shown = py_repr(&String::from_utf8_lossy(&key));
                    return Err(self.src.error(
                        format!(
                            "redefinition of group name {shown} as group {gid}; was group {ogid}"
                        ),
                        key.len().saturating_add(1),
                    ));
                }
                self.groupdict.insert(key, gid);
            }
            self.groups = self.groups.saturating_add(1);
            self.open_groups.push(gid);
            Some(gid)
        } else {
            None
        };
        let sub_verbose = (*verbose || add.x) && !del.x;
        let (body, nullable) = self.parse_sub(sub_verbose, nested.saturating_add(1))?;
        if !self.src.matches(b')')? {
            return Err(self.src.error(
                "missing ), unterminated subpattern",
                self.src.tell().saturating_sub(start),
            ));
        }
        if let Some(gid) = group {
            self.open_groups.retain(|&g| g != gid);
        }
        if atomic {
            self.unsupported("atomic group");
        }
        if add.l {
            self.unsupported("the L (locale) flag");
        }
        let (on, off) = (add.rust(), del.rust());
        let text = match (on.is_empty(), off.is_empty()) {
            (true, true) => format!("(?:{body})"),
            (false, true) => format!("(?{on}:{body})"),
            (true, false) => format!("(?-{off}:{body})"),
            (false, false) => format!("(?{on}-{off}:{body})"),
        };
        Ok(Some((text, Item::Other, nullable)))
    }

    /// `_parse_flags`: `None` for global flags `(?...)`, else the scoped
    /// `(add, del)` of `(?...:` / `(?...-...:`.
    fn parse_flags(&mut self, first: u8) -> PResult<Option<(Flags, Flags)>> {
        let mut add = Flags::default();
        let mut del = Flags::default();
        let mut ch = Tok::Char(first);
        if first != b'-' {
            while let Tok::Char(c) = ch {
                if c == b'u' {
                    return Err(self.src.error(
                        "bad inline flags: cannot use 'u' flag with a bytes pattern",
                        0,
                    ));
                }
                add.set(c);
                // TYPE_FLAGS: a, L (u rejected above) are mutually exclusive
                if matches!(c, b'a' | b'L') && add.a && add.l {
                    return Err(self.src.error(
                        "bad inline flags: flags 'a', 'u' and 'L' are incompatible",
                        0,
                    ));
                }
                let Some(next) = self.src.get()? else {
                    return Err(self.src.error("missing -, : or )", 0));
                };
                ch = next;
                if ch.char_in(b")-:") {
                    break;
                }
                if !matches!(ch, Tok::Char(c) if is_flag(c)) {
                    let alpha =
                        matches!(ch, Tok::Char(c) if c.is_ascii_alphabetic() || is_latin1_alpha(c));
                    let msg = if alpha {
                        "unknown flag"
                    } else {
                        "missing -, : or )"
                    };
                    return Err(self.src.error(msg, ch.len()));
                }
            }
        }
        if ch.is(b')') {
            let merged = &mut self.global_flags;
            for (on, c) in [
                (add.i, b'i'),
                (add.m, b'm'),
                (add.s, b's'),
                (add.x, b'x'),
                (add.a, b'a'),
                (add.l, b'L'),
                (add.t, b't'),
            ] {
                if on {
                    merged.set(c);
                }
            }
            return Ok(None);
        }
        if add.t {
            return Err(self
                .src
                .error("bad inline flags: cannot turn on global flag", 1));
        }
        if ch.is(b'-') {
            let Some(next) = self.src.get()? else {
                return Err(self.src.error("missing flag", 0));
            };
            ch = next;
            if !matches!(ch, Tok::Char(c) if is_flag(c)) {
                let alpha =
                    matches!(ch, Tok::Char(c) if c.is_ascii_alphabetic() || is_latin1_alpha(c));
                let msg = if alpha {
                    "unknown flag"
                } else {
                    "missing flag"
                };
                return Err(self.src.error(msg, ch.len()));
            }
            while let Tok::Char(c) = ch {
                if matches!(c, b'a' | b'u' | b'L') {
                    return Err(self.src.error(
                        "bad inline flags: cannot turn off flags 'a', 'u' and 'L'",
                        0,
                    ));
                }
                del.set(c);
                let Some(next) = self.src.get()? else {
                    return Err(self.src.error("missing :", 0));
                };
                ch = next;
                if ch.is(b':') {
                    break;
                }
                if !matches!(ch, Tok::Char(c) if is_flag(c)) {
                    let alpha =
                        matches!(ch, Tok::Char(c) if c.is_ascii_alphabetic() || is_latin1_alpha(c));
                    let msg = if alpha { "unknown flag" } else { "missing :" };
                    return Err(self.src.error(msg, ch.len()));
                }
            }
        }
        if del.t {
            return Err(self
                .src
                .error("bad inline flags: cannot turn off global flag", 1));
        }
        if add.intersects(del) {
            return Err(self
                .src
                .error("bad inline flags: flag turned on and off", 1));
        }
        Ok(Some((add, del)))
    }

    /// `_escape`, outside a class.
    fn escape(&mut self, c: u8) -> PResult<(String, Item, bool)> {
        let esc_text = |c: u8| format!("\\{}", byte_text(c));
        match c {
            b'A' => return Ok(("\\A".into(), Item::At, true)),
            b'b' => return Ok(("\\b".into(), Item::At, true)),
            b'B' => return Ok(("\\B".into(), Item::At, true)),
            b'Z' => return Ok(("\\z".into(), Item::At, true)),
            b'd' | b'D' | b's' | b'S' | b'w' | b'W' => {
                return Ok((format!("\\{}", char::from(c)), Item::Other, false));
            }
            _ => {}
        }
        let mut out = String::new();
        if let Some(v) = simple_escape(c) {
            lit(&mut out, v);
            return Ok((out, Item::Other, false));
        }
        match c {
            b'x' => {
                let digits = self.src.getwhile(2, HEXDIGITS)?;
                if digits.len() != 2 {
                    let escape = format!("\\x{}", bytes_text(&digits));
                    let len = digits.len().saturating_add(2);
                    return Err(self.src.error(format!("incomplete escape {escape}"), len));
                }
                lit(&mut out, parse_radix(&digits, 16));
                Ok((out, Item::Other, false))
            }
            b'0' => {
                let digits = self.src.getwhile(2, OCTDIGITS)?;
                let mut all = vec![b'0'];
                all.extend(digits);
                lit(&mut out, parse_radix(&all, 8));
                Ok((out, Item::Other, false))
            }
            b'1'..=b'9' => {
                let mut escape = vec![c];
                if self.src.next_in(DIGITS) {
                    if let Some(Tok::Char(d)) = self.src.get()? {
                        escape.push(d);
                    }
                    let two_octal = escape.iter().all(|d| OCTDIGITS.contains(d));
                    if two_octal && self.src.next_in(OCTDIGITS) {
                        if let Some(Tok::Char(d)) = self.src.get()? {
                            escape.push(d);
                        }
                        let v = parse_radix(&escape, 8);
                        if v > 0o377 {
                            let shown = format!("\\{}", bytes_text(&escape));
                            return Err(self.src.error(
                                format!("octal escape value {shown} outside of range 0-0o377"),
                                escape.len().saturating_add(1),
                            ));
                        }
                        lit(&mut out, v);
                        return Ok((out, Item::Other, false));
                    }
                }
                let group = usize::try_from(parse_radix(&escape, 10)).unwrap_or(usize::MAX);
                if group < self.groups {
                    if !self.checkgroup(group) {
                        return Err(self.src.error(
                            "cannot refer to an open group",
                            escape.len().saturating_add(1),
                        ));
                    }
                    self.checklookbehindgroup(group)?;
                    self.unsupported("backreference");
                    return Ok(("(?:)".into(), Item::Other, true));
                }
                Err(self
                    .src
                    .error(format!("invalid group reference {group}"), escape.len()))
            }
            c if c.is_ascii_alphabetic() => {
                Err(self.src.error(format!("bad escape {}", esc_text(c)), 2))
            }
            c => {
                lit(&mut out, u64::from(c));
                Ok((out, Item::Other, false))
            }
        }
    }

    /// `_class_escape`, inside a class.
    fn class_escape(&mut self, c: u8) -> PResult<ClassCode> {
        if let Some(v) = simple_escape(c) {
            return Ok(ClassCode::Literal(v));
        }
        match c {
            // ESCAPES comes first inside a class: \b is a backspace
            b'b' => return Ok(ClassCode::Literal(0x08)),
            b'd' => return Ok(ClassCode::Category("\\d")),
            b'D' => return Ok(ClassCode::Category("\\D")),
            b's' => return Ok(ClassCode::Category("\\s")),
            b'S' => return Ok(ClassCode::Category("\\S")),
            b'w' => return Ok(ClassCode::Category("\\w")),
            b'W' => return Ok(ClassCode::Category("\\W")),
            _ => {}
        }
        match c {
            b'x' => {
                let digits = self.src.getwhile(2, HEXDIGITS)?;
                if digits.len() != 2 {
                    let escape = format!("\\x{}", bytes_text(&digits));
                    let len = digits.len().saturating_add(2);
                    return Err(self.src.error(format!("incomplete escape {escape}"), len));
                }
                Ok(ClassCode::Literal(parse_radix(&digits, 16)))
            }
            b'0'..=b'7' => {
                let mut escape = vec![c];
                escape.extend(self.src.getwhile(2, OCTDIGITS)?);
                let v = parse_radix(&escape, 8);
                if v > 0o377 {
                    let shown = format!("\\{}", bytes_text(&escape));
                    return Err(self.src.error(
                        format!("octal escape value {shown} outside of range 0-0o377"),
                        escape.len().saturating_add(1),
                    ));
                }
                Ok(ClassCode::Literal(v))
            }
            b'8' | b'9' => Err(self.src.error(format!("bad escape \\{}", char::from(c)), 2)),
            c if c.is_ascii_alphabetic() => {
                Err(self.src.error(format!("bad escape \\{}", char::from(c)), 2))
            }
            c => Ok(ClassCode::Literal(u64::from(c))),
        }
    }

    /// A character class, after its `[`.
    fn class(&mut self) -> PResult<String> {
        let here = self.src.tell().saturating_sub(1);
        let negate = self.src.matches(b'^')?;
        let mut members: Vec<String> = Vec::new();
        let unterminated = |p: &Self| {
            p.src.error(
                "unterminated character set",
                p.src.tell().saturating_sub(here),
            )
        };
        loop {
            let Some(this) = self.src.get()? else {
                return Err(unterminated(self));
            };
            if this.is(b']') && !members.is_empty() {
                break;
            }
            let code1 = match this {
                Tok::Esc(c) => self.class_escape(c)?,
                Tok::Char(c) => ClassCode::Literal(u64::from(c)),
            };
            if self.src.matches(b'-')? {
                let Some(that) = self.src.get()? else {
                    return Err(unterminated(self));
                };
                if that.is(b']') {
                    members.push(class_member(&code1));
                    members.push("\\x2D".into());
                    break;
                }
                let code2 = match that {
                    Tok::Esc(c) => self.class_escape(c)?,
                    Tok::Char(c) => ClassCode::Literal(u64::from(c)),
                };
                let bad = || format!("bad character range {}-{}", this.text(), that.text());
                let (ClassCode::Literal(lo), ClassCode::Literal(hi)) = (&code1, &code2) else {
                    let len = this.len().saturating_add(1).saturating_add(that.len());
                    return Err(self.src.error(bad(), len));
                };
                if hi < lo {
                    let len = this.len().saturating_add(1).saturating_add(that.len());
                    return Err(self.src.error(bad(), len));
                }
                let mut m = String::new();
                lit_class(&mut m, *lo);
                m.push('-');
                lit_class(&mut m, *hi);
                members.push(m);
            } else {
                members.push(class_member(&code1));
            }
        }
        Ok(format!(
            "[{}{}]",
            if negate { "^" } else { "" },
            members.concat()
        ))
    }
}

fn class_member(code: &ClassCode) -> String {
    match code {
        ClassCode::Literal(v) => {
            let mut m = String::new();
            lit_class(&mut m, *v);
            m
        }
        ClassCode::Category(c) => (*c).to_string(),
    }
}

fn lit_class(out: &mut String, c: u64) {
    let c = u8::try_from(c).unwrap_or(u8::MAX);
    let _ = write!(out, "\\x{c:02X}");
}

/// `ESCAPES` other than `\b` (whose meaning depends on the context).
fn simple_escape(c: u8) -> Option<u64> {
    Some(match c {
        b'a' => 0x07,
        b'f' => 0x0c,
        b'n' => 0x0a,
        b'r' => 0x0d,
        b't' => 0x09,
        b'v' => 0x0b,
        b'\\' => 0x5c,
        _ => return None,
    })
}

/// Latin-1 letters count as alphabetic for `str.isalpha()` in flag messages.
fn is_latin1_alpha(c: u8) -> bool {
    matches!(c, 0xaa | 0xb5 | 0xba | 0xc0..=0xd6 | 0xd8..=0xf6 | 0xf8..=0xff)
}

fn parse_radix(digits: &[u8], radix: u64) -> u64 {
    digits.iter().fold(0u64, |acc, &d| {
        let v = char::from(d).to_digit(36).map_or(0, u64::from);
        acc.saturating_mul(radix).saturating_add(v)
    })
}

fn repeat_count(digits: &[u8]) -> PResult<u64> {
    let v = parse_radix(digits, 10);
    // int() of a long digit string saturates here; Python raises the same
    // OverflowError for any value at or above MAXREPEAT.
    if v >= MAXREPEAT || digits.len() > 20 {
        return Err(PyError::Plain("the repetition number is too large".into()));
    }
    Ok(v)
}

fn tok_bytes(toks: &[Tok]) -> Vec<u8> {
    toks.iter()
        .flat_map(|t| match *t {
            Tok::Char(c) => vec![c],
            Tok::Esc(c) => vec![b'\\', c],
        })
        .collect()
}

/// `repr()` of a short ASCII-ish str.
fn py_repr(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}
