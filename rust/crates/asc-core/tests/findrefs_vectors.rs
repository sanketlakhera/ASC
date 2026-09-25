#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
//! Vector files generated from the Python oracle by `conformance/gen_vectors.py`.

use asc_core::AscError;
use asc_core::findrefs::{pattern, verify};
use asc_core::mutf8::encode_mutf8;
use serde::Deserialize;
use std::collections::BTreeSet;

fn vectors(name: &str) -> String {
    let path = format!(
        "{}/../../conformance/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(Deserialize)]
struct InsnCase {
    hex: String,
    start: usize,
    end: usize,
    atomic: bool,
    plain: bool,
}

/// INSN_VERIFY: the walk agrees with Python's pattern, in both compiled forms,
/// on every committed stream.
#[test]
fn insn_verify_walk_matches_both_python_patterns() {
    let cases: Vec<InsnCase> = serde_json::from_str(&vectors("insn_verify.json")).unwrap();
    assert!(cases.len() >= 20_000);
    let mut accepted = 0;
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(c.atomic, c.plain, "case {i}: the two Python forms disagree");
        let got = verify::walk_reaches(&unhex(&c.hex), c.start, c.end);
        assert_eq!(
            got, c.atomic,
            "case {i}: {} [{}, {})",
            c.hex, c.start, c.end
        );
        accepted += usize::from(got);
    }
    // both outcomes are well represented
    assert!(accepted > cases.len() / 5 && accepted < cases.len() * 4 / 5);
}

#[derive(Deserialize)]
struct PatternVectors {
    haystack_hex: String,
    cases: Vec<PatternCase>,
}

#[derive(Deserialize)]
struct PatternCase {
    pattern: Vec<u16>,
    error: Option<String>,
    nuls: Option<Vec<usize>>,
}

/// Python bytes patterns: the same `re.error` text for every pattern Python
/// rejects; for every pattern Python accepts and the translation runs, the
/// same strings (first NUL at or after each match end).
#[test]
fn patterns_match_python_re() {
    let v: PatternVectors = serde_json::from_str(&vectors("patterns.json")).unwrap();
    let hay = unhex(&v.haystack_hex);
    let (mut ran, mut refused) = (0, 0);
    for c in &v.cases {
        let shown = String::from_utf16_lossy(&c.pattern);
        let compiled = pattern::compile(&encode_mutf8(&c.pattern));
        match (&c.error, compiled) {
            (Some(expected), Err(AscError::PatternError(got))) => {
                assert_eq!(&got, expected, "pattern {shown:?}");
            }
            (Some(expected), other) => {
                panic!("pattern {shown:?}: Python raised {expected:?}, Rust gave {other:?}")
            }
            (None, Err(AscError::UnsupportedPattern(_))) => refused += 1,
            (None, Err(e)) => panic!("pattern {shown:?}: Python compiled it, Rust: {e}"),
            (None, Ok(re)) => {
                ran += 1;
                let nuls: BTreeSet<usize> = re
                    .find_iter(&hay)
                    .filter_map(|m| {
                        hay[m.end()..]
                            .iter()
                            .position(|&b| b == 0)
                            .map(|p| m.end() + p)
                    })
                    .collect();
                let expected: BTreeSet<usize> = c.nuls.clone().unwrap().into_iter().collect();
                assert_eq!(nuls, expected, "pattern {shown:?}");
            }
        }
    }
    assert!(ran > 500, "only {ran} patterns ran ({refused} refused)");
}

/// Constructs where `regex` syntax differs from Python's.
#[test]
fn python_syntax_is_translated_not_passed_through() {
    let hay = b"\x05token\0\x03a{b\0\x03<x>\0\x03a&b\0";
    let strings = |p: &str| -> Result<BTreeSet<usize>, AscError> {
        let re = pattern::compile(p.as_bytes())?;
        Ok(re
            .find_iter(hay)
            .filter_map(|m| {
                hay[m.end()..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|q| m.end() + q)
            })
            .collect())
    };
    // a brace that does not start a repeat is a literal
    assert_eq!(strings("a{").unwrap(), [11].into());
    assert_eq!(strings("a{b").unwrap(), [11].into());
    // {,n} is {0,n}
    assert_eq!(strings("tok{,1}en").unwrap(), [6].into());
    // \< is a literal <, not a word boundary
    assert_eq!(strings("\\<x").unwrap(), [16].into());
    // && inside a class is two literals, not an intersection
    assert_eq!(strings("[&&]").unwrap(), [21].into());
    // [[a] is a class of [ and a
    assert_eq!(strings("x[[>]").unwrap(), [16].into());
    // Python rejects what regex would accept
    for (p, msg) in [
        ("\\x{41}", "incomplete escape \\x at position 0"),
        ("(?<n>x)", "unknown extension ?<n at position 1"),
        (
            "a(?i)b",
            "global flags not at the start of the expression at position 1",
        ),
        ("^*", "nothing to repeat at position 1"),
        ("\\z", "bad escape \\z at position 0"),
    ] {
        match pattern::compile(p.as_bytes()) {
            Err(AscError::PatternError(m)) => assert_eq!(m, msg, "{p}"),
            other => panic!("{p}: {other:?}"),
        }
    }
    // Python accepts what regex cannot express
    for p in [
        "(?<=t)oken",
        "(?=t)",
        "(t)\\1",
        "(?>t)",
        "to++ken",
        "(?L)t",
        "|token",
        "t*?",
    ] {
        assert!(
            matches!(
                pattern::compile(p.as_bytes()),
                Err(AscError::UnsupportedPattern(_))
            ),
            "{p}"
        );
    }
}
