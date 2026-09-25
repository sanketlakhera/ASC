//! Hidden probes for the differential tests.
//!
//! `asc verify-insns`: stdin lines `HEX START END` (`-` for an empty stream),
//! prints `1` or `0` per line,
//! the verifier's answer for that instruction stream (`verify_differential.py`).
//!
//! `asc regex-probe HAYSTACK`: stdin lines of hex-encoded (MUTF-8) patterns;
//! prints one JSON object per line: `{"error": ...}` (the Python `re.error`
//! text), `{"unsupported": ...}`, or the matches over the haystack as counts
//! and SHA-256 of the spans and of the first-NUL-after-end positions
//! (`regex_differential.py`).

use asc_core::AscError;
use asc_core::findrefs::{pattern, verify};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};

fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn digest(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn verify_insns() -> i32 {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return 1 };
        let mut parts = line.split_whitespace();
        let (Some(hex), Some(start), Some(end)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let buf = if hex == "-" {
            Some(Vec::new())
        } else {
            unhex(hex)
        };
        let (Some(buf), Ok(start), Ok(end)) = (buf, start.parse(), end.parse()) else {
            return 1;
        };
        let _ = writeln!(out, "{}", u8::from(verify::walk_reaches(&buf, start, end)));
    }
    let _ = out.flush();
    0
}

pub fn regex_probe(haystack: &[u8]) -> i32 {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return 1 };
        let Some(pat) = unhex(line.trim()) else {
            return 1;
        };
        let result = match pattern::compile(&pat) {
            Err(AscError::UnsupportedPattern(m)) => json!({ "unsupported": m }),
            Err(e) => json!({ "error": e.to_string() }),
            Ok(re) => {
                let mut spans = String::from("[");
                let mut nuls = BTreeSet::new();
                let mut n = 0usize;
                for m in re.find_iter(haystack) {
                    if n > 0 {
                        spans.push(',');
                    }
                    spans.push_str(&format!("[{},{}]", m.start(), m.end()));
                    n = n.saturating_add(1);
                    if let Some(p) = haystack.get(m.end()..).and_then(memchr_nul) {
                        nuls.insert(m.end().saturating_add(p));
                    }
                }
                spans.push(']');
                let nul_list: Vec<String> = nuls.iter().map(ToString::to_string).collect();
                json!({
                    "spans": n,
                    "spans_sha256": digest(&spans),
                    "nuls": nuls.len(),
                    "nuls_sha256": digest(&format!("[{}]", nul_list.join(","))),
                })
            }
        };
        let _ = writeln!(out, "{result}");
    }
    let _ = out.flush();
    0
}

fn memchr_nul(r: &[u8]) -> Option<usize> {
    r.iter().position(|&b| b == 0)
}
