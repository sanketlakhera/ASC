#![no_main]

//! A pattern and a DEX: the Python-regex translator on arbitrary pattern bytes,
//! then the string locator (region, attribution) with that pattern. Only
//! panics, OOM and timeouts are findings.
//!
//! Input: first byte = pattern length (mod 64), then the pattern, then the DEX.

use asc_core::dex::Dex;
use asc_core::findrefs::pattern;
use asc_core::findrefs::string::StringLocator;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = usize::from(n % 64).min(rest.len());
    let (pat, dex_bytes) = rest.split_at(n);
    let _ = pattern::translate(pat);
    let _ = pattern::compile(pat);
    // the same bytes as a query string (latin-1 to UTF-16 units), MUTF-8
    // encoded by locate as the CLI would
    let units: Vec<u16> = pat.iter().map(|&b| u16::from(b)).collect();
    let Ok(dex) = Dex::new(dex_bytes) else {
        return;
    };
    if let Ok(loc) = StringLocator::build(&dex) {
        let _ = loc.locate(dex_bytes, &units);
        let _ = loc.locate(dex_bytes, &[u16::from(b'.')]);
    }
});
