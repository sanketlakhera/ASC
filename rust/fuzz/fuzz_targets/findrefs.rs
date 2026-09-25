#![no_main]

//! The whole findrefs pipeline (`AscHandler.findrefs`) on arbitrary DEX bytes
//! with a fixed query list covering every locator mode. Only panics, OOM and
//! timeouts are findings.

use asc_core::dex::iter_logical_dex_buffers;
use asc_core::findrefs::member::MemberQuery;
use asc_core::findrefs::{self, Query};
use libfuzzer_sys::fuzz_target;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn queries() -> Vec<Query> {
    let member = |class: Option<(&str, bool)>, name: Option<&str>| MemberQuery {
        class: class.map(|(c, p)| (units(c), p)),
        name: name.map(units),
    };
    vec![
        Query::String(units("token")),
        Query::String(units(".")),
        Query::String(units("(?i)a|b")),
        Query::Type(units("L")),
        Query::Type(units("Lexample/Test;")),
        Query::Method(member(None, Some("first"))),
        Query::Method(member(Some(("Lexample/Test;", true)), None)),
        Query::Method(member(Some(("Lexample/Test;", true)), Some("i"))),
        Query::Method(member(Some(("example", false)), Some("."))),
        Query::Field(member(None, Some("."))),
        Query::Field(member(Some(("L", false)), None)),
    ]
}

fuzz_target!(|data: &[u8]| {
    let queries = queries();
    for (name, buf) in iter_logical_dex_buffers("classes.dex", data) {
        for q in &queries {
            let _ = findrefs::findrefs(&name, &buf, q);
        }
    }
});
