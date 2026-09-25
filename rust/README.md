# asc: the Rust port of Droid ASC

A single binary with no Python at runtime. It is built milestone by milestone
against the Python implementation, which acts as the oracle: for every input,
stdout, stderr and the exit code must be the bytes Python produces.

| Command | Status |
|---|---|
| `asc findrefs` | available (M2) |
| `asc getclass` | M3 (DEX rebuild) and M5 (DAD decompiler) |
| `asc getmanifest` | M4 (AXML) |
| help and usage text | M6 |

## Build

```sh
cd rust
cargo build --release          # target/release/asc
```

The toolchain is pinned in `rust-toolchain.toml` (1.98.1). The fuzz crate in
`fuzz/` needs `cargo +nightly`.

## `asc findrefs`

Same grammar as `droidasc findrefs`, including argparse's quirks (options
interleaved with positionals, `--threads=4`, `-oFILE`, unique prefixes such
as `--deb` and `--fuzzy`; `--thr` is ambiguous between `--threads` and
`--thread` and is rejected, as in Python):

```sh
asc findrefs app.apk string token -o string_refs.txt
asc findrefs app.apk type com.poc.Main
asc findrefs app.apk method onCreate --class com.poc.Main
asc findrefs --threads 16 app.apk method notify --class MainActivity --fuzzy-class
asc findrefs app.apk field apiKey
```

Output lines are `{dex} | {Lclass;}->{method} | matched=({a}; {b})`, one per
referencing method, in DEX entry order (ascending compressed size), then
method index. `-o FILE` receives the same bytes.

### Patterns

String, type, fuzzy-class and name queries are Python `re` patterns over
bytes, exactly as in the Python tool: the query is MUTF-8 encoded and matched
against the whole string_data region (so `.` also matches the NUL between two
strings). The Rust port parses each pattern with a port of CPython 3.12's
`re._parser` and translates it for the `regex` crate, so Python syntax keeps
its Python meaning: `a{` and `x{}` are literals, `{,3}` means `{0,3}`, `\<` is
a literal `<`, `&&` inside a class is two characters, `(?<name>...)` and `\z`
are errors. A pattern Python rejects gets the same `Error:` text Python prints
(`missing ), unterminated subpattern at position 0`).

Refused with `Error: unsupported pattern syntax: ...` (exit 1), because the
`regex` crate cannot express them:

- lookahead and lookbehind: `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`
- backreferences: `\1`, `(?P=name)`
- conditional groups: `(?(1)yes|no)`
- atomic groups `(?>...)` and possessive repeats (`a*+`, `a++`, `a?+`, `a{2}+`)
- the locale flag `(?L)`
- a pattern that can match the empty string *and* prefers an empty option
  somewhere: a lazy repeat (`a*?`, `x??`) or an alternative that can match
  empty before another one (`|token`, `x*|y`). After an empty match at a
  position, Python's `finditer` looks for a non-empty match at the same
  position, which `regex` cannot do, and the two would report different
  strings. Patterns that cannot match empty (`tok.n`, `a|b`) and greedy ones
  whose empty option comes last (`\d*`, `y|x*`) are unaffected.
- a pattern whose compiled form exceeds `regex`'s size limit (very large
  repetition counts)

Known differences outside patterns:

- Python prints a `FutureWarning` to stderr for class syntax such as `[[a]`
  or `[a--b]`; `asc` does not. Matches are the same.
- `--threads N` in Python forks N worker processes up front, so a very large
  N fails with an operating-system error that depends on the platform and its
  process limits. `asc` runs at most one thread per DEX entry.

## Conformance

The Python side runs in the oracle environment (Python 3.12, androguard 4.1.3):

```sh
uv run --python 3.12 --with androguard==4.1.3 python rust/conformance/gen_golden.py   # regenerate goldens (clean tree)
python rust/conformance/check.py --only findrefs --bin rust/target/release/asc    # CLI goldens
python rust/conformance/check.py --findrefs --bin rust/target/release/asc        # findrefs stage dumps
python rust/conformance/check.py --primitives --bin rust/target/release/asc      # M1 primitives
python rust/conformance/verify_differential.py --bin rust/target/release/asc --streams 1000000
python rust/conformance/regex_differential.py --bin rust/target/release/asc --patterns 20000
python rust/fuzz/differential.py --dump findrefs --bin rust/target/release/asc rust/fuzz/corpus/tinydex_walk
python rust/conformance/sweep.py mut --byte-mutations 700 --u32-mutations 300 --no-getclass --bin rust/target/release/asc
python tests/benchmark_compare.py --baseline . --candidate-bin rust/target/release/asc
```

`docs/M2_FINDREFS.md` records what M2 changed and the results of each check.
