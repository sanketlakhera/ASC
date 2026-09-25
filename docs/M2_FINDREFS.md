# Milestone 2 (M2): `asc findrefs`

M2 ships the first user-facing Rust command, `asc findrefs`, byte-identical to
`droidasc findrefs`. The plan is the Obsidian note "Droid ASC M2 findrefs"; this
file records what was built, where the implementation departs from the plan and
why, and the result of every exit check.

---

## 1. Status

| Step | Content | Exit check | Result |
|---|---|---|---|
| M2.0 | Oracle fixes F1–F4, golden expansion, `dump_findrefs.py`, `check.py --findrefs`, `differential.py --dump` | sweep 0/0, benchmark gate vs `b3e649e`, goldens, tag | done except the tag (needs a commit) |
| M2.1 | `string.rs`, `types.rs`, pattern translation | string/type maps and queries match | done |
| M2.2 | `member.rs` | method/field maps, 12 locator counts | done |
| M2.3 | `insn.rs`, `verify.rs`, `insn_verify.json`, `verify_differential.py` | insn map matches; 20,000 vectors; 10⁶ differential | done |
| M2.4 | `scan.rs`, `mod.rs`, `format.rs`, `asc dump-findrefs` | stage dump 0 differences; 16 counts | done |
| M2.5 | APK orchestration, `asc findrefs` CLI, `--debug`, `-o` | CLI goldens byte-identical | done |
| M2.6 | fuzz targets, `sweep.py --bin`, `differential.py --dump findrefs` | 1 h per target clean, 0 differing, sweep parity | done |
| M2.7 | `benchmark_compare.py --candidate-bin`, `asc bench-findrefs`, CI | Rust faster on every stage | done |

---

## 2. Oracle changes (M2.0)

All four change no output on any DEX d8 or dx writes. The string locator check
compared old and new over the workload DEX and the 10 DEXes of `Ads Solution
June.apk`, 529 queries: 0 differing, 11 where the old code raised `KeyError`.

| # | Problem | Fix | Tests |
|---|---|---|---|
| F1 | `findrefs string ''` (and `.`, `token.`) printed `Error: 0`: the empty match at the region end found no NUL and looked up offset 0 | `""` returns the empty set, as `TypeLocator` already did | `StringAttributionTests.test_empty_pattern_matches_nothing` |
| F2 | A match was attributed to "the string after the next NUL, minus one index", wrong whenever string_data is not contiguous and in string_ids order, and a `KeyError` when a match consumed the last terminator | The string holding the first NUL at or after the match end: the greatest string_data_off not above it (highest idx among equal offsets). The region runs from the lowest string_data_item to the terminator of the highest | `StringAttributionTests` (6 tests) |
| F3 | With two failing DEX entries, the error printed depended on which worker finished first | Failures are buffered like results and raised when the cursor reaches them: every entry before the first failing one is printed, then its error | `ErrorOrderTests` (both orders) |
| F4 | *New.* `_match_clz_mids` / `_match_clz_fids` iterate a set of ids and decode each name; on a corrupt DEX several names can fail, and which error fires depended on CPython set slot order (`{3, 9}` iterates 9 first) | iterate `sorted(...)`; the result set is unchanged | `MemberNameOrderTests` |

F2 made the gated `unit/string_locator` stage 46% faster: the old build filled
a 68,000-entry dict (7 ms); the new one sorts the offset array once (2.5 ms). A
match that ends at or before the NUL found for the previous match belongs to
the same string and is skipped, which removes a rescan of the workload's
430 KB R8 metadata string for every "View" inside it.

Tests: 67 Python tests pass (was 58); the new ones fail on the pre-M2 oracle
except the two that pin preserved behaviour.

---

## 3. Harness changes

| File | Change |
|---|---|
| `rust/conformance/dump_findrefs.py` | New. Per logical DEX: `string_map`, `type_map`, `method_map`, `field_map`, `insn_map` (walk, bucket table and `method_bounds` as SHA-256 of their canonical JSON), and 15–23 queries with located ids, scan offsets, marks, verified owners and lines. Lists over 64 entries are stored as count, hash and head |
| `rust/conformance/gen_golden.py` | 3 new corpus APKs (F3 in both orders, an APK without DEX entries); findrefs CLI cases from 11 to 117; `findrefs/findrefs.json.gz` per corpus APK; per-query `error_prefix_only`, `exit_code_only`, `rust_expect`, `no_output_file`; `--debug` numbers normalised to `N` |
| `rust/conformance/check.py` | `--findrefs` (stage dumps), `--only <command>`, the per-query flags |
| all three CLI harnesses | stdout and stderr are captured as bytes. `subprocess.run(text=True)` turns every `\r` into `\n`, on both sides, so a real `\r` vs `\n` difference was invisible (the sweep found a method name holding `\r`) |
| `rust/conformance/gen_vectors.py` | `vectors/insn_verify.json` (20,000 streams, both Python regex forms), `vectors/patterns.json` (2,999 patterns with Python's `re.error` text or matched strings) |
| `rust/conformance/verify_differential.py`, `insn_streams.py` | INSN_VERIFY differential through `asc verify-insns` |
| `rust/conformance/regex_differential.py` | Pattern differential through `asc regex-probe` over the workload's string_data |
| `rust/conformance/sweep.py` | `--bin`: every findrefs case also through `asc findrefs`, compared on exit code, stdout, stderr |
| `rust/fuzz/differential.py` | `--dump primitives|findrefs` |
| `tests/benchmark_compare.py` | `--candidate-bin`: `cli_findrefs` through the Rust CLI and the new `rust_unit` case (`asc bench-findrefs`); a Rust metric must have a lower median, not only avoid a significant slowdown |

---

## 4. Rust implementation

`asc-core/src/findrefs/`:

| Module | Python source | Notes |
|---|---|---|
| `pattern.rs` | `re._parser` (3.12) | Port of the tokenizer and parser; emits a `regex::bytes` pattern from the parsed items, every literal as `\xNN`. `re.error` text and positions reproduced |
| `string.rs` | `string_locator.py` | F2 attribution; one `memchr` per NUL, reused across matches |
| `types.rs`, `member.rs`, `index.rs` | `type_locator.py`, `method_locator.py`, `field_locator.py` | The `defaultdict(set)` maps as sorted `(key, id)` arrays. Precise class plus name compares code points, as `str.find` does |
| `insn.rs` | `insn_locator.py` | Bucket table sized `len / 16`; merged owners as a persistent list, since copying `old + [new]` as Python does keeps every intermediate list alive (quadratic in methods sharing a bucket) |
| `verify.rs` | `INSN_VERIFY` | A deterministic instruction walk; `pos > endpos` never matches, bounds clamp like `fullmatch` |
| `scan.rs` | `code_item_scan.py` | One loop; `memchr2` for the two string opcodes |
| `format.rs`, `mod.rs` | `AscHandler` | Lazy build order string → type → member, instruction map only when something was located |

`asc-core/src/apk.rs`: `map_ordered`, a scoped thread pool that emits results in
item order and holds failures until the cursor reaches them; reusable for
`getclass` in M3. `asc-cli`: `argparse.rs` (a port of Python 3.12 argparse's
matching for this grammar), `findrefs_cmd.rs`, and hidden `dump-findrefs`,
`verify-insns`, `regex-probe`, `bench-findrefs`.

---

## 5. Departures from the plan

**Decision R, refined.** The plan compiles queries with `regex::bytes` and
refuses what it rejects. That is not enough: `regex` accepts several Python
patterns with another meaning (`\<` is a word boundary, `[a&&b]` an
intersection, `\x{41}` and `(?<name>...)` valid, `^*` allowed, a global flag
anywhere), so plain compilation would diverge silently. Queries are parsed as
Python parses them and re-emitted. As a result `a{`, `x{}` and `{,3}` work as
in Python instead of being refused. Refused, with `Error: unsupported pattern
syntax: ...`: lookaround, backreferences, conditionals, atomic groups,
possessive repeats, `(?L)`, and (new, below) empty-preferring nullable patterns.

**Empty-match iteration (new finding).** Plan section 5 says empty matches
iterate identically in both engines. They do not: after an empty match at `p`,
CPython's `finditer` looks for a non-empty match at `p` (`must_advance`), while
`regex` moves to `p + 1`. This only matters when the pattern can match empty
and prefers an empty option (`|token`, `x*|y`, `a*?`), but then the results
really differ (`(?m)|...{,}` attributes 1 string in Python, 678 in Rust on the
same data). Such patterns are refused. The rule was checked by the pattern
differential: 0 NUL-set differences on every pattern accepted.

**Decision E, exceeded.** Planned: match only the `Error: ` prefix of `re.error`
messages. Achieved: the exact text, 0 differences on 8,601 rejected patterns.
`error_prefix_only` is kept on the one golden that uses it.

**Argparse prefixes.** The plan says `--thr 4` is accepted. In Python 3.12 it
is ambiguous (`--threads`, `--thread`) and exits 2; `asc` does the same, and a
golden pins it.

**`--threads` above the process limit.** Python's `ProcessPoolExecutor` with the
fork context starts all `max_workers` processes at once, so a very large value
fails with an OS error that depends on the platform and its limits (on macOS
`[Errno 35]` at the process limit, `[Errno 22]` from 32,767, an int overflow
from 2³¹ − 1).
Not reproduced: `asc` runs one thread per entry at most. `--threads 0` and
negative values print Python's message, as decided (T).

**Python warnings.** A class such as `[[a]` or `[a--b]` makes Python print a
`FutureWarning` on stderr; `asc` prints nothing. Matches are the same.

---

## 6. Results

| Check | Result |
|---|---|
| `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo test` | clean; 17 findrefs unit and property tests, 3 vector tests, the 16 reference counts |
| `check.py --only findrefs` (CLI goldens) | 117 / 117 byte-identical, also with a debug build |
| `check.py --findrefs` (stage dumps) | 28 / 28 corpus APKs, including the workload and the 10-DEX Ads APK |
| `check.py --primitives` (M1) | still 28 / 28 |
| `differential.py --dump findrefs` | 4,029 fuzz inputs, 0 differing |
| `verify_differential.py --streams 1000000` | atomic vs plain Python: 0; Rust vs Python: 0 (496,087 accepted) |
| `regex_differential.py --patterns 20000` | error text 0, NUL set 0, wrongly refused 0 |
| `sweep.py mut --byte-mutations 700 --u32-mutations 300 --no-getclass --bin` | 21,000 findrefs cases: 0 LEAK, 0 TIMEOUT, RUST-DIFF 0 |
| `sweep.py trunc --no-getclass --bin` | 12,824 cases: 0 LEAK, 0 TIMEOUT, RUST-DIFF 0 |
| Fuzz, 1 h per target (ASan, 64 MiB allocation cap, 10 s per input) | `string_locator` 1,609,818 runs, `insn_locator` 4,403,528, `findrefs` 1,797,544: no crash, OOM or timeout; slowest input under 1 s |
| `benchmark_compare.py --baseline b3e649e` (Python oracle vs M1), 31 samples | passes. `string_locator` −46%, `type_locator` −32%; two ungated ~50 µs precise-class cases +4% and +14% (F4's `sorted` of a few ids) |
| `benchmark_compare.py --candidate-bin`, 31 samples | passes: Rust faster on all 21 metrics. `cli_findrefs` 34 ms vs 202 ms (5.9×); stages 4.8× (`method_ref_scan`) to 26× |

---

## 7. Open

- **Commit and tag.** Goldens were generated with `--allow-dirty` against the
  working tree. After committing: regenerate them from the clean tree, commit
  them, tag `oracle-m2`.
- **`cli_findrefs` under 30 ms** (a target, not a gate) is not reached: the median
  is 34 ms, most of it inflating the workload's 9.6 MB DEX (~31 ms with zlib-rs,
  level with CPython's zlib).
- Parent plan trap table: rows for the section 4 traps, and F4 and the
  empty-match finding, are not yet added to the Obsidian note.
- `getclass` and `getmanifest` goldens fail against `asc` until M3 and M4
  (`check.py --only findrefs` exists for this).
