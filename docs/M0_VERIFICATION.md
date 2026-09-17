# M0 Verification Report

Independent check of the work described in `M0_ORACLE_PREPARATION.md`: commit `86fe46d` plus the uncommitted step 5, 6 and 7 changes. Round 1 was performed on 17 Sep 2026 against the first version of those changes. Round 2 (section 5 onward) re-verifies the tree after the author addressed the round 1 findings.

**Round 2 verdict:** the code is correct on valid input and changes no output. All suites pass on Python 3.11 and 3.12. The harness now records the right environment, keeps raw stdout, and passes 14 / 14. Two things still block the M0 exit criteria: a gated benchmark regression in the string locator, and the goldens being generated from a dirty tree. Corrupt-input handling is clean for every truncation but not for byte mutations.

---

## 1. Round 1: what was verified and how

| Check | Method | Result |
|---|---|---|
| Test suites | `tests/run_tests.py --require-decompiler` on Python 3.12 + androguard 4.1.3 (pinned oracle env) and on Python 3.14.7 + androguard 4.1.4 (repo `.venv`) | 50 / 50 pass on both. Unit suite 41, integration suite 9, matching the document |
| Output equivalence | 202 classes sampled from the reference workload DEX and `Ads Solution June.apk` decompiled, rebuilt-DEX SHA-256 recorded, nine findrefs queries captured, one getclass CLI run captured; compared against the verified capture from the M0 session | Byte-identical Java for all 202 classes, identical DEX hashes, identical findrefs and getclass output. The hardening changed no behaviour on valid input |
| Decompiler determinism | Same capture under `PYTHONHASHSEED=41`, compared with earlier seeds 1, 2, 3, 7, 11, 31, 32 | Identical |
| Stubbed modules (step 6) | The 202-class capture repeated with every module in `_STUBBED_MODULES` imported for real before `decompiler.py` loads, so the stubs are skipped | Identical Java for all 202 classes. The stubs do not change decompiler output |
| Corrupt-input tests (step 5) | Ran the seven `CorruptInputTests`, then probed further with DEX bodies truncated at 0x70, 0x90, 0xB0 bytes inside an APK | The seven cases pass. Deeper truncation leaked internal messages (fixed in round 2, see 5.3) |
| Conformance harness (step 7) | `check.py --bin <wrapper around the pinned oracle>` | 10 / 10 pass, as the document stated |
| Timing | `tests/benchmark_compare.py --baseline <main worktree> --samples 15 --cases unit core cli_getclass` | No gated regression at that time |

## 2. Round 1 findings and their round 2 status

| # | Finding | Round 2 status |
|---|---|---|
| 1 | Goldens generated with Python 3.14.7 / androguard 4.1.4, not the pinned oracle | **Resolved.** Every `meta.json` records Python 3.12.14 and androguard 4.1.3 |
| 2 | Recorded revision `86fe46d` hid a dirty tree | **Partly resolved.** `meta.json` now records `86fe46d-dirty`, `git_dirty: true` and the SHA-256 of `git diff HEAD`, and that hash matches the current tree. The goldens are still from a dirty tree, so they must be regenerated after the commit. `--allow-dirty` has `default=True`, so the flag is a no-op and the refusal path never triggers |
| 3 | `.gitignore` swallowed `*.apk` / `*.dex` under the harness | **Resolved.** `git check-ignore` confirms `!rust/conformance/**` re-includes the corpus and `rebuilt.dex`. Side effect: it also re-includes `__pycache__` and `*.pyc` under that directory. None exist today, but a run of the scripts from that directory will create them |
| 4 | Blank lines stripped from stdout | **Resolved.** `clean_cli_output` returns raw text unless `--debug` is in the arguments. The getclass golden now has 14 lines |
| 5 | Workload and real APK unused by any query | **Partly resolved.** The real APK now backs a getclass and a getmanifest golden. The workload backs one findrefs query for `token`, whose golden is **empty** because the workload has no such string, so the only real-code findrefs golden proves nothing. The `mutf8` fixture is built but no query uses it |
| 6 | No getmanifest golden | **Resolved.** Two goldens, synthetic and real |
| 7 | Level 2 (rebuilt DEX) never checked | **Not resolved.** `--check-dex` only hashes a `candidate_rebuilt.dex` if some external step has already left that file in the golden directory. Nothing produces it, so the option can never fail. It needs the `getdex` subcommand from M3; until then say so in the docstring rather than presenting it as a check |
| 8 | Level 3 claimed in docstring | **Resolved** |
| 9 | Static-field query targeted a class with no fields | **Resolved.** One hit line on `Lexample/Statics;->SECOND` |
| 10 | Deflate error embedded zlib text | **Resolved.** `corrupt deflate stream in classes.dex` |
| 11 | getmanifest leaked `[Errno 2]` | **Resolved.** `APK file not found: <path>` on all three commands, with a test |
| 12 | Truncated DEX leaked on the findrefs path | **Resolved for truncation, open for mutation.** See 5.3. The document also claims `dex_container.py` was hardened; the diff contains no change to that file |
| 13 | Post-flush cancel check "lost" | **Withdrawn.** `_inflate_deflate_chunks` is identical to `86fe46d`; the round 1 note was wrong |
| 14 | Commit message under-describes | Unchanged; still applies to `86fe46d` |

---

## 3. Round 1 timing (for the record)

Paired comparison against `main` (`ff1df85`), 15 samples: all eleven gated metrics passed; `core/decompile` +2.8 %, `cli_getclass` +2.0 %, `unit/dexmethod` +10.6 % (ungated).

---

## 4. Round 2: what was verified and how

| Check | Method | Result |
|---|---|---|
| Test suites | `run_tests.py --require-decompiler`, unit and integration, on three environments: Python 3.11.16 + androguard 4.1.3, Python 3.12.14 + androguard 4.1.3 (pinned oracle), Python 3.12.14 + androguard 4.1.4 (repo `.venv`) | 43 / 43 and 9 / 9 on all three. Matches the document. Note `uv run --python 3.12` rebuilt the repo `.venv` as 3.12, so 3.14 is no longer covered locally; CI runs 3.11 and 3.12, which are |
| Output equivalence | Same 202-class capture as round 1, rerun on the current tree with the pinned oracle, `diff -r` against the verified M0 capture | Identical: Java text, rebuilt DEX hashes, findrefs and getclass output |
| Golden metadata | Parsed all 14 `meta.json` entries | Python 3.12.14, androguard 4.1.3, revision `86fe46d-dirty`, one diff hash equal to `sha256(git diff HEAD)` of the tree as verified |
| Conformance harness | `check.py --bin <pinned oracle wrapper> --check-dex` | 14 / 14 pass |
| androguard pin sensitivity | `check.py` with the androguard 4.1.4 environment as candidate | 14 / 14 pass. The 4.1.3 pin is not load-bearing for the current goldens, which is good to know but does not remove the need to pin |
| Corrupt input, truncation | Every truncation length of the three fixture DEXes (432 + 472 + 928 lengths) driven in-process through seven findrefs queries and two getclass targets, 16,488 cases; any exception that is not a `ValueError` with a contract message counts as a leak | findrefs: 0 leaks. getclass: 4 leaks, one family (5.3) |
| Corrupt input, mutation | 300 seeded single-byte and 4-byte mutations of the same fixtures, 2,700 cases, 3 s / 5 s watchdog | findrefs: 6 leaks, 44 timeouts. getclass: 21 leaks (5.3) |
| Timing | `benchmark_compare.py --baseline <worktree at 86fe46d> --cases unit core cli_getclass cli_findrefs` (default samples), so base = committed M0, candidate = working tree | **Gate fails**: `unit/string_locator` +22.2 %, p < 0.001 (5.1) |

---

## 5. Round 2 findings

### 5.1 Must fix: gated benchmark regression

`unit/string_locator` is 22 % slower than `86fe46d` and the harness exits non-zero. The cause is the new per-string check in `StringLocator._build_map` (`string_locator.py`): `if data_offset >= len(buf)` inside the loop over every string id, with `len(buf)` evaluated each iteration. On the workload DEX that loop runs 68,154 times.

Loop variants measured in isolation on the workload DEX, best of 7 × 20 runs:

| Variant | Time | vs HEAD |
|---|---|---|
| HEAD (no check) | 12.9 ms | 0 |
| working tree (check, `len(buf)` per iteration) | 15.7 ms | +21 % |
| check with `len(buf)` hoisted to a local | 13.7 ms | +5.6 % |
| no per-item check, one `max(stridx_map) >= len(buf)` after the loop | 14.1 ms | +8.8 % |
| bulk read with `array('I')`, one `max()` check, `dict(zip(...))` | 8.2 ms | −37 % |

Hoisting alone does not clear the 3 % floor. The `array('I')` variant clears it with room and keeps the check; it must guard `sys.byteorder` (or `byteswap()`), because `array` is native-endian while DEX is little-endian. An alternative is to drop the per-item check and let the consumers validate, since `read_uleb128_len` and `_read_string_bytes` are now guarded; then `bad string_data offset` disappears from the findrefs path and its test expectation changes.

Other ungated movements in the same run: `unit/dexmethod` +4.2 % (p < 0.001) and `unit/field_locator_precise_class_field` +18.5 % on a 31 µs operation. Gated metrics other than the string locator: `cli_getclass` +2.7 %, `unit/code_scan` +3.2 % (not significant), the rest within ±1.6 %.

### 5.2 Must fix before goldens are frozen

1. **Regenerate after committing.** All 14 goldens cite `86fe46d-dirty`. Make `--allow-dirty` default to `False` so the generator refuses a dirty tree unless asked.
2. **Corpus APKs are not reproducible.** `zipfile.writestr` stamps the current time into every entry, so each generator run produces different APK hashes, new golden directories, and leaves the old ones behind. Three stale directories from the 14:29 run (`7d193802…`, `c50e1580…`, `c7d2ff2f…`) are on disk, absent from `manifest.json`, and would be committed with the rest. Write entries with a fixed `ZipInfo.date_time` (for example 1980-01-01), and have the generator clear the golden directory first.
3. **`check.py` never verifies the APK it runs.** It resolves the corpus file by name and ignores `meta.apk_sha256`. Compare the hash and refuse on mismatch, otherwise a regenerated corpus silently tests against goldens made from a different file.

### 5.3 Corrupt-input handling after step 5

Truncation is now handled cleanly on the findrefs path for every prefix of every fixture: only contract messages (`bad DEX magic or header size`, `bad string_ids range`, `bad string_data offset`, `unterminated uleb128`, `unterminated string_data_item`) or a normal result. That closes round 1 item 12 as stated.

Remaining leaks, with the frame that raises:

| Path | Trigger | Exception | Where |
|---|---|---|---|
| getclass | static-field fixture truncated at 319–321 bytes | `IndexError: index out of bounds on dimension 1` | `dex_parser.py:5` `parse_encoded_value`, `data[pos]` past the end of `static_values` |
| getclass | same fixture truncated at 322 bytes | `ValueError: byte must be in range(0, 256)` | `dex_parser.py:161` `rebuild_encoded_value`, empty value bytes from a truncated element |
| findrefs field, string | mutated `method_ids` offset or size | `struct.error: unpack_from requires a buffer of at least N bytes` | `tinydex.py:469` `__getitem__` via `get_method` (`tinydex.py:454`) and `DexMethod.__init__` (`tinydex.py:181`) |
| getclass | mutated `proto_ids` data | `struct.error` | `tinydex.py:140` `parameters_type` via `dex_remapper.py:284` |
| getclass | mutated bytes that survive rebuild | `struct.error: unpack requires a buffer of 16 bytes` | androguard parsing the rebuilt DEX, from `decompiler.py:344` |

The `struct.error` from a mutated method table is reachable from the CLI on the findrefs path, which is the path round 1 flagged. Guard `get_method`, `get_field`, `get_proto` and `parameters_type` in `tinydex.py` the same way `get_type` and `_read_string_bytes` now are, and bound `parse_encoded_value` by the buffer length.

**Hangs.** 44 of 2,700 mutated inputs did not finish within 3 seconds. The stack in every sampled case is `insn_locator.py:93` `_encoded_method_parse` inside `_class_data_parse`, looping over a mutated `class_data` count in the billions. This is not a message leak, but a Rust port that bounds these loops will diverge from an oracle that spins, so decide the contract now: either cap counts by the remaining buffer and raise `bad class_data`, or accept the spin. Raising is cheaper to specify.

### 5.4 Harness coverage

- The workload findrefs golden is empty. `tests/fixtures/reference-baseline.json` holds 16 queries with known hit counts on that DEX; use those as the workload queries so the real-code goldens have content.
- No query uses the `mutf8` fixture. Add a `findrefs string` with a non-ASCII pattern and a `getclass` on the emoji-named class, since MUTF-8 handling is the trap the fixture exists for.
- No getclass golden on the DEX 041 container.
- `getmanifest_stored` golden is four lines: three of XML plus the trailing newline `print` adds. The Rust CLI must reproduce that trailing newline; worth a note in the vault's trap table.

### 5.5 Document accuracy

`M0_ORACLE_PREPARATION.md` is accurate on test counts (43 + 9), on 14 / 14, and on the meta fields. Three claims need correcting: `dex_container.py` was not changed; `--check-dex` is a stub, not a verification; "Level 2 candidate verification path" overstates the same stub. Section 4 item 13 can cite that `_inflate_deflate_chunks` is unchanged from `86fe46d`.

---

## 6. Recommended order

1. 5.1: fix the string locator loop and rerun `benchmark_compare.py` against `86fe46d`. This is an M0 exit criterion.
2. 5.3: bounds checks in `tinydex.py` member accessors and `dex_parser.py`; decide the hang contract.
3. Commit, then 5.2: deterministic corpus, clean golden dir, hash check, dirty refusal, regenerate. Tag that commit as the oracle.
4. 5.4 coverage additions can go in the same regeneration.
5. 5.5 wording fixes in the milestone document.

---

## 7. Round 3: fixes applied for 5.1 and 5.2

Applied on 17 Sep 2026 after round 2, then verified the same way.

| Change | File | Effect |
|---|---|---|
| String-id table read in bulk with `array('I')` (byte-order guarded, `struct.iter_unpack` fallback), one `max()` bounds check, `dict.update(zip(...))` | `droidasc/asc_core/findrefs/locator/string_locator.py` | `unit/string_locator` −31.0 % vs `86fe46d`. Same `bad string_data offset` message |
| Per-method `code_off` bounds check removed from `_encoded_method_parse`; `parse()` maps `struct.error` to `bad code_item offset` once per DEX | `droidasc/asc_core/findrefs/locator/insn_locator.py` | `unit/insn_locator` back to +0.3 % (one intermediate run had it at +3.4 %, over the floor). Contract message unchanged, confirmed on the sweep's `static u32@317` case |
| `--allow-dirty` defaults to `False`; the dirty check ignores the generator's own output directories; the golden directory is wiped before generation | `rust/conformance/gen_golden.py` | Goldens can only cite a checked-out revision unless explicitly overridden; stale cases cannot linger |
| Corpus entries written with a fixed `ZipInfo.date_time` (1980-01-01) | `rust/conformance/gen_golden.py` | Corpus APKs and therefore golden directory names are reproducible run to run |
| Corpus APK SHA-256 compared with `meta.apk_sha256` before each case | `rust/conformance/check.py` | A regenerated or swapped corpus cannot pass silently against old goldens |
| `uv.lock` ignored | `.gitignore` | Repo installs from `requirements.txt`; the oracle pin lives in the harness docstring, and an untracked lockfile no longer makes the tree look dirty |

Benchmark after the fixes, base `86fe46d`, candidate working tree, all four case groups: exit 0, no gated regression. Gated metrics: `cli_findrefs` −2.4 %, `cli_getclass` 0.0 %, `core/decompile` −0.1 %, `unit/insn_locator` +0.3 %, `unit/string_locator` −31.0 %, others within ±0.6 %. Ungated: `unit/dexmethod` +5.4 % and the precise-class lookups +4 % to +5 % (absolute cost 1–3 µs), from the step 5 guards in `tinydex.py`; unchanged from round 2 and accepted.

Suites after the fixes on Python 3.12.14 + androguard 4.1.3: 43 / 43 unit, 9 / 9 integration.

Still open from round 2, deferred by decision: 5.3 mutation leaks and hangs, 5.4 coverage, 5.5 wording in the milestone document.
