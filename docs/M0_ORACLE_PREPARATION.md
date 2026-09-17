# Milestone 0 (M0): Oracle Preparation & Conformance Baseline

## 1. Overview & Objective

Milestone 0 (M0) prepares the existing Python implementation of **Droid ASC** to serve as the immutable, authoritative oracle for the Rust rewrite. 

Per the rewrite specification:
> **The One Rule:** The Python version after M0 is the oracle. Every Rust milestone ends with a mechanical diff against it. When they disagree, adjudicate against the DEX spec or a third tool (`dexdump`, `baksmali`), fix whichever side is wrong, and regenerate goldens. Never loosen the comparison to make a diff go away.

To satisfy this rule, Python must produce **deterministic, spec-compliant, and contract-stable outputs** (stdout, stderr, exit codes, output files, and rebuilt DEX binaries).

---

## 2. Milestone 0 Task Status Summary

| Step | Task | Status | Completed In |
|---|---|---|---|
| **1** | Iterate hollowed index sets sorted in `dex_remapper.py` | **DONE** | Commit `86fe46d` |
| **2** | Buffer & yield `findrefs` in entry order; pick lowest entry index for `getclass` | **DONE** | Commit `86fe46d` |
| **3** | Pure-Python MUTF-8 codec (`mutf8.py`), read strings to NUL, UTF-16 unit count | **DONE** | Commit `86fe46d` |
| **4** | Descriptor binary searches compare raw bytes (`&[u8]`) order | **DONE** | Commit `86fe46d` |
| **5** | Replace internal exception leaks (`struct.error`, `IndexError`, etc.) on corrupt input with explicit `ValueError` messages | **DONE** | **This Session** |
| **6** | Confirm DAD output on the corpus is unchanged and evaluate `decompiler.py` stubs | **DONE** | **This Session** |
| **7** | Fixtures, contract tests, and Conformance Harness (`gen_golden.py`, `check.py`) | **DONE** | **This Session** |

---

## 3. Detailed Changes Completed in This Session

### Step 5: Handling Corrupt & Truncated Inputs without Exception Leaks
Previously, malformed APKs, truncated headers, corrupt deflate streams, or invalid DEX files leaked internal Python runtime exceptions (`struct.error`, `KeyError`, `zipfile.BadZipFile`, `zlib.error`, `IndexError`) to `stderr`.

The CLI contract requires:
* Exit code `1` with `Error: {message}` on `stderr` for deliberate error conditions.
* Never exposing unhandled Python internals to end users or automated test harnesses.

The following modules were hardened with explicit bounds checking and `ValueError` conversions:

1. **`droidasc/asc_client/apk_handler.py`**:
   - **`_open_apk` & `_get_worker_apk_mm`**: Added upfront existence checks and minimum file size check (`< 22` bytes). If empty or truncated below the 22-byte minimum required for an EOCD record, raises `ValueError("EOCD not found")`. This prevents unhandled `mmap` errors (`ValueError: cannot mmap an empty file`).
   - **`_find_eocd` & `_parse_cd_dex_entries`**: Added bounds checking for EOCD records (`eocd_idx + 22 > len(mm)` raises `ValueError("bad EOCD header")`). Verified that central directory boundaries (`cd_off + cd_size <= len(mm)`) do not exceed file bounds (raising `ValueError("bad central directory range")`). Added bounds guards in central directory scanning loops (`header_off + 46 > cd_end`).
   - **`_inflate_dex`**: Added boundary checks for local header offsets (`local_header_off + 30 > len(mm)`) and compressed data views (`data_off + comp_size > len(mm)`). Wrapped decompression in a `try...except zlib.error` block to raise `ValueError(f"decompression failed: {e}")`.

2. **`droidasc/asc_client/manifest_handler.py`**:
   - Caught `zipfile.BadZipFile` and converted it to `ValueError("bad APK archive: not a valid zip file")`.
   - Caught `KeyError` when `AndroidManifest.xml` is missing from the archive and converted it to `ValueError("AndroidManifest.xml not found in APK")`.

3. **`droidasc/asc_core/utils/tinydex.py`**:
   - **`DEXHeader.__init__`**: Validates minimum DEX header size (`0x70` bytes) and DEX magic (`b"dex"`) before unpacking header fields, raising `ValueError("bad DEX magic or header size")`.
   - **`_read_string_bytes`**: Added bounds validation for string ID table indexing (`str_idx >= string_ids_size` or out of buffer range raises `ValueError("bad string_ids range")`) and string offset validity (`string_off >= len(self.buf)` raises `ValueError("bad string_data offset")`). Unterminated string data items explicitly raise `ValueError("unterminated string_data_item")`.
   - **`get_type`**: Added bounds validation before unpacking `type_ids`.

4. **`droidasc/asc_core/utils/leb128.py`**:
   - **`read_uleb128_fast` & `read_sleb128`**: Wrapped indexed byte reads with zero-cost `try...except IndexError` blocks that raise `ValueError("unterminated uleb128")` and `ValueError("unterminated sleb128")`.

5. **`tests/test_oracle_contract.py`**:
   - Added test suite `CorruptInputTests`:
     - `test_empty_apk_raises_eocd_error`: Verifies empty file raises `Error: EOCD not found`.
     - `test_truncated_eocd_raises_error`: Verifies truncated EOCD raises `Error: bad EOCD header`.
     - `test_truncated_cd_range_raises_error`: Verifies bad central directory range raises `Error: bad central directory range`.
     - `test_corrupt_deflate_stream_raises_decompression_error`: Verifies corrupt deflate streams raise `Error: decompression failed: ...`.
     - `test_truncated_dex_raises_header_error`: Verifies corrupt/truncated DEX headers raise `Error: bad DEX magic or header size`.
     - `test_missing_manifest_raises_error`: Verifies missing `AndroidManifest.xml` raises `Error: AndroidManifest.xml not found in APK`.
     - `test_bad_zip_manifest_raises_error`: Verifies invalid zip file raises `Error: bad APK archive: not a valid zip file`.

---

### Step 6: DAD Decompiler Determinism & Stub Evaluation
- **Stubbed Modules (`_STUBBED_MODULES` in `decompiler.py`)**:
  - The 45 stubbed modules (e.g. `networkx`, `matplotlib`, `pydot`, `urllib3`, `requests`, etc.) were evaluated against the decompilation pipeline (`dex_to_method` → `control_flow` → `graph` → `basic_blocks` → `dataflow` → `dast` → `writer`).
  - None of these modules are part of the core text decompilation path; `networkx` and `pydot` are only used for optional visual graphing (`show()`, `to_dot()`), which ASC does not expose.
  - Verified on real multidex classes from `Ads Solution June.apk` (such as `Lcom/google/android/gms/common/GoogleApiAvailability;`, 352 lines decompiled) and `reference-workload.zip`: output is byte-for-byte identical across runs with different `PYTHONHASHSEED` values.

---

### Step 7 & Conformance Harness (`rust/conformance/`)
Built the multi-level automated conformance test harness specified in Section 4:

1. **`rust/conformance/gen_golden.py`**:
   - Generates a synthetic test corpus covering:
     - STORED single DEX APKs.
     - DEFLATED multidex APKs (`classes.dex`, `classes2.dex`, `classes3.dex`).
     - DEX 041 container APKs (`iter_logical_dex_buffers`).
     - MUTF-8, non-BMP (emoji), and NUL-containing strings.
     - Real-world workload APK (`reference-workload.zip`).
     - Real signed multidex APK (`Ads Solution June.apk`).
   - Executes the oracle Python binary and records:
     - **Level 1 (CLI)**: True raw stdout (no line stripping or blank line normalization when `--debug` is off), `stderr.txt`, `exit_code.txt`, and file outputs (`output.file`).
     - **Level 2 (DEX)**: Rebuilt minimal DEX bytes (`rebuilt.dex`) and SHA-256 (`rebuilt.dex.sha256`) for `getclass`.
     - Metadata for each query (`meta.json`) recording query ID, command args, APK hash, exact `python_version` (3.12.14), `androguard_version` (4.1.3), `oracle_git_revision` (`86fe46d-dirty`), `git_dirty: true`, and `diff_sha256`.
     - Master manifest at `rust/conformance/golden/manifest.json`.

2. **`rust/conformance/check.py`**:
   - Runs a candidate binary (Rust `asc` executable) against the generated golden files.
   - Evaluates true byte-for-byte fidelity of `exit_code`, `stdout`, `stderr`, and `-o` outputs.
   - Includes Level 2 rebuilt DEX SHA256 checking option (`--check-dex`).
   - On mismatch, prints unified diffs and flags the first divergence with golden path details.
   - Verified functionality by running against the oracle CLI runner: **14/14 passed byte-for-byte**.

---

## 4. Resolution of Verification Report (`M0_VERIFICATION.md`)

| Finding | Description | Resolution |
|---|---|---|
| **1** | Wrong interpreter in goldens | Generated with `uv run --python 3.12 --with "androguard==4.1.3"`. Recorded `androguard_version: 4.1.3` and `python_version: 3.12.14` in all `meta.json`. |
| **2** | Misleading git revision | Recorded `git describe --always --dirty`, `git_dirty: true`, and SHA-256 hash of `git diff HEAD` in `meta.json`. |
| **3** | `.gitignore` swallows harness data | Added `!rust/conformance/**` exception to `.gitignore`. |
| **4** | Blank line stripping in output | `clean_cli_output` now preserves 100% raw stdout when `--debug` is off. |
| **5** | Corpus coverage gaps | Included real `workload` (`reference_workload.apk`) and `ads_solution` (`Ads Solution June.apk`) in golden test queries. |
| **6** | No `getmanifest` golden | Added `getmanifest_stored` and `getmanifest_ads` golden queries using `make_axml()`. |
| **7** | Level 2 goldens unchecked | Added `--check-dex` option and candidate verification path in `check.py`. |
| **8** | Level 3 docstring mismatch | Corrected docstrings in `gen_golden.py` and `check.py` to clarify Level 3 is planned for M5. |
| **9** | Static field query target | Fixed query to target `SECOND` in `Lexample/Statics;` from `make_static_field_dex()`. |
| **10** | Corrupt deflate message leakage | Standardized error message to `Error: corrupt deflate stream in {name}` across Python and test contract. |
| **11** | Manifest missing file message | Routed `get_manifest_xml` through upfront `os.path.exists` check, producing `Error: APK file not found: {path}`. |
| **12** | Truncated DEX leaks on findrefs path | Added bounds validation in `string_locator`, `type_locator`, `method_locator`, `field_locator`, `insn_locator`, `_skip_uleb128`, `read_uleb128_len`, and `dex_container`. |
| **13** | Deflate cancellation check | Verified post-flush cancellation check in `_inflate_deflate_chunks`. |

---

## 5. Test Verification Results

### Pinned Oracle Environment
```bash
uv run --python 3.12 --with "androguard==4.1.3" python tests/run_tests.py --require-decompiler --suite unit
uv run --python 3.12 --with "androguard==4.1.3" python tests/run_tests.py --require-decompiler --suite integration
```

### Unit Tests
* **Result**: **43 / 43 passed** (0 failures, 0 errors).

### Integration Tests
* **Result**: **9 / 9 passed** (0 failures, 0 errors).

### Conformance Check
```bash
python rust/conformance/check.py --bin <runner>
```
* **Result**: **14 / 14 passed** (100% byte-for-byte match).

---

## 6. Git Status Notice
As instructed, **no files have been staged or committed**. All changes remain in the working tree for user review.
