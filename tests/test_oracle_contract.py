"""Output contracts that any reimplementation must reproduce.

These pin down behaviour that used to depend on interpreter internals or on
wrong string handling: MUTF-8 decoding and encoding, byte-ordered descriptor
lookup, deterministic index allocation in the rebuilt DEX, and findrefs output
order across DEX entries. None of them need androguard.
"""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from dex_fixture import DEFAULT_STRINGS, make_dex, make_dex041_container
from droidasc.asc_client.apk_handler import ApkHandler
from droidasc.asc_core.core.dex.dex_constructor import DexHollower
from droidasc.asc_core.core.dex.dex_manager import DexManager
from droidasc.asc_core.findrefs.locator.method_locator import MethodLocator
from droidasc.asc_core.findrefs.locator.string_locator import StringLocator
from droidasc.asc_core.utils.leb128 import read_uleb128_fast
from droidasc.asc_core.utils.mutf8 import decode_mutf8, encode_mutf8, utf16_len
from droidasc.asc_core.utils.tinydex import DEX

ROOT = Path(__file__).resolve().parents[1]
EMOJI = '\U0001F600'
EMOJI_MUTF8 = b'\xed\xa0\xbd\xed\xb8\x80'
MIXED = 'tok\x00en' + EMOJI + 'é'
MIXED_MUTF8 = b'tok\xc0\x80en' + EMOJI_MUTF8 + b'\xc3\xa9'
MIXED_STRINGS = DEFAULT_STRINGS[:5] + [(MIXED_MUTF8, 9)]


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / 'main.py'), *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)


class Mutf8Tests(unittest.TestCase):
    def test_codec_matches_dex_encoding(self):
        for text, encoded, units in (('abc', b'abc', 3), ('a\x00b', b'a\xc0\x80b', 3),
                                     ('é', b'\xc3\xa9', 1), (EMOJI, EMOJI_MUTF8, 2),
                                     ('\ud800', b'\xed\xa0\x80', 1), (MIXED, MIXED_MUTF8, 9)):
            with self.subTest(text=text):
                self.assertEqual(encode_mutf8(text), encoded)
                self.assertEqual(decode_mutf8(encoded), text)
                self.assertEqual(utf16_len(text), units)

    def test_malformed_input_is_replaced_not_raised(self):
        self.assertEqual(decode_mutf8(b'\xff\xfe'), '��')


class StringTableTests(unittest.TestCase):
    def setUp(self):
        self.raw = make_dex(strings=MIXED_STRINGS)
        self.dex = DEX.parse(memoryview(self.raw), 'mixed.dex')

    def test_string_is_read_to_its_terminator(self):
        self.assertEqual(self.dex.strings[5], MIXED)
        self.assertEqual(self.dex.get_string_bytes(5), MIXED_MUTF8)

    def test_search_query_is_encoded_as_mutf8(self):
        locator = StringLocator(self.dex)
        self.assertEqual(locator.locate(EMOJI), {5})
        self.assertEqual(locator.locate('tok\x00en'), {5})
        self.assertEqual(locator.locate('token'), set())

    def test_rebuilt_string_data_keeps_mutf8_and_utf16_length(self):
        data = DexManager(self.raw).extract_and_rebuild('Lexample/Test;')
        rebuilt = DEX.parse(memoryview(data), 'rebuilt.dex')
        table = [rebuilt.strings[i] for i in range(len(rebuilt.strings))]
        idx = table.index(MIXED)
        self.assertEqual(rebuilt.get_string_bytes(idx), MIXED_MUTF8)
        string_off = struct.unpack_from('<I', data, rebuilt.header.strings[0] + 4 * idx)[0]
        self.assertEqual(read_uleb128_fast(data, string_off)[0], 9)


class StringAttributionTests(unittest.TestCase):
    """A string query is a bytes regex over the whole string_data region. Each
    match belongs to the string holding the first NUL at or after its end: the
    string with the greatest string_data_off not above that NUL."""

    def locate(self, raw, query):
        return StringLocator(DEX.parse(memoryview(bytes(raw)), 'fixture.dex')).locate(query)

    def permute(self, raw, order):
        """Rewrite make_dex()'s contiguous string_data in place with its items
        laid out in `order` (string indices), and repoint string_ids."""
        raw = bytearray(raw)
        ids_off, = struct.unpack_from('<I', raw, 0x3C)
        offs = [struct.unpack_from('<I', raw, ids_off + 4 * i)[0] for i in range(len(order))]
        end = raw.index(b'\0', offs[-1] + 1) + 1
        items = [bytes(raw[a:b]) for a, b in zip(offs, offs[1:] + [end])]
        pos = offs[0]
        for idx in order:
            raw[pos:pos + len(items[idx])] = items[idx]
            struct.pack_into('<I', raw, ids_off + 4 * idx, pos)
            pos += len(items[idx])
        return raw

    def test_empty_pattern_matches_nothing(self):
        # used to leak KeyError 0 ("Error: 0"): the empty match at the region
        # end finds no NUL after it
        self.assertEqual(self.locate(make_dex(), ''), set())
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', make_dex())
            result = run_cli('findrefs', str(apk), 'string', '')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def test_match_through_the_final_terminator_belongs_to_no_string(self):
        self.assertEqual(self.locate(make_dex(), 'token.'), set())
        self.assertEqual(self.locate(make_dex(), 'token\\x00'), set())

    def test_match_through_a_terminator_belongs_to_the_next_string(self):
        # 'first\0' + uleb(6) + 's' of 'second'
        self.assertEqual(self.locate(make_dex(), 'first..s'), {4})

    def test_every_string_is_reachable(self):
        self.assertEqual(self.locate(make_dex(), '.'), set(range(6)))

    def test_string_data_out_of_string_ids_order(self):
        # layout: token, first, second, Lexample/Test;, Ljava/lang/Object;, V
        raw = self.permute(make_dex(), [5, 3, 4, 0, 1, 2])
        self.assertEqual(self.locate(raw, 'token'), {5})
        self.assertEqual(self.locate(raw, 'first'), {3})
        self.assertEqual(self.locate(raw, 'Object'), {1})
        self.assertEqual(self.locate(raw, 'first..s'), {4})
        # the region ends at the terminator of the highest string_data_item
        self.assertEqual(self.locate(raw, 'V'), {2})
        self.assertEqual(self.locate(raw, 'V.'), set())

    def test_duplicate_offsets_resolve_to_the_highest_index(self):
        raw = bytearray(make_dex())
        ids_off = struct.unpack_from('<I', raw, 0x3C)[0]
        struct.pack_into('<I', raw, ids_off + 4 * 4, struct.unpack_from('<I', raw, ids_off + 4 * 3)[0])
        self.assertEqual(self.locate(raw, 'first'), {4})


class MemberNameOrderTests(unittest.TestCase):
    """A precise class with a name filters the class's members by their decoded
    names; on a corrupt DEX several names can fail, and the one reported must be
    the lowest id, not whichever a CPython set yields first."""

    def test_names_are_read_in_ascending_id_order(self):
        from types import SimpleNamespace
        from droidasc.asc_core.findrefs.locator.field_locator import FieldLocator

        class Undecodable:
            def __init__(self, idx):
                self.idx = idx

            @property
            def name(self):
                raise ValueError(f'bad name {self.idx}')

        class Failing:
            def __getitem__(self, idx):
                return Undecodable(idx)

        ids = {3, 9}
        self.assertEqual(list(ids), [9, 3])  # set order differs from id order here
        for cls, method in ((MethodLocator, '_match_clz_mids'), (FieldLocator, '_match_clz_fids')):
            with self.subTest(locator=cls.__name__):
                locator = cls.__new__(cls)
                locator.dex = SimpleNamespace(methods=Failing(), fields=Failing())
                with self.assertRaisesRegex(ValueError, '^bad name 3$'):
                    getattr(locator, method)(set(ids), 'x')


class ErrorOrderTests(unittest.TestCase):
    """With several failing DEX entries, findrefs prints every entry before the
    first failing one (in entry order) and then that entry's error, however the
    workers finish."""

    def run_apk(self, entries):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in entries:
                    archive.writestr(name, data)
            return [run_cli('findrefs', str(apk), '--threads', '3', 'string', 'token') for _ in range(2)]

    def test_first_failing_entry_in_entry_order_wins(self):
        # Entry order is ascending compressed size: valid, slow failure, fast failure.
        # The fast one finishes first; it must not be the one reported.
        from dex_fixture import make_fast_bad_string_ids_dex, make_slow_insns_overrun_dex
        results = self.run_apk([('classes.dex', make_dex()),
                                ('classes2.dex', make_slow_insns_overrun_dex()),
                                ('classes3.dex', make_fast_bad_string_ids_dex())])
        for result in results:
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, 'classes.dex | Lexample/Test;->first | matched=(token)\n'
                                            'classes.dex | Lexample/Test;->second | matched=(token)\n')
            self.assertEqual(result.stderr, 'Error: bad code_item offset\n')

    def test_later_failure_is_not_reported(self):
        # Entry order: valid, fast failure, slow failure.
        from dex_fixture import make_fast_bad_string_ids_dex, make_slow_insns_overrun_dex
        results = self.run_apk([('classes.dex', make_dex()),
                                ('classes2.dex', make_fast_bad_string_ids_dex(padding=8 << 10)),
                                ('classes3.dex', make_slow_insns_overrun_dex())])
        for result in results:
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout.count('\n'), 2)
            self.assertEqual(result.stderr, 'Error: bad string_ids range\n')


class DescriptorOrderTests(unittest.TestCase):
    """type_ids sort by MUTF-8 bytes; surrogate pairs sort below U+E000..U+FFFF
    in bytes but above them by code point, so str comparison misses them."""
    EMOJI_CLASS = 'L' + EMOJI + ';'
    STRINGS = [b'Ljava/lang/Object;', (b'L' + EMOJI_MUTF8 + b';', 4), b'L\xef\xbf\xbd;', b'L\xef\xbf\xbe;',
               b'V', b'first', b'second', b'token']

    def setUp(self):
        self.raw = make_dex(strings=self.STRINGS, types=[0, 1, 2, 3, 4], class_type=1, super_type=0,
                            void_type=4, void_string=4, method_names=(5, 6), const_string=7)
        self.dex = DEX.parse(memoryview(self.raw), 'order.dex')

    def test_get_class_compares_bytes(self):
        clazz = self.dex.get_class(self.EMOJI_CLASS)
        self.assertIsNotNone(clazz)
        self.assertEqual(clazz.fullname, self.EMOJI_CLASS)

    def test_precise_type_lookup_compares_bytes(self):
        locator = MethodLocator(self.dex)
        self.assertEqual(locator._find_type_idx_precisely(self.EMOJI_CLASS), 1)
        self.assertEqual(locator._find_type_idx_precisely('L�;'), 2)
        self.assertEqual(locator._find_type_idx_precisely('Lmissing;'), -1)

    def test_apk_scan_finds_non_bmp_class_name(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', self.raw)
            hit = ApkHandler(str(apk)).get_class_dex(self.EMOJI_CLASS)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], 'classes.dex')


class RebuildOrderTests(unittest.TestCase):
    def test_hollowed_indices_are_mapped_in_ascending_order(self):
        # 17 strings so the hollowed set {16, 9} is not already in ascending
        # slot order inside a CPython set; the contract is ascending index.
        strings = DEFAULT_STRINGS + [b'x%02d' % i for i in range(6, 17)]
        raw = make_dex(strings=strings)
        original_hollow = DexHollower.hollow

        def hollow(self):
            original_hollow(self)
            self.hlw_strs.add(16)
            self.hlw_strs.add(9)

        with patch.object(DexHollower, 'hollow', hollow):
            first = DexManager(raw).extract_and_rebuild('Lexample/Test;')
            second = DexManager(raw).extract_and_rebuild('Lexample/Test;')
        self.assertEqual(bytes(first), bytes(second))
        rebuilt = DEX.parse(memoryview(first), 'rebuilt.dex')
        table = [rebuilt.strings[i] for i in range(len(rebuilt.strings))]
        self.assertLess(table.index('x09'), table.index('x16'))


class EntryOrderTests(unittest.TestCase):
    def test_findrefs_output_follows_entry_order(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('classes.dex', make_dex(padding=6000))
                archive.writestr('classes2.dex', make_dex())
                archive.writestr('classes3.dex', make_dex(padding=3000))
            outputs = [run_cli('findrefs', str(apk), '--threads', '3', 'string', 'token') for _ in range(3)]
        for result in outputs:
            self.assertEqual(result.returncode, 0, result.stderr)
            names = [line.split(' | ')[0] for line in result.stdout.splitlines()]
            self.assertEqual(names, ['classes2.dex'] * 2 + ['classes3.dex'] * 2 + ['classes.dex'] * 2)
        self.assertEqual(len({result.stdout for result in outputs}), 1)

    def test_dex041_container_entries_are_searched(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('classes.dex', make_dex041_container({}, {'padding': 64}))
            result = run_cli('findrefs', str(apk), '--threads', '1', 'string', 'token')
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [line.split(' | ')[0] for line in result.stdout.splitlines()]
        self.assertEqual(names, ['classes.dex!classes1.dex'] * 2 + ['classes.dex!classes2.dex'] * 2)


class CorruptInputTests(unittest.TestCase):
    """Corrupt or truncated inputs must exit 1 with an explicit Error: message,
    never leaking internal Python exceptions (struct.error, KeyError, zlib.error)."""

    def test_empty_apk_raises_eocd_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            f.flush()
            result = run_cli('findrefs', f.name, 'string', 'token')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: EOCD not found', result.stderr)

    def test_truncated_eocd_raises_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            f.write(b'\x00' * 10 + b'PK\x05\x06' + b'\x00' * 10)
            f.flush()
            result = run_cli('findrefs', f.name, 'string', 'token')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: bad EOCD header', result.stderr)

    def test_truncated_cd_range_raises_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            eocd = b'PK\x05\x06' + b'\x00' * 8 + struct.pack('<IIH', 1000, 1000, 0)
            f.write(eocd)
            f.flush()
            result = run_cli('findrefs', f.name, 'string', 'token')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: bad central directory range', result.stderr)

    def test_corrupt_deflate_stream_raises_decompression_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            with zipfile.ZipFile(f, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('classes.dex', b'hello world from classes dex')
            f.seek(0)
            data = bytearray(f.read())
            # Corrupt compressed payload at offset 45
            data[45:55] = b'\xff' * 10
            f.seek(0)
            f.write(data)
            f.flush()
            result = run_cli('findrefs', f.name, 'string', 'token')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: corrupt deflate stream in classes.dex', result.stderr)

    def test_truncated_dex_raises_header_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('classes.dex', b'dex\n035\x00short')
            f.flush()
            result = run_cli('findrefs', f.name, 'string', 'token')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: bad DEX magic or header size', result.stderr)

    def test_truncated_dex_bodies_raise_clean_errors(self):
        raw = make_dex()
        for trunc, expected in ((0x70, 'bad string_ids range'),
                                (0x90, 'bad string_data offset'),
                                (0xB0, 'bad string_data offset')):
            with self.subTest(trunc=hex(trunc)):
                with tempfile.NamedTemporaryFile(suffix='.apk') as f:
                    with zipfile.ZipFile(f, 'w') as zf:
                        zf.writestr('classes.dex', raw[:trunc])
                    f.flush()
                    result = run_cli('findrefs', f.name, 'string', 'token')
                self.assertEqual(result.returncode, 1)
                self.assertIn(f'Error: {expected}', result.stderr)

    def test_missing_apk_file_raises_error(self):
        for cmd in ('findrefs', 'getclass', 'getmanifest'):
            with self.subTest(command=cmd):
                result = run_cli(cmd, '/nonexistent_file_12345.apk', 'string', 'token') if cmd == 'findrefs' else (
                    run_cli(cmd, '/nonexistent_file_12345.apk', 'Ltest/Cls;') if cmd == 'getclass' else
                    run_cli(cmd, '/nonexistent_file_12345.apk')
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn('Error: APK file not found: /nonexistent_file_12345.apk', result.stderr)

    def test_missing_manifest_raises_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('classes.dex', b'dummy')
            f.flush()
            result = run_cli('getmanifest', f.name)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: AndroidManifest.xml not found in APK', result.stderr)

    def test_bad_zip_manifest_raises_error(self):
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            f.write(b'not a zip file')
            f.flush()
            result = run_cli('getmanifest', f.name)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: bad APK archive: not a valid zip file', result.stderr)


class TinydexCorruptionTests(unittest.TestCase):
    """Corrupt DEX bodies reach tinydex as clean ValueErrors, never struct.error,
    and a failed class_data walk leaves nothing behind for the next caller."""

    # make_dex() places the single class_data at 294:
    # counts 0,0,2,0 | m0: diff 0, flags 9, code_off 0x90 0x02 | m1: diff 1, ...
    CLASS_DATA = 294
    M1_DIFF = CLASS_DATA + 8
    M0_CODE_OFF = CLASS_DATA + 6

    def parse(self, raw):
        return DEX.parse(memoryview(bytes(raw)), 'classes.dex')

    def assert_class_data_error(self, raw, message):
        cls = self.parse(raw).classes[0]
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                with self.assertRaisesRegex(ValueError, f'^{message}$'):
                    cls._parse_class_data()
                self.assertEqual((cls._fields, cls._methods), ([], []))

    def test_fixture_layout(self):
        raw = make_dex()
        self.assertEqual(struct.unpack_from('<I', raw, 176 + 24)[0], self.CLASS_DATA)
        self.assertEqual(raw[self.M1_DIFF], 1)

    def test_repeated_method_index_is_bad_class_data(self):
        raw = bytearray(make_dex())
        raw[self.M1_DIFF] = 0
        self.assert_class_data_error(raw, 'bad class_data')

    def test_method_index_past_buffer_is_bad_method_ids_range(self):
        # Move method_ids so entry 0 is the last whole entry and entry 1 runs past the end.
        raw = bytearray(make_dex())
        struct.pack_into('<I', raw, 0x5C, len(raw) - 12)
        self.assert_class_data_error(raw, 'bad method_ids range')

    def test_code_item_header_past_end_is_bad_code_item_offset(self):
        raw = bytearray(make_dex())
        off = len(raw) - 8
        raw[self.M0_CODE_OFF:self.M0_CODE_OFF + 2] = bytes([off & 0x7F | 0x80, off >> 7])
        cls = self.parse(raw).classes[0]
        cls._parse_class_data()
        with self.assertRaisesRegex(ValueError, '^bad code_item offset$'):
            cls.methods[0].bytecode

    def test_insns_past_end_is_bad_code_item_offset(self):
        # insns_size far past the buffer: bytecode used to return a truncated
        # body, and the findrefs locator filled ~5e8 buckets and never finished.
        raw = bytearray(make_dex())
        code_off = struct.unpack_from('<H', raw, self.M0_CODE_OFF)[0]
        code_off = (code_off & 0x7F) | ((code_off >> 8) << 7)
        struct.pack_into('<I', raw, code_off + 12, 0x77777777)
        cls = self.parse(raw).classes[0]
        cls._parse_class_data()
        with self.assertRaisesRegex(ValueError, '^bad code_item offset$'):
            cls.methods[0].bytecode
        with tempfile.NamedTemporaryFile(suffix='.apk') as f:
            with zipfile.ZipFile(f, 'w') as zf:
                zf.writestr('classes.dex', bytes(raw))
            f.flush()
            result = run_cli('findrefs', f.name, 'method', 'first')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Error: bad code_item offset', result.stderr)

    def test_truncated_type_list_is_bad_type_list_offset(self):
        raw = bytearray(make_dex())
        protos_off = struct.unpack_from('<I', raw, 0x4C)[0]
        struct.pack_into('<I', raw, protos_off + 8, len(raw) - 2)
        with self.assertRaisesRegex(ValueError, '^bad type_list offset$'):
            self.parse(raw).get_prototype(0).parameters_type
