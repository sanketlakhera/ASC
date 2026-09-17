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
