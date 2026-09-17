import importlib
import importlib.util
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_axml, make_dex, make_dex041_container, make_static_field_dex
from droidasc.asc_core.core.dex.dex_manager import DexManager
from droidasc.asc_core.utils.dex_parser import parse_encoded_array
from droidasc.asc_core.utils.tinydex import DEX

ROOT = Path(__file__).resolve().parents[1]


class RebuildTests(unittest.TestCase):
    def test_rebuilt_dex_keeps_signature_and_checksum_zero(self):
        data = DexManager(make_dex()).extract_and_rebuild('Lexample/Test;')
        self.assertEqual(data[8:32], bytes(24))

    def test_rebuild_keeps_static_values_and_field_operands_aligned(self):
        data = DexManager(make_static_field_dex()).extract_and_rebuild('Lexample/Statics;')
        dex = DEX.parse(memoryview(data), 'rebuilt.dex')
        clazz = dex.classes[0]
        static_fields = [field for field in clazz.fields if field.is_static]
        static_values_off = struct.unpack_from('<I', data, clazz._class_def_off + 28)[0]
        values = parse_encoded_array(memoryview(data), static_values_off, set(), set(), set(), set())

        self.assertEqual([field.name for field in static_fields], ['FIRST', 'SECOND'])
        self.assertEqual([int.from_bytes(value[1], 'little', signed=True) for value in values], [11, 22])

        method = next(method for method in clazz.methods if method.name == 'getSecond')
        field_idx = method.bytecode[2] | (method.bytecode[3] << 8)
        self.assertEqual(dex.fields[field_idx].name, 'SECOND')


@unittest.skipUnless(importlib.util.find_spec('androguard'), 'install requirements.txt for decompiler tests')
class DecompilerTests(unittest.TestCase):
    def test_decompile_keeps_dummy_fast_path_and_class_zero(self):
        script = """
import sys
sys.path.insert(0, 'tests')
from dex_fixture import make_dex
loaded = []
sys.addaudithook(lambda event, args: loaded.append(args[0]) if event == 'import' else None)
from droidasc.asc_client.asc_handler import AscHandler
for _ in range(2):
    source = AscHandler().getclass(make_dex(), 'Lexample/Test;')
    assert 'class Test' in source
    assert 'void first()' in source
    assert 'void second()' in source
for name in ('email', 'xml.sax.saxutils', 'networkx', 'loguru'):
    assert type(sys.modules[name]).__name__ == 'DummyModule', name
    assert not any(module == name or module.startswith(name + '.') for module in loaded), name
assert sys.modules['mutf8.cmutf8'].decode_modified_utf8.__module__ == '_asc_client_mutf8_py'
"""
        result = subprocess.run([sys.executable, '-c', script], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_on_stored_and_compressed_multidex_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    with zipfile.ZipFile(apk, 'w', compression=compression) as archive:
                        archive.writestr('classes.dex', make_dex())
                        archive.writestr('classes2.dex', make_dex())
                    search = subprocess.run(
                        [sys.executable, str(ROOT / 'main.py'), 'findrefs', str(apk), '--threads', '2', 'string', 'token'],
                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(search.returncode, 0, search.stderr)
                    self.assertEqual(len(search.stdout.splitlines()), 4, search.stdout)
                    source = subprocess.run(
                        [sys.executable, str(ROOT / 'main.py'), 'getclass', str(apk), 'example.Test', '--threads', '2'],
                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(source.returncode, 0, source.stderr)
                    self.assertIn('class Test', source.stdout)

    def test_getclass_prefers_smallest_entry_when_class_is_defined_twice(self):
        other = make_dex(strings=[b'Lexample/Test;', b'Ljava/lang/Object;', b'V', b'fourth', b'third', b'token'])
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('classes.dex', make_dex(padding=6000))
                archive.writestr('classes2.dex', other)
            outputs = []
            for _ in range(3):
                result = subprocess.run(
                    [sys.executable, str(ROOT / 'main.py'), 'getclass', str(apk), 'example.Test', '--threads', '2'],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(result.stdout)
        for source in outputs:
            self.assertIn('void fourth()', source)
            self.assertNotIn('void first()', source)
        self.assertEqual(len(set(outputs)), 1)

    def test_getclass_from_dex041_container(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('classes.dex', make_dex041_container({'padding': 64}, {}))
            result = subprocess.run(
                [sys.executable, str(ROOT / 'main.py'), 'getclass', str(apk), 'example.Test', '--threads', '1'],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('class Test', result.stdout)

    def test_getmanifest_decodes_binary_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            output = Path(directory) / 'AndroidManifest.xml'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('AndroidManifest.xml', make_axml())
                archive.writestr('classes.dex', make_dex())
            result = subprocess.run(
                [sys.executable, str(ROOT / 'main.py'), 'getmanifest', str(apk), '-o', str(output)],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')
            self.assertIn('package="example.app"', result.stdout)
            self.assertIn('android:versionCode="1"', result.stdout)
            self.assertIn('<application/>', result.stdout)
            # stdout is print()ed (adds a newline); the -o file gets the text
            # plus a newline only if it lacked one
            self.assertEqual(result.stdout, output.read_text(encoding='utf-8') + '\n')

    def test_decompiled_source_is_identical_across_processes(self):
        # DAD used to declare local variables in set order, which changed per
        # process. Decompile a class with several declarations twice, in two
        # interpreters, and require identical text.
        script = """
import sys, zipfile
sys.path.insert(0, '.')
from droidasc.asc_client.asc_handler import AscHandler
with zipfile.ZipFile('tests/fixtures/reference-workload.zip') as archive:
    dex = archive.read('classes.dex')
for name in ('Landroidx/appcompat/widget/DropDownListView;', 'Landroidx/core/view/NestedScrollingChildHelper;'):
    sys.stdout.write(AscHandler().getclass(dex, name))
"""
        outputs = []
        for _ in range(2):
            result = subprocess.run([sys.executable, '-c', script], cwd=ROOT,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.append(result.stdout)
        self.assertIn('class DropDownListView', outputs[0])
        self.assertEqual(outputs[0], outputs[1])

    def test_gui_store_can_decompile_twice_and_then_search(self):
        from droidasc.asc_client.gui.runtime import GuiDexStore
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', make_dex())
            store = GuiDexStore(str(apk), max_workers=1)
            store.load()
            first = store.get_source('Lexample/Test;')
            store.source_cache.clear()
            self.assertEqual(store.get_source('Lexample/Test;'), first)
            self.assertIn('class Test', first[1])
            self.assertTrue(store.search_members('method', 'first'))

    def test_gui_store_subprocess_search_uses_package_module(self):
        from droidasc.asc_client.gui.runtime import GuiDexStore
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', make_dex())
            store = GuiDexStore(str(apk), max_workers=1)
            store.load()
            result = store.search('string', 'token', max_workers=1)
            self.assertEqual(result['backend'], 'subprocess')
            self.assertEqual(result['total_hits'], 2)
            self.assertEqual(len(result['results']), 2)
