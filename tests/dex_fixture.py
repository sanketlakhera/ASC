"""Build small DEX files (and one binary AndroidManifest.xml) for tests.

make_dex() with no arguments is the historic fixture: two static methods
sharing one code_item, six strings with 'token' last. Its byte layout must
stay stable because tests patch header and map offsets in it directly.
"""
import hashlib
import struct
import zlib


def uleb(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


DEFAULT_STRINGS = [b'Lexample/Test;', b'Ljava/lang/Object;', b'V', b'first', b'second', b'token']


def make_dex(strings=None, types=None, class_type=0, super_type=1, void_type=2, void_string=2,
             method_names=(3, 4), const_string=5, base=0, magic=b'dex\n035\0', padding=0):
    """Build a one-class DEX.

    strings      list of MUTF-8 payloads, sorted by bytes; an entry may be a
                 (payload, utf16_len) pair when the UTF-16 length differs from
                 the byte length.
    types        string index per type_id (default [0, 1, 2]).
    class_type / super_type / void_type   type indices used by the class def
                 and the '()V' prototype; void_string is the shorty string.
    method_names two string indices, both methods share one code_item that
                 does `const-string v0, string@const_string; return-void`.
    base         added to every stored offset, for DEX 041 containers whose
                 logical DEX files keep container-absolute offsets.
    padding      bytes of incompressible data appended inside file_size, to
                 give entries distinct compressed sizes.
    """
    strings = list(DEFAULT_STRINGS if strings is None else strings)
    types = [0, 1, 2] if types is None else list(types)
    entries = [(s, len(s)) if isinstance(s, (bytes, bytearray)) else tuple(s) for s in strings]
    buf = bytearray(112)
    sections = [(0, 1, base)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off + base))
        buf.extend(data)
        return off

    string_ids = section(1, len(entries), bytes(4 * len(entries)))
    type_ids = section(2, len(types), struct.pack('<%dI' % len(types), *types))
    proto_ids = section(3, 1, struct.pack('<III', void_string, void_type, 0))
    method_ids = section(5, 2, struct.pack('<HHIHHI', class_type, 0, method_names[0],
                                           class_type, 0, method_names[1]))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)
    string_data = b''.join(uleb(u16) + payload + b'\0' for payload, u16 in entries)
    off = section(0x2002, len(entries), string_data, align=1)
    for i, (payload, u16) in enumerate(entries):
        struct.pack_into('<I', buf, string_ids + 4 * i, off + base)
        off += len(uleb(u16)) + len(payload) + 1
    # const-string v0, string@N; return-void
    code = section(0x2001, 1, struct.pack('<HHHHII', 1, 0, 0, 0, 0, 3)
                   + b'\x1a\0' + struct.pack('<H', const_string) + b'\x0e\0')
    class_data = section(0x2000, 1, b'\0\0\x02\0' + b'\0\x09' + uleb(code + base)
                         + b'\x01\x09' + uleb(code + base), align=1)
    struct.pack_into('<IIIIIIII', buf, class_defs, class_type, 1, super_type, 0, 0xffffffff, 0,
                     class_data + base, 0)
    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off + base))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))
    if padding:
        seed = b'droidasc'
        while len(seed) < padding:
            seed += hashlib.sha256(seed[-32:]).digest()
        buf.extend(seed[:padding])
        buf.extend(b'\0' * (-len(buf) % 4))
    buf[:8] = magic
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off + base)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(entries), string_ids + base, len(types), type_ids + base, 1, proto_ids + base,
                     0, 0, 2, method_ids + base, 1, class_defs + base, len(buf) - data_off, data_off + base)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)


def make_dex041_container(*logical):
    """Concatenate make_dex(...) kwargs dicts into one DEX 041 container."""
    out = b''
    for kwargs in logical:
        out += make_dex(base=len(out), magic=b'dex\n041\0', **kwargs)
    return out


def make_static_field_dex():
    """Build a DEX whose static_values and sget field operand must agree."""
    strings = [b'Lexample/Statics;', b'Ljava/lang/Object;', b'I', b'FIRST', b'SECOND', b'getSecond']
    buf = bytearray(112)
    sections = [(0, 1, 0)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off))
        buf.extend(data)
        return off

    string_ids = section(1, len(strings), bytes(4 * len(strings)))
    type_ids = section(2, 3, struct.pack('<III', 0, 1, 2))
    proto_ids = section(3, 1, struct.pack('<III', 2, 2, 0))
    field_ids = section(4, 2, struct.pack('<HHIHHI', 0, 2, 3, 0, 2, 4))
    method_ids = section(5, 1, struct.pack('<HHI', 0, 0, 5))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)

    string_data_off = section(0x2002, len(strings),
                              b''.join(uleb(len(s)) + s + b'\0' for s in strings), align=1)
    off = string_data_off
    for i, value in enumerate(strings):
        struct.pack_into('<I', buf, string_ids + 4 * i, off)
        off += len(uleb(len(value))) + len(value) + 1

    # sget v0, field@1 (SECOND); return v0
    code = section(0x2001, 1, struct.pack('<HHHHII', 1, 0, 0, 0, 0, 3) + b'\x60\x00\x01\x00\x0f\x00')
    class_data = section(0x2000, 1, b'\x02\x00\x01\x00' + b'\x00\x09\x01\x09' + b'\x00\x09' + uleb(code), align=1)
    static_values = section(0x2005, 1, b'\x02\x04\x0b\x04\x16', align=1)
    struct.pack_into('<IIIIIIII', buf, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, static_values)

    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))

    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(strings), string_ids, 3, type_ids, 1, proto_ids,
                     2, field_ids, 1, method_ids, 1, class_defs, len(buf) - data_off, data_off)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)


def make_axml():
    """Build a minimal binary AndroidManifest.xml:

    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="example.app" android:versionCode="1">
        <application/>
    </manifest>
    """
    pool = ['manifest', 'package', 'example.app', 'android',
            'http://schemas.android.com/apk/res/android', 'versionCode', 'application']
    idx = {s: i for i, s in enumerate(pool)}
    NONE = 0xffffffff

    data = bytearray()
    offsets = []
    for s in pool:
        offsets.append(len(data))
        encoded = s.encode('utf-16-le')
        data += struct.pack('<H', len(encoded) // 2) + encoded + b'\0\0'
    data += b'\0' * (-len(data) % 4)
    strings_start = 28 + 4 * len(pool)
    string_pool = struct.pack('<HHIIIIII', 0x0001, 28, strings_start + len(data), len(pool), 0, 0,
                              strings_start, 0)
    string_pool += struct.pack('<%dI' % len(pool), *offsets) + data

    def chunk(kind, body):
        # ResXMLTree_node: 8-byte chunk header + lineNumber + comment = 16-byte
        # header; body already starts with lineNumber and comment
        return struct.pack('<HHI', kind, 16, 8 + len(body)) + body

    def attr(ns, name, raw, dtype, value):
        return struct.pack('<IIIHBBI', ns, name, raw, 8, 0, dtype, value)

    line_comment = struct.pack('<II', 1, NONE)
    attrs = attr(NONE, idx['package'], idx['example.app'], 0x03, idx['example.app']) \
        + attr(idx['http://schemas.android.com/apk/res/android'], idx['versionCode'], NONE, 0x10, 1)
    body = b''.join([
        chunk(0x0100, line_comment + struct.pack('<II', idx['android'],
                                                 idx['http://schemas.android.com/apk/res/android'])),
        chunk(0x0102, line_comment + struct.pack('<IIHHHHHH', NONE, idx['manifest'], 20, 20, 2, 0, 0, 0) + attrs),
        chunk(0x0102, line_comment + struct.pack('<IIHHHHHH', NONE, idx['application'], 20, 20, 0, 0, 0, 0)),
        chunk(0x0103, line_comment + struct.pack('<II', NONE, idx['application'])),
        chunk(0x0103, line_comment + struct.pack('<II', NONE, idx['manifest'])),
        chunk(0x0101, line_comment + struct.pack('<II', idx['android'],
                                                 idx['http://schemas.android.com/apk/res/android'])),
    ])
    return struct.pack('<HHI', 0x0003, 8, 8 + len(string_pool) + len(body)) + string_pool + body
