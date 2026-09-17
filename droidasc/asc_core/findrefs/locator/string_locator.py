from .base_locator import BaseLocator
import array
import struct
import sys
from ...utils.leb128 import read_uleb128_len
from ...utils.mutf8 import encode_mutf8
import re
import time

# Auth: MG1937
_STRUCT_I = struct.Struct('<I')

# r8 using MUTF8 to handle string payload,
# so 0x00 will be encoded to 0xC0 0x80
class StringLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.stridx_map = {} # {string_data_off : string_idx}
        self.strdata_start = 0
        self.strdata_end = 0
        self.parsed = False
    
    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        string_ids_off, string_ids_size = self.header.strings
        stridx_map = self.stridx_map
        buf = self.buf
        if not string_ids_size:
            self.parsed = True
            self._debug_log("build_map", t_start, 0)
            return
        ids_len = string_ids_size * 4
        if string_ids_off + ids_len > len(buf):
            raise ValueError("bad string_ids range")
        # Bulk-read the string_ids table: one native array decode plus one
        # max() is ~40% faster than a per-entry unpack loop, and validating
        # inside that loop cost +22% on the gated string_locator benchmark.
        offsets = array.array('I')
        if offsets.itemsize == 4:
            offsets.frombytes(buf[string_ids_off:string_ids_off + ids_len])
            if sys.byteorder != 'little':
                offsets.byteswap()
        else:
            offsets = [o for (o,) in struct.iter_unpack('<I', buf[string_ids_off:string_ids_off + ids_len])]
        if max(offsets) >= len(buf):
            raise ValueError("bad string_data offset")
        self.strdata_start = offsets[0]
        data_offset = offsets[-1]
        stridx_map.update(zip(offsets, range(string_ids_size)))
        # Include the final string_data_item. The existing lookup maps a
        # match through the following string offset, so add an end sentinel
        # for the final item without changing that mapping scheme.
        uleb_len = read_uleb128_len(buf, data_offset)
        raw_obj = buf.obj if hasattr(buf, "obj") and buf.obj is not None else bytes(buf)
        end_idx = raw_obj.find(b'\x00', data_offset + uleb_len)
        if end_idx < 0:
            raise ValueError("unterminated string_data_item")
        self.strdata_end = end_idx + 1
        stridx_map[self.strdata_end] = string_ids_size
        self.parsed = True
        self._debug_log("build_map", t_start, len(stridx_map))

    def _match_string_offset(self, string : str):
        buf = self.buf
        # The query is a bytes regex run over MUTF-8 payloads, so encode its
        # literal characters the same way (NUL -> C0 80, non-BMP -> surrogate
        # pair). Regex metacharacters are ASCII and unaffected.
        string = encode_mutf8(string)
        strdata_start = self.strdata_start
        strdata_end = self.strdata_end
        submem = buf[strdata_start: strdata_end]
        
        mm = submem.obj
        pattern = re.compile(string)
        
        # offsets = []
        for match in pattern.finditer(submem):
            offset = strdata_start + match.end()
            offset = mm.find(b'\x00', offset, strdata_end)
            yield offset + 1
            # offsets.append(offset + 1) # skip over 00 byte
        # return offsets

    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        stridx_map = self.stridx_map
        located_idx = set()
        for offset in self._match_string_offset(string):
            located_idx.add(stridx_map[offset] - 1)
        # return set for O(1) lookup
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx
        
