from .base_locator import BaseLocator
import array
from bisect import bisect_right
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
        # string_data_off of every string, ascending; a match is attributed
        # through a binary search over it (see locate)
        self.starts = ()
        # string idx at each position of starts, or None when starts is the
        # string_ids table itself (already in ascending order)
        self.order = None
        self.strdata_start = 0
        self.strdata_end = 0
        self.parsed = False

    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        string_ids_off, string_ids_size = self.header.strings
        buf = self.buf
        if not string_ids_size:
            self.parsed = True
            self._debug_log("build_map", t_start, 0)
            return
        ids_len = string_ids_size * 4
        if string_ids_off + ids_len > len(buf):
            raise ValueError("bad string_ids range")
        # Bulk-read the string_ids table: one native array decode is ~40%
        # faster than a per-entry unpack loop.
        offsets = array.array('I')
        if offsets.itemsize == 4:
            offsets.frombytes(buf[string_ids_off:string_ids_off + ids_len])
            if sys.byteorder != 'little':
                offsets.byteswap()
            ordered = sorted(offsets)
            in_order = array.array('I', ordered) == offsets
        else:
            offsets = [o for (o,) in struct.iter_unpack('<I', buf[string_ids_off:string_ids_off + ids_len])]
            ordered = sorted(offsets)
            in_order = ordered == offsets
        if ordered[-1] >= len(buf):
            raise ValueError("bad string_data offset")
        # d8 and dx lay string_data out in string_ids order, so the table is
        # usually its own sorted form. Otherwise sort the indices by offset;
        # the sort is stable, so among equal offsets the highest idx is last,
        # which is the one bisect_right lands on.
        if in_order:
            self.starts = offsets
        else:
            self.order = sorted(range(string_ids_size), key=offsets.__getitem__)
            self.starts = ordered
        # The searched region runs from the lowest string_data_item to the
        # terminator of the highest one.
        self.strdata_start = ordered[0]
        data_offset = ordered[-1]
        uleb_len = read_uleb128_len(buf, data_offset)
        raw_obj = buf.obj if hasattr(buf, "obj") and buf.obj is not None else bytes(buf)
        end_idx = raw_obj.find(b'\x00', data_offset + uleb_len)
        if end_idx < 0:
            raise ValueError("unterminated string_data_item")
        self.strdata_end = end_idx + 1
        self.parsed = True
        self._debug_log("build_map", t_start, string_ids_size)

    def _match_nul_offsets(self, string : str):
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

        last_nul = -1
        for match in pattern.finditer(submem):
            end = strdata_start + match.end()
            # Match ends ascend: a match ending at or before the NUL found for
            # an earlier one has that same NUL, so the same string, already
            # yielded. One long string with many matches is scanned once.
            if end <= last_nul:
                continue
            # the first NUL at or after the match end; a match that consumed
            # the final terminator has none (and neither has any later match)
            offset = mm.find(b'\x00', end, strdata_end)
            if offset < 0:
                break
            last_nul = offset
            yield offset

    # A match belongs to the string holding the first NUL at or after its end:
    # the string with the greatest string_data_off not above that NUL (the
    # highest idx among equal offsets). On string_data laid out contiguously in
    # string_ids order that NUL is the string's own terminator.
    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        located_idx = set()
        if string == "":
            self._debug_log("locate", t_start, 0)
            return located_idx
        starts = self.starts
        order = self.order
        for offset in self._match_nul_offsets(string):
            pos = bisect_right(starts, offset) - 1
            located_idx.add(pos if order is None else order[pos])
        # return set for O(1) lookup
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx

