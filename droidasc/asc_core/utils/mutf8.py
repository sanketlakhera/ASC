"""Modified UTF-8 (MUTF-8) as used by DEX string_data_item payloads.

MUTF-8 differs from UTF-8 in two ways: U+0000 is encoded as the two bytes
C0 80 so the payload never contains a NUL, and characters outside the BMP are
encoded as a UTF-16 surrogate pair, each half as a 3-byte sequence (CESU-8).
The uleb128 prefix of a string_data_item is the length in UTF-16 code units,
not bytes.

Only the standard library is used: this module is imported on the findrefs
path, which must stay importable with ``python -S``.
"""
import struct


def _has_surrogates(s: str) -> bool:
    try:
        s.encode('utf-8')
    except UnicodeEncodeError:
        return True
    return False


def decode_mutf8(data: bytes) -> str:
    """Decode a MUTF-8 payload (without its NUL terminator).

    Surrogate pairs are combined into one code point. A lone surrogate is kept
    as a lone surrogate in the returned str, which Python permits. Malformed
    input never raises: it is decoded as UTF-8 with replacement characters.
    """
    if data.isascii():
        return data.decode('ascii')
    try:
        s = data.replace(b'\xc0\x80', b'\x00').decode('utf-8', 'surrogatepass')
    except UnicodeDecodeError:
        return data.decode('utf-8', 'replace')
    if _has_surrogates(s):
        s = s.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
    return s


def encode_mutf8(s: str) -> bytes:
    """Encode str to MUTF-8 (without terminator). Inverse of decode_mutf8."""
    if s.isascii() and '\x00' not in s:
        return s.encode('ascii')
    units = s.encode('utf-16-le', 'surrogatepass')
    out = bytearray()
    for unit in struct.unpack('<%dH' % (len(units) >> 1), units):
        if 0 < unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out.append(0xC0 | (unit >> 6))
            out.append(0x80 | (unit & 0x3F))
        else:
            out.append(0xE0 | (unit >> 12))
            out.append(0x80 | ((unit >> 6) & 0x3F))
            out.append(0x80 | (unit & 0x3F))
    return bytes(out)


def utf16_len(s: str) -> int:
    """Length of s in UTF-16 code units: the value of the string_data_item prefix."""
    if s.isascii():
        return len(s)
    return len(s.encode('utf-16-le', 'surrogatepass')) >> 1
