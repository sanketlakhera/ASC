#![forbid(unsafe_code)]

pub mod dex;
pub mod error;
pub mod inflate;
pub mod leb128;
pub mod mutf8;
pub mod opcode;
pub mod zip;

pub use dex::{
    ClassInfo, CodeItemInfo, Dex, FieldInfo, Header, MethodInfo, ProtoInfo, TypeInfo, TypeKind,
    dex041_logical_offsets, is_dex041_container, iter_logical_dex_buffers,
    normalize_dex041_logical, parse_descriptor,
};
pub use error::AscError;
pub use inflate::inflate_entry;
pub use leb128::{
    read_sleb128, read_uleb128, skip_uleb128, uleb128_len, write_sleb128, write_uleb128,
};
pub use mutf8::{DexStr, decode_mutf8, encode_mutf8, utf16_len};
pub use opcode::{Format, IndexKind, OPCODES, Opcode, VerifyFlags};
pub use zip::{DexEntry, Eocd, decode_utf8_ignore, find_eocd, parse_cd_dex_entries};
