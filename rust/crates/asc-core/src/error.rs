use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AscError {
    EocdNotFound,
    BadEocdHeader,
    BadCentralDirectoryRange,
    BadLocalHeaderSignature,
    BadCompressedDataRange,
    UnsupportedCompressionMethod(u16),
    CorruptDeflateStream(String),
    SizeMismatch { expected: u32, got: usize },
    ApkFileNotFound(String),
    BadDexMagicOrHeaderSize,
    BadStringIdsRange,
    BadStringDataOffset,
    BadStringDataOff,
    BadTypeIdsRange,
    BadTypeIdToStringIdx,
    BadProtoIdsRange,
    BadMethodIdsRange,
    BadFieldIdsRange,
    BadClassDefsRange,
    BadCodeItemOffset,
    UnterminatedUleb128,
    UnterminatedSleb128,
    UnterminatedStringDataItem,
    ClassNotFoundInApk(String),
    ClassNotFoundInDex(String),
    ClassNotIndexed(String),
    Custom(String),
}

impl std::error::Error for AscError {}

impl fmt::Display for AscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EocdNotFound => write!(f, "EOCD not found"),
            Self::BadEocdHeader => write!(f, "bad EOCD header"),
            Self::BadCentralDirectoryRange => write!(f, "bad central directory range"),
            Self::BadLocalHeaderSignature => write!(f, "bad local header signature"),
            Self::BadCompressedDataRange => write!(f, "bad compressed data range"),
            Self::UnsupportedCompressionMethod(method) => {
                write!(f, "unsupported compression method: {method}")
            }
            Self::CorruptDeflateStream(name) => write!(f, "corrupt deflate stream in {name}"),
            Self::SizeMismatch { expected, got } => {
                write!(f, "size mismatch: expect {expected}, got {got}")
            }
            Self::ApkFileNotFound(path) => write!(f, "APK file not found: {path}"),
            Self::BadDexMagicOrHeaderSize => write!(f, "bad DEX magic or header size"),
            Self::BadStringIdsRange => write!(f, "bad string_ids range"),
            Self::BadStringDataOffset => write!(f, "bad string_data offset"),
            Self::BadStringDataOff => write!(f, "bad string_data_off"),
            Self::BadTypeIdsRange => write!(f, "bad type_ids range"),
            Self::BadTypeIdToStringIdx => write!(f, "bad type_id->string_idx"),
            Self::BadProtoIdsRange => write!(f, "bad proto_ids range"),
            Self::BadMethodIdsRange => write!(f, "bad method_ids range"),
            Self::BadFieldIdsRange => write!(f, "bad field_ids range"),
            Self::BadClassDefsRange => write!(f, "bad class_defs range"),
            Self::BadCodeItemOffset => write!(f, "bad code_item offset"),
            Self::UnterminatedUleb128 => write!(f, "unterminated uleb128"),
            Self::UnterminatedSleb128 => write!(f, "unterminated sleb128"),
            Self::UnterminatedStringDataItem => write!(f, "unterminated string_data_item"),
            Self::ClassNotFoundInApk(name) => write!(f, "Class {name} not found in APK."),
            Self::ClassNotFoundInDex(name) => write!(f, "Class {name} not found in DEX."),
            Self::ClassNotIndexed(name) => write!(f, "class not indexed: {name}"),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}
