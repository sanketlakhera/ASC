use crate::dex::descriptor::{TypeInfo, parse_descriptor};
use crate::dex::header::Header;
use crate::error::AscError;
use crate::leb128::read_uleb128;
use crate::mutf8::{DexStr, decode_mutf8, encode_mutf8};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoInfo {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub param_type_idxs: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldInfo {
    pub index: u32,
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
    pub access_flags: u32,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodInfo {
    pub index: u32,
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
    pub is_direct: bool,
    pub is_virtual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassInfo {
    pub class_idx: u32,
    pub class_def_off: u32,
    pub class_data_off: u32,
    pub fullname: DexStr,
    pub static_fields: Vec<[u32; 2]>,   // [field_idx, access_flags]
    pub instance_fields: Vec<[u32; 2]>, // [field_idx, access_flags]
    pub direct_methods: Vec<[u32; 3]>,  // [method_idx, access_flags, code_off]
    pub virtual_methods: Vec<[u32; 3]>, // [method_idx, access_flags, code_off]
    pub all_methods: Vec<MethodInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeItemInfo<'a> {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns_bytes: &'a [u8],
}

pub struct Dex<'a> {
    pub buf: &'a [u8],
    pub header: Header,
}

impl<'a> Dex<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, AscError> {
        let header = Header::parse(buf)?;
        Ok(Self { buf, header })
    }

    /// Returns raw MUTF-8 payload without the terminating NUL byte.
    pub fn get_string_bytes(&self, str_idx: usize) -> Result<&'a [u8], AscError> {
        let (off, count) = self.header.strings;
        if str_idx >= count {
            return Err(AscError::BadStringIdsRange);
        }
        let entry_off = off
            .checked_add(str_idx.checked_mul(4).ok_or(AscError::BadStringIdsRange)?)
            .ok_or(AscError::BadStringIdsRange)?;
        let string_off_bytes = self
            .buf
            .get(entry_off..entry_off + 4)
            .ok_or(AscError::BadStringIdsRange)?;
        let string_off = u32::from_le_bytes(string_off_bytes.try_into().unwrap()) as usize;

        if string_off >= self.buf.len() {
            return Err(AscError::BadStringDataOffset);
        }

        let (_utf16_len, uleb_sz) = read_uleb128(self.buf, string_off)?;
        let data_start = string_off + uleb_sz;
        if data_start > self.buf.len() {
            return Err(AscError::UnterminatedStringDataItem);
        }

        let remainder = &self.buf[data_start..];
        let null_pos = remainder
            .iter()
            .position(|&b| b == 0)
            .ok_or(AscError::UnterminatedStringDataItem)?;

        Ok(&self.buf[data_start..data_start + null_pos])
    }

    /// Decodes string at `str_idx` into a `DexStr`.
    pub fn get_string(&self, str_idx: usize) -> Result<DexStr, AscError> {
        let bytes = self.get_string_bytes(str_idx)?;
        Ok(decode_mutf8(bytes))
    }

    /// Returns the string offset in the DEX buffer for `str_idx`.
    pub fn get_string_data_off(&self, str_idx: usize) -> Result<usize, AscError> {
        let (off, count) = self.header.strings;
        if str_idx >= count {
            return Err(AscError::BadStringIdsRange);
        }
        let entry_off = off + str_idx * 4;
        let string_off_bytes = self
            .buf
            .get(entry_off..entry_off + 4)
            .ok_or(AscError::BadStringIdsRange)?;
        Ok(u32::from_le_bytes(string_off_bytes.try_into().unwrap()) as usize)
    }

    /// Returns parsed `TypeInfo` for `type_idx`.
    pub fn get_type(&self, type_idx: usize) -> Result<(usize, TypeInfo), AscError> {
        let (off, count) = self.header.types;
        if type_idx >= count {
            return Err(AscError::BadTypeIdsRange);
        }
        let entry_off = off
            .checked_add(type_idx.checked_mul(4).ok_or(AscError::BadTypeIdsRange)?)
            .ok_or(AscError::BadTypeIdsRange)?;
        let str_idx_bytes = self
            .buf
            .get(entry_off..entry_off + 4)
            .ok_or(AscError::BadTypeIdsRange)?;
        let str_idx = u32::from_le_bytes(str_idx_bytes.try_into().unwrap()) as usize;
        let desc = self.get_string(str_idx)?;
        let info = parse_descriptor(&desc);
        Ok((str_idx, info))
    }

    /// Returns parsed `ProtoInfo` for `proto_idx`.
    pub fn get_prototype(&self, proto_idx: usize) -> Result<ProtoInfo, AscError> {
        let (off, count) = self.header.prototypes;
        if proto_idx >= count {
            return Err(AscError::BadProtoIdsRange);
        }
        let entry_off = off + proto_idx * 12;
        let bytes = self
            .buf
            .get(entry_off..entry_off + 12)
            .ok_or(AscError::BadProtoIdsRange)?;

        let shorty_idx = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let return_type_idx = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let parameters_off = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

        let mut param_type_idxs = Vec::new();
        if parameters_off != 0 {
            let p_off = parameters_off as usize;
            let sz_bytes = self
                .buf
                .get(p_off..p_off + 4)
                .ok_or(AscError::BadMethodIdsRange)?;
            let size = u32::from_le_bytes(sz_bytes.try_into().unwrap()) as usize;
            let mut curr = p_off + 4;
            for _ in 0..size {
                let type_bytes = self
                    .buf
                    .get(curr..curr + 2)
                    .ok_or(AscError::BadMethodIdsRange)?;
                param_type_idxs.push(u16::from_le_bytes(type_bytes.try_into().unwrap()));
                curr += 2;
            }
        }

        Ok(ProtoInfo {
            shorty_idx,
            return_type_idx,
            parameters_off,
            param_type_idxs,
        })
    }

    /// Returns parsed `FieldInfo` for `field_idx`.
    pub fn get_field(&self, field_idx: usize) -> Result<FieldInfo, AscError> {
        let (off, count) = self.header.fields;
        if field_idx >= count {
            return Err(AscError::BadFieldIdsRange);
        }
        let entry_off = off + field_idx * 8;
        let bytes = self
            .buf
            .get(entry_off..entry_off + 8)
            .ok_or(AscError::BadFieldIdsRange)?;

        let class_idx = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let type_idx = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let name_idx = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

        Ok(FieldInfo {
            index: field_idx as u32,
            class_idx,
            type_idx,
            name_idx,
            access_flags: 0,
            is_static: false,
        })
    }

    /// Returns parsed `MethodInfo` for `method_idx`.
    pub fn get_method(&self, method_idx: usize) -> Result<MethodInfo, AscError> {
        let (off, count) = self.header.methods;
        if method_idx >= count {
            return Err(AscError::BadMethodIdsRange);
        }
        let entry_off = off + method_idx * 8;
        let bytes = self
            .buf
            .get(entry_off..entry_off + 8)
            .ok_or(AscError::BadMethodIdsRange)?;

        let class_idx = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let proto_idx = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let name_idx = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

        Ok(MethodInfo {
            index: method_idx as u32,
            class_idx,
            proto_idx,
            name_idx,
            access_flags: 0,
            code_off: 0,
            is_direct: false,
            is_virtual: false,
        })
    }

    /// Parses `ClassInfo` for class definition index `class_def_idx`.
    pub fn get_class(&self, class_def_idx: usize) -> Result<ClassInfo, AscError> {
        let (off, count) = self.header.classes;
        if class_def_idx >= count {
            return Err(AscError::BadClassDefsRange);
        }
        let entry_off = off + class_def_idx * 32;
        let bytes = self
            .buf
            .get(entry_off..entry_off + 32)
            .ok_or(AscError::BadClassDefsRange)?;

        let class_idx = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let class_data_off = u32::from_le_bytes(bytes[24..28].try_into().unwrap());

        let (_str_idx, type_info) = self.get_type(class_idx as usize)?;
        let fullname = type_info.descriptor;

        let mut static_fields = Vec::new();
        let mut instance_fields = Vec::new();
        let mut direct_methods = Vec::new();
        let mut virtual_methods = Vec::new();
        let mut all_methods = Vec::new();

        if class_data_off != 0 {
            let mut p = class_data_off as usize;
            let (static_fields_size, n) = read_uleb128(self.buf, p)?;
            p += n;
            let (instance_fields_size, n) = read_uleb128(self.buf, p)?;
            p += n;
            let (direct_methods_size, n) = read_uleb128(self.buf, p)?;
            p += n;
            let (virtual_methods_size, n) = read_uleb128(self.buf, p)?;
            p += n;

            let mut f_idx = 0u32;
            for _ in 0..static_fields_size {
                let (diff, n) = read_uleb128(self.buf, p)?;
                p += n;
                f_idx += diff as u32;
                let (flags, n) = read_uleb128(self.buf, p)?;
                p += n;
                static_fields.push([f_idx, flags as u32]);
            }

            let mut f_idx = 0u32;
            for _ in 0..instance_fields_size {
                let (diff, n) = read_uleb128(self.buf, p)?;
                p += n;
                f_idx += diff as u32;
                let (flags, n) = read_uleb128(self.buf, p)?;
                p += n;
                instance_fields.push([f_idx, flags as u32]);
            }

            let mut m_idx = 0u32;
            for _ in 0..direct_methods_size {
                let (diff, n) = read_uleb128(self.buf, p)?;
                p += n;
                m_idx += diff as u32;
                let (flags, n) = read_uleb128(self.buf, p)?;
                p += n;
                let (code_off, n) = read_uleb128(self.buf, p)?;
                p += n;
                direct_methods.push([m_idx, flags as u32, code_off as u32]);

                if let Ok(mut method) = self.get_method(m_idx as usize) {
                    method.access_flags = flags as u32;
                    method.code_off = code_off as u32;
                    method.is_direct = true;
                    all_methods.push(method);
                }
            }

            let mut m_idx = 0u32;
            for _ in 0..virtual_methods_size {
                let (diff, n) = read_uleb128(self.buf, p)?;
                p += n;
                m_idx += diff as u32;
                let (flags, n) = read_uleb128(self.buf, p)?;
                p += n;
                let (code_off, n) = read_uleb128(self.buf, p)?;
                p += n;
                virtual_methods.push([m_idx, flags as u32, code_off as u32]);

                if let Ok(mut method) = self.get_method(m_idx as usize) {
                    method.access_flags = flags as u32;
                    method.code_off = code_off as u32;
                    method.is_virtual = true;
                    all_methods.push(method);
                }
            }
        }

        Ok(ClassInfo {
            class_idx,
            class_def_off: entry_off as u32,
            class_data_off,
            fullname,
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
            all_methods,
        })
    }

    /// Reads code_item header and instruction bytes at `code_off`.
    pub fn get_code_item(&self, code_off: usize) -> Result<CodeItemInfo<'a>, AscError> {
        let bytes = self
            .buf
            .get(code_off..code_off + 16)
            .ok_or(AscError::BadCodeItemOffset)?;

        let registers_size = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let ins_size = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let outs_size = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let tries_size = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let debug_info_off = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let insns_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap());

        let insns_byte_len = (insns_size as usize)
            .checked_mul(2)
            .ok_or(AscError::BadCodeItemOffset)?;
        let insns_start = code_off + 16;
        let insns_end = insns_start
            .checked_add(insns_byte_len)
            .ok_or(AscError::BadCodeItemOffset)?;

        let insns_bytes = self
            .buf
            .get(insns_start..insns_end)
            .ok_or(AscError::BadCodeItemOffset)?;

        Ok(CodeItemInfo {
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
            insns_bytes,
        })
    }

    /// Finds `type_idx` by binary searching `type_ids` using target MUTF-8 bytes.
    pub fn find_type_idx(&self, target_bytes: &[u8]) -> Result<Option<usize>, AscError> {
        find_type_idx_raw(self.buf, target_bytes)
    }

    /// Finds a class by its descriptor name (e.g. "Lexample/Test;").
    /// Returns the class definition index (0..class_count) if found.
    pub fn find_class(&self, fullname: &str) -> Result<Option<usize>, AscError> {
        let (string_off, string_count) = self.header.strings;
        let string_end = string_off
            .checked_add(
                string_count
                    .checked_mul(4)
                    .ok_or(AscError::BadStringIdsRange)?,
            )
            .ok_or(AscError::BadStringIdsRange)?;
        if string_end > self.buf.len() {
            return Err(AscError::BadStringIdsRange);
        }

        let (type_off, type_count) = self.header.types;
        let type_end = type_off
            .checked_add(type_count.checked_mul(4).ok_or(AscError::BadTypeIdsRange)?)
            .ok_or(AscError::BadTypeIdsRange)?;
        if type_end > self.buf.len() {
            return Err(AscError::BadTypeIdsRange);
        }

        let (class_off, class_count) = self.header.classes;
        let class_end = class_off
            .checked_add(
                class_count
                    .checked_mul(32)
                    .ok_or(AscError::BadClassDefsRange)?,
            )
            .ok_or(AscError::BadClassDefsRange)?;
        if class_end > self.buf.len() {
            return Err(AscError::BadClassDefsRange);
        }

        let target_units: Vec<u16> = fullname.encode_utf16().collect();
        let target_bytes = encode_mutf8(&target_units);

        let type_idx = match self.find_type_idx(&target_bytes)? {
            Some(idx) => idx as u32,
            None => return Ok(None),
        };

        for idx in 0..class_count {
            let def_off = class_off + idx * 32;
            if let Some(bytes) = self.buf.get(def_off..def_off + 4) {
                let cls_type_idx = u32::from_le_bytes(bytes.try_into().unwrap());
                if cls_type_idx == type_idx {
                    return Ok(Some(idx));
                }
            }
        }

        Ok(None)
    }

    /// Checks whether this DEX defines the class matching `target_bytes`.
    pub fn defines_class(&self, target_bytes: &[u8]) -> Result<bool, AscError> {
        dex_defines_class_raw(self.buf, target_bytes)
    }
}

/// Reads raw string bytes for string data at `str_off`.
/// Matches Python `apk_handler._read_string_data_bytes`.
pub fn read_string_data_bytes(buf: &[u8], str_off: usize) -> Result<&[u8], AscError> {
    if str_off >= buf.len() {
        return Err(AscError::BadStringDataOff);
    }
    let (_utf16_len, uleb_sz) = read_uleb128(buf, str_off)?;
    let data_start = str_off
        .checked_add(uleb_sz)
        .ok_or(AscError::UnterminatedStringDataItem)?;
    if data_start > buf.len() {
        return Err(AscError::UnterminatedStringDataItem);
    }
    let remainder = &buf[data_start..];
    let null_pos = remainder
        .iter()
        .position(|&b| b == 0)
        .ok_or(AscError::UnterminatedStringDataItem)?;
    Ok(&remainder[..null_pos])
}

/// Binary searches `type_ids` in a raw DEX buffer for `target_bytes`.
/// Matches Python `apk_handler._find_type_idx`.
pub fn find_type_idx_raw(buf: &[u8], target_bytes: &[u8]) -> Result<Option<usize>, AscError> {
    if buf.len() < 0x70 || buf.get(..3) != Some(b"dex") {
        return Ok(None);
    }

    let string_count = u32::from_le_bytes(buf[0x38..0x3c].try_into().unwrap()) as usize;
    let string_off = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap()) as usize;
    let type_count = u32::from_le_bytes(buf[0x40..0x44].try_into().unwrap()) as usize;
    let type_off = u32::from_le_bytes(buf[0x44..0x48].try_into().unwrap()) as usize;

    if string_count == 0 || type_count == 0 {
        return Ok(None);
    }

    let string_end = string_off
        .checked_add(
            string_count
                .checked_mul(4)
                .ok_or(AscError::BadStringIdsRange)?,
        )
        .ok_or(AscError::BadStringIdsRange)?;
    if string_end > buf.len() {
        return Err(AscError::BadStringIdsRange);
    }

    let type_end = type_off
        .checked_add(type_count.checked_mul(4).ok_or(AscError::BadTypeIdsRange)?)
        .ok_or(AscError::BadTypeIdsRange)?;
    if type_end > buf.len() {
        return Err(AscError::BadTypeIdsRange);
    }

    let mut left = 0usize;
    let mut right = type_count - 1;

    while left <= right {
        let mid = (left + right) / 2;
        let entry_off = type_off + mid * 4;
        let str_idx_bytes = buf
            .get(entry_off..entry_off + 4)
            .ok_or(AscError::BadTypeIdsRange)?;
        let str_idx = u32::from_le_bytes(str_idx_bytes.try_into().unwrap()) as usize;
        if str_idx >= string_count {
            return Err(AscError::BadTypeIdToStringIdx);
        }
        let str_off_bytes = buf
            .get(string_off + str_idx * 4..string_off + str_idx * 4 + 4)
            .ok_or(AscError::BadStringIdsRange)?;
        let str_off = u32::from_le_bytes(str_off_bytes.try_into().unwrap()) as usize;
        if str_off >= buf.len() {
            return Err(AscError::BadStringDataOff);
        }

        let desc_bytes = read_string_data_bytes(buf, str_off)?;

        match desc_bytes.cmp(target_bytes) {
            std::cmp::Ordering::Equal => return Ok(Some(mid)),
            std::cmp::Ordering::Less => left = mid + 1,
            std::cmp::Ordering::Greater => {
                if mid == 0 {
                    break;
                }
                right = mid - 1;
            }
        }
    }

    Ok(None)
}

/// Checks if `class_defs` table contains `type_idx`.
/// Matches Python `apk_handler._class_defs_contains_type_idx`.
pub fn class_defs_contains_type_idx_raw(buf: &[u8], type_idx: u32) -> Result<bool, AscError> {
    if buf.len() < 0x68 {
        return Ok(false);
    }
    let class_count = u32::from_le_bytes(buf[0x60..0x64].try_into().unwrap()) as usize;
    let class_off = u32::from_le_bytes(buf[0x64..0x68].try_into().unwrap()) as usize;

    if class_count == 0 {
        return Ok(false);
    }

    let class_end = class_off
        .checked_add(
            class_count
                .checked_mul(32)
                .ok_or(AscError::BadClassDefsRange)?,
        )
        .ok_or(AscError::BadClassDefsRange)?;
    if class_end > buf.len() {
        return Err(AscError::BadClassDefsRange);
    }

    let needle = type_idx.to_le_bytes();
    let slice = &buf[class_off..class_end];

    let mut pos = 0;
    while pos + 4 <= slice.len() {
        if let Some(p) = slice[pos..].windows(4).position(|w| w == needle) {
            let abs_p = pos + p;
            if abs_p % 32 == 0 {
                return Ok(true);
            }
            pos = abs_p + 1;
        } else {
            break;
        }
    }

    Ok(false)
}

/// Checks if raw DEX buffer defines class with target descriptor bytes.
/// Matches Python `apk_handler._dex_defines_class`.
pub fn dex_defines_class_raw(buf: &[u8], target_bytes: &[u8]) -> Result<bool, AscError> {
    match find_type_idx_raw(buf, target_bytes)? {
        Some(idx) => class_defs_contains_type_idx_raw(buf, idx as u32),
        None => Ok(false),
    }
}
