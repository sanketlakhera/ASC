use crate::bytes::{record, u16_at, u32_at, until_nul};
use crate::dex::descriptor::{TypeInfo, parse_descriptor};
use crate::dex::header::Header;
use crate::error::AscError;
use crate::leb128::{read_uleb128, skip_uleb128};
use crate::mutf8::{DexStr, decode_mutf8, encode_mutf8};
use std::collections::HashSet;

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
    pub index: u64,
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
    pub access_flags: u64,
    pub code_off: u64,
    pub is_direct: bool,
    pub is_virtual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassInfo {
    pub class_idx: u32,
    pub class_def_off: u32,
    pub class_data_off: u32,
    pub fullname: DexStr,
    // uleb values are up to 35 bits and Python never truncates them, hence u64.
    pub static_fields: Vec<[u64; 2]>,   // [field_idx, access_flags]
    pub instance_fields: Vec<[u64; 2]>, // [field_idx, access_flags]
    pub direct_methods: Vec<[u64; 3]>,  // [method_idx, access_flags, code_off]
    pub virtual_methods: Vec<[u64; 3]>, // [method_idx, access_flags, code_off]
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
        let string_off = u32_at(self.buf, entry_off).ok_or(AscError::BadStringIdsRange)? as usize;

        if string_off >= self.buf.len() {
            return Err(AscError::BadStringDataOffset);
        }

        let (_utf16_len, uleb_sz) = read_uleb128(self.buf, string_off)?;
        string_off
            .checked_add(uleb_sz)
            .and_then(|data_start| self.buf.get(data_start..))
            .and_then(until_nul)
            .ok_or(AscError::UnterminatedStringDataItem)
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
        str_idx
            .checked_mul(4)
            .and_then(|rel| rel.checked_add(off))
            .and_then(|entry_off| u32_at(self.buf, entry_off))
            .map(|string_off| string_off as usize)
            .ok_or(AscError::BadStringIdsRange)
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
        let str_idx = u32_at(self.buf, entry_off).ok_or(AscError::BadTypeIdsRange)? as usize;
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
        let entry_off = proto_idx
            .checked_mul(12)
            .and_then(|rel| rel.checked_add(off))
            .ok_or(AscError::BadProtoIdsRange)?;
        let bytes = record(self.buf, entry_off, 12).ok_or(AscError::BadProtoIdsRange)?;
        let field = |o| u32_at(bytes, o).ok_or(AscError::BadProtoIdsRange);

        let shorty_idx = field(0)?;
        let return_type_idx = field(4)?;
        let parameters_off = field(8)?;

        let mut param_type_idxs = Vec::new();
        if parameters_off != 0 {
            let p_off = parameters_off as usize;
            let size = u32_at(self.buf, p_off).ok_or(AscError::BadTypeListOffset)? as usize;
            // The u32 read above guarantees `p_off + 4 <= len`.
            let list = self.buf.get(p_off.saturating_add(4)..).unwrap_or_default();
            let mut items = list.as_chunks::<2>().0.iter();
            for _ in 0..size {
                let item = items.next().ok_or(AscError::BadTypeListOffset)?;
                param_type_idxs.push(u16::from_le_bytes(*item));
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
        let (class_idx, type_idx, name_idx) = field_idx
            .checked_mul(8)
            .and_then(|rel| rel.checked_add(off))
            .and_then(|entry_off| id_entry_at(self.buf, entry_off))
            .ok_or(AscError::BadFieldIdsRange)?;

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
        let (class_idx, proto_idx, name_idx) = method_idx
            .checked_mul(8)
            .and_then(|rel| rel.checked_add(off))
            .and_then(|entry_off| id_entry_at(self.buf, entry_off))
            .ok_or(AscError::BadMethodIdsRange)?;

        Ok(MethodInfo {
            index: method_idx as u64,
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
        let mut class = self.get_class_data(class_def_idx)?;
        // Python resolves `fullname` lazily, after class_data has been walked, so a
        // corrupt class_data error wins over a bad type index.
        let (_str_idx, type_info) = self.get_type(class.class_idx as usize)?;
        class.fullname = type_info.descriptor;
        Ok(class)
    }

    /// Like `get_class` but leaves `fullname` empty: the class_def and class_data
    /// only, which is all Python's code_item walk touches.
    pub fn get_class_data(&self, class_def_idx: usize) -> Result<ClassInfo, AscError> {
        let (class, res) = self.get_class_data_partial(class_def_idx);
        res.map(|()| class)
    }

    /// `get_class_data` that also returns what was walked before an error. Python
    /// mutates each cached DexMethod as soon as its entry resolves, so entries read
    /// before a failure still change later readers; callers modelling that need them.
    pub fn get_class_data_partial(
        &self,
        class_def_idx: usize,
    ) -> (ClassInfo, Result<(), AscError>) {
        let mut class = ClassInfo {
            class_idx: 0,
            class_def_off: 0,
            class_data_off: 0,
            fullname: DexStr::new(Vec::new()),
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
            all_methods: Vec::new(),
        };
        let res = self.walk_class_data(class_def_idx, &mut class);
        (class, res)
    }

    fn walk_class_data(&self, class_def_idx: usize, class: &mut ClassInfo) -> Result<(), AscError> {
        let (off, count) = self.header.classes;
        if class_def_idx >= count {
            return Err(AscError::BadClassDefsRange);
        }
        let entry_off = class_def_idx
            .checked_mul(32)
            .and_then(|rel| rel.checked_add(off))
            .ok_or(AscError::BadClassDefsRange)?;
        let bytes = record(self.buf, entry_off, 32).ok_or(AscError::BadClassDefsRange)?;
        let field = |o| u32_at(bytes, o).ok_or(AscError::BadClassDefsRange);

        class.class_idx = field(0)?;
        class.class_def_off = entry_off as u32;
        class.class_data_off = field(24)?;
        if class.class_data_off == 0 {
            return Ok(());
        }

        // Reads the next uleb128 of class_data and steps past it.
        let mut p = class.class_data_off as usize;
        let mut next_uleb = || -> Result<u64, AscError> {
            let (value, n) = read_uleb128(self.buf, p)?;
            p = p.checked_add(n).ok_or(AscError::UnterminatedUleb128)?;
            Ok(value)
        };
        let static_fields_size = next_uleb()?;
        let instance_fields_size = next_uleb()?;
        let direct_methods_size = next_uleb()?;
        let virtual_methods_size = next_uleb()?;

        // Python accumulates indices as unbounded ints and resolves each entry as
        // soon as it is read (tinydex DexField / DexMethod), so the running index
        // is u64 and every entry is bounds-checked against the buffer, not the count.
        // A repeat inside a list, or a member of both lists of a pair, is
        // "bad class_data", checked before the entry resolves (tinydex order).
        let mut static_idxs = HashSet::new();
        for (size, is_static) in [(static_fields_size, true), (instance_fields_size, false)] {
            let mut f_idx = 0u64;
            for i in 0..size {
                let diff = next_uleb()?;
                f_idx = f_idx.saturating_add(diff);
                let flags = next_uleb()?;
                if (i > 0 && diff == 0) || (!is_static && static_idxs.contains(&f_idx)) {
                    return Err(AscError::BadClassData);
                }
                if !self.id_entry_in_buf(self.header.fields.0, f_idx) {
                    return Err(AscError::BadFieldIdsRange);
                }
                if is_static {
                    static_idxs.insert(f_idx);
                    class.static_fields.push([f_idx, flags]);
                } else {
                    class.instance_fields.push([f_idx, flags]);
                }
            }
        }

        let mut direct_idxs = HashSet::new();
        for (size, is_direct) in [(direct_methods_size, true), (virtual_methods_size, false)] {
            let mut m_idx = 0u64;
            for i in 0..size {
                let diff = next_uleb()?;
                m_idx = m_idx.saturating_add(diff);
                let flags = next_uleb()?;
                let code_off = next_uleb()?;
                if (i > 0 && diff == 0) || (!is_direct && direct_idxs.contains(&m_idx)) {
                    return Err(AscError::BadClassData);
                }
                let entry = self
                    .read_id_entry(self.header.methods.0, m_idx)
                    .ok_or(AscError::BadMethodIdsRange)?;
                if is_direct {
                    direct_idxs.insert(m_idx);
                    class.direct_methods.push([m_idx, flags, code_off]);
                } else {
                    class.virtual_methods.push([m_idx, flags, code_off]);
                }
                class.all_methods.push(MethodInfo {
                    index: m_idx,
                    class_idx: entry.0,
                    proto_idx: entry.1,
                    name_idx: entry.2,
                    access_flags: flags,
                    code_off,
                    is_direct,
                    is_virtual: !is_direct,
                });
            }
        }
        Ok(())
    }

    /// Whether the 8-byte `field_ids` / `method_ids` entry `idx` of the table at
    /// `table_off` lies inside the buffer. Python checks only this, not the count.
    fn id_entry_in_buf(&self, table_off: usize, idx: u64) -> bool {
        idx.checked_mul(8)
            .and_then(|o| o.checked_add(table_off as u64))
            .and_then(|o| o.checked_add(8))
            .is_some_and(|end| end <= self.buf.len() as u64)
    }

    /// Reads the `(u16, u16, u32)` id entry `idx` with Python's buffer-only bound.
    fn read_id_entry(&self, table_off: usize, idx: u64) -> Option<(u16, u16, u32)> {
        if !self.id_entry_in_buf(table_off, idx) {
            return None;
        }
        let off = (idx as usize).checked_mul(8)?.checked_add(table_off)?;
        id_entry_at(self.buf, off)
    }

    /// Reads code_item header and instruction bytes at `code_off`.
    pub fn get_code_item(&self, code_off: usize) -> Result<CodeItemInfo<'a>, AscError> {
        let bytes = self
            .buf
            .get(code_off..code_off.saturating_add(16))
            .ok_or(AscError::BadCodeItemOffset)?;

        let half = |o| u16_at(bytes, o).ok_or(AscError::BadCodeItemOffset);
        let word = |o| u32_at(bytes, o).ok_or(AscError::BadCodeItemOffset);

        let registers_size = half(0)?;
        let ins_size = half(2)?;
        let outs_size = half(4)?;
        let tries_size = half(6)?;
        let debug_info_off = word(8)?;
        let insns_size = word(12)?;

        // Python slices `buf[off + 16 : off + 16 + insns_size * 2]`, which clamps
        // silently at the buffer end; only the 16-byte header is a contract error.
        let after_header = self
            .buf
            .get(code_off.saturating_add(16)..)
            .unwrap_or_default();
        let insns_len = (insns_size as usize).saturating_mul(2);
        let insns_bytes = after_header.get(..insns_len).unwrap_or(after_header);

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
        let units: Vec<u16> = fullname.encode_utf16().collect();
        self.find_class_units(&units)
    }

    /// `find_class` for a name held as UTF-16 units, which may contain lone
    /// surrogates the way a Python `str` can.
    pub fn find_class_units(&self, fullname: &[u16]) -> Result<Option<usize>, AscError> {
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

        let target_bytes = encode_mutf8(fullname);

        // tinydex `DEX.get_class`: resolves descriptors through `get_string_bytes`, so a
        // bad string index reports "bad string_ids range", unlike the APK-scan search
        // in `find_type_idx_raw` ("bad type_id->string_idx").
        // Inclusive bounds and `(left + right) / 2` exactly as Python, so the same
        // strings are probed and the same error fires first.
        let mut type_idx = None;
        let (mut left, mut right) = (0i64, (type_count as i64).saturating_sub(1));
        while left <= right {
            let mid = left.midpoint(right) as usize;
            let desc_idx = mid
                .checked_mul(4)
                .and_then(|rel| rel.checked_add(type_off))
                .and_then(|entry_off| u32_at(self.buf, entry_off))
                .ok_or(AscError::BadTypeIdsRange)?;
            match self
                .get_string_bytes(desc_idx as usize)?
                .cmp(target_bytes.as_slice())
            {
                std::cmp::Ordering::Equal => {
                    type_idx = Some(mid as u32);
                    break;
                }
                std::cmp::Ordering::Less => left = (mid as i64).saturating_add(1),
                std::cmp::Ordering::Greater => right = (mid as i64).saturating_sub(1),
            }
        }
        let Some(type_idx) = type_idx else {
            return Ok(None);
        };

        for idx in 0..class_count {
            let cls_type_idx = idx
                .checked_mul(32)
                .and_then(|rel| rel.checked_add(class_off))
                .and_then(|def_off| u32_at(self.buf, def_off));
            if cls_type_idx == Some(type_idx) {
                return Ok(Some(idx));
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
    // apk_handler skips the prefix with the unbounded `_skip_uleb128`, not the
    // five-byte `read_uleb128_fast` tinydex uses.
    let data_start = skip_uleb128(buf, str_off)?;
    buf.get(data_start..)
        .and_then(until_nul)
        .ok_or(AscError::UnterminatedStringDataItem)
}

/// Binary searches `type_ids` in a raw DEX buffer for `target_bytes`.
/// Matches Python `apk_handler._find_type_idx`.
pub fn find_type_idx_raw(buf: &[u8], target_bytes: &[u8]) -> Result<Option<usize>, AscError> {
    // `Header::parse` fails exactly when the buffer is short or lacks the magic.
    let Ok(header) = Header::parse(buf) else {
        return Ok(None);
    };
    let (string_off, string_count) = header.strings;
    let (type_off, type_count) = header.types;

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
    let mut right = type_count.saturating_sub(1);

    while left <= right {
        let mid = left.midpoint(right);
        let str_idx = mid
            .checked_mul(4)
            .and_then(|rel| rel.checked_add(type_off))
            .and_then(|entry_off| u32_at(buf, entry_off))
            .ok_or(AscError::BadTypeIdsRange)? as usize;
        if str_idx >= string_count {
            return Err(AscError::BadTypeIdToStringIdx);
        }
        let str_off = str_idx
            .checked_mul(4)
            .and_then(|rel| rel.checked_add(string_off))
            .and_then(|entry_off| u32_at(buf, entry_off))
            .ok_or(AscError::BadStringIdsRange)? as usize;
        if str_off >= buf.len() {
            return Err(AscError::BadStringDataOff);
        }

        let desc_bytes = read_string_data_bytes(buf, str_off)?;

        match desc_bytes.cmp(target_bytes) {
            std::cmp::Ordering::Equal => return Ok(Some(mid)),
            // `mid < type_count`, so this cannot saturate.
            std::cmp::Ordering::Less => left = mid.saturating_add(1),
            std::cmp::Ordering::Greater => {
                let Some(below) = mid.checked_sub(1) else {
                    break;
                };
                right = below;
            }
        }
    }

    Ok(None)
}

/// Checks if `class_defs` table contains `type_idx`.
/// Matches Python `apk_handler._class_defs_contains_type_idx`.
pub fn class_defs_contains_type_idx_raw(buf: &[u8], type_idx: u32) -> Result<bool, AscError> {
    // Both reads succeed exactly when `buf.len() >= 0x68`.
    let (Some(class_count), Some(class_off)) = (u32_at(buf, 0x60), u32_at(buf, 0x64)) else {
        return Ok(false);
    };
    let (class_count, class_off) = (class_count as usize, class_off as usize);

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
    let slice = buf
        .get(class_off..class_end)
        .ok_or(AscError::BadClassDefsRange)?;

    // Python scans every match of the needle and accepts the first 32-byte
    // aligned one, which is the same as testing each aligned window.
    Ok(slice.windows(4).step_by(32).any(|w| w == needle))
}

/// Checks if raw DEX buffer defines class with target descriptor bytes.
/// Matches Python `apk_handler._dex_defines_class`.
pub fn dex_defines_class_raw(buf: &[u8], target_bytes: &[u8]) -> Result<bool, AscError> {
    match find_type_idx_raw(buf, target_bytes)? {
        Some(idx) => class_defs_contains_type_idx_raw(buf, idx as u32),
        None => Ok(false),
    }
}

/// Reads a `field_ids` / `method_ids` entry, `(u16, u16, u32)`, at `off`.
fn id_entry_at(buf: &[u8], off: usize) -> Option<(u16, u16, u32)> {
    let entry = record(buf, off, 8)?;
    Some((u16_at(entry, 0)?, u16_at(entry, 2)?, u32_at(entry, 4)?))
}
