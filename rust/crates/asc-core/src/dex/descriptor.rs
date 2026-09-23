use crate::mutf8::DexStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Primitive(u8),
    Class,
    Array,
}

impl TypeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primitive(_) => "primitive",
            Self::Class => "class",
            Self::Array => "array",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeInfo {
    pub descriptor: DexStr,
    pub dim: usize,
    pub kind: TypeKind,
    pub primitive_value: Option<u8>,
    pub class_value: Option<DexStr>,
}

pub fn parse_descriptor(desc: &DexStr) -> TypeInfo {
    let units = desc.as_slice();
    let mut dim = 0;
    while dim < units.len() && units[dim] == b'[' as u16 {
        dim += 1;
    }

    if dim > 0 {
        return TypeInfo {
            descriptor: desc.clone(),
            dim,
            kind: TypeKind::Array,
            primitive_value: None,
            class_value: None,
        };
    }

    if units.len() == 1 {
        let prim = match units[0] {
            0x56 => Some(0), // 'V'
            0x5A => Some(1), // 'Z'
            0x42 => Some(2), // 'B'
            0x53 => Some(3), // 'S'
            0x43 => Some(4), // 'C'
            0x49 => Some(5), // 'I'
            0x4A => Some(6), // 'J'
            0x46 => Some(7), // 'F'
            0x44 => Some(8), // 'D'
            _ => None,
        };
        if let Some(val) = prim {
            return TypeInfo {
                descriptor: desc.clone(),
                dim: 0,
                kind: TypeKind::Primitive(val),
                primitive_value: Some(val),
                class_value: None,
            };
        }
    }

    TypeInfo {
        descriptor: desc.clone(),
        dim: 0,
        kind: TypeKind::Class,
        primitive_value: None,
        class_value: Some(desc.clone()),
    }
}
