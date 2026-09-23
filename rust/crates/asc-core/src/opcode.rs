use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Format {
    K10x,
    K12x,
    K11n,
    K11x,
    K10t,
    K20t,
    K22x,
    K21t,
    K21s,
    K21h,
    K21c,
    K23x,
    K22b,
    K22t,
    K22s,
    K22c,
    K32x,
    K30t,
    K31t,
    K31i,
    K31c,
    K35c,
    K3rc,
    K51l,
    K45cc,
    K4rcc,
}

impl Format {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::K10x => "k10x",
            Self::K12x => "k12x",
            Self::K11n => "k11n",
            Self::K11x => "k11x",
            Self::K10t => "k10t",
            Self::K20t => "k20t",
            Self::K22x => "k22x",
            Self::K21t => "k21t",
            Self::K21s => "k21s",
            Self::K21h => "k21h",
            Self::K21c => "k21c",
            Self::K23x => "k23x",
            Self::K22b => "k22b",
            Self::K22t => "k22t",
            Self::K22s => "k22s",
            Self::K22c => "k22c",
            Self::K32x => "k32x",
            Self::K30t => "k30t",
            Self::K31t => "k31t",
            Self::K31i => "k31i",
            Self::K31c => "k31c",
            Self::K35c => "k35c",
            Self::K3rc => "k3rc",
            Self::K51l => "k51l",
            Self::K45cc => "k45cc",
            Self::K4rcc => "k4rcc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndexKind {
    None,
    StringRef,
    TypeRef,
    FieldRef,
    MethodRef,
    MethodAndProtoRef,
    CallSiteRef,
    MethodHandleRef,
    ProtoRef,
}

impl IndexKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "kIndexNone",
            Self::StringRef => "kIndexStringRef",
            Self::TypeRef => "kIndexTypeRef",
            Self::FieldRef => "kIndexFieldRef",
            Self::MethodRef => "kIndexMethodRef",
            Self::MethodAndProtoRef => "kIndexMethodAndProtoRef",
            Self::CallSiteRef => "kIndexCallSiteRef",
            Self::MethodHandleRef => "kIndexMethodHandleRef",
            Self::ProtoRef => "kIndexProtoRef",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifyFlags(pub u32);

pub const VFLAG_NAMES: &[&str] = &[
    "kVerifyNothing",
    "kVerifyRegA",
    "kVerifyRegB",
    "kVerifyRegAWide",
    "kVerifyRegBWide",
    "kVerifyRegBString",
    "kVerifyRegBType",
    "kVerifyRegCType",
    "kVerifyRegBNewInstance",
    "kVerifyRegCNewArray",
    "kVerifyRegBFilledNewArray",
    "kVerifyVarArg",
    "kVerifyVarArgRange",
    "kVerifyArrayData",
    "kVerifyBranchTarget",
    "kVerifySwitchTargets",
    "kVerifyRegC",
    "kVerifyRegCWide",
    "kVerifyError",
    "kVerifyRegCField",
    "kVerifyRegBField",
    "kVerifyRegBMethod",
    "kVerifyVarArgNonZero",
    "kVerifyVarArgRangeNonZero",
    "kVerifyRegHPrototype",
    "kVerifyRegBCallSite",
    "kVerifyRegBMethodHandle",
    "kVerifyRegBPrototype",
];

impl VerifyFlags {
    pub fn contains(&self, bit: u32) -> bool {
        (self.0 & bit) == bit
    }

    /// Return flag names list in declaration order (matching Python IntFlag member list).
    pub fn flag_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        for (i, &name) in VFLAG_NAMES.iter().enumerate() {
            if (self.0 & (1 << i)) != 0 {
                names.push(name);
            }
        }
        names
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Opcode {
    pub name: &'static str,
    pub len: u8,
    pub fmt: Format,
    pub idx: IndexKind,
    pub verify: VerifyFlags,
}

include!(concat!(env!("OUT_DIR"), "/opcodes.rs"));
