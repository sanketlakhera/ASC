use regex::Regex;
use std::env;
use std::fs;
use std::path::Path;

const VFLAGS: &[&str] = &[
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

fn fmt_variant(name: &str) -> &'static str {
    match name {
        "k10x" => "Format::K10x",
        "k12x" => "Format::K12x",
        "k11n" => "Format::K11n",
        "k11x" => "Format::K11x",
        "k10t" => "Format::K10t",
        "k20t" => "Format::K20t",
        "k22x" => "Format::K22x",
        "k21t" => "Format::K21t",
        "k21s" => "Format::K21s",
        "k21h" => "Format::K21h",
        "k21c" => "Format::K21c",
        "k23x" => "Format::K23x",
        "k22b" => "Format::K22b",
        "k22t" => "Format::K22t",
        "k22s" => "Format::K22s",
        "k22c" => "Format::K22c",
        "k32x" => "Format::K32x",
        "k30t" => "Format::K30t",
        "k31t" => "Format::K31t",
        "k31i" => "Format::K31i",
        "k31c" => "Format::K31c",
        "k35c" => "Format::K35c",
        "k3rc" => "Format::K3rc",
        "k51l" => "Format::K51l",
        "k45cc" => "Format::K45cc",
        "k4rcc" => "Format::K4rcc",
        _ => panic!("unknown format: {}", name),
    }
}

fn idx_variant(name: &str) -> &'static str {
    match name {
        "kIndexNone" => "IndexKind::None",
        "kIndexStringRef" => "IndexKind::StringRef",
        "kIndexTypeRef" => "IndexKind::TypeRef",
        "kIndexFieldRef" => "IndexKind::FieldRef",
        "kIndexMethodRef" => "IndexKind::MethodRef",
        "kIndexMethodAndProtoRef" => "IndexKind::MethodAndProtoRef",
        "kIndexCallSiteRef" => "IndexKind::CallSiteRef",
        "kIndexMethodHandleRef" => "IndexKind::MethodHandleRef",
        "kIndexProtoRef" => "IndexKind::ProtoRef",
        _ => panic!("unknown index kind: {}", name),
    }
}

fn vflag_mask(flags_str: &str) -> u32 {
    let mut mask = 0u32;
    for part in flags_str.split('|') {
        let flag = part.trim();
        if let Some(pos) = VFLAGS.iter().position(|&f| f == flag) {
            mask |= 1 << pos;
        } else {
            panic!("unknown verify flag: {}", flag);
        }
    }
    mask
}

fn main() {
    println!("cargo:rerun-if-changed=resource/dex_instruction_list.h");

    let header_path = Path::new("resource/dex_instruction_list.h");
    let content = fs::read_to_string(header_path).expect("failed to read dex_instruction_list.h");

    let pattern = Regex::new(
        r#"V\((0x[0-9A-Fa-f]+),\s*(\w+),\s*("[\w\/-]+"),\s*(k(\d)[0-9a-z]+),\s*(kIndex\w+),.+?,\s*(kVerify\w+(?:\s*\|\s*kVerify\w+)*)\)"#,
    )
    .expect("invalid regex pattern");

    let mut table: [Option<String>; 256] = std::array::from_fn(|_| None);

    for line in content.lines() {
        if !line.contains("kIndex") || line.contains("kIndexUnknown") {
            continue;
        }

        if let Some(caps) = pattern.captures(line) {
            let opcode_str = caps.get(1).unwrap().as_str();
            let opcode = u8::from_str_radix(opcode_str.trim_start_matches("0x"), 16).unwrap();
            let name = caps.get(3).unwrap().as_str();
            let fmt = caps.get(4).unwrap().as_str();
            let oplen: u8 = caps.get(5).unwrap().as_str().parse().unwrap();
            let idx = caps.get(6).unwrap().as_str();
            let vflags_str = caps.get(7).unwrap().as_str();

            let fmt_code = fmt_variant(fmt);
            let idx_code = idx_variant(idx);
            let vflags_mask = vflag_mask(vflags_str);

            let entry_code = format!(
                "Some(Opcode {{\n        name: {name},\n        len: {oplen},\n        fmt: {fmt_code},\n        idx: {idx_code},\n        verify: VerifyFlags({vflags_mask}),\n    }})"
            );
            table[opcode as usize] = Some(entry_code);
        }
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("opcodes.rs");

    let mut out = String::new();
    out.push_str("pub static OPCODES: [Option<Opcode>; 256] = [\n");
    for (i, entry) in table.iter().enumerate() {
        if let Some(code) = entry {
            out.push_str(&format!("    /* 0x{i:02x} */ {code},\n"));
        } else {
            out.push_str(&format!("    /* 0x{i:02x} */ None,\n"));
        }
    }
    out.push_str("];\n");

    fs::write(dest_path, out).unwrap();
}
