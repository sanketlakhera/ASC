use asc_core::opcode::OPCODES;
use std::fs;

#[test]
fn test_vendored_header_equals_python_header() {
    let vendored_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/resource/dex_instruction_list.h"
    );
    let python_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../droidasc/asc_core/resource/dex_instruction_list.h"
    );

    let vendored = fs::read(vendored_path).expect("failed to read vendored header");
    let original = fs::read(python_path).expect("failed to read original header");
    assert_eq!(
        vendored, original,
        "vendored dex_instruction_list.h must equal python header byte for byte"
    );
}

#[test]
fn test_opcodes_table_sanity() {
    // 0x00 is nop (len 1)
    let nop = OPCODES[0x00].expect("0x00 nop must be present");
    assert_eq!(nop.name, "nop");
    assert_eq!(nop.len, 1);
    assert_eq!(nop.verify.flag_names(), vec!["kVerifyNothing"]);

    // 0x01 is move (len 1, kVerifyRegA | kVerifyRegB)
    let mov = OPCODES[0x01].expect("0x01 move must be present");
    assert_eq!(mov.name, "move");
    assert_eq!(mov.len, 1);
    assert_eq!(mov.verify.flag_names(), vec!["kVerifyRegA", "kVerifyRegB"]);

    // 0x1a is const-string (len 2, string ref)
    let const_str = OPCODES[0x1a].expect("0x1a const-string must be present");
    assert_eq!(const_str.name, "const-string");
    assert_eq!(const_str.len, 2);

    // Unused byte (e.g. 0x3e) must be None
    assert!(OPCODES[0x3e].is_none());
}
