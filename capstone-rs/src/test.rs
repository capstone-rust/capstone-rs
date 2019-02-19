use super::arch::*;
use super::*;
use capstone_sys::cs_group_type;
use std::collections::HashSet;

const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
const ARM_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

// Aliases for group types
const JUMP: cs_group_type::Type = cs_group_type::CS_GRP_JUMP;
const CALL: cs_group_type::Type = cs_group_type::CS_GRP_CALL;
const RET: cs_group_type::Type = cs_group_type::CS_GRP_RET;
const INT: cs_group_type::Type = cs_group_type::CS_GRP_INT;
const IRET: cs_group_type::Type = cs_group_type::CS_GRP_IRET;

#[test]
fn test_x86_simple() {
    match Capstone::new().x86().mode(x86::ArchMode::Mode64).build() {
        Ok(cs) => match cs.disasm_all(X86_CODE, 0x1000) {
            Ok(insns) => {
                assert_eq!(insns.len(), 2);
                let is: Vec<_> = insns.iter().collect();
                assert_eq!(is[0].mnemonic().unwrap(), "push");
                assert_eq!(is[1].mnemonic().unwrap(), "mov");

                assert_eq!(is[0].address(), 0x1000);
                assert_eq!(is[1].address(), 0x1001);

                assert_eq!(is[0].bytes(), b"\x55");
                assert_eq!(is[1].bytes(), b"\x48\x8b\x05\xb8\x13\x00\x00");
            }
            Err(err) => assert!(false, "Couldn't disasm instructions: {}", err),
        },
        Err(e) => {
            assert!(false, "Couldn't create a cs engine: {}", e);
        }
    }
}

#[test]
fn test_arm_simple() {
    match Capstone::new().arm().mode(arm::ArchMode::Arm).build() {
        Ok(cs) => match cs.disasm_all(ARM_CODE, 0x1000) {
            Ok(insns) => {
                assert_eq!(insns.len(), 2);
                let is: Vec<_> = insns.iter().collect();
                assert_eq!(is[0].mnemonic().unwrap(), "streq");
                assert_eq!(is[1].mnemonic().unwrap(), "strheq");

                assert_eq!(is[0].address(), 0x1000);
                assert_eq!(is[1].address(), 0x1004);
            }
            Err(err) => assert!(false, "Couldn't disasm instructions: {}", err),
        },
        Err(e) => {
            assert!(false, "Couldn't create a cs engine: {}", e);
        }
    }
}

#[test]
fn test_arm64_none() {
    let cs = Capstone::new()
        .arm64()
        .mode(arm64::ArchMode::Arm)
        .build()
        .unwrap();
    assert!(cs.disasm_all(ARM_CODE, 0x1000).unwrap().is_empty());
}

#[test]
fn test_x86_names() {
    match Capstone::new().x86().mode(x86::ArchMode::Mode32).build() {
        Ok(cs) => {
            let reg_id = RegId(1);
            match cs.reg_name(reg_id) {
                Some(reg_name) => assert_eq!(reg_name, "ah"),
                None => assert!(false, "Couldn't get register name"),
            }

            let insn_id = InsnId(1);
            match cs.insn_name(insn_id) {
                Some(insn_name) => assert_eq!(insn_name, "aaa"),
                None => assert!(false, "Couldn't get instruction name"),
            }

            assert_eq!(cs.group_name(InsnGroupId(1)), Some(String::from("jump")));

            let reg_id = RegId(250);
            match cs.reg_name(reg_id) {
                Some(_) => assert!(false, "invalid register worked"),
                None => {}
            }

            let insn_id = InsnId(6000);
            match cs.insn_name(insn_id) {
                Some(_) => assert!(false, "invalid instruction worked"),
                None => {}
            }

            assert_eq!(cs.group_name(InsnGroupId(250)), None);
        }
        Err(e) => {
            assert!(false, "Couldn't create a cs engine: {}", e);
        }
    }
}

#[test]
fn test_detail_false_fail() {
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_detail(false).unwrap();
    let insns = cs.disasm_all(X86_CODE, 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();

    assert_eq!(cs.insn_detail(&insns[0]).unwrap_err(), Error::DetailOff);
    assert_eq!(cs.insn_detail(&insns[1]).unwrap_err(), Error::DetailOff);
}

#[test]
fn test_detail_true() {
    let mut cs1 = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs1.set_detail(true).unwrap();

    let cs2 = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .unwrap();

    for cs in [cs1, cs2].iter_mut() {
        let insns = cs.disasm_all(X86_CODE, 0x1000).unwrap();
        let insns: Vec<_> = insns.iter().collect();
        let insn_group_ids = [
            cs_group_type::CS_GRP_JUMP,
            cs_group_type::CS_GRP_CALL,
            cs_group_type::CS_GRP_RET,
            cs_group_type::CS_GRP_INT,
            cs_group_type::CS_GRP_IRET,
        ];
        for insn_idx in 0..1 + 1 {
            let detail = cs
                .insn_detail(&insns[insn_idx])
                .expect("Unable to get detail");
            let groups: Vec<_> = detail.groups().collect();
            for insn_group_id in &insn_group_ids {
                let insn_group = InsnGroupId(*insn_group_id as InsnGroupIdInt);
                assert_eq!(groups.contains(&insn_group), false);
            }
        }
    }
}

fn test_instruction_helper(
    cs: &Capstone,
    insn: &Insn,
    mnemonic_name: &str,
    bytes: &[u8],
    has_default_syntax: bool,
) {
    println!("{:?}", insn);

    // Check mnemonic
    if has_default_syntax {
        // insn_name() does not respect current syntax
        // does not always match the internal mnemonic
        cs.insn_name(insn.id())
            .expect("Failed to get instruction name");
    }
    assert_eq!(
        mnemonic_name,
        insn.mnemonic().expect("Failed to get mnemonic"),
        "Did not match contained insn.mnemonic"
    );

    // Assert instruction bytes match
    assert_eq!(bytes, insn.bytes());
}

fn test_instruction_detail_helper<T>(
    cs: &Capstone,
    insn: &Insn,
    info: &DetailedInsnInfo<T>,
    has_default_syntax: bool,
) where
    T: Into<ArchOperand> + Clone,
{
    // Check mnemonic
    if has_default_syntax {
        // insn_name() does not respect current syntax
        // does not always match the internal mnemonic
        cs.insn_name(insn.id())
            .expect("Failed to get instruction name");
    }
    assert_eq!(
        info.mnemonic,
        insn.mnemonic().expect("Failed to get mnemonic"),
        "Did not match contained insn.mnemonic"
    );

    // Assert instruction bytes match
    assert_eq!(info.bytes, insn.bytes());

    let detail = cs.insn_detail(insn).expect("Could not get detail");
    let arch_detail = detail.arch_detail();
    let arch_ops = arch_detail.operands();

    let expected_ops: Vec<_> = info
        .operands
        .iter()
        .map(|expected_op| {
            let expected_op: ArchOperand = (*expected_op).clone().into();
            expected_op
        })
        .collect();
    assert_eq!(expected_ops, arch_ops, "operands do not match");
}

/// Assert instruction belongs or does not belong to groups, testing both insn_belongs_to_group
/// and insn_group_ids
fn test_instruction_group_helper<R: Into<u32>>(
    cs: &Capstone,
    insn: &Insn,
    mnemonic_name: &str,
    bytes: &[u8],
    expected_groups: &[cs_group_type::Type],
    expected_regs_read: &[R],
    expected_regs_write: &[R],
    has_default_syntax: bool,
) where
    R: Into<u32> + Copy,
{
    test_instruction_helper(&cs, insn, mnemonic_name, bytes, has_default_syntax);
    let detail = cs.insn_detail(insn).expect("Unable to get detail");

    // Assert expected instruction groups is a subset of computed groups through ids
    let instruction_group_ids: HashSet<InsnGroupId> = detail.groups().collect();
    let expected_groups_ids: HashSet<InsnGroupId> = expected_groups
        .iter()
        .map(|&x| InsnGroupId(x as u8))
        .collect();
    assert!(
        expected_groups_ids.is_subset(&instruction_group_ids),
        "Expected groups {:?} does NOT match computed insn groups {:?} with ",
        expected_groups_ids,
        instruction_group_ids
    );

    // Assert expected instruction groups is a subset of computed groups through enum
    let expected_groups_set: HashSet<InsnGroupId> = expected_groups
        .iter()
        .map(|&x| InsnGroupId(x as u8))
        .collect();
    assert!(
        expected_groups_set.is_subset(&instruction_group_ids),
        "Expected groups {:?} does NOT match computed insn groups {:?}",
        expected_groups_set,
        instruction_group_ids
    );

    macro_rules! assert_regs_match {
        ($expected:expr, $actual_regs:expr, $msg:expr) => {{
            let mut expected_regs: Vec<_> = $expected
                .iter()
                .map(|x| RegId(x.clone().into() as RegIdInt))
                .collect();
            expected_regs.sort_unstable();
            let mut regs: Vec<_> = $actual_regs.collect();
            regs.sort_unstable();
            assert_eq!(expected_regs, regs, $msg);
        }};
    }

    assert_regs_match!(
        expected_regs_read,
        detail.regs_read(),
        "read_regs did not match"
    );
    assert_regs_match!(
        expected_regs_write,
        detail.regs_write(),
        "write_regs did not match"
    );
}

fn instructions_match_group<R>(
    cs: &mut Capstone,
    expected_insns: &[(&str, &[u8], &[cs_group_type::Type], &[R], &[R])],
    has_default_syntax: bool,
) where
    R: Into<u32> + Copy,
{
    let insns_buf: Vec<u8> = expected_insns
        .iter()
        .flat_map(|&(_, bytes, _, _, _)| bytes)
        .map(|x| *x)
        .collect();

    // Details required to get groups information
    cs.set_detail(true).unwrap();

    let insns = cs
        .disasm_all(&insns_buf, 0x1000)
        .expect("Failed to disassemble");
    let insns: Vec<Insn> = insns.iter().collect();

    // Check number of instructions
    assert_eq!(insns.len(), expected_insns.len());

    for (
        insn,
        &(
            expected_mnemonic,
            expected_bytes,
            expected_groups,
            expected_regs_read,
            expected_regs_write,
        ),
    ) in insns.iter().zip(expected_insns)
    {
        test_instruction_group_helper(
            &cs,
            insn,
            expected_mnemonic,
            expected_bytes,
            expected_groups,
            expected_regs_read,
            expected_regs_write,
            has_default_syntax,
        )
    }
}

fn instructions_match(
    cs: &mut Capstone,
    expected_insns: &[(&str, &[u8])],
    has_default_syntax: bool,
) {
    let insns_buf: Vec<u8> = expected_insns
        .iter()
        .flat_map(|&(_, bytes)| bytes)
        .map(|x| *x)
        .collect();

    // Details required to get groups information
    cs.set_detail(true).unwrap();

    let insns = cs
        .disasm_all(&insns_buf, 0x1000)
        .expect("Failed to disassemble");
    let insns: Vec<_> = insns.iter().collect();

    // Check number of instructions
    assert_eq!(
        insns.len(),
        expected_insns.len(),
        "Wrong number of instructions"
    );

    for (insn, &(expected_mnemonic, expected_bytes)) in insns.iter().zip(expected_insns) {
        test_instruction_helper(
            &cs,
            insn,
            expected_mnemonic,
            expected_bytes,
            has_default_syntax,
        )
    }
}

fn instructions_match_detail<T>(
    cs: &mut Capstone,
    info: &[DetailedInsnInfo<T>],
    has_default_syntax: bool,
) where
    T: Into<ArchOperand> + Clone,
{
    let insns_buf: Vec<u8> = info
        .iter()
        .flat_map(|ref info| info.bytes)
        .map(|x| *x)
        .collect();

    // Details required to get groups information
    cs.set_detail(true).unwrap();

    // todo(tmfink) eliminate check
    if info.len() == 0 {
        // Input was empty, which will cause disasm_all() to fail
        return;
    }

    let insns = cs
        .disasm_all(&insns_buf, 0x1000)
        .expect("Failed to disassemble");
    let insns: Vec<_> = insns.iter().collect();

    // Check number of instructions
    assert_eq!(insns.len(), info.len());

    for (insn, info) in insns.iter().zip(info) {
        test_instruction_detail_helper(&cs, insn, info, has_default_syntax)
    }
}

#[test]
fn test_instruction_details() {
    use arch::x86::X86Reg;
    use arch::x86::X86Reg::*;

    let expected_insns: &[(
        &str,
        &[u8],
        &[cs_group_type::Type],
        &[X86Reg::Type],
        &[X86Reg::Type],
    )] = &[
        ("nop", b"\x90", &[], &[], &[]),
        ("je", b"\x74\x05", &[JUMP], &[X86_REG_EFLAGS], &[]),
        (
            "call",
            b"\xe8\x28\x07\x00\x00",
            &[CALL],
            &[X86_REG_RIP, X86_REG_RSP],
            &[X86_REG_RSP],
        ),
        ("ret", b"\xc3", &[RET], &[X86_REG_RSP], &[X86_REG_RSP]),
        ("syscall", b"\x0f\x05", &[INT], &[], &[]),
        ("iretd", b"\xcf", &[IRET], &[], &[]),
        ("sub", b"\x48\x83\xec\x08", &[], &[], &[X86_REG_EFLAGS]),
        ("test", b"\x48\x85\xc0", &[], &[], &[X86_REG_EFLAGS]),
        ("mov", b"\x48\x8b\x05\x95\x4a\x4d\x00", &[], &[], &[]),
        ("mov", b"\xb9\x04\x02\x00\x00", &[], &[], &[]),
    ];

    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    instructions_match_group(&mut cs, expected_insns, true);
}

fn test_insns_match(cs: &mut Capstone, insns: &[(&str, &[u8])]) {
    for &(mnemonic, bytes) in insns.iter() {
        let insns = cs.disasm_all(bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        let insn = insns.iter().next().unwrap();
        assert_eq!(insn.mnemonic(), Some(mnemonic));
    }
}

fn test_extra_mode_helper(
    arch: Arch,
    mode: Mode,
    extra_mode: &[ExtraMode],
    valid_both_insns: &[(&str, &[u8])],
    valid_extra_mode: &[(&str, &[u8])],
) {
    let extra_mode = extra_mode.iter().map(|x| *x);
    let mut cs = Capstone::new_raw(arch, mode, extra_mode, None).unwrap();

    test_insns_match(&mut cs, valid_both_insns);

    for &(_, _) in valid_extra_mode.iter() {
        // Capstone will disassemble instructions not allowed by the current mode
        // assert!(
        //     cs.disasm_all(bytes, 0x1000).is_err(),
        //     "Disassembly succeeded when on instruction when it should not have for {:?}",
        //     bytes);
    }

    test_insns_match(&mut cs, valid_both_insns);
    test_insns_match(&mut cs, valid_extra_mode);
}

#[test]
fn test_extra_mode() {
    test_extra_mode_helper(
        Arch::ARM,
        Mode::Arm,
        &[ExtraMode::V8],
        &[("str", b"\x04\xe0\x2d\xe5")],
        &[("vcvtt.f64.f16", b"\xe0\x3b\xb2\xee")],
    );
}

fn test_arch_mode_endian_insns(
    cs: &mut Capstone,
    arch: Arch,
    mode: Mode,
    endian: Option<Endian>,
    extra_mode: &[ExtraMode],
    insns: &[(&str, &[u8])],
) {
    let expected_insns: Vec<(&str, &[u8])> = insns
        .iter()
        .map(|&(mnemonic, bytes)| (mnemonic, bytes))
        .collect();

    let mut cs_raw =
        Capstone::new_raw(arch, mode, extra_mode.iter().map(|x| *x), endian).unwrap();
    let mut cs_raw_endian_set =
        Capstone::new_raw(arch, mode, extra_mode.iter().map(|x| *x), None).unwrap();
    if let Some(some_endian) = endian {
        cs_raw_endian_set
            .set_endian(some_endian)
            .expect("Failed to set endianness");
    }

    instructions_match(cs, expected_insns.as_slice(), true);
    instructions_match(&mut cs_raw, expected_insns.as_slice(), true);
    instructions_match(&mut cs_raw_endian_set, expected_insns.as_slice(), true);
}

#[derive(Copy, Clone, Debug)]
struct DetailedInsnInfo<'a, T: 'a + Into<ArchOperand>> {
    pub mnemonic: &'a str,
    pub bytes: &'a [u8],
    pub operands: &'a [T],
}
type DII<'a, T> = DetailedInsnInfo<'a, T>;

impl<'a, T> DetailedInsnInfo<'a, T>
where
    T: Into<ArchOperand>,
{
    fn new(mnemonic: &'a str, bytes: &'a [u8], operands: &'a [T]) -> DetailedInsnInfo<'a, T>
    where
        T: Into<ArchOperand>,
    {
        DetailedInsnInfo {
            mnemonic,
            bytes,
            operands,
        }
    }
}

fn test_arch_mode_endian_insns_detail<T>(
    cs: &mut Capstone,
    arch: Arch,
    mode: Mode,
    endian: Option<Endian>,
    extra_mode: &[ExtraMode],
    insns: &[DetailedInsnInfo<T>],
) where
    T: Into<ArchOperand> + Clone,
{
    let extra_mode = extra_mode.iter().map(|x| *x);
    let mut cs_raw = Capstone::new_raw(arch, mode, extra_mode, endian).unwrap();

    instructions_match_detail(&mut cs_raw, insns, true);
    instructions_match_detail(cs, insns, true);
}

#[test]
fn test_syntax() {
    use arch::x86::X86Reg;
    use arch::x86::X86Reg::*;

    let expected_insns: &[(
        &str,
        &str,
        &[u8],
        &[cs_group_type::Type],
        &[X86Reg::Type],
        &[X86Reg::Type],
    )] = &[
        ("nop", "nop", b"\x90", &[], &[], &[]),
        ("je", "je", b"\x74\x05", &[JUMP], &[X86_REG_EFLAGS], &[]),
        (
            "call",
            "callq",
            b"\xe8\x28\x07\x00\x00",
            &[CALL],
            &[X86_REG_RIP, X86_REG_RSP],
            &[X86_REG_RSP],
        ),
        ("ret", "retq", b"\xc3", &[RET], &[X86_REG_RSP], &[X86_REG_RSP]),
        ("syscall", "syscall", b"\x0f\x05", &[INT], &[], &[]),
        ("iretd", "iretl", b"\xcf", &[IRET], &[], &[]),
        (
            "sub",
            "subq",
            b"\x48\x83\xec\x08",
            &[],
            &[],
            &[X86_REG_EFLAGS],
        ),
        (
            "test",
            "testq",
            b"\x48\x85\xc0",
            &[],
            &[],
            &[X86_REG_EFLAGS],
        ),
        (
            "mov",
            "movq",
            b"\x48\x8b\x05\x95\x4a\x4d\x00",
            &[],
            &[],
            &[],
        ),
        ("mov", "movl", b"\xb9\x04\x02\x00\x00", &[], &[], &[]),
    ];

    let expected_insns_intel: Vec<(
        &str,
        &[u8],
        &[cs_group_type::Type],
        &[X86Reg::Type],
        &[X86Reg::Type],
    )> = expected_insns
        .iter()
        .map(|&(mnemonic, _, bytes, groups, reads, writes)| {
            (mnemonic, bytes, groups, reads, writes)
        })
        .collect();
    let expected_insns_att: Vec<(
        &str,
        &[u8],
        &[cs_group_type::Type],
        &[X86Reg::Type],
        &[X86Reg::Type],
    )> = expected_insns
        .iter()
        .map(|&(_, mnemonic, bytes, groups, reads, writes)| {
            (mnemonic, bytes, groups, reads, writes)
        })
        .collect();

    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .syntax(x86::ArchSyntax::Intel)
        .build()
        .unwrap();
    instructions_match_group(&mut cs, &expected_insns_intel, true);

    cs.set_syntax(Syntax::Intel).unwrap();
    instructions_match_group(&mut cs, &expected_insns_intel, true);

    cs.set_syntax(Syntax::Att).unwrap();
    instructions_match_group(&mut cs, &expected_insns_att, false);
}

// @todo(tmfink) test invalid syntax once we check for invalid options
#[test]
fn test_invalid_syntax() {
    // These do no support any syntax change
    let rules = [(Arch::ARM, Mode::Thumb)];
    let syntaxes = [
        // Syntax::Intel,
        // Syntax::Att,
        // Syntax::NoRegName,
    ];

    for &(arch, mode) in rules.iter() {
        let mut cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None).unwrap();
        for &syntax in syntaxes.iter() {
            let result = cs.set_syntax(syntax);
            assert!(result.is_err(), "Expected Err, got {:?}", result);
        }
    }
}

// todo(tmfink): enable test once we test for valid modes
#[test]
#[ignore]
fn test_invalid_mode() {
    if let Err(err) = Capstone::new_raw(Arch::PPC, Mode::Thumb, NO_EXTRA_MODE, None) {
        assert_eq!(err, Error::InvalidMode);
    } else {
        panic!("Should fail to create given modes");
    }
}

#[test]
fn test_capstone_version() {
    let (major, minor) = Capstone::lib_version();
    println!("Capstone lib version: ({}, {})", major, minor);
    assert!(major > 0 && major < 100, "Invalid major version {}", major);
    assert!(minor < 500, "Invalid minor version {}", minor);
}

#[test]
fn test_capstone_supports_arch() {
    let architectures = vec![
        Arch::ARM,
        Arch::ARM64,
        Arch::MIPS,
        Arch::X86,
        Arch::PPC,
        Arch::SPARC,
        Arch::SYSZ,
        Arch::XCORE,
        // Arch::M68K,
    ];

    println!("Supported architectures");
    for arch in architectures {
        let supports_arch = Capstone::supports_arch(arch);
        println!("  {:?}: {}", arch, if supports_arch { "yes" } else { "no" });
    }
}

#[test]
fn test_capstone_is_diet() {
    println!("Capstone is diet: {}", Capstone::is_diet());
}

#[test]
fn test_arch_arm() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Arm)
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Arm,
        None,
        &[],
        &[
            ("bl", b"\xed\xff\xff\xeb"),
            ("str", b"\x04\xe0\x2d\xe5"),
            ("andeq", b"\x00\x00\x00\x00"),
            ("str", b"\xe0\x83\x22\xe5"),
            ("mcreq", b"\xf1\x02\x03\x0e"),
            ("mov", b"\x00\x00\xa0\xe3"),
            ("strb", b"\x02\x30\xc1\xe7"),
            ("cmp", b"\x00\x00\x53\xe3"),
            ("setend", b"\x00\x02\x01\xf1"),
            ("ldm", b"\x05\x40\xd0\xe8"),
            ("strdeq", b"\xf4\x80\x00\x00"),
        ],
    );
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Thumb,
        None,
        &[],
        &[
            ("bx", b"\x70\x47"),
            ("blx", b"\x00\xf0\x10\xe8"),
            ("mov", b"\xeb\x46"),
            ("sub", b"\x83\xb0"),
            ("ldr", b"\xc9\x68"),
            ("cbz", b"\x1f\xb1"),
            ("wfi", b"\x30\xbf"),
            ("cpsie.w", b"\xaf\xf3\x20\x84"),
            ("tbb", b"\xd1\xe8\x00\xf0"),
            ("movs", b"\xf0\x24"),
            ("lsls", b"\x04\x07"),
            ("subs", b"\x1f\x3c"),
            ("stm", b"\xf2\xc0"),
            ("movs", b"\x00\x00"),
            ("mov.w", b"\x4f\xf0\x00\x01"),
            ("ldr", b"\x46\x6c"),
        ],
    );
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Thumb,
        None,
        &[],
        &[
            ("mov.w", b"\x4f\xf0\x00\x01"),
            ("pop.w", b"\xbd\xe8\x00\x88"),
            ("tbb", b"\xd1\xe8\x00\xf0"),
            ("it", b"\x18\xbf"),
            ("iteet", b"\xad\xbf"),
            ("vdupne.8", b"\xf3\xff\x0b\x0c"),
            ("msr", b"\x86\xf3\x00\x89"),
            ("msr", b"\x80\xf3\x00\x8c"),
            ("sxtb.w", b"\x4f\xfa\x99\xf6"),
            ("vaddw.u16", b"\xd0\xff\xa2\x01"),
        ],
    );
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .extra_mode([arm::ArchExtraMode::MClass].iter().map(|x| *x))
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Thumb,
        None,
        &[ExtraMode::MClass],
        &[("mrs", b"\xef\xf3\x02\x80")],
    );
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Arm)
            .extra_mode([arm::ArchExtraMode::V8].iter().map(|x| *x))
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Arm,
        None,
        &[ExtraMode::V8],
        &[
            ("vcvtt.f64.f16", b"\xe0\x3b\xb2\xee"),
            ("crc32b", b"\x42\x00\x01\xe1"),
            ("dmb", b"\x51\xf0\x7f\xf5"),
        ],
    );
}

#[test]
fn test_arch_arm_detail() {
    use arch::arm::ArmOperandType::*;
    use arch::arm::*;
    use capstone_sys::arm_op_mem;

    let r0_op = ArmOperand {
        op_type: Reg(RegId(ArmReg::ARM_REG_R0 as RegIdInt)),
        ..Default::default()
    };

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Arm)
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Arm,
        Some(Endian::Little),
        &[],
        &[
            // bl	#0xfbc
            DII::new(
                "bl",
                b"\xed\xff\xff\xeb",
                &[ArmOperand {
                    op_type: Imm(0xfbc),
                    ..Default::default()
                }],
            ),
            // str     lr, [sp, #-4]!
            DII::new(
                "str",
                b"\x04\xe0\x2d\xe5",
                &[
                    ArmOperand {
                        op_type: Reg(RegId(ArmReg::ARM_REG_LR as RegIdInt)),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Mem(ArmOpMem(arm_op_mem {
                            base: ArmReg::ARM_REG_SP,
                            index: 0,
                            scale: 1,
                            disp: -4,
                            lshift: 0,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // andeq   r0, r0, r0
            DII::new(
                "andeq",
                b"\x00\x00\x00\x00",
                &[r0_op.clone(), r0_op.clone(), r0_op.clone()],
            ),
            // str     r8, [r2, #-0x3e0]!
            DII::new(
                "str",
                b"\xe0\x83\x22\xe5",
                &[
                    ArmOperand {
                        op_type: Reg(RegId(ArmReg::ARM_REG_R8 as RegIdInt)),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Mem(ArmOpMem(arm_op_mem {
                            base: ArmReg::ARM_REG_R2,
                            index: 0,
                            scale: 1,
                            disp: -992,
                            lshift: 0,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // mcreq   p2, #0, r0, c3, c1, #7
            DII::new(
                "mcreq",
                b"\xf1\x02\x03\x0e",
                &[
                    ArmOperand {
                        op_type: Pimm(2),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Imm(0),
                        ..Default::default()
                    },
                    r0_op.clone(),
                    ArmOperand {
                        op_type: Cimm(3),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Cimm(1),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Imm(7),
                        ..Default::default()
                    },
                ],
            ),
            // mov     r0, #0
            DII::new(
                "mov",
                b"\x00\x00\xa0\xe3",
                &[
                    r0_op.clone(),
                    ArmOperand {
                        op_type: Imm(0),
                        ..Default::default()
                    },
                ],
            ),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .build()
            .unwrap(),
        Arch::ARM,
        Mode::Thumb,
        None,
        &[],
        &[DII::new(
            "bx",
            b"\x70\x47",
            &[ArmOperand {
                op_type: Reg(RegId(ArmReg::ARM_REG_LR as RegIdInt)),
                ..Default::default()
            }],
        )],
    );
}

#[test]
fn test_arch_arm64() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .build()
            .unwrap(),
        Arch::ARM64,
        Mode::Arm,
        None,
        &[],
        &[
            ("mrs", b"\x09\x00\x38\xd5"),
            ("msr", b"\xbf\x40\x00\xd5"),
            ("msr", b"\x0c\x05\x13\xd5"),
            ("tbx", b"\x20\x50\x02\x0e"),
            ("scvtf", b"\x20\xe4\x3d\x0f"),
            ("fmla", b"\x00\x18\xa0\x5f"),
            ("fmov", b"\xa2\x00\xae\x9e"),
            ("dsb", b"\x9f\x37\x03\xd5"),
            ("dmb", b"\xbf\x33\x03\xd5"),
            ("isb", b"\xdf\x3f\x03\xd5"),
            ("mul", b"\x21\x7c\x02\x9b"),
            ("lsr", b"\x21\x7c\x00\x53"),
            ("sub", b"\x00\x40\x21\x4b"),
            ("ldr", b"\xe1\x0b\x40\xb9"),
            ("cneg", b"\x20\x04\x81\xda"),
            ("add", b"\x20\x08\x02\x8b"),
            ("ldr", b"\x10\x5b\xe8\x3c"),
        ],
    );
}

#[test]
fn test_arch_arm64_detail() {
    use arch::arm64::Arm64OperandType::*;
    use arch::arm64::Arm64Pstate::*;
    use arch::arm64::Arm64Reg::*;
    use arch::arm64::Arm64Sysreg::*;
    use arch::arm64::Arm64Vas::*;
    use arch::arm64::Arm64Vess::*;
    use arch::arm64::*;
    use capstone_sys::arm64_op_mem;

    let s0 = Arm64Operand {
        op_type: Reg(RegId(ARM64_REG_S0 as RegIdInt)),
        ..Default::default()
    };
    let x0 = Arm64Operand {
        op_type: Reg(RegId(ARM64_REG_X0 as RegIdInt)),
        ..Default::default()
    };
    let x1 = Arm64Operand {
        op_type: Reg(RegId(ARM64_REG_X1 as RegIdInt)),
        ..Default::default()
    };
    let x2 = Arm64Operand {
        op_type: Reg(RegId(ARM64_REG_X2 as RegIdInt)),
        ..Default::default()
    };

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .build()
            .unwrap(),
        Arch::ARM64,
        Mode::Arm,
        None,
        &[],
        &[
            // mrs x9, midr_el1
            DII::new(
                "mrs",
                b"\x09\x00\x38\xd5",
                &[
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_X9 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: RegMrs(ARM64_SYSREG_MIDR_EL1),
                        ..Default::default()
                    },
                ],
            ),
            // msr spsel, #0
            DII::new(
                "msr",
                b"\xbf\x40\x00\xd5",
                &[
                    Arm64Operand {
                        op_type: Pstate(ARM64_PSTATE_SPSEL),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: Imm(0),
                        ..Default::default()
                    },
                ],
            ),
            // tbx  v0.8b, {v1.16b, v2.16b, v3.16b}, v2.8b
            DII::new(
                "tbx",
                b"\x20\x50\x02\x0e",
                &[
                    Arm64Operand {
                        vas: ARM64_VAS_8B,
                        op_type: Reg(RegId(ARM64_REG_V0 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        vas: ARM64_VAS_16B,
                        op_type: Reg(RegId(ARM64_REG_V1 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        vas: ARM64_VAS_16B,
                        op_type: Reg(RegId(ARM64_REG_V2 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        vas: ARM64_VAS_16B,
                        op_type: Reg(RegId(ARM64_REG_V3 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        vas: ARM64_VAS_8B,
                        op_type: Reg(RegId(ARM64_REG_V2 as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // scvtf v0.2s, v1.2s, #3
            DII::new(
                "scvtf",
                b"\x20\xe4\x3d\x0f",
                &[
                    Arm64Operand {
                        vas: ARM64_VAS_2S,
                        op_type: Reg(RegId(ARM64_REG_V0 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        vas: ARM64_VAS_2S,
                        op_type: Reg(RegId(ARM64_REG_V1 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: Imm(3),
                        ..Default::default()
                    },
                ],
            ),
            // fmla s0, s0, v0.s[3]
            DII::new(
                "fmla",
                b"\x00\x18\xa0\x5f",
                &[
                    s0.clone(),
                    s0.clone(),
                    Arm64Operand {
                        vector_index: Some(3),
                        vess: ARM64_VESS_S,
                        op_type: Reg(RegId(ARM64_REG_V0 as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // fmov x2, v5.d[1]
            DII::new(
                "fmov",
                b"\xa2\x00\xae\x9e",
                &[
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_X2 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        vector_index: Some(1),
                        vess: ARM64_VESS_D,
                        op_type: Reg(RegId(ARM64_REG_V5 as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // dsb nsh
            DII::new(
                "dsb",
                b"\x9f\x37\x03\xd5",
                &[Arm64Operand {
                    op_type: Barrier(Arm64BarrierOp::ARM64_BARRIER_NSH),
                    ..Default::default()
                }],
            ),
            // dmb osh
            DII::new(
                "dmb",
                b"\xbf\x33\x03\xd5",
                &[Arm64Operand {
                    op_type: Barrier(Arm64BarrierOp::ARM64_BARRIER_OSH),
                    ..Default::default()
                }],
            ),
            // isb
            DII::new("isb", b"\xdf\x3f\x03\xd5", &[]),
            // mul x1, x1, x2
            DII::new(
                "mul",
                b"\x21\x7c\x02\x9b",
                &[x1.clone(), x1.clone(), x2.clone()],
            ),
            // lsr w1, w1, #0
            DII::new(
                "lsr",
                b"\x21\x7c\x00\x53",
                &[
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_W1 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_W1 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: Imm(0),
                        ..Default::default()
                    },
                ],
            ),
            // sub w0, w0, w1, uxtw
            DII::new(
                "sub",
                b"\x00\x40\x21\x4b",
                &[
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_W0 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_W0 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        ext: Arm64Extender::ARM64_EXT_UXTW,
                        op_type: Reg(RegId(ARM64_REG_W1 as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // ldr w1, [sp, #8]
            DII::new(
                "ldr",
                b"\xe1\x0b\x40\xb9",
                &[
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_W1 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        op_type: Mem(Arm64OpMem(arm64_op_mem {
                            base: ARM64_REG_SP,
                            index: 0,
                            disp: 8,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // cneg x0, x1, ne
            DII::new("cneg", b"\x20\x04\x81\xda", &[x0.clone(), x1.clone()]),
            // add x0, x1, x2, lsl #2
            DII::new(
                "add",
                b"\x20\x08\x02\x8b",
                &[
                    x0.clone(),
                    x1.clone(),
                    Arm64Operand {
                        shift: Arm64Shift::Lsl(2),
                        ..x2
                    },
                ],
            ),
            // ldr q16, [x24, w8, uxtw #4]
            DII::new(
                "ldr",
                b"\x10\x5b\xe8\x3c",
                &[
                    Arm64Operand {
                        op_type: Reg(RegId(ARM64_REG_Q16 as RegIdInt)),
                        ..Default::default()
                    },
                    Arm64Operand {
                        shift: Arm64Shift::Lsl(4),
                        ext: Arm64Extender::ARM64_EXT_UXTW,
                        op_type: Mem(Arm64OpMem(arm64_op_mem {
                            base: ARM64_REG_X24,
                            index: ARM64_REG_W8,
                            disp: 0,
                        })),
                        ..Default::default()
                    },
                ],
            ),
        ],
    );
}

#[test]
fn test_arch_evm() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .evm()
            .mode(evm::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::EVM,
        Mode::Default,
        None,
        &[],
        &[("push1", b"\x60\x61"), ("pop", b"\x50")],
    );
}

#[test]
fn test_arch_mips() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mips()
            .mode(mips::ArchMode::Mips32R6)
            .build()
            .unwrap(),
        Arch::MIPS,
        Mode::Mips32R6,
        Some(Endian::Little),
        &[],
        &[("ori", b"\x56\x34\x21\x34"), ("srl", b"\xc2\x17\x01\x00")],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mips()
            .mode(mips::ArchMode::Mips32R6)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::MIPS,
        Mode::Mips32R6,
        Some(Endian::Big),
        &[],
        &[
            ("ori", b"\x34\x21\x34\x56"),
            ("jal", b"\x0C\x10\x00\x97"),
            ("nop", b"\x00\x00\x00\x00"),
            ("addiu", b"\x24\x02\x00\x0c"),
            ("lw", b"\x8f\xa2\x00\x00"),
            ("ori", b"\x34\x21\x34\x56"),
        ],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mips()
            .mode(mips::ArchMode::Mips32R6)
            .extra_mode([mips::ArchExtraMode::Micro].iter().map(|x| *x))
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::MIPS,
        Mode::Mips32R6,
        Some(Endian::Big),
        &[ExtraMode::Micro],
        &[
            ("break", b"\x00\x07\x00\x07"),
            ("wait", b"\x00\x11\x93\x7c"),
            ("syscall", b"\x01\x8c\x8b\x7c"),
            ("rotrv", b"\x00\xc7\x48\xd0"),
        ],
    );
}

#[test]
fn test_arch_mips_detail() {
    use arch::mips::MipsOperand::*;
    use arch::mips::*;
    use capstone_sys::mips_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .mips()
            .mode(mips::ArchMode::Mips32R6)
            .build()
            .unwrap(),
        Arch::MIPS,
        Mode::Mips32R6,
        Some(Endian::Little),
        &[],
        &[
            DII::new(
                "ori",
                b"\x56\x34\x21\x34",
                &[Reg(RegId(3)), Reg(RegId(3)), Imm(13398)],
            ),
            DII::new(
                "srl",
                b"\xc2\x17\x01\x00",
                &[Reg(RegId(4)), Reg(RegId(3)), Imm(31)],
            ),
            DII::new("syscall", b"\x0c\x00\x00\x00", &[]),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .mips()
            .mode(mips::ArchMode::Mips32R6)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::MIPS,
        Mode::Mips32R6,
        Some(Endian::Big),
        &[],
        &[DII::new(
            "lw",
            b"\x8f\xa2\x00\x00",
            &[
                Reg(RegId(MipsReg::MIPS_REG_V0 as RegIdInt)),
                Mem(MipsOpMem(mips_op_mem {
                    base: MipsReg::MIPS_REG_SP,
                    disp: 0,
                })),
            ],
        )],
    );
}

#[test]
fn test_arch_ppc() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .ppc()
            .mode(ppc::ArchMode::Mode32)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::PPC,
        // Mode::Mode32,
        Mode::Default,
        Some(Endian::Big),
        &[],
        &[
            ("bdnzla+", b"\x43\x20\x0c\x07"),
            ("bdztla", b"\x41\x56\xff\x17"),
            ("lwz", b"\x80\x20\x00\x00"),
            ("lwz", b"\x80\x3f\x00\x00"),
            ("vpkpx", b"\x10\x43\x23\x0e"),
            ("stfs", b"\xd0\x44\x00\x80"),
            ("crand", b"\x4c\x43\x22\x02"),
            ("cmpwi", b"\x2d\x03\x00\x80"),
            ("addc", b"\x7c\x43\x20\x14"),
            ("mulhd.", b"\x7c\x43\x20\x93"),
            ("bdnzlrl+", b"\x4f\x20\x00\x21"),
            ("bgelrl-", b"\x4c\xc8\x00\x21"),
            ("bne", b"\x40\x82\x00\x14"),
        ],
    );
}

#[test]
fn test_arch_ppc_detail() {
    use arch::ppc::PpcOperand::*;
    use arch::ppc::PpcReg::*;
    use arch::ppc::*;
    use capstone_sys::ppc_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .ppc()
            .mode(ppc::ArchMode::Mode64)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::PPC,
        Mode::Mode64,
        Some(Endian::Big),
        &[],
        &[
            // lwz     r1, 0(0)
            DII::new(
                "lwz",
                b"\x80\x20\x00\x00",
                &[
                    Reg(RegId(PPC_REG_R1 as RegIdInt)),
                    Mem(PpcOpMem(ppc_op_mem { base: 44, disp: 0 })),
                ],
            ),
            // lwz     r1, 0(r31)
            DII::new(
                "lwz",
                b"\x80\x3f\x00\x00",
                &[
                    Reg(RegId(PPC_REG_R1 as RegIdInt)),
                    Mem(PpcOpMem(ppc_op_mem {
                        base: PPC_REG_R31,
                        disp: 0,
                    })),
                ],
            ),
            // vpkpx   v2, v3, v4
            DII::new(
                "vpkpx",
                b"\x10\x43\x23\x0e",
                &[
                    Reg(RegId(PPC_REG_V2 as RegIdInt)),
                    Reg(RegId(PPC_REG_V3 as RegIdInt)),
                    Reg(RegId(PPC_REG_V4 as RegIdInt)),
                ],
            ),
            // stfs    f2, 0x80(r4)
            DII::new(
                "stfs",
                b"\xd0\x44\x00\x80",
                &[
                    Reg(RegId(PPC_REG_F2 as RegIdInt)),
                    Mem(PpcOpMem(ppc_op_mem {
                        base: PPC_REG_R4,
                        disp: 0x80,
                    })),
                ],
            ),
            // crand   2, 3, 4
            DII::new(
                "crand",
                b"\x4c\x43\x22\x02",
                &[
                    Reg(RegId(PPC_REG_R2 as RegIdInt)),
                    Reg(RegId(PPC_REG_R3 as RegIdInt)),
                    Reg(RegId(PPC_REG_R4 as RegIdInt)),
                ],
            ),
            // cmpwi   cr2, r3, 0x80
            DII::new(
                "cmpwi",
                b"\x2d\x03\x00\x80",
                &[
                    Reg(RegId(PPC_REG_CR2 as RegIdInt)),
                    Reg(RegId(PPC_REG_R3 as RegIdInt)),
                    Imm(0x80),
                ],
            ),
            // addc    r2, r3, r4
            DII::new(
                "addc",
                b"\x7c\x43\x20\x14",
                &[
                    Reg(RegId(PPC_REG_R2 as RegIdInt)),
                    Reg(RegId(PPC_REG_R3 as RegIdInt)),
                    Reg(RegId(PPC_REG_R4 as RegIdInt)),
                ],
            ),
            // mulhd.  r2, r3, r4
            DII::new(
                "mulhd.",
                b"\x7c\x43\x20\x93",
                &[
                    Reg(RegId(PPC_REG_R2 as RegIdInt)),
                    Reg(RegId(PPC_REG_R3 as RegIdInt)),
                    Reg(RegId(PPC_REG_R4 as RegIdInt)),
                ],
            ),
            // bdnzlrl+
            DII::new("bdnzlrl+", b"\x4f\x20\x00\x21", &[]),
            // bgelrl- cr2
            DII::new(
                "bgelrl-",
                b"\x4c\xc8\x00\x21",
                &[Reg(RegId(PPC_REG_CR2 as RegIdInt))],
            ),
        ],
    );
}

#[test]
fn test_arch_sparc() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::Default,
        None,
        &[],
        &[
            ("cmp", b"\x80\xa0\x40\x02"),
            ("jmpl", b"\x85\xc2\x60\x08"),
            ("restore", b"\x85\xe8\x20\x01"),
            ("restore", b"\x81\xe8\x00\x00"),
            ("mov", b"\x90\x10\x20\x01"),
            ("casx", b"\xd5\xf6\x10\x16"),
            ("sethi", b"\x21\x00\x00\x0a"),
            ("add", b"\x86\x00\x40\x02"),
            ("nop", b"\x01\x00\x00\x00"),
            ("bne", b"\x12\xbf\xff\xff"),
            ("ba", b"\x10\xbf\xff\xff"),
            ("add", b"\xa0\x02\x00\x09"),
            ("fbg", b"\x0d\xbf\xff\xff"),
            ("st", b"\xd4\x20\x60\x00"),
            ("ldsb", b"\xd4\x4e\x00\x16"),
            ("brnz,a,pn", b"\x2a\xc2\x80\x03"),
        ],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::V9)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::V9,
        Some(Endian::Big),
        &[],
        &[
            ("fcmps", b"\x81\xa8\x0a\x24"),
            ("fstox", b"\x89\xa0\x10\x20"),
            ("fqtoi", b"\x89\xa0\x1a\x60"),
            ("fnegq", b"\x89\xa0\x00\xe0"),
        ],
    );
}

#[test]
fn test_arch_sparc_detail() {
    use arch::sparc::SparcOperand::*;
    use arch::sparc::SparcReg::*;
    use arch::sparc::*;
    use capstone_sys::sparc_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::Default,
        None,
        &[],
        &[
            // cmp     %g1, %g2
            DII::new(
                "cmp",
                b"\x80\xa0\x40\x02",
                &[
                    Reg(RegId(SPARC_REG_G1 as RegIdInt)),
                    Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                ],
            ),
            // jmpl    %o1+8, %g2
            DII::new(
                "jmpl",
                b"\x85\xc2\x60\x08",
                &[
                    Mem(SparcOpMem(sparc_op_mem {
                        base: SPARC_REG_O1 as u8,
                        index: 0,
                        disp: 8,
                    })),
                    Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                ],
            ),
            // restore %g0, 1, %g2
            DII::new(
                "restore",
                b"\x85\xe8\x20\x01",
                &[
                    Reg(RegId(SPARC_REG_G0 as RegIdInt)),
                    Imm(1),
                    Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                ],
            ),
            // mov     1, %o0
            DII::new(
                "mov",
                b"\x90\x10\x20\x01",
                &[Imm(1), Reg(RegId(SPARC_REG_O0 as RegIdInt))],
            ),
            // casx    [%i0], %l6, %o2
            DII::new(
                "casx",
                b"\xd5\xf6\x10\x16",
                &[
                    Mem(SparcOpMem(sparc_op_mem {
                        base: SPARC_REG_I0 as u8,
                        index: 0,
                        disp: 0,
                    })),
                    Reg(RegId(SPARC_REG_L6 as RegIdInt)),
                    Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                ],
            ),
            // sethi   0xa, %l0
            DII::new(
                "sethi",
                b"\x21\x00\x00\x0a",
                &[Imm(0xa), Reg(RegId(SPARC_REG_L0 as RegIdInt))],
            ),
            // add     %g1, %g2, %g3
            DII::new(
                "add",
                b"\x86\x00\x40\x02",
                &[
                    Reg(RegId(SPARC_REG_G1 as RegIdInt)),
                    Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                    Reg(RegId(SPARC_REG_G3 as RegIdInt)),
                ],
            ),
            // nop
            DII::new("nop", b"\x01\x00\x00\x00", &[]),
            // bne     0x1020
            DII::new("bne", b"\x12\xbf\xff\xff", &[Imm(0x101c)]),
            // ba      0x1024
            DII::new("ba", b"\x10\xbf\xff\xff", &[Imm(0x1020)]),
            // add     %o0, %o1, %l0
            DII::new(
                "add",
                b"\xa0\x02\x00\x09",
                &[
                    Reg(RegId(SPARC_REG_O0 as RegIdInt)),
                    Reg(RegId(SPARC_REG_O1 as RegIdInt)),
                    Reg(RegId(SPARC_REG_L0 as RegIdInt)),
                ],
            ),
            // fbg     0x102c
            DII::new("fbg", b"\x0d\xbf\xff\xff", &[Imm(0x1028)]),
            // st      %o2, [%g1]
            DII::new(
                "st",
                b"\xd4\x20\x60\x00",
                &[
                    Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                    Mem(SparcOpMem(sparc_op_mem {
                        base: SPARC_REG_G1 as u8,
                        index: 0,
                        disp: 0,
                    })),
                ],
            ),
            // ldsb    [%i0+%l6], %o2
            DII::new(
                "ldsb",
                b"\xd4\x4e\x00\x16",
                &[
                    Mem(SparcOpMem(sparc_op_mem {
                        base: SPARC_REG_I0 as u8,
                        index: SPARC_REG_L6 as u8,
                        disp: 0,
                    })),
                    Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                ],
            ),
            // brnz,a,pn       %o2, 0x1048
            DII::new(
                "brnz,a,pn",
                b"\x2a\xc2\x80\x03",
                &[Reg(RegId(SPARC_REG_O2 as RegIdInt)), Imm(0x1044)],
            ),
        ],
    );

    let f0_f4 = [
        Reg(RegId(SPARC_REG_F0 as RegIdInt)),
        Reg(RegId(SPARC_REG_F4 as RegIdInt)),
    ];

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::V9)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::V9,
        None,
        &[],
        &[
            // fcmps   %f0, %f4
            DII::new("fcmps", b"\x81\xa8\x0a\x24", &f0_f4),
            // fstox   %f0, %f4
            DII::new("fstox", b"\x89\xa0\x10\x20", &f0_f4),
            // fqtoi   %f0, %f4
            DII::new("fqtoi", b"\x89\xa0\x1a\x60", &f0_f4),
            // fnegq   %f0, %f4
            DII::new("fnegq", b"\x89\xa0\x00\xe0", &f0_f4),
        ],
    );
}

#[test]
fn test_arch_systemz() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .sysz()
            .mode(sysz::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::SYSZ,
        Mode::Default,
        None,
        &[],
        &[
            ("adb", b"\xed\x00\x00\x00\x00\x1a"),
            ("a", b"\x5a\x0f\x1f\xff"),
            ("afi", b"\xc2\x09\x80\x00\x00\x00"),
            ("br", b"\x07\xf7"),
            ("xiy", b"\xeb\x2a\xff\xff\x7f\x57"),
            ("xy", b"\xe3\x01\xff\xff\x7f\x57"),
            ("stmg", b"\xeb\x00\xf0\x00\x00\x24"),
            ("ear", b"\xb2\x4f\x00\x78"),
            ("clije", b"\xec\x18\x00\x00\xc1\x7f"),
        ],
    );
}

#[test]
fn test_arch_x86() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode16)
            .build()
            .unwrap(),
        Arch::X86,
        Mode::Mode16,
        None,
        &[],
        &[
            ("lea", b"\x8d\x4c\x32"),
            ("or", b"\x08\x01"),
            ("fadd", b"\xd8\x81\xc6\x34"),
            ("adc", b"\x12\x00"),
            ("add", b"\x00\x05"),
            ("and", b"\x23\x01"),
            ("add", b"\x00\x00"),
            ("mov", b"\x36\x8b\x84\x91\x23"),
            ("add", b"\x01\x00"),
            ("add", b"\x00\x41\x8d"),
            ("test", b"\x84\x39"),
            ("mov", b"\x89\x67\x00"),
            ("add", b"\x00\x8d\x87\x89"),
            ("add", b"\x67\x00\x00"),
            ("mov", b"\xb4\xc6"),
        ],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode32)
            .build()
            .unwrap(),
        Arch::X86,
        Mode::Mode32,
        None,
        &[],
        &[
            ("lea", b"\x8d\x4c\x32\x08"),
            ("add", b"\x01\xd8"),
            ("add", b"\x81\xc6\x34\x12\x00\x00"),
            ("add", b"\x05\x23\x01\x00\x00"),
            ("mov", b"\x36\x8b\x84\x91\x23\x01\x00\x00"),
            ("inc", b"\x41"),
            ("lea", b"\x8d\x84\x39\x89\x67\x00\x00"),
            ("lea", b"\x8d\x87\x89\x67\x00\x00"),
            ("mov", b"\xb4\xc6"),
        ],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode64)
            .build()
            .unwrap(),
        Arch::X86,
        Mode::Mode64,
        None,
        &[],
        &[("push", b"\x55"), ("mov", b"\x48\x8b\x05\xb8\x13\x00\x00")],
    );
}

#[test]
fn test_arch_x86_detail() {
    use arch::x86::X86OperandType::*;
    use arch::x86::X86Reg::*;
    use arch::x86::*;
    use capstone_sys::*;

    // X86 16bit (Intel syntax)
    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode16)
            .build()
            .unwrap(),
        Arch::X86,
        Mode::Mode16,
        None,
        &[],
        &[
            // lea     cx, word ptr [si + 0x32]
            DII::new(
                "lea",
                b"\x8d\x4c\x32",
                &[
                    X86Operand {
                        size: 2,
                        op_type: Reg(RegId(X86_REG_CX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 2,
                        op_type: Mem(X86OpMem(x86_op_mem {
                            segment: 0,
                            base: X86_REG_SI,
                            index: 0,
                            scale: 1,
                            disp: 0x32,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // or      byte ptr [bx + di], al
            DII::new(
                "or",
                b"\x08\x01",
                &[
                    X86Operand {
                        size: 1,
                        op_type: Mem(X86OpMem(x86_op_mem {
                            segment: 0,
                            base: X86_REG_BX,
                            index: X86_REG_DI,
                            scale: 1,
                            disp: 0,
                        })),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 1,
                        op_type: Reg(RegId(X86_REG_AL as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // fadd    dword ptr [bx + di + 0x34c6]
            DII::new(
                "fadd",
                b"\xd8\x81\xc6\x34",
                &[X86Operand {
                    size: 4,
                    op_type: Mem(X86OpMem(x86_op_mem {
                        segment: 0,
                        base: X86_REG_BX,
                        index: X86_REG_DI,
                        scale: 1,
                        disp: 0x34c6,
                    })),
                    ..Default::default()
                }],
            ),
            // adc     al, byte ptr [bx + si]
            DII::new(
                "adc",
                b"\x12\x00",
                &[
                    X86Operand {
                        size: 1,
                        op_type: Reg(RegId(X86_REG_AL as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 1,
                        op_type: Mem(X86OpMem(x86_op_mem {
                            segment: 0,
                            base: X86_REG_BX,
                            index: X86_REG_SI,
                            scale: 1,
                            disp: 0,
                        })),
                        ..Default::default()
                    },
                ],
            ),
        ],
    );

    // X86 32bit
    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode32)
            .build()
            .unwrap(),
        Arch::X86,
        Mode::Mode32,
        None,
        &[],
        &[
            // leal    8(%edx, %esi), %ecx
            DII::new(
                "lea",
                b"\x8d\x4c\x32\x08",
                &[
                    X86Operand {
                        size: 4,
                        op_type: Reg(RegId(X86_REG_ECX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 4,
                        op_type: Mem(X86OpMem(x86_op_mem {
                            segment: 0,
                            base: X86_REG_EDX,
                            index: X86_REG_ESI,
                            scale: 1,
                            disp: 8,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // addl    %ebx, %eax
            DII::new(
                "add",
                b"\x01\xd8",
                &[
                    X86Operand {
                        size: 4,
                        op_type: Reg(RegId(X86_REG_EAX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 4,
                        op_type: Reg(RegId(X86_REG_EBX as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // addl    $0x1234, %esi
            DII::new(
                "add",
                b"\x81\xc6\x34\x12\x00\x00",
                &[
                    X86Operand {
                        size: 4,
                        op_type: Reg(RegId(X86_REG_ESI as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 4,
                        op_type: Imm(0x1234),
                        ..Default::default()
                    },
                ],
            ),
        ],
    );

    // X86 64
    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode64)
            .build()
            .unwrap(),
        Arch::X86,
        Mode::Mode64,
        None,
        &[],
        &[
            // push    rbp
            DII::new(
                "push",
                b"\x55",
                &[X86Operand {
                    size: 8,
                    op_type: Reg(RegId(X86_REG_RBP as RegIdInt)),
                    ..Default::default()
                }],
            ),
            // mov     rax, qword ptr [rip + 0x13b8]
            DII::new(
                "mov",
                b"\x48\x8b\x05\xb8\x13\x00\x00",
                &[
                    X86Operand {
                        size: 8,
                        op_type: Reg(RegId(X86_REG_RAX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 8,
                        op_type: Mem(X86OpMem(x86_op_mem {
                            segment: 0,
                            base: X86_REG_RIP,
                            index: 0,
                            scale: 1,
                            disp: 0x13b8,
                        })),
                        ..Default::default()
                    },
                ],
            ),
        ],
    );
}

#[test]
fn test_arch_xcore() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .xcore()
            .mode(xcore::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::XCORE,
        Mode::Default,
        None,
        &[],
        &[
            ("get", b"\xfe\x0f"),
            ("ldw", b"\xfe\x17"),
            ("setd", b"\x13\x17"),
            ("init", b"\xc6\xfe\xec\x17"),
            ("divu", b"\x97\xf8\xec\x4f"),
            ("lda16", b"\x1f\xfd\xec\x37"),
            ("ldw", b"\x07\xf2\x45\x5b"),
            ("lmul", b"\xf9\xfa\x02\x06"),
            ("add", b"\x1b\x10"),
            ("ldaw", b"\x09\xfd\xec\xa7"),
        ],
    );
}

// XXX todo(tmfink) investigate upstream xcore operand bugs
#[test]
fn test_arch_xcore_detail() {
    use arch::xcore::XcoreOperand::*;
    use arch::xcore::XcoreReg::*;
    use arch::xcore::*;
    use capstone_sys::xcore_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .xcore()
            .mode(xcore::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::XCORE,
        Mode::Default,
        None,
        &[],
        &[
            // get     r11, ed
            DII::new(
                "get",
                b"\xfe\x0f",
                &[
                    Reg(RegId(XCORE_REG_R11 as RegIdInt)),
                    Reg(RegId(XCORE_REG_ED as RegIdInt)),
                ],
            ),
            // ldw     et, sp[4]
            DII::new(
                "ldw",
                b"\xfe\x17",
                &[
                    Reg(RegId(XCORE_REG_ET as RegIdInt)),
                    Mem(XcoreOpMem(xcore_op_mem {
                        base: XCORE_REG_SP as u8,
                        index: XCORE_REG_INVALID as u8,
                        disp: 4,
                        direct: 1,
                    })),
                ],
            ),
            // setd    res[r3], r4
            DII::new("setd", b"\x13\x17", &[Reg(RegId(XCORE_REG_R4 as RegIdInt))]),
            // init    t[r2]:lr, r1
            DII::new(
                "init",
                b"\xc6\xfe\xec\x17",
                &[
                    Mem(XcoreOpMem(xcore_op_mem {
                        base: XCORE_REG_R2 as u8,
                        index: XCORE_REG_LR as u8,
                        disp: 0,
                        direct: 1,
                    })),
                    Reg(RegId(XCORE_REG_R1 as RegIdInt)),
                ],
            ),
            // divu    r9, r1, r3
            DII::new(
                "divu",
                b"\x97\xf8\xec\x4f",
                &[
                    Reg(RegId(XCORE_REG_R9 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R1 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R3 as RegIdInt)),
                ],
            ),
            // lda16   r9, r3[-r11]
            DII::new(
                "lda16",
                b"\x1f\xfd\xec\x37",
                &[Reg(RegId(XCORE_REG_R9 as RegIdInt))],
            ),
            // ldw     dp, dp[0x81c5]
            DII::new(
                "ldw",
                b"\x07\xf2\x45\x5b",
                &[Reg(RegId(XCORE_REG_DP as RegIdInt))],
            ),
            // lmul    r11, r0, r2, r5, r8, r10
            DII::new(
                "lmul",
                b"\xf9\xfa\x02\x06",
                &[
                    Reg(RegId(XCORE_REG_R11 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R0 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R2 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R5 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R8 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R10 as RegIdInt)),
                ],
            ),
            // add     r1, r2, r3
            DII::new(
                "add",
                b"\x1b\x10",
                &[
                    Reg(RegId(XCORE_REG_R1 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R2 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R3 as RegIdInt)),
                ],
            ),
            // add     r0, r8, 9
            DII::new(
                "add",
                b"\x01\x96",
                &[
                    Reg(RegId(XCORE_REG_R0 as RegIdInt)),
                    Reg(RegId(XCORE_REG_R8 as RegIdInt)),
                    Imm(9),
                ],
            ),
        ],
    );
}
