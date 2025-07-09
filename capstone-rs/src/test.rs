#![allow(
    clippy::approx_constant,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::upper_case_acronyms
)]

use core::ffi::c_uint;
use core::{convert::TryInto, fmt::Debug, mem::MaybeUninit};

use alloc::vec::Vec;
#[cfg(feature = "full")]
use {alloc::string::String, std::collections::HashSet};

use capstone_sys::cs_group_type;
use pretty_assertions::assert_eq;

use super::arch::*;
use super::*;

const X86_CODE: &[u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
const ARM_CODE: &[u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
const CBPF_CODE: &[u8] = b"\x94\x09\x00\x00\x37\x13\x03\x00\
                          \x87\x00\x00\x00\x00\x00\x00\x00\
                          \x07\x00\x00\x00\x00\x00\x00\x00\
                          \x16\x00\x00\x00\x00\x00\x00\x00\
                          \x80\x00\x00\x00\x00\x00\x00\x00";
const EBPF_CODE: &[u8] = b"\x97\x09\x00\x00\x37\x13\x03\x00\
                        \xdc\x02\x00\x00\x20\x00\x00\x00\
                        \x30\x00\x00\x00\x00\x00\x00\x00\
                        \xdb\x3a\x00\x01\x00\x00\x00\x00\
                        \x84\x02\x00\x00\x00\x00\x00\x00\
                        \x6d\x33\x17\x02\x00\x00\x00\x00";

// Aliases for group types
const JUMP: cs_group_type::Type = cs_group_type::CS_GRP_JUMP;
const CALL: cs_group_type::Type = cs_group_type::CS_GRP_CALL;
const RET: cs_group_type::Type = cs_group_type::CS_GRP_RET;
const INT: cs_group_type::Type = cs_group_type::CS_GRP_INT;
const IRET: cs_group_type::Type = cs_group_type::CS_GRP_IRET;

/// Used as start address for testing
const START_TEST_ADDR: u64 = 0x1000;

#[cfg(feature = "arch_x86")]
#[test]
fn test_x86_simple() {
    match Capstone::new().x86().mode(x86::ArchMode::Mode64).build() {
        Ok(cs) => match cs.disasm_all(X86_CODE, START_TEST_ADDR) {
            Ok(insns) => {
                assert_eq!(insns.len(), 2);
                let is: Vec<_> = insns.iter().collect();
                #[cfg(feature = "full")]
                {
                    assert_eq!(is[0].mnemonic().unwrap(), "push");
                    assert_eq!(is[1].mnemonic().unwrap(), "mov");
                }
                assert_eq!(is[0].address(), START_TEST_ADDR);
                assert_eq!(is[1].address(), START_TEST_ADDR + 1);

                assert_eq!(is[0].bytes(), b"\x55");
                assert_eq!(is[1].bytes(), b"\x48\x8b\x05\xb8\x13\x00\x00");
            }
            Err(err) => panic!("Couldn't disasm instructions: {}", err),
        },
        Err(e) => {
            panic!("Couldn't create a cs engine: {}", e);
        }
    }
}

#[cfg(feature = "arch_arm")]
#[test]
fn test_arm_simple() {
    match Capstone::new().arm().mode(arm::ArchMode::Arm).build() {
        Ok(cs) => match cs.disasm_all(ARM_CODE, START_TEST_ADDR) {
            Ok(insns) => {
                assert_eq!(insns.len(), 2);
                let is: Vec<_> = insns.iter().collect();
                #[cfg(feature = "full")]
                {
                    assert_eq!(is[0].mnemonic().unwrap(), "streq");
                    assert_eq!(is[1].mnemonic().unwrap(), "strheq");
                }
                assert_eq!(is[0].address(), START_TEST_ADDR);
                assert_eq!(is[1].address(), START_TEST_ADDR + 4);
            }
            Err(err) => panic!("Couldn't disasm instructions: {}", err),
        },
        Err(e) => {
            panic!("Couldn't create a cs engine: {}", e);
        }
    }
}

#[cfg(feature = "arch_aarch64")]
#[test]
fn test_aarch64_none() {
    let cs = Capstone::new()
        .aarch64()
        .mode(aarch64::ArchMode::Arm)
        .build()
        .unwrap();
    assert!(cs.disasm_all(ARM_CODE, START_TEST_ADDR).unwrap().is_empty());
}

#[cfg(all(feature = "full", feature = "arch_x86"))]
#[test]
fn test_x86_names() {
    match Capstone::new().x86().mode(x86::ArchMode::Mode32).build() {
        Ok(cs) => {
            let reg_id = RegId(1);
            match cs.reg_name(reg_id) {
                Some(reg_name) => assert_eq!(reg_name, "ah"),
                None => panic!("Couldn't get register name"),
            }

            let insn_id = InsnId(1);
            match cs.insn_name(insn_id) {
                Some(insn_name) => assert_eq!(insn_name, "aaa"),
                None => panic!("Couldn't get instruction name"),
            }

            assert_eq!(cs.group_name(InsnGroupId(1)), Some(String::from("jump")));

            let reg_id = RegId(250);
            if cs.reg_name(reg_id).is_some() {
                panic!("invalid register worked")
            }

            let insn_id = InsnId(6000);
            if cs.insn_name(insn_id).is_some() {
                panic!("invalid instruction worked")
            }

            assert_eq!(cs.group_name(InsnGroupId(250)), None);
        }
        Err(e) => {
            panic!("Couldn't create a cs engine: {}", e);
        }
    }
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_detail_false_fail() {
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_detail(false).unwrap();
    let insns = cs.disasm_all(X86_CODE, START_TEST_ADDR).unwrap();
    let insns: Vec<_> = insns.iter().collect();

    assert_eq!(cs.insn_detail(insns[0]).unwrap_err(), Error::DetailOff);
    assert_eq!(cs.insn_detail(insns[1]).unwrap_err(), Error::DetailOff);
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_skipdata() {
    use capstone_sys::x86_insn;

    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_detail(false).unwrap();
    cs.set_skipdata(true).unwrap();

    let x86_code_skip: &[u8] = b"\x2f\x6c";

    let insns = cs.disasm_all(x86_code_skip, 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();
    assert_eq!(insns.len(), 2);
    assert_eq!(insns[0].id().0, x86_insn::X86_INS_INVALID as u32);
    assert_eq!(insns[1].id().0, x86_insn::X86_INS_INSB as u32);
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_unsigned() {
    // default is signed
    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();

    let insns = cs.disasm_all(b"\x66\x83\xc0\x80", 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].op_str(), Some("ax, -0x80"));

    // this time with unsigned operand
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_unsigned(true).unwrap();

    let insns = cs.disasm_all(b"\x66\x83\xc0\x80", 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].op_str(), Some("ax, 0xff80"));
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_mnemonic() {
    use capstone_sys::x86_insn;

    let x86_code: &[u8] = b"\x6c";

    // default mnemonic
    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    let insns = cs.disasm_all(x86_code, 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].id().0, x86_insn::X86_INS_INSB as u32);
    assert_eq!(insns[0].mnemonic(), Some("insb"));

    // override mnemonic
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_mnemonic(InsnId(x86_insn::X86_INS_INSB as InsnIdInt), Some("abcd"))
        .unwrap();
    let insns = cs.disasm_all(x86_code, 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].id().0, x86_insn::X86_INS_INSB as u32);
    assert_eq!(insns[0].mnemonic(), Some("abcd"));

    // revert override
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_mnemonic(InsnId(x86_insn::X86_INS_INSB as InsnIdInt), Some("abcd"))
        .unwrap();
    cs.set_mnemonic(InsnId(x86_insn::X86_INS_INSB as InsnIdInt), None)
        .unwrap();
    let insns = cs.disasm_all(x86_code, 0x1000).unwrap();
    let insns: Vec<_> = insns.iter().collect();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].id().0, x86_insn::X86_INS_INSB as u32);
    assert_eq!(insns[0].mnemonic(), Some("insb"));

    // override with invalid mnemonic should fail
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    assert!(cs
        .set_mnemonic(
            InsnId(x86_insn::X86_INS_INSB as InsnIdInt),
            Some("\x00abcd")
        )
        .is_err());
}

#[cfg(all(feature = "full", feature = "arch_x86"))]
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
        let insns = cs.disasm_all(X86_CODE, START_TEST_ADDR).unwrap();
        let insns: Vec<_> = insns.iter().collect();
        let insn_group_ids = [
            cs_group_type::CS_GRP_JUMP,
            cs_group_type::CS_GRP_CALL,
            cs_group_type::CS_GRP_RET,
            cs_group_type::CS_GRP_INT,
            cs_group_type::CS_GRP_IRET,
        ];
        for insn in insns.iter() {
            let detail = cs.insn_detail(insn).expect("Unable to get detail");
            let groups = detail.groups();
            for insn_group_id in &insn_group_ids {
                let insn_group = InsnGroupId(*insn_group_id as InsnGroupIdInt);
                assert!(!groups.contains(&insn_group));
            }
        }
    }
}

#[allow(unused)]
fn test_instruction_helper(
    cs: &Capstone,
    insn: &Insn,
    mnemonic_name: &str,
    bytes: &[u8],
    has_default_syntax: bool,
) {
    println!("{insn:x?}");

    // Check mnemonic
    if has_default_syntax && cfg!(feature = "full") {
        // insn_name() does not respect current syntax
        // does not always match the internal mnemonic
        cs.insn_name(insn.id())
            .expect("Failed to get instruction name");
    }
    #[cfg(feature = "full")]
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
    if has_default_syntax && cfg!(feature = "full") {
        // insn_name() does not respect current syntax
        // does not always match the internal mnemonic
        cs.insn_name(insn.id())
            .expect("Failed to get instruction name");
    }
    #[cfg(feature = "full")]
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
    assert_eq!(
        expected_ops,
        arch_ops,
        "operands do not match for \"{}\" (bytes={:02x?})",
        insn,
        insn.bytes()
    );
}

#[cfg(feature = "full")]
/// Assert instruction belongs or does not belong to groups, testing both insn_belongs_to_group
/// and insn_group_ids
fn test_instruction_group_helper<R: Copy + Debug + TryInto<RegIdInt>>(
    cs: &Capstone,
    insn: &Insn,
    mnemonic_name: &str,
    bytes: &[u8],
    expected_groups: &[cs_group_type::Type],
    expected_regs_read: &[R],
    expected_regs_write: &[R],
    has_default_syntax: bool,
) {
    test_instruction_helper(cs, insn, mnemonic_name, bytes, has_default_syntax);
    let detail = cs.insn_detail(insn).expect("Unable to get detail");

    // Assert expected instruction groups is a subset of computed groups through ids
    let instruction_group_ids: HashSet<InsnGroupId> = detail.groups().iter().copied().collect();
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
            let mut expected_regs: Vec<RegId> = $expected
                .iter()
                .map(|&x| {
                    RegId(
                        x.try_into()
                            .unwrap_or_else(|_| panic!("Failed to convert {:?} to RegIdInt", x)),
                    )
                })
                .collect();
            expected_regs.sort_unstable();
            let mut regs: Vec<RegId> = $actual_regs.iter().map(|&x| x.into()).collect();
            regs.sort_unstable();
            assert_eq!(expected_regs, regs, $msg);
        }};
    }

    assert_regs_match!(
        expected_regs_read,
        detail.regs_read(),
        "read_regs did not match in insn {insn:?}"
    );
    assert_regs_match!(
        expected_regs_write,
        detail.regs_write(),
        "write_regs did not match in insn {insn:?}"
    );
}

type ExpectedInsns<'a, R> = (
    &'a str,
    &'a [u8],
    &'a [cs_group_type::Type],
    &'a [R],
    &'a [R],
);

#[allow(unused)]
fn instructions_match_group<R: Copy + Debug + TryInto<RegIdInt>>(
    cs: &mut Capstone,
    expected_insns: &[ExpectedInsns<R>],
    has_default_syntax: bool,
) {
    let insns_buf: Vec<u8> = expected_insns
        .iter()
        .flat_map(|&(_, bytes, _, _, _)| bytes)
        .copied()
        .collect();

    // Details required to get groups information
    cs.set_detail(true).unwrap();

    let insns = cs
        .disasm_all(&insns_buf, START_TEST_ADDR)
        .expect("Failed to disassemble");
    let insns: Vec<&Insn> = insns.iter().collect();

    // Check number of instructions
    assert_eq!(insns.len(), expected_insns.len(), "number of insns");

    #[cfg(feature = "full")]
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
            cs,
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
        .copied()
        .collect();

    // Details required to get groups information
    cs.set_detail(true).unwrap();

    let insns = cs
        .disasm_all(&insns_buf, START_TEST_ADDR)
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
            cs,
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
    let insns_buf: Vec<u8> = info.iter().flat_map(|info| info.bytes).copied().collect();

    // Details required to get groups information
    cs.set_detail(true).unwrap();

    // todo(tmfink) eliminate check
    if info.is_empty() {
        // Input was empty, which will cause disasm_all() to fail
        return;
    }

    let insns = cs
        .disasm_all(&insns_buf, START_TEST_ADDR)
        .expect("Failed to disassemble");
    let insns: Vec<_> = insns.iter().collect();

    // Check number of instructions
    assert_eq!(
        insns.len(),
        info.len(),
        "Number of instructions {} does not match number of provided instruction info structs {}",
        insns.len(),
        info.len(),
    );

    for (insn, info) in insns.iter().zip(info) {
        test_instruction_detail_helper(cs, insn, info, has_default_syntax)
    }
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_instruction_details() {
    use crate::arch::x86::X86Reg;
    use crate::arch::x86::X86Reg::*;

    let expected_insns: &[ExpectedInsns<X86Reg::Type>] = &[
        ("nop", b"\x90", &[], &[], &[]),
        (
            "je",
            b"\x74\x05",
            &[JUMP],
            &[X86_REG_EFLAGS],
            &[X86_REG_EIP],
        ),
        (
            "call",
            b"\xe8\x28\x07\x00\x00",
            &[CALL],
            &[X86_REG_RIP, X86_REG_RSP],
            &[X86_REG_RSP, X86_REG_RIP],
        ),
        (
            "ret",
            b"\xc3",
            &[RET],
            &[X86_REG_RSP],
            &[X86_REG_RIP, X86_REG_RSP],
        ),
        ("syscall", b"\x0f\x05", &[INT], &[], &[]),
        ("iretd", b"\xcf", &[IRET], &[], &[]),
        (
            "sub",
            b"\x48\x83\xec\x08",
            &[],
            &[X86_REG_RSP],
            &[X86_REG_RSP, X86_REG_EFLAGS],
        ),
        (
            "test",
            b"\x48\x85\xc0",
            &[],
            &[X86_REG_RAX],
            &[X86_REG_EFLAGS],
        ),
        (
            "mov",
            b"\x48\x8b\x05\x95\x4a\x4d\x00",
            &[],
            &[X86_REG_RIP],
            &[X86_REG_RAX],
        ),
        ("mov", b"\xb9\x04\x02\x00\x00", &[], &[], &[X86_REG_ECX]),
    ];

    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    instructions_match_group(&mut cs, expected_insns, true);
}

#[allow(unused)]
fn test_insns_match(cs: &mut Capstone, insns: &[(&str, &[u8])]) {
    for &(mnemonic, bytes) in insns.iter() {
        let insns = cs.disasm_all(bytes, START_TEST_ADDR).unwrap();
        assert_eq!(insns.len(), 1);
        #[cfg(feature = "full")]
        assert_eq!(insns.iter().next().unwrap().mnemonic(), Some(mnemonic));
    }
}

fn test_extra_mode_helper(
    arch: Arch,
    mode: Mode,
    extra_mode: &[ExtraMode],
    valid_both_insns: &[(&str, &[u8])],
    valid_extra_mode: &[(&str, &[u8])],
) {
    let extra_mode = extra_mode.iter().copied();
    let mut cs = Capstone::new_raw(arch, mode, extra_mode, None).unwrap();

    test_insns_match(&mut cs, valid_both_insns);

    for &(_, _) in valid_extra_mode.iter() {
        // Capstone will disassemble instructions not allowed by the current mode
        // assert!(
        //     cs.disasm_all(bytes, START_TEST_ADDR).is_err(),
        //     "Disassembly succeeded when on instruction when it should not have for {:?}",
        //     bytes);
    }

    test_insns_match(&mut cs, valid_both_insns);
    test_insns_match(&mut cs, valid_extra_mode);
}

#[cfg(feature = "arch_arm")]
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

    let mut cs_raw = Capstone::new_raw(arch, mode, extra_mode.iter().copied(), endian).unwrap();
    let mut cs_raw_endian_set =
        Capstone::new_raw(arch, mode, extra_mode.iter().copied(), None).unwrap();
    if let Some(some_endian) = endian {
        cs_raw_endian_set
            .set_endian(some_endian)
            .expect("Failed to set endianness");
    }

    instructions_match(cs, expected_insns.as_slice(), true);
    instructions_match(&mut cs_raw, expected_insns.as_slice(), true);
    instructions_match(&mut cs_raw_endian_set, expected_insns.as_slice(), true);
}

#[allow(unused)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "full", derive(Debug))]
struct DetailedInsnInfo<'a, T: 'a + Into<ArchOperand>> {
    pub mnemonic: &'a str,
    pub bytes: &'a [u8],
    pub operands: &'a [T],
}

#[allow(clippy::upper_case_acronyms)]
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
    let extra_mode = extra_mode.iter().copied();
    let mut cs_raw = Capstone::new_raw(arch, mode, extra_mode, endian).unwrap();

    instructions_match_detail(&mut cs_raw, insns, true);
    instructions_match_detail(cs, insns, true);
}

#[cfg(all(feature = "full", feature = "arch_x86"))]
#[test]
fn test_syntax() {
    use crate::arch::x86::X86Reg;
    use crate::arch::x86::X86Reg::*;

    let expected_insns: &[(
        &str,
        &str,
        &[u8],
        &[cs_group_type::Type],
        &[X86Reg::Type],
        &[X86Reg::Type],
    )] = &[
        ("nop", "nop", b"\x90", &[], &[], &[]),
        (
            "je",
            "je",
            b"\x74\x05",
            &[JUMP],
            &[X86_REG_EFLAGS],
            &[X86_REG_EIP],
        ),
        (
            "call",
            "callq",
            b"\xe8\x28\x07\x00\x00",
            &[CALL],
            &[X86_REG_RIP, X86_REG_RSP],
            &[X86_REG_RSP, X86_REG_RIP],
        ),
        (
            "ret",
            "retq",
            b"\xc3",
            &[RET],
            &[X86_REG_RSP],
            &[X86_REG_RSP, X86_REG_RIP],
        ),
        ("syscall", "syscall", b"\x0f\x05", &[INT], &[], &[]),
        ("iretd", "iretl", b"\xcf", &[IRET], &[], &[]),
        (
            "sub",
            "subq",
            b"\x48\x83\xec\x08",
            &[],
            &[X86_REG_RSP],
            &[X86_REG_EFLAGS, X86_REG_RSP],
        ),
        (
            "test",
            "testq",
            b"\x48\x85\xc0",
            &[],
            &[X86_REG_RAX],
            &[X86_REG_EFLAGS],
        ),
        (
            "mov",
            "movq",
            b"\x48\x8b\x05\x95\x4a\x4d\x00",
            &[],
            &[X86_REG_RIP],
            &[X86_REG_RAX],
        ),
        (
            "mov",
            "movl",
            b"\xb9\x04\x02\x00\x00",
            &[],
            &[],
            &[X86_REG_ECX],
        ),
    ];

    let expected_insns_intel: Vec<ExpectedInsns<X86Reg::Type>> = expected_insns
        .iter()
        .map(|&(mnemonic, _, bytes, groups, reads, writes)| {
            (mnemonic, bytes, groups, reads, writes)
        })
        .collect();
    let expected_insns_att: Vec<ExpectedInsns<X86Reg::Type>> = expected_insns
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

    // In this case, MASM and Intel syntaxes match
    cs.set_syntax(Syntax::Masm).unwrap();
    instructions_match_group(&mut cs, &expected_insns_intel, false);
}

// @todo(tmfink) test invalid syntax once we check for invalid options
#[cfg(feature = "arch_arm")]
#[test]
fn test_invalid_syntax() {
    // These do no support any syntax change
    let rules = [(Arch::ARM, Mode::Thumb)];
    let syntaxes = [
        // Syntax::Intel,
        // Syntax::Att,
        // Syntax::Masm,
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
    println!("Capstone lib version: ({major}, {minor})");
    assert!(major > 0 && major < 100, "Invalid major version {}", major);
    assert!(minor < 500, "Invalid minor version {}", minor);
}

#[test]
fn test_capstone_supports_arch() {
    let architectures = vec![
        Arch::ARM,
        Arch::AARCH64,
        Arch::MIPS,
        Arch::X86,
        Arch::PPC,
        Arch::SPARC,
        Arch::SYSTEMZ,
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

#[cfg(feature = "arch_arc")]
#[test]
fn test_arch_arc() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arc()
            .mode(arc::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::ARC,
        Mode::Default,
        None,
        &[],
        &[("ld", b"\x04\x11\x00\x00"), ("ld.aw", b"\x04\x11\x00\x02")],
    );
}

#[cfg(feature = "arch_arc")]
#[test]
fn test_arch_arc_detail() {
    use crate::arch::arc::ArcOperand;
    use capstone_sys::arc_reg::*;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .arc()
            .mode(arc::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::ARC,
        Mode::Default,
        None,
        &[],
        &[
            // ld %r0, [%r1, 4]
            DII::new(
                "ld",
                b"\x04\x11\x00\x00",
                &[
                    ArcOperand {
                        op_type: arc::ArcOperandType::Reg(RegId(ARC_REG_R0 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    ArcOperand {
                        op_type: arc::ArcOperandType::Reg(RegId(ARC_REG_R1 as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    ArcOperand {
                        op_type: arc::ArcOperandType::Imm(4),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
            // ld.aw %r0, [%r1, 4]
            DII::new(
                "ld.aw",
                b"\x04\x11\x00\x02",
                &[
                    ArcOperand {
                        op_type: arc::ArcOperandType::Reg(RegId(ARC_REG_R0 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    ArcOperand {
                        op_type: arc::ArcOperandType::Reg(RegId(ARC_REG_R1 as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    ArcOperand {
                        op_type: arc::ArcOperandType::Imm(4),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_arm")]
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
            ("vdupge.8", b"\xf3\xff\x0b\x0c"),
            ("msrlt", b"\x86\xf3\x00\x89"),
            ("msrlt", b"\x80\xf3\x00\x8c"),
            ("sxtbge.w", b"\x4f\xfa\x99\xf6"),
            ("vaddw.u16", b"\xd0\xff\xa2\x01"),
        ],
    );
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .extra_mode([arm::ArchExtraMode::MClass].iter().copied())
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
            .extra_mode([arm::ArchExtraMode::V8].iter().copied())
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

#[cfg(feature = "arch_arm")]
#[test]
fn test_arch_arm_detail() {
    use crate::arch::arm::ArmOperandType::*;
    use crate::arch::arm::*;
    use capstone_sys::arm_op_mem;
    use capstone_sys::arm_spsr_cpsr_bits;

    let r0_op_read = ArmOperand {
        op_type: Reg(RegId(ArmReg::ARM_REG_R0 as RegIdInt)),
        access: Some(AccessType::ReadOnly),
        ..Default::default()
    };
    let r0_op_write = ArmOperand {
        op_type: Reg(RegId(ArmReg::ARM_REG_R0 as RegIdInt)),
        access: Some(AccessType::WriteOnly),
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
                    access: Some(RegAccessType::ReadOnly),
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
                        access: Some(AccessType::ReadOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Mem(ArmOpMem(arm_op_mem {
                            base: ArmReg::ARM_REG_SP,
                            index: 0,
                            scale: 0,
                            disp: 4,
                            align: 0,
                        })),
                        subtracted: true,
                        access: Some(AccessType::WriteOnly),
                        ..Default::default()
                    },
                ],
            ),
            // andeq   r0, r0, r0
            DII::new(
                "andeq",
                b"\x00\x00\x00\x00",
                &[r0_op_write.clone(), r0_op_read.clone(), r0_op_read.clone()],
            ),
            // str     r8, [r2, #-0x3e0]!
            DII::new(
                "str",
                b"\xe0\x83\x22\xe5",
                &[
                    ArmOperand {
                        op_type: Reg(RegId(ArmReg::ARM_REG_R8 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Mem(ArmOpMem(arm_op_mem {
                            base: ArmReg::ARM_REG_R2,
                            index: 0,
                            scale: 0,
                            disp: 992,
                            align: 0,
                        })),
                        subtracted: true,
                        access: Some(AccessType::WriteOnly),
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
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Imm(0),
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                    r0_op_read.clone(),
                    ArmOperand {
                        op_type: Cimm(3),
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Cimm(1),
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Imm(7),
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                ],
            ),
            // mov     r0, #0
            DII::new(
                "mov",
                b"\x00\x00\xa0\xe3",
                &[
                    r0_op_write,
                    ArmOperand {
                        op_type: Imm(0),
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                ],
            ),
            // msr CPSR_fc, r1
            DII::new(
                "msr",
                b"\x01\xf0\x29\xe1",
                &[
                    ArmOperand {
                        op_type: Cpsr(
                            arm_spsr_cpsr_bits::ARM_FIELD_CPSR_F
                                | arm_spsr_cpsr_bits::ARM_FIELD_CPSR_C,
                        ),
                        access: Some(RegAccessType::WriteOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: Reg(RegId(ArmReg::ARM_REG_R1 as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                        ..Default::default()
                    },
                ],
            ),
            // mrs r2, SP_svc
            DII::new(
                "mrs",
                b"\x00\x23\x03\xe1",
                &[
                    ArmOperand {
                        op_type: Reg(RegId(ArmReg::ARM_REG_R2 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                        ..Default::default()
                    },
                    ArmOperand {
                        op_type: BankedReg(ArmBankedReg::ARM_BANKEDREG_SP_SVC),
                        access: Some(RegAccessType::ReadOnly),
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
                access: Some(AccessType::ReadOnly),
                ..Default::default()
            }],
        )],
    );
}

#[cfg(feature = "arch_aarch64")]
#[test]
fn test_arch_aarch64() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .aarch64()
            .mode(aarch64::ArchMode::Arm)
            .build()
            .unwrap(),
        Arch::AARCH64,
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

#[cfg(feature = "arch_aarch64")]
#[test]
fn test_arch_aarch64_detail() {
    use crate::arch::aarch64::AArch64OperandType::*;
    use crate::arch::aarch64::AArch64Reg::*;
    use crate::arch::aarch64::*;
    use capstone_sys::aarch64_op_mem;
    use capstone_sys::aarch64_op_sme;
    use capstone_sys::aarch64_op_sme__bindgen_ty_1;
    use capstone_sys::aarch64_reg;

    let s0 = AArch64Operand {
        op_type: Reg(RegId(AARCH64_REG_S0 as RegIdInt)),
        ..Default::default()
    };
    let x0 = AArch64Operand {
        op_type: Reg(RegId(AARCH64_REG_X0 as RegIdInt)),
        ..Default::default()
    };
    let x1 = AArch64Operand {
        op_type: Reg(RegId(AARCH64_REG_X1 as RegIdInt)),
        ..Default::default()
    };
    let x2 = AArch64Operand {
        op_type: Reg(RegId(AARCH64_REG_X2 as RegIdInt)),
        ..Default::default()
    };

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .aarch64()
            .mode(aarch64::ArchMode::Arm)
            .build()
            .unwrap(),
        Arch::AARCH64,
        Mode::Arm,
        None,
        &[],
        &[
            // mrs x9, midr_el1
            DII::new(
                "mrs",
                b"\x09\x00\x38\xd5",
                &[
                    AArch64Operand {
                        access: Some(RegAccessType::WriteOnly),
                        op_type: Reg(RegId(AARCH64_REG_X9 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        op_type: RegMrs(AArch64Sysreg::AARCH64_SYSREG_MIDR_EL1),
                        ..Default::default()
                    },
                ],
            ),
            // msr spsel, #0
            DII::new(
                "msr",
                b"\xbf\x40\x00\xd5",
                &[
                    AArch64Operand {
                        // spsel is part of pstate
                        op_type: PStateImm015(AArch64PStateImm015::AARCH64_PSTATEIMM0_15_SPSEL),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
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
                    AArch64Operand {
                        access: Some(AccessType::ReadWrite),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_8B,
                        op_type: Reg(RegId(AARCH64_REG_D0 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_16B,
                        op_type: Reg(RegId(AARCH64_REG_Q1 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_16B,
                        op_type: Reg(RegId(AARCH64_REG_Q2 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_16B,
                        op_type: Reg(RegId(AARCH64_REG_Q3 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(RegAccessType::ReadOnly),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_8B,
                        op_type: Reg(RegId(AARCH64_REG_D2 as RegIdInt)),
                        ..Default::default()
                    },
                ],
            ),
            // scvtf v0.2s, v1.2s, #3
            DII::new(
                "scvtf",
                b"\x20\xe4\x3d\x0f",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_2S,
                        op_type: Reg(RegId(AARCH64_REG_D0 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_2S,
                        op_type: Reg(RegId(AARCH64_REG_D1 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
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
                    AArch64Operand {
                        access: Some(AccessType::ReadWrite),
                        ..s0.clone()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        ..s0
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        vector_index: Some(3),
                        op_type: Reg(RegId(AARCH64_REG_Q0 as RegIdInt)),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_S,
                        ..Default::default()
                    },
                ],
            ),
            // fmov x2, v5.d[1]
            DII::new(
                "fmov",
                b"\xa2\x00\xae\x9e",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(AARCH64_REG_X2 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        vector_index: Some(1),
                        op_type: Reg(RegId(AARCH64_REG_Q5 as RegIdInt)),
                        vas: AArch64Vas::AARCH64LAYOUT_VL_D,
                        ..Default::default()
                    },
                ],
            ),
            // dsb nsh
            DII::new(
                "dsb",
                b"\x9f\x37\x03\xd5",
                &[AArch64Operand {
                    op_type: Db(AArch64Db::AARCH64_DB_NSH),
                    ..Default::default()
                }],
            ),
            // dmb osh
            DII::new(
                "dmb",
                b"\xbf\x33\x03\xd5",
                &[AArch64Operand {
                    op_type: Db(AArch64Db::AARCH64_DB_OSH),
                    ..Default::default()
                }],
            ),
            // isb
            DII::new("isb", b"\xdf\x3f\x03\xd5", &[]),
            // mul x1, x1, x2
            DII::new(
                "mul",
                b"\x21\x7c\x02\x9b",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        ..x1.clone()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        ..x1.clone()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        ..x2.clone()
                    },
                ],
            ),
            // lsr w1, w1, #0
            DII::new(
                "lsr",
                b"\x21\x7c\x00\x53",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(AARCH64_REG_W1 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        op_type: Reg(RegId(AARCH64_REG_W1 as RegIdInt)),
                        shift: AArch64Shift::Lsr(0),
                        ..Default::default()
                    },
                ],
            ),
            // sub w0, w0, w1, uxtw
            DII::new(
                "sub",
                b"\x00\x40\x21\x4b",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(AARCH64_REG_W0 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        op_type: Reg(RegId(AARCH64_REG_W0 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        op_type: Reg(RegId(AARCH64_REG_W1 as RegIdInt)),
                        ext: AArch64Extender::AARCH64_EXT_UXTW,
                        shift: AArch64Shift::Lsl(0),
                        ..Default::default()
                    },
                ],
            ),
            // ldr w1, [sp, #8]
            DII::new(
                "ldr",
                b"\xe1\x0b\x40\xb9",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(AARCH64_REG_W1 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        op_type: Mem(AArch64OpMem(aarch64_op_mem {
                            base: AARCH64_REG_SP as aarch64_reg::Type,
                            index: 0,
                            disp: 8,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // cneg x0, x1, ne
            DII::new(
                "cneg",
                b"\x20\x04\x81\xda",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        ..x0.clone()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        ..x1.clone()
                    },
                ],
            ),
            // add x0, x1, x2, lsl #2
            DII::new(
                "add",
                b"\x20\x08\x02\x8b",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        ..x0
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        ..x1
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        shift: AArch64Shift::Lsl(2),
                        ..x2
                    },
                ],
            ),
            // ldr q16, [x24, w8, uxtw #4]
            DII::new(
                "ldr",
                b"\x10\x5b\xe8\x3c",
                &[
                    AArch64Operand {
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(AARCH64_REG_Q16 as RegIdInt)),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(AccessType::ReadOnly),
                        shift: AArch64Shift::Lsl(4),
                        ext: AArch64Extender::AARCH64_EXT_UXTW,
                        op_type: Mem(AArch64OpMem(aarch64_op_mem {
                            base: AARCH64_REG_X24 as aarch64_reg::Type,
                            index: AARCH64_REG_W8 as aarch64_reg::Type,
                            disp: 0,
                        })),
                        ..Default::default()
                    },
                ],
            ),
            // smstart
            DII::new("smstart", b"\x7f\x47\x03\xd5", &[]),
            // smstart sm
            DII::new(
                "smstart",
                b"\x7f\x43\x03\xd5",
                &[AArch64Operand {
                    op_type: Svcr(AArch64Svcr::AARCH64_SVCR_SVCRSM),
                    ..Default::default()
                }],
            ),
            // ldr za[w12, 4], [x0, #4, mul vl]
            DII::new(
                "ldr",
                b"\x04\x00\x00\xe1",
                &[
                    AArch64Operand {
                        access: Some(RegAccessType::WriteOnly),
                        op_type: Sme(AArch64OpSme(aarch64_op_sme {
                            type_: capstone_sys::aarch64_sme_op_type::AARCH64_SME_OP_TILE_VEC,
                            tile: AARCH64_REG_ZA as aarch64_reg::Type,
                            slice_reg: AARCH64_REG_W12 as aarch64_reg::Type,
                            slice_offset: aarch64_op_sme__bindgen_ty_1 { imm: 4 },
                            has_range_offset: false,
                            is_vertical: false,
                        })),
                        ..Default::default()
                    },
                    AArch64Operand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: Mem(AArch64OpMem(aarch64_op_mem {
                            base: AARCH64_REG_X0 as aarch64_reg::Type,
                            index: 0,
                            disp: 4,
                        })),
                        ..Default::default()
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_alpha")]
#[test]
fn test_arch_alpha() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .alpha()
            .mode(alpha::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::ALPHA,
        Mode::Default,
        None,
        &[],
        &[("ldah", b"\x02\x00\xbb\x27"), ("lda", b"\x50\x7a\xbd\x23")],
    );
}

#[cfg(feature = "arch_alpha")]
#[test]
fn test_arch_alpha_detail() {
    use crate::arch::alpha::AlphaOperand;
    use crate::arch::alpha::AlphaOperandType;
    use capstone_sys::alpha_reg::*;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .alpha()
            .mode(alpha::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::ALPHA,
        Mode::Arm,
        None,
        &[],
        &[
            // ldah $15, 2($13)
            DII::new(
                "ldah",
                b"\x02\x00\xbb\x27",
                &[
                    AlphaOperand {
                        access: Some(RegAccessType::WriteOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R15 as RegIdInt)),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Imm(2),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R13 as RegIdInt)),
                    },
                ],
            ),
            // lda $15, 0x7a50($15)
            DII::new(
                "lda",
                b"\x50\x7a\xbd\x23",
                &[
                    AlphaOperand {
                        access: Some(RegAccessType::WriteOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R15 as RegIdInt)),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Imm(0x7a50),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R15 as RegIdInt)),
                    },
                ],
            ),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .alpha()
            .mode(alpha::ArchMode::Default)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::ALPHA,
        Mode::Arm,
        Some(Endian::Big),
        &[],
        &[
            // ldah $15, 2($13)
            DII::new(
                "ldah",
                b"\x27\xbb\x00\x02",
                &[
                    AlphaOperand {
                        access: Some(RegAccessType::WriteOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R15 as RegIdInt)),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Imm(2),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R13 as RegIdInt)),
                    },
                ],
            ),
            // lda $15, 0x7a50($15)
            DII::new(
                "lda",
                b"\x23\xbd\x7a\x50",
                &[
                    AlphaOperand {
                        access: Some(RegAccessType::WriteOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R15 as RegIdInt)),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Imm(0x7a50),
                    },
                    AlphaOperand {
                        access: Some(RegAccessType::ReadOnly),
                        op_type: AlphaOperandType::Reg(RegId(Alpha_REG_R15 as RegIdInt)),
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_bpf")]
#[test]
fn test_arch_bpf_cbpf() {
    let cs = Capstone::new()
        .bpf()
        .mode(bpf::ArchMode::Cbpf)
        .endian(Endian::Little)
        .detail(true)
        .build()
        .unwrap();
    let insns = cs.disasm_all(CBPF_CODE, 0x1000);
    match insns {
        Ok(ins) => {
            for i in ins.as_ref() {
                println!();
                eprintln!("{i}");

                let detail: InsnDetail = cs.insn_detail(i).expect("Failed to get insn detail");
                let arch_detail: ArchDetail = detail.arch_detail();
                let ops = arch_detail.operands();

                let output: &[(&str, String)] = &[
                    ("insn id:", format!("{:?}", i.id().0)),
                    ("bytes:", format!("{:?}", i.bytes())),
                    ("read regs:", reg_names(&cs, detail.regs_read())),
                    ("write regs:", reg_names(&cs, detail.regs_write())),
                    ("insn groups:", group_names(&cs, detail.groups())),
                ];

                for (name, message) in output.iter() {
                    eprintln!("{:4}{:12} {}", "", name, message);
                }

                println!("{:4}operands: {}", "", ops.len());
                for op in ops {
                    eprintln!("{:8}{:?}", "", op);
                }
            }
        }

        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

#[cfg(feature = "arch_bpf")]
#[test]
fn test_arch_bpf_ebpf() {
    let cs = Capstone::new()
        .bpf()
        .mode(bpf::ArchMode::Ebpf)
        .endian(Endian::Little)
        .detail(true)
        .build()
        .unwrap();
    let insns = cs.disasm_all(EBPF_CODE, 0x1000);
    match insns {
        Ok(ins) => {
            for i in ins.as_ref() {
                println!();
                eprintln!("{i}");

                let detail: InsnDetail = cs.insn_detail(i).expect("Failed to get insn detail");
                let arch_detail: ArchDetail = detail.arch_detail();
                let ops = arch_detail.operands();

                let output: &[(&str, String)] = &[
                    ("insn id:", format!("{:?}", i.id().0)),
                    ("bytes:", format!("{:?}", i.bytes())),
                    ("read regs:", reg_names(&cs, detail.regs_read())),
                    ("write regs:", reg_names(&cs, detail.regs_write())),
                    ("insn groups:", group_names(&cs, detail.groups())),
                ];

                for (name, message) in output.iter() {
                    eprintln!("{:4}{:12} {}", "", name, message);
                }

                println!("{:4}operands: {}", "", ops.len());
                for op in ops {
                    eprintln!("{:8}{:?}", "", op);
                }
            }
        }

        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

#[cfg(feature = "arch_bpf")]
#[test]
fn test_arch_bpf_detail() {
    use crate::arch::bpf::BpfOperand::*;
    use crate::arch::bpf::BpfReg::*;
    use crate::arch::bpf::*;
    use capstone_sys::*;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .bpf()
            .mode(bpf::ArchMode::Ebpf)
            .endian(Endian::Little)
            .detail(true)
            .build()
            .unwrap(),
        Arch::BPF,
        Mode::Ebpf,
        None,
        &[],
        &[
            // r1 = 0x1
            DII::new(
                "mov64",
                b"\xb7\x01\x00\x00\x01\x00\x00\x00",
                &[Reg(RegId(BPF_REG_R1 as RegIdInt)), Imm(1)],
            ),
            // r0 = *(u32 *)(r10 - 0xc)
            DII::new(
                "ldxw",
                b"\x61\xa0\xf4\xff\x00\x00\x00\x00",
                &[
                    Reg(RegId(BPF_REG_R0 as RegIdInt)),
                    Mem(BpfOpMem(bpf_op_mem {
                        base: BPF_REG_R10,
                        disp: 0xfff4,
                    })),
                ],
            ),
            // *(u32 *)(r10 - 0xc) = r1
            DII::new(
                "stxw",
                b"\x63\x1a\xf4\xff\x00\x00\x00\x00",
                &[
                    Mem(BpfOpMem(bpf_op_mem {
                        base: BPF_REG_R10,
                        disp: 0xfff4,
                    })),
                    Reg(RegId(BPF_REG_R1 as RegIdInt)),
                ],
            ),
            // exit
            DII::new("exit", b"\x95\x00\x00\x00\x00\x00\x00\x00", &[]),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .bpf()
            .mode(bpf::ArchMode::Cbpf)
            .endian(Endian::Little)
            .detail(true)
            .build()
            .unwrap(),
        Arch::BPF,
        Mode::Cbpf,
        None,
        &[],
        &[
            DII::new("txa", b"\x87\x00\x00\x00\x00\x00\x00\x00", &[]),
            DII::new(
                "ret",
                b"\x16\x00\x00\x00\x00\x00\x00\x00",
                &[Reg(RegId(BPF_REG_A as RegIdInt))],
            ),
        ],
    );
}

#[cfg(feature = "arch_evm")]
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

#[cfg(feature = "arch_evm")]
#[test]
fn test_arch_evm_detail() {
    let ops: &[arch::m68k::M68kOperand] = &[];
    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .evm()
            .mode(evm::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::EVM,
        Mode::Default,
        None,
        &[],
        &[DII::new("push1", b"\x60\x61", ops)],
    );
}

#[cfg(feature = "arch_hppa")]
#[test]
fn test_arch_hppa() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .hppa()
            .mode(hppa::ArchMode::Hppa20)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::HPPA,
        Mode::Hppa20,
        Some(Endian::Big),
        &[],
        &[
            ("ldsid", b"\x00\x20\x50\xa2"),
            ("mtsp", b"\x00\x01\x58\x20"),
        ],
    );
}

#[cfg(feature = "arch_hppa")]
#[test]
fn test_arch_hppa_detail() {
    use crate::arch::hppa::{HppaMem, HppaOperand};
    use capstone_sys::{hppa_mem, hppa_reg::*};

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .hppa()
            .mode(hppa::ArchMode::Hppa20)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::HPPA,
        Mode::Hppa20,
        Some(Endian::Big),
        &[],
        &[
            DII::new(
                "ldsid",
                b"\x00\x20\x50\xa2",
                &[
                    HppaOperand {
                        op_type: hppa::HppaOperandType::Mem(HppaMem(hppa_mem {
                            base: HPPA_REG_GR1,
                            space: HPPA_REG_SR1,
                        })),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    HppaOperand {
                        op_type: hppa::HppaOperandType::Reg(RegId(HPPA_REG_GR2 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                ],
            ),
            // mtsp r1, sr1
            DII::new(
                "mtsp",
                b"\x00\x01\x58\x20",
                &[
                    HppaOperand {
                        op_type: hppa::HppaOperandType::Reg(RegId(HPPA_REG_GR1 as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    HppaOperand {
                        op_type: hppa::HppaOperandType::Reg(RegId(HPPA_REG_SR1 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_loongarch")]
#[test]
fn test_arch_loongarch() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .loongarch()
            .mode(loongarch::ArchMode::LoongArch32)
            .build()
            .unwrap(),
        Arch::LOONGARCH,
        Mode::LoongArch32,
        None,
        &[],
        &[
            ("lu12i.w", b"\x0c\x00\x08\x14"),
            ("addi.w", b"\x8c\xfd\xbf\x02"),
        ],
    );
}

#[cfg(feature = "arch_loongarch")]
#[test]
fn test_arch_loongarch_detail() {
    use crate::arch::loongarch::{LoongArchOpMem, LoongArchOperand};
    use capstone_sys::{loongarch_op_mem, loongarch_reg::*};

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .loongarch()
            .mode(loongarch::ArchMode::LoongArch32)
            .build()
            .unwrap(),
        Arch::LOONGARCH,
        Mode::LoongArch32,
        None,
        &[],
        &[
            // lu12i.w $t0, 0x4000
            DII::new(
                "lu12i.w",
                b"\x0c\x00\x08\x14",
                &[
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Reg(RegId(
                            LOONGARCH_REG_T0 as RegIdInt,
                        )),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Imm(0x4000),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
            // addi.w $t0, $t0, -1
            DII::new(
                "addi.w",
                b"\x8c\xfd\xbf\x02",
                &[
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Reg(RegId(
                            LOONGARCH_REG_T0 as RegIdInt,
                        )),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Reg(RegId(
                            LOONGARCH_REG_T0 as RegIdInt,
                        )),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Imm(-1),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .loongarch()
            .mode(loongarch::ArchMode::LoongArch64)
            .build()
            .unwrap(),
        Arch::LOONGARCH,
        Mode::LoongArch64,
        None,
        &[],
        &[
            // st.d $s1, $sp, 8
            DII::new(
                "st.d",
                b"\x78\x20\xc0\x29",
                &[
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Reg(RegId(
                            LOONGARCH_REG_S1 as RegIdInt,
                        )),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    LoongArchOperand {
                        op_type: loongarch::LoongArchOperandType::Mem(LoongArchOpMem(
                            loongarch_op_mem {
                                base: LOONGARCH_REG_SP as c_uint,
                                index: 0,
                                disp: 8,
                            },
                        )),
                        access: Some(RegAccessType::WriteOnly),
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_m680x")]
#[test]
fn test_arch_m680x_detail() {
    use crate::arch::m680x::M680xOperandType::*;
    use crate::arch::m680x::M680xReg::*;
    use crate::arch::m680x::*;
    use capstone_sys::m680x_op_idx;

    let op_idx_zero = m680x_op_idx {
        base_reg: M680X_REG_INVALID,
        offset_reg: M680X_REG_INVALID,
        offset: 0,
        offset_addr: 0,
        offset_bits: 0,
        inc_dec: 0,
        flags: 0,
    };

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .m680x()
            .mode(m680x::ArchMode::M680x6301)
            .build()
            .unwrap(),
        Arch::M680X,
        Mode::M680x6301,
        None,
        &[],
        &[
            // tim     #16;0,x
            DII::new(
                "tim",
                b"\x6b\x10\x00",
                &[
                    M680xOperand {
                        op_type: Imm(16),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Indexed(M680xOpIdx(m680x_op_idx {
                            base_reg: M680X_REG_X,
                            offset_bits: 8,
                            ..op_idx_zero
                        })),
                        size: 1,
                    },
                ],
            ),
            // aim     #16,$00
            DII::new(
                "aim",
                b"\x71\x10\x00",
                &[
                    M680xOperand {
                        op_type: Imm(16),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Direct { direct_addr: 0 },
                        size: 1,
                    },
                ],
            ),
            // oim     #16,$10
            DII::new(
                "oim",
                b"\x72\x10\x10",
                &[
                    M680xOperand {
                        op_type: Imm(16),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Direct { direct_addr: 0x10 },
                        size: 1,
                    },
                ],
            ),
            // rts
            DII::new("rts", b"\x39", &[]),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .m680x()
            .mode(m680x::ArchMode::M680x6309)
            .build()
            .unwrap(),
        Arch::M680X,
        Mode::M680x6309,
        None,
        &[],
        &[
            // oim     #16,$10
            DII::new(
                "oim",
                b"\x01\x10\x10",
                &[
                    M680xOperand {
                        op_type: Imm(16),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Direct { direct_addr: 0x10 },
                        size: 1,
                    },
                ],
            ),
            // aim     #16;-16,x
            DII::new(
                "aim",
                b"\x62\x10\x10",
                &[
                    M680xOperand {
                        op_type: Imm(16),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Indexed(M680xOpIdx(m680x_op_idx {
                            base_reg: M680X_REG_X,
                            offset: -16,
                            offset_bits: 5,
                            offset_addr: START_TEST_ADDR as u16 - 10,
                            ..op_idx_zero
                        })),
                        size: 1,
                    },
                ],
            ),
            // tim     #16,$1000
            DII::new(
                "tim",
                b"\x7b\x10\x10\x00",
                &[
                    M680xOperand {
                        op_type: Imm(16),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Extended {
                            address: 0x1000,
                            indirect: false,
                        },
                        size: 1,
                    },
                ],
            ),
            // ldq     #1234567890
            DII::new(
                "ldq",
                b"\xcd\x49\x96\x02\xd2",
                &[
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_Q as RegIdInt)),
                        size: 4,
                    },
                    M680xOperand {
                        op_type: Imm(1234567890),
                        size: 4,
                    },
                ],
            ),
            // addr    y,u
            DII::new(
                "addr",
                b"\x10\x30\x23",
                &[
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_Y as RegIdInt)),
                        size: 2,
                    },
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_U as RegIdInt)),
                        size: 2,
                    },
                ],
            ),
            // pshsw
            DII::new(
                "pshsw",
                b"\x10\x38",
                &[
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_S as RegIdInt)),
                        size: 2,
                    },
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_W as RegIdInt)),
                        size: 2,
                    },
                ],
            ),
            // puluw
            DII::new(
                "puluw",
                b"\x10\x3b",
                &[
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_U as RegIdInt)),
                        size: 2,
                    },
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_W as RegIdInt)),
                        size: 2,
                    },
                ],
            ),
            // comw
            DII::new(
                "comw",
                b"\x10\x53",
                &[M680xOperand {
                    op_type: Reg(RegId(M680X_REG_W as RegIdInt)),
                    size: 2,
                }],
            ),
            // tstw
            DII::new(
                "tstw",
                b"\x10\x5d",
                &[M680xOperand {
                    op_type: Reg(RegId(M680X_REG_W as RegIdInt)),
                    size: 2,
                }],
            ),
            // band    a,0,3,$10
            DII::new(
                "band",
                b"\x11\x30\x43\x10",
                &[
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_A as RegIdInt)),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Constant(0),
                        size: 0,
                    },
                    M680xOperand {
                        op_type: Constant(3),
                        size: 0,
                    },
                    M680xOperand {
                        op_type: Direct { direct_addr: 0x10 },
                        size: 1,
                    },
                ],
            ),
            // stbt    cc,4,5,$10
            DII::new(
                "stbt",
                b"\x11\x37\x25\x10",
                &[
                    M680xOperand {
                        op_type: Reg(RegId(M680X_REG_CC as RegIdInt)),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Constant(4),
                        size: 0,
                    },
                    M680xOperand {
                        op_type: Constant(5),
                        size: 0,
                    },
                    M680xOperand {
                        op_type: Direct { direct_addr: 0x10 },
                        size: 1,
                    },
                ],
            ),
            // tfm     x+,y+
            DII::new(
                "tfm",
                b"\x11\x38\x12",
                &[
                    M680xOperand {
                        op_type: Indexed(M680xOpIdx(m680x_op_idx {
                            base_reg: M680X_REG_X,
                            inc_dec: 1,
                            flags: 6,
                            ..op_idx_zero
                        })),
                        size: 1,
                    },
                    M680xOperand {
                        op_type: Indexed(M680xOpIdx(m680x_op_idx {
                            base_reg: M680X_REG_Y,
                            inc_dec: 1,
                            flags: 6,
                            ..op_idx_zero
                        })),
                        size: 1,
                    },
                ],
            ),
        ],
    );

    let empty_ops: &[M680xOperand] = &[];

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .m680x()
            .mode(m680x::ArchMode::M680x6800)
            .build()
            .unwrap(),
        Arch::M680X,
        Mode::M680x6800,
        None,
        &[],
        &[
            // nop
            DII::new("nop", b"\x01", empty_ops),
            // dex
            DII::new(
                "dex",
                b"\x09",
                &[M680xOperand {
                    op_type: Reg(RegId(M680X_REG_X as RegIdInt)),
                    size: 2,
                }],
            ),
            // psha
            DII::new(
                "psha",
                b"\x36",
                &[M680xOperand {
                    op_type: Reg(RegId(M680X_REG_A as RegIdInt)),
                    size: 1,
                }],
            ),
            // lsr     127,x
            DII::new(
                "lsr",
                b"\x64\x7f",
                &[M680xOperand {
                    op_type: Indexed(M680xOpIdx(m680x_op_idx {
                        base_reg: M680X_REG_X,
                        offset: 127,
                        offset_bits: 8,
                        ..op_idx_zero
                    })),
                    size: 1,
                }],
            ),
            // lsr     $1000
            DII::new(
                "lsr",
                b"\x74\x10\x00",
                &[M680xOperand {
                    op_type: Extended {
                        address: 0x1000,
                        indirect: false,
                    },
                    size: 1,
                }],
            ),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .m680x()
            .mode(m680x::ArchMode::M680x6801)
            .build()
            .unwrap(),
        Arch::M680X,
        Mode::M680x6801,
        None,
        &[],
        &[
            // lsrd
            DII::new(
                "lsrd",
                b"\x04",
                &[M680xOperand {
                    op_type: Reg(RegId(M680X_REG_D as RegIdInt)),
                    size: 2,
                }],
            ),
            // asld
            DII::new(
                "asld",
                b"\x05",
                &[M680xOperand {
                    op_type: Reg(RegId(M680X_REG_D as RegIdInt)),
                    size: 2,
                }],
            ),
        ],
    );
}

#[cfg(feature = "arch_m68k")]
#[test]
fn test_arch_m68k_detail() {
    use crate::arch::m68k::M68kOperand::*;
    use crate::arch::m68k::M68kReg::*;
    use crate::arch::m68k::*;
    use capstone_sys::m68k_address_mode::*;
    use capstone_sys::m68k_op_mem;

    let mem_zero = m68k_op_mem {
        base_reg: M68K_REG_INVALID,
        index_reg: M68K_REG_INVALID,
        in_base_reg: M68K_REG_INVALID,
        in_disp: 0,
        out_disp: 0,
        disp: 0,
        scale: 0,
        bitfield: 0,
        width: 0,
        offset: 0,
        index_size: 0,
    };

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .m68k()
            .mode(m68k::ArchMode::M68k040)
            .build()
            .unwrap(),
        Arch::M68K,
        Mode::M68k040,
        Some(Endian::Big),
        &[],
        &[
            // mulu.l  d0, d4:d5
            DII::new(
                "mulu.l",
                b"\x4c\x00\x54\x04",
                &[
                    Reg(RegId(M68K_REG_D0 as RegIdInt)),
                    RegPair(
                        RegId(M68K_REG_D4 as RegIdInt),
                        RegId(M68K_REG_D5 as RegIdInt),
                    ),
                ],
            ),
            // movem.l d0-d2/a2-a3, -(a7)
            DII::new(
                "movem.l",
                b"\x48\xe7\xe0\x30",
                &[
                    RegBits(
                        M68kRegisterBits::from_register_iter(
                            [
                                M68K_REG_D0,
                                M68K_REG_D1,
                                M68K_REG_D2,
                                M68K_REG_A2,
                                M68K_REG_A3,
                            ]
                            .iter()
                            .copied(),
                        )
                        .unwrap(),
                    ),
                    Mem(M68kOpMem {
                        op_mem: mem_zero,
                        address_mode: M68K_AM_REGI_ADDR_PRE_DEC,
                        extra_info: M68kOpMemExtraInfo::Reg(RegId(M68K_REG_A7 as RegIdInt)),
                    }),
                ],
            ),
            // movem.l (a7)+, d0-d2/a2-a3
            DII::new(
                "movem.l",
                b"\x4c\xdf\x0c\x07",
                &[
                    Mem(M68kOpMem {
                        op_mem: mem_zero,
                        address_mode: M68K_AM_REGI_ADDR_POST_INC,
                        extra_info: M68kOpMemExtraInfo::Reg(RegId(M68K_REG_A7 as RegIdInt)),
                    }),
                    RegBits(
                        M68kRegisterBits::from_register_iter(
                            [
                                M68K_REG_D0,
                                M68K_REG_D1,
                                M68K_REG_D2,
                                M68K_REG_A2,
                                M68K_REG_A3,
                            ]
                            .iter()
                            .copied(),
                        )
                        .unwrap(),
                    ),
                ],
            ),
            // add.w   d0, d2
            DII::new(
                "add.w",
                b"\xd4\x40",
                &[
                    Reg(RegId(M68K_REG_D0 as RegIdInt)),
                    Reg(RegId(M68K_REG_D2 as RegIdInt)),
                ],
            ),
            // or.w    d3, (a2)+
            DII::new(
                "or.w",
                b"\x87\x5a",
                &[
                    Reg(RegId(M68K_REG_D3 as RegIdInt)),
                    Mem(M68kOpMem {
                        op_mem: mem_zero,
                        address_mode: M68K_AM_REGI_ADDR_POST_INC,
                        extra_info: M68kOpMemExtraInfo::Reg(RegId(M68K_REG_A2 as RegIdInt)),
                    }),
                ],
            ),
            // nop
            DII::new("nop", b"\x4e\x71", &[]),
            // andi.l  #$c0dec0de, (a4, d5.l * 4)
            DII::new(
                "andi.l",
                b"\x02\xb4\xc0\xde\xc0\xde\x5c\x00",
                &[
                    Imm(0xc0dec0de),
                    Mem(M68kOpMem {
                        op_mem: m68k_op_mem {
                            base_reg: M68K_REG_A4,
                            index_reg: M68K_REG_D5,
                            index_size: 1, // l
                            scale: 4,
                            ..mem_zero
                        },
                        address_mode: M68K_AM_AREGI_INDEX_BASE_DISP,
                        extra_info: M68kOpMemExtraInfo::None,
                    }),
                ],
            ),
            // move.b  d0, ([a6, d7.w], $123)
            DII::new(
                "move.b",
                b"\x1d\x80\x71\x12\x01\x23",
                &[
                    Reg(RegId(M68K_REG_D0 as RegIdInt)),
                    Mem(M68kOpMem {
                        op_mem: m68k_op_mem {
                            base_reg: M68K_REG_A6,
                            index_reg: M68K_REG_D7,
                            out_disp: 0x123, // $123 treated as hex
                            index_size: 0,   // w
                            ..mem_zero
                        },
                        address_mode: M68K_AM_MEMI_PRE_INDEX,
                        extra_info: M68kOpMemExtraInfo::None,
                    }),
                ],
            ),
            // fadd.s  #3.141500, fp0
            DII::new(
                "fadd.s",
                b"\xf2\x3c\x44\x22\x40\x49\x0e\x56",
                &[FpSingle(3.1415), Reg(RegId(M68K_REG_FP0 as RegIdInt))],
            ),
            // scc.b   d5
            DII::new("scc.b", b"\x54\xc5", &[Reg(RegId(M68K_REG_D5 as RegIdInt))]),
            // fmove.s #1000.000000, fp0
            DII::new(
                "fmove.s",
                b"\xf2\x3c\x44\x00\x44\x7a\x00\x00",
                &[FpSingle(1000.000000), Reg(RegId(M68K_REG_FP0 as RegIdInt))],
            ),
            // fsub    fp2, fp4
            DII::new(
                "fsub",
                b"\xf2\x00\x0a\x28",
                &[
                    Reg(RegId(M68K_REG_FP2 as RegIdInt)),
                    Reg(RegId(M68K_REG_FP4 as RegIdInt)),
                ],
            ),
            // jsr     $12.l
            DII::new(
                "jsr",
                b"\x4e\xb9\x00\x00\x00\x12",
                &[Mem(M68kOpMem {
                    op_mem: m68k_op_mem { ..mem_zero },
                    address_mode: M68K_AM_ABSOLUTE_DATA_LONG,
                    extra_info: M68kOpMemExtraInfo::Imm(0x12),
                })],
            ),
            // rts
            DII::new("rts", b"\x4e\x75", &[]),
        ],
    );
}

#[cfg(feature = "arch_mips")]
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
            .extra_mode([mips::ArchExtraMode::Micro].iter().copied())
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

#[cfg(feature = "arch_mips")]
#[test]
fn test_arch_mips_detail() {
    use crate::arch::mips::MipsOperand::*;
    use crate::arch::mips::*;
    use capstone_sys::mips_op_mem;
    use capstone_sys::mips_reg::*;

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
            // ori $at, $at, 0x3456
            DII::new(
                "ori",
                b"\x56\x34\x21\x34",
                &[
                    Reg(RegId(MIPS_REG_AT as RegIdInt)),
                    Reg(RegId(MIPS_REG_AT as RegIdInt)),
                    Imm(13398),
                ],
            ),
            // srl $v0, $at, 0x1f
            DII::new(
                "srl",
                b"\xc2\x17\x01\x00",
                &[
                    Reg(RegId(MIPS_REG_V0 as RegIdInt)),
                    Reg(RegId(MIPS_REG_AT as RegIdInt)),
                    Imm(31),
                ],
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

#[cfg(feature = "arch_mos65xx")]
#[test]
fn test_arch_mos65xx() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xx6502)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xx6502,
        None,
        &[],
        &[("lda", b"\xa1\xa2"), ("ora", b"\x0d\x34\x12")],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xx65c02)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xx65c02,
        None,
        &[],
        &[
            ("inc", b"\x1a"),
            ("dec", b"\x3a"),
            ("nop", b"\x02\x12"),
            ("nop", b"\x03"),
            ("nop", b"\x5c\x34\x12"),
        ],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xxW65c02)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xxW65c02,
        None,
        &[],
        &[("rmb0", b"\x07\x12"), ("rmb2", b"\x27\x12")],
    );

    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xx65816LongMx)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xx65816LongMx,
        None,
        &[],
        &[("lda", b"\xa9\x34\x12"), ("mvp", b"\x44\x34\x12")],
    );
}

#[cfg(feature = "arch_mos65xx")]
#[test]
fn test_arch_mos65xx_detail() {
    use crate::arch::mos65xx::Mos65xxOperand::*;
    use capstone_sys::mos65xx_reg::*;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xx6502)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xx6502,
        None,
        &[],
        &[
            DII::new("lda", b"\xa1\xa2", &[Mem(0xa2)]),
            DII::new("ora", b"\x0d\x34\x12", &[Mem(0x1234)]),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xx65c02)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xx65c02,
        None,
        &[],
        &[
            DII::new("inc", b"\x1a", &[Reg(RegId(MOS65XX_REG_ACC as RegIdInt))]),
            DII::new("dec", b"\x3a", &[Reg(RegId(MOS65XX_REG_ACC as RegIdInt))]),
            DII::new("nop", b"\x02\x12", &[]),
            DII::new("nop", b"\x03", &[]),
            DII::new("nop", b"\x5c\x34\x12", &[]),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xxW65c02)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xxW65c02,
        None,
        &[],
        &[
            DII::new("rmb0", b"\x07\x12", &[Mem(0x12)]),
            DII::new("rmb2", b"\x27\x12", &[Mem(0x12)]),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .mos65xx()
            .mode(mos65xx::ArchMode::Mos65xx65816LongMx)
            .build()
            .unwrap(),
        Arch::MOS65XX,
        Mode::Mos65xx65816LongMx,
        None,
        &[],
        &[
            DII::new("lda", b"\xa9\x34\x12", &[Imm(0x1234)]),
            DII::new("mvp", b"\x44\x34\x12", &[Mem(0x12), Mem(0x34)]),
        ],
    );
}

#[cfg(feature = "arch_powerpc")]
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
            ("bcla", b"\x43\x20\x0c\x07"),
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
            ("bflrl-", b"\x4c\xc8\x00\x21"),
            ("bf", b"\x40\x82\x00\x14"),
        ],
    );
}

#[cfg(feature = "arch_powerpc")]
#[test]
fn test_arch_ppc_detail() {
    use crate::arch::ppc::PpcOperand::*;
    use crate::arch::ppc::PpcReg::*;
    use crate::arch::ppc::*;
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
                    Mem(PpcOpMem(ppc_op_mem {
                        base: PPC_REG_ZERO,
                        disp: 0,
                        offset: 0,
                    })),
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
                        offset: 0,
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
                        offset: 0,
                    })),
                ],
            ),
            // crand   2, 3, 4
            DII::new(
                "crand",
                b"\x4c\x43\x22\x02",
                &[
                    Reg(RegId(PPC_REG_CR0EQ as RegIdInt)),
                    Reg(RegId(PPC_REG_CR0UN as RegIdInt)),
                    Reg(RegId(PPC_REG_CR1LT as RegIdInt)),
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
                    Reg(RegId(PPC_REG_X2 as RegIdInt)),
                    Reg(RegId(PPC_REG_X3 as RegIdInt)),
                    Reg(RegId(PPC_REG_X4 as RegIdInt)),
                ],
            ),
            // bdnzlrl+
            DII::new("bdnzlrl+", b"\x4f\x20\x00\x21", &[]),
            // bflrl- 4*cr2+lt
            DII::new(
                "bflrl-",
                b"\x4c\xc8\x00\x21",
                &[Reg(RegId(PPC_REG_CR2LT as RegIdInt))],
            ),
        ],
    );
}

#[cfg(feature = "arch_sh")]
#[test]
fn test_arch_sh() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .sh()
            .mode(sh::ArchMode::Sh4a)
            .build()
            .unwrap(),
        Arch::SH,
        Mode::Sh4a,
        None,
        &[],
        &[
            ("add", b"\x0c\x31"),
            ("mov.b", b"\x10\x20"),
            ("mov.l", b"\x22\x21"),
        ],
    );
}

#[cfg(feature = "arch_sh")]
#[test]
fn test_arch_sh_detail() {
    use crate::arch::sh::ShOpMem;
    use crate::arch::sh::ShOperand;
    use capstone_sys::sh_op_mem;
    use capstone_sys::sh_reg;
    use capstone_sys::sh_reg::*;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .sh()
            .mode(sh::ArchMode::Sh4a)
            .build()
            .unwrap(),
        Arch::SH,
        Mode::Sh4a,
        None,
        &[],
        &[
            // add r0, r1
            DII::new(
                "add",
                b"\x0c\x31",
                &[
                    ShOperand::Reg(RegId(SH_REG_R0 as RegIdInt)),
                    ShOperand::Reg(RegId(SH_REG_R1 as RegIdInt)),
                ],
            ),
            // mov.b r1,@r0
            DII::new(
                "mov.b",
                b"\x10\x20",
                &[
                    ShOperand::Reg(RegId(SH_REG_R1 as RegIdInt)),
                    ShOperand::Mem(ShOpMem(sh_op_mem {
                        address: capstone_sys::sh_op_mem_type::SH_OP_MEM_REG_IND,
                        reg: SH_REG_R0 as sh_reg::Type,
                        disp: 0,
                    })),
                ],
            ),
            // mov.l @r3+,r4
            DII::new(
                "mov.l",
                b"\x36\x64",
                &[
                    ShOperand::Mem(ShOpMem(sh_op_mem {
                        address: capstone_sys::sh_op_mem_type::SH_OP_MEM_REG_POST,
                        reg: SH_REG_R3 as sh_reg::Type,
                        disp: 0,
                    })),
                    ShOperand::Reg(RegId(SH_REG_R4 as RegIdInt)),
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_sparc")]
#[test]
fn test_arch_sparc() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::V9)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::V9,
        Some(Endian::Big),
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
            .endian(Endian::Big)
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

#[cfg(feature = "arch_sparc")]
#[test]
fn test_arch_sparc_detail() {
    use crate::arch::sparc::SparcOperandType::*;
    use crate::arch::sparc::SparcReg::*;
    use crate::arch::sparc::*;
    use capstone_sys::sparc_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::V9)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::V9,
        Some(Endian::Big),
        &[],
        &[
            // cmp     %g1, %g2
            DII::new(
                "cmp",
                b"\x80\xa0\x40\x02",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G1 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                ],
            ),
            // jmpl    %o1+8, %g2
            DII::new(
                "jmpl",
                b"\x85\xc2\x60\x08",
                &[
                    SparcOperand {
                        op_type: Mem(SparcOpMem(sparc_op_mem {
                            base: SPARC_REG_O1,
                            index: 0,
                            disp: 8,
                        })),
                        access: None,
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // restore %g0, 1, %g2
            DII::new(
                "restore",
                b"\x85\xe8\x20\x01",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G0 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Imm(1),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // mov     1, %o0
            DII::new(
                "mov",
                b"\x90\x10\x20\x01",
                &[
                    SparcOperand {
                        op_type: Imm(1),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O0 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // casx    [%i0], %l6, %o2
            DII::new(
                "casx",
                b"\xd5\xf6\x10\x16",
                &[
                    SparcOperand {
                        op_type: Mem(SparcOpMem(sparc_op_mem {
                            base: SPARC_REG_I0,
                            index: 0,
                            disp: 0,
                        })),
                        access: None,
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_L6 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // sethi   0xa, %l0
            DII::new(
                "sethi",
                b"\x21\x00\x00\x0a",
                &[
                    SparcOperand {
                        op_type: Imm(0xa),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_L0 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // add     %g1, %g2, %g3
            DII::new(
                "add",
                b"\x86\x00\x40\x02",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G1 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G2 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_G3 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // nop
            DII::new("nop", b"\x01\x00\x00\x00", &[]),
            // bne     0x1020
            DII::new(
                "bne",
                b"\x12\xbf\xff\xff",
                &[SparcOperand {
                    op_type: Imm(0x101c),
                    access: Some(AccessType::ReadOnly),
                }],
            ),
            // ba      0x1024
            DII::new(
                "ba",
                b"\x10\xbf\xff\xff",
                &[SparcOperand {
                    op_type: Imm(0x1020),
                    access: Some(AccessType::ReadOnly),
                }],
            ),
            // add     %o0, %o1, %l0
            DII::new(
                "add",
                b"\xa0\x02\x00\x09",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O0 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O1 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_L0 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // fbg     0x102c
            DII::new(
                "fbg",
                b"\x0d\xbf\xff\xff",
                &[SparcOperand {
                    op_type: Imm(0x1028),
                    access: Some(AccessType::ReadOnly),
                }],
            ),
            // st      %o2, [%g1]
            DII::new(
                "st",
                b"\xd4\x20\x60\x00",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Mem(SparcOpMem(sparc_op_mem {
                            base: SPARC_REG_G1,
                            index: 0,
                            disp: 0,
                        })),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // ldsb    [%i0+%l6], %o2
            DII::new(
                "ldsb",
                b"\xd4\x4e\x00\x16",
                &[
                    SparcOperand {
                        op_type: Mem(SparcOpMem(sparc_op_mem {
                            base: SPARC_REG_I0,
                            index: SPARC_REG_L6,
                            disp: 0,
                        })),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // brnz,a,pn       %o2, 0x1048
            DII::new(
                "brnz,a,pn",
                b"\x2a\xc2\x80\x03",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Imm(0x1044),
                        access: Some(AccessType::ReadOnly),
                    },
                ],
            ),
            // membar #LoadLoad
            DII::new(
                "membar",
                b"\x81\x43\xe0\x01",
                &[SparcOperand {
                    op_type: MembarTag(SparcMembarTag::SPARC_MEMBAR_TAG_LOADLOAD),
                    access: Some(AccessType::ReadOnly),
                }],
            ),
            // ldstuba [%i0+%l6] 4, %o2
            DII::new(
                "ldstuba",
                b"\xd4\xee\x00\x96",
                &[
                    SparcOperand {
                        op_type: Mem(SparcOpMem(sparc_op_mem {
                            base: SPARC_REG_I0,
                            index: SPARC_REG_L6,
                            disp: 0,
                        })),
                        access: Some(AccessType::ReadWrite),
                    },
                    SparcOperand {
                        op_type: Asi(SparcAsi::SPARC_ASITAG_ASI_N),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_O2 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
        ],
    );

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .sparc()
            .mode(sparc::ArchMode::V9)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::SPARC,
        Mode::V9,
        Some(Endian::Big),
        &[],
        &[
            // fcmps   %f0, %f4
            DII::new(
                "fcmps",
                b"\x81\xa8\x0a\x24",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_F0 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_F4 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                ],
            ),
            // fstox   %f0, %f4
            DII::new(
                "fstox",
                b"\x89\xa0\x10\x20",
                &[
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_F0 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    // writes to f4-f5, aka d2
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_D2 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // fqtoi   %f0, %f4
            DII::new(
                "fqtoi",
                b"\x89\xa0\x1a\x60",
                &[
                    // reads from f0-f3, aka q0
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_Q0 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_F4 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
            // fnegq   %f0, %f4
            DII::new(
                "fnegq",
                b"\x89\xa0\x00\xe0",
                &[
                    // reads from f0-f3, aka q0
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_Q0 as RegIdInt)),
                        access: Some(AccessType::ReadOnly),
                    },
                    // writes to f4-f7, aka q1
                    SparcOperand {
                        op_type: Reg(RegId(SPARC_REG_Q1 as RegIdInt)),
                        access: Some(AccessType::WriteOnly),
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_systemz")]
#[test]
fn test_arch_systemz() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .systemz()
            .mode(systemz::ArchMode::SystemZGeneric)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::SYSTEMZ,
        Mode::SystemZGeneric,
        Some(Endian::Big),
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

#[cfg(feature = "arch_systemz")]
#[test]
fn test_arch_systemz_detail() {
    use crate::arch::systemz::SystemZOperand::*;
    use crate::arch::systemz::SystemZReg::*;
    use crate::arch::systemz::*;
    use capstone_sys::systemz_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .systemz()
            .mode(systemz::ArchMode::SystemZGeneric)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::SYSTEMZ,
        Mode::SystemZGeneric,
        Some(Endian::Big),
        &[],
        &[
            // br %r7
            DII::new(
                "br",
                b"\x07\xf7",
                &[Reg(RegId(SYSTEMZ_REG_R7D as RegIdInt))],
            ),
            // ear %r7, %a8
            DII::new(
                "ear",
                b"\xb2\x4f\x00\x78",
                &[
                    Reg(RegId(SYSTEMZ_REG_R7L as RegIdInt)),
                    Reg(RegId(SYSTEMZ_REG_A8 as RegIdInt)),
                ],
            ),
            // adb %f0, 0
            DII::new(
                "adb",
                b"\xed\x00\x00\x00\x00\x1a",
                &[
                    Reg(RegId(SYSTEMZ_REG_F0D as RegIdInt)),
                    Mem(SystemZOpMem(systemz_op_mem {
                        am: capstone_sys::systemz_addr_mode::SYSTEMZ_AM_BDX,
                        base: 0,
                        index: 0,
                        length: 0,
                        disp: 0,
                    })),
                ],
            ),
            // afi %r0, -0x80000000
            DII::new(
                "afi",
                b"\xc2\x09\x80\x00\x00\x00",
                &[Reg(RegId(SYSTEMZ_REG_R0L as RegIdInt)), Imm(-0x80000000)],
            ),
            // a %r0, 0xfff(%r15, %r1)
            DII::new(
                "a",
                b"\x5a\x0f\x1f\xff",
                &[
                    Reg(RegId(SYSTEMZ_REG_R0L as RegIdInt)),
                    Mem(SystemZOpMem(systemz_op_mem {
                        base: SYSTEMZ_REG_R1D as u8,
                        index: SYSTEMZ_REG_R15D as u8,
                        disp: 0xfff,
                        length: 0,
                        am: capstone_sys::systemz_addr_mode::SYSTEMZ_AM_BDX,
                    })),
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_tms320c64x")]
#[test]
fn test_arch_tms320c64x_detail() {
    use crate::arch::tms320c64x::{
        Tms320c64xFuntionalUnit, Tms320c64xMemDirection, Tms320c64xMemDisplayType,
        Tms320c64xMemModify, Tms320c64xOpMem, Tms320c64xOperand::*, Tms320c64xReg::*,
    };
    use capstone_sys::tms320c64x_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .tms320c64x()
            .mode(tms320c64x::ArchMode::Default)
            .endian(Endian::Big)
            .build()
            .unwrap(),
        Arch::TMS320C64X,
        Mode::Default,
        Some(Endian::Big),
        &[],
        &[
            // add.D1    a11, a4, a3
            DII::new(
                "add.D1",
                b"\x01\xac\x88\x40",
                &[
                    Reg(RegId(TMS320C64X_REG_A11 as RegIdInt)),
                    Reg(RegId(TMS320C64X_REG_A4 as RegIdInt)),
                    Reg(RegId(TMS320C64X_REG_A3 as RegIdInt)),
                ],
            ),
            // [ a1] add.D2    b11, b4, b3     ||
            DII::new(
                "[ a1] add.D2",
                b"\x81\xac\x88\x43",
                &[
                    Reg(RegId(TMS320C64X_REG_B11 as RegIdInt)),
                    Reg(RegId(TMS320C64X_REG_B4 as RegIdInt)),
                    Reg(RegId(TMS320C64X_REG_B3 as RegIdInt)),
                ],
            ),
            // ldbu.D2T2 *+b15[0x46], b5
            DII::new(
                "ldbu.D2T2",
                b"\x02\x80\x46\x9e",
                &[
                    Mem(Tms320c64xOpMem(tms320c64x_op_mem {
                        base: TMS320C64X_REG_B15 as c_uint,
                        disp: 0x46,
                        unit: Tms320c64xFuntionalUnit::L as c_uint,
                        scaled: false as c_uint,
                        disptype: Tms320c64xMemDisplayType::Constant as c_uint,
                        direction: Tms320c64xMemDirection::Forward as c_uint,
                        modify: Tms320c64xMemModify::No as c_uint,
                    })),
                    Reg(RegId(TMS320C64X_REG_B5 as RegIdInt)),
                ],
            ),
            // NOP
            DII::new("NOP", b"\x00\x00\x00\x00", &[]),
            // ldbu.D1T2 *++a4[1], b5
            DII::new(
                "ldbu.D1T2",
                b"\x02\x90\x32\x96",
                &[
                    Mem(Tms320c64xOpMem(tms320c64x_op_mem {
                        base: TMS320C64X_REG_A4 as c_uint,
                        disp: 0x1,
                        unit: Tms320c64xFuntionalUnit::L as c_uint,
                        scaled: true as c_uint,
                        disptype: Tms320c64xMemDisplayType::Constant as c_uint,
                        direction: Tms320c64xMemDirection::Forward as c_uint,
                        modify: Tms320c64xMemModify::Pre as c_uint,
                    })),
                    Reg(RegId(TMS320C64X_REG_B5 as RegIdInt)),
                ],
            ),
            // ldbu.D2T2 *+b15[0x46], b5
            DII::new(
                "ldbu.D2T2",
                b"\x02\x80\x46\x9e",
                &[
                    Mem(Tms320c64xOpMem(tms320c64x_op_mem {
                        base: TMS320C64X_REG_B15 as c_uint,
                        disp: 0x46,
                        unit: Tms320c64xFuntionalUnit::L as c_uint,
                        scaled: false as c_uint,
                        disptype: Tms320c64xMemDisplayType::Constant as c_uint,
                        direction: Tms320c64xMemDirection::Forward as c_uint,
                        modify: Tms320c64xMemModify::No as c_uint,
                    })),
                    Reg(RegId(TMS320C64X_REG_B5 as RegIdInt)),
                ],
            ),
            // lddw.D1T2 *+a15[4], b11:b10
            DII::new(
                "lddw.D1T2",
                b"\x05\x3c\x83\xe6",
                &[
                    Mem(Tms320c64xOpMem(tms320c64x_op_mem {
                        base: TMS320C64X_REG_A15 as c_uint,
                        disp: 0x4,
                        unit: Tms320c64xFuntionalUnit::L as c_uint,
                        scaled: true as c_uint,
                        disptype: Tms320c64xMemDisplayType::Constant as c_uint,
                        direction: Tms320c64xMemDirection::Forward as c_uint,
                        modify: Tms320c64xMemModify::No as c_uint,
                    })),
                    RegPair(
                        RegId(TMS320C64X_REG_B11 as RegIdInt),
                        RegId(TMS320C64X_REG_B10 as RegIdInt),
                    ),
                ],
            ),
            // ldndw.D1T1        *+a3(a4), a23:a22
            DII::new(
                "ldndw.D1T1",
                b"\x0b\x0c\x8b\x24",
                &[
                    Mem(Tms320c64xOpMem(tms320c64x_op_mem {
                        base: TMS320C64X_REG_A3 as c_uint,
                        disp: TMS320C64X_REG_A4 as c_uint,
                        unit: Tms320c64xFuntionalUnit::D as c_uint,
                        scaled: false as c_uint,
                        disptype: Tms320c64xMemDisplayType::Register as c_uint,
                        direction: Tms320c64xMemDirection::Forward as c_uint,
                        modify: Tms320c64xMemModify::No as c_uint,
                    })),
                    RegPair(
                        RegId(TMS320C64X_REG_A23 as RegIdInt),
                        RegId(TMS320C64X_REG_A22 as RegIdInt),
                    ),
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_tricore")]
#[test]
fn test_arch_tricore() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .tricore()
            .mode(tricore::ArchMode::TriCore162)
            .build()
            .unwrap(),
        Arch::TRICORE,
        Mode::TriCore162,
        None,
        &[],
        &[("ld.a", b"\x09\xcf\xbc\xf5")],
    );
}

#[cfg(feature = "arch_tricore")]
#[test]
fn test_arch_tricore_detail() {
    use crate::arch::tricore::TriCoreOpMem;
    use crate::arch::tricore::TriCoreOperand;
    use capstone_sys::tricore_op_mem;
    use capstone_sys::tricore_reg::*;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .tricore()
            .mode(tricore::ArchMode::TriCore162)
            .build()
            .unwrap(),
        Arch::TRICORE,
        Mode::TriCore162,
        None,
        &[],
        &[
            // ld.a a15, [+a12]#-4
            DII::new(
                "ld.a",
                b"\x09\xcf\xbc\xf5",
                &[
                    TriCoreOperand::Reg(RegId(TRICORE_REG_A15 as RegIdInt)),
                    TriCoreOperand::Mem(TriCoreOpMem(tricore_op_mem {
                        base: TRICORE_REG_A12 as u8,
                        disp: -4,
                    })),
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_x86")]
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

#[cfg(feature = "arch_x86")]
#[test]
fn test_arch_x86_detail() {
    use crate::arch::x86::X86OperandType::*;
    use crate::arch::x86::X86Reg::*;
    use crate::arch::x86::*;
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
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(X86_REG_CX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 2,
                        access: Some(AccessType::ReadOnly),
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
                        access: Some(AccessType::ReadWrite),
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
                        access: Some(AccessType::ReadOnly),
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
                    access: Some(AccessType::ReadOnly),
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
                        access: Some(AccessType::ReadWrite),
                        op_type: Reg(RegId(X86_REG_AL as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 1,
                        access: Some(AccessType::ReadOnly),
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
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(X86_REG_ECX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 4,
                        access: Some(AccessType::ReadOnly),
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
                        access: Some(AccessType::ReadWrite),
                        op_type: Reg(RegId(X86_REG_EAX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 4,
                        access: Some(AccessType::ReadOnly),
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
                        access: Some(AccessType::ReadWrite),
                        op_type: Reg(RegId(X86_REG_ESI as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 4,
                        access: None,
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
                    access: Some(AccessType::ReadOnly),
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
                        access: Some(AccessType::WriteOnly),
                        op_type: Reg(RegId(X86_REG_RAX as RegIdInt)),
                        ..Default::default()
                    },
                    X86Operand {
                        size: 8,
                        access: Some(AccessType::ReadOnly),
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

#[cfg(feature = "arch_xcore")]
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
#[cfg(feature = "arch_xcore")]
#[test]
fn test_arch_xcore_detail() {
    use crate::arch::xcore::XcoreOperand::*;
    use crate::arch::xcore::XcoreReg::*;
    use crate::arch::xcore::*;
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

#[cfg(feature = "arch_xtensa")]
#[test]
fn test_arch_xtensa() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .xtensa()
            .mode(xtensa::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::XTENSA,
        Mode::Default,
        None,
        &[],
        &[("abs", b"\x60\x51\x60"), ("add.n", b"\x1a\x23")],
    );
}

#[cfg(feature = "arch_xtensa")]
#[test]
fn test_arch_xtensa_detail() {
    use crate::arch::xtensa::{XtensaOpMem, XtensaOperand};
    use capstone_sys::{cs_xtensa_op_mem, xtensa_reg::*};

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .xtensa()
            .mode(xtensa::ArchMode::Default)
            .build()
            .unwrap(),
        Arch::XTENSA,
        Mode::Default,
        None,
        &[],
        &[
            // abs a5, a6
            DII::new(
                "abs",
                b"\x60\x51\x60",
                &[
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Reg(RegId(XTENSA_REG_A5 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Reg(RegId(XTENSA_REG_A6 as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
            // add.n a2, a3, a1
            DII::new(
                "add.n",
                b"\x1a\x23",
                &[
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Reg(RegId(XTENSA_REG_A2 as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Reg(RegId(XTENSA_REG_A3 as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                    },
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Reg(RegId(XTENSA_REG_SP as RegIdInt)),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
            // l32i.n a1, a3, 8
            DII::new(
                "l32i.n",
                b"\x18\x23",
                &[
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Reg(RegId(XTENSA_REG_SP as RegIdInt)),
                        access: Some(RegAccessType::WriteOnly),
                    },
                    XtensaOperand {
                        op_type: xtensa::XtensaOperandType::Mem(XtensaOpMem(cs_xtensa_op_mem {
                            base: XTENSA_REG_A3 as u8,
                            disp: 8,
                        })),
                        access: Some(RegAccessType::ReadOnly),
                    },
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_riscv")]
#[test]
fn test_arch_riscv() {
    test_arch_mode_endian_insns(
        &mut Capstone::new()
            .riscv()
            .mode(riscv::ArchMode::RiscV64)
            .extra_mode([riscv::ArchExtraMode::RiscVC].iter().copied())
            .build()
            .unwrap(),
        Arch::RISCV,
        Mode::RiscV64,
        None,
        &[ExtraMode::RiscVC],
        &[
            ("addi", b"\x93\x00\x31\x00"),
            ("add", b"\xb3\x00\x31\x00"),
            ("ld", b"\x03\xb2\x82\x00"),
            ("c.ebreak", b"\x02\x90"),
            ("c.addi", b"\x05\x04"),
            ("c.add", b"\x2a\x94"),
            ("c.ld", b"\x0c\x66"),
        ],
    );
}

#[cfg(feature = "arch_riscv")]
#[test]
fn test_arch_riscv_detail() {
    use crate::arch::riscv::RiscVOperand::*;
    use crate::arch::riscv::RiscVReg::*;
    use crate::arch::riscv::*;
    use capstone_sys::riscv_op_mem;

    test_arch_mode_endian_insns_detail(
        &mut Capstone::new()
            .riscv()
            .mode(riscv::ArchMode::RiscV64)
            .extra_mode([riscv::ArchExtraMode::RiscVC].iter().copied())
            .build()
            .unwrap(),
        Arch::RISCV,
        Mode::RiscV64,
        None,
        &[ExtraMode::RiscVC],
        &[
            // addi x1, x2, 3
            DII::new(
                "addi",
                b"\x93\x00\x31\x00",
                &[
                    Reg(RegId(RISCV_REG_X1 as RegIdInt)),
                    Reg(RegId(RISCV_REG_X2 as RegIdInt)),
                    Imm(3),
                ],
            ),
            // add x1, x2, x3
            DII::new(
                "add",
                b"\xb3\x00\x31\x00",
                &[
                    Reg(RegId(RISCV_REG_X1 as RegIdInt)),
                    Reg(RegId(RISCV_REG_X2 as RegIdInt)),
                    Reg(RegId(RISCV_REG_X3 as RegIdInt)),
                ],
            ),
            // ld x4, 8(x5)
            DII::new(
                "ld",
                b"\x03\xb2\x82\x00",
                &[
                    Reg(RegId(RISCV_REG_X4 as RegIdInt)),
                    Mem(RiscVOpMem(riscv_op_mem {
                        base: RISCV_REG_X5 as c_uint,
                        disp: 8,
                    })),
                ],
            ),
            // c.ebreak
            DII::new("c.ebreak", b"\x02\x90", &[]),
            // c.addi x8, 1
            DII::new(
                "c.addi",
                b"\x05\x04",
                &[Reg(RegId(RISCV_REG_X8 as RegIdInt)), Imm(1)],
            ),
            // c.add x8, x10
            DII::new(
                "c.add",
                b"\x2a\x94",
                &[
                    Reg(RegId(RISCV_REG_X8 as RegIdInt)),
                    Reg(RegId(RISCV_REG_X10 as RegIdInt)),
                ],
            ),
            // c.ld x11, 8(x12)
            DII::new(
                "c.ld",
                b"\x0c\x66",
                &[
                    Reg(RegId(RISCV_REG_X11 as RegIdInt)),
                    Mem(RiscVOpMem(riscv_op_mem {
                        base: RISCV_REG_X12 as u32,
                        disp: 8,
                    })),
                ],
            ),
        ],
    );
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_insn_size_and_alignment() {
    use capstone_sys::cs_insn;

    // Ensure that Insn and cs_insn have the same size
    // and alignment so that they can be safely transmuted
    // from and to each other:

    assert_eq!(
        core::mem::size_of::<Insn>(),
        core::mem::size_of::<cs_insn>(),
        "sizeof(Insn) == sizeof(cs_insn)"
    );

    assert_eq!(
        core::mem::align_of::<Insn>(),
        core::mem::align_of::<cs_insn>(),
        "alignof(Insn) == alignof(cs_insn)"
    );

    // Make sure that conversion is valid:

    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();
    cs.set_detail(false).unwrap();
    let insns = cs.disasm_all(X86_CODE, START_TEST_ADDR).unwrap();
    let insns_slice: &[Insn] = &insns;

    assert_eq!(insns.len(), insns_slice.len());

    for (original, transmuted) in insns.iter().zip(insns_slice.iter()) {
        assert_eq!(original.id(), transmuted.id());
    }
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_insn_from_raw() {
    use capstone_sys::cs_insn;

    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .build()
        .unwrap();

    let insns = cs.disasm_all(X86_CODE, START_TEST_ADDR).unwrap();
    for insn in insns.iter() {
        let raw_insn = &insn.insn as *const cs_insn;
        let from_raw_insn = unsafe { Insn::from_raw(raw_insn) };
        assert_eq!(format!("{:?}", from_raw_insn), format!("{:?}", insn));
    }
}

#[cfg(feature = "arch_x86")]
#[test]
fn test_owned_insn() {
    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .unwrap();

    let insns = cs.disasm_all(X86_CODE, START_TEST_ADDR).unwrap();
    let owned: Vec<OwnedInsn> = insns.iter().map(|i| i.into()).collect();
    for (insn, owned) in insns.iter().zip(&owned) {
        assert_eq!(format!("{:?}", insn), format!("{:?}", owned));
    }

    // test disasm_iter
    let mut iter_insns = cs.disasm_iter(X86_CODE, START_TEST_ADDR).unwrap();
    let mut iter_owned: Vec<OwnedInsn> = vec![];
    while let Some(insn) = iter_insns.next() {
        iter_owned.push((&insn).into());
    }
    for (insn, owned) in insns.iter().zip(&iter_owned) {
        assert_eq!(format!("{:?}", insn), format!("{:?}", owned));
    }
}

/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg(feature = "full")]
struct RegAccessVec {
    read: Vec<RegId>,
    write: Vec<RegId>,
}

#[cfg(feature = "full")]
impl RegAccessVec {
    /// Sort read and write fields
    fn sort(&mut self) {
        self.read.sort_unstable();
        self.write.sort_unstable();
    }
}

/// Get the registers which are read and written
#[cfg(feature = "full")]
fn regs_access_vec(cs: &Capstone, insn: &Insn) -> CsResult<RegAccessVec> {
    let mut regs_read = [MaybeUninit::uninit(); REGS_ACCESS_BUF_LEN];
    let mut regs_write = [MaybeUninit::uninit(); REGS_ACCESS_BUF_LEN];

    let reg_access = cs.regs_access(insn, &mut regs_read, &mut regs_write)?;

    Ok(RegAccessVec {
        read: reg_access.read.to_vec(),
        write: reg_access.write.to_vec(),
    })
}

#[cfg(feature = "full")]
fn assert_regs_access_matches(
    cs: &mut Capstone,
    bytes: &[u8],
    expected_regs_access: CsResult<&[RegAccessVec]>,
) {
    let expected_regs_access = expected_regs_access.map(|accesses: &[RegAccessVec]| {
        accesses
            .iter()
            .map(|regs| {
                let mut regs = regs.clone();
                regs.sort();
                regs
            })
            .collect::<Vec<RegAccessVec>>()
    });
    let insns = cs.disasm_all(bytes, 0x1000).unwrap();
    let reg_access: CsResult<Vec<RegAccessVec>> = insns
        .iter()
        .map(|insn| {
            regs_access_vec(cs, insn).map(|mut regs| {
                regs.sort();
                regs
            })
        })
        .collect();
    let reg_access = reg_access.as_ref().map(|access| access.as_slice());
    assert_eq!(reg_access, expected_regs_access.as_deref());
}

fn as_reg_access<T: TryInto<RegIdInt> + Copy + Debug>(read: &[T], write: &[T]) -> RegAccessVec {
    let as_reg_access = |input: &[T]| -> Vec<RegId> {
        input
            .iter()
            .copied()
            .map(|reg| {
                RegId(
                    reg.try_into()
                        .unwrap_or_else(|_| panic!("Failed to create RegInt")),
                )
            })
            .collect()
    };
    RegAccessVec {
        read: as_reg_access(read),
        write: as_reg_access(write),
    }
}

#[cfg(feature = "full")]
fn test_regs_access(
    mut cs: Capstone,
    code: &[u8],
    expected_regs_access: CsResult<&[RegAccessVec]>,
) {
    // should always fail when not in debug mode
    assert_regs_access_matches(&mut cs, code, CsResult::Err(Error::DetailOff));

    // now detail is enabled, check for expected outcome
    cs.set_detail(true).expect("failed to set detail");
    assert_regs_access_matches(&mut cs, code, expected_regs_access);
}

#[cfg(all(feature = "full", feature = "arch_arm"))]
#[test]
fn test_regs_access_arm() {
    use crate::arch::arm::ArmReg::*;

    test_regs_access(
        Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .build()
            .unwrap(),
        b"\xf0\xbd",
        CsResult::Ok(&[as_reg_access(
            &[ARM_REG_SP],
            &[
                ARM_REG_SP, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC,
            ],
        )]),
    );
}

#[cfg(all(feature = "full", feature = "arch_tms320c64x"))]
#[test]
fn test_regs_tms320c64x() {
    test_regs_access(
        Capstone::new()
            .tms320c64x()
            .mode(tms320c64x::ArchMode::Default)
            .build()
            .unwrap(),
        b"\x01\xac\x88\x40",
        CsResult::Err(Error::UnsupportedArch),
    );
}

// regression tests
#[cfg(feature = "arch_aarch64")]
#[test]
fn test_issue_175() {
    let cs = Capstone::new()
        .aarch64()
        .detail(true)
        .mode(aarch64::ArchMode::Arm)
        .build()
        .unwrap();

    let insns = cs.disasm_all(&[0x0c, 0x44, 0x3b, 0xd5], 0).unwrap();
    for i in insns.as_ref() {
        let id = cs.insn_detail(&i).unwrap();
        let ad = id.arch_detail();
        let aarch = ad.aarch64().unwrap();

        println!("{i} (dt: {:?})", aarch.operands().collect::<Vec<_>>());
    }
}
