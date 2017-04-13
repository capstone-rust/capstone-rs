extern crate libc;

pub mod instruction;
pub mod constants;
mod ffi;
pub mod capstone;

pub use instruction::*;
pub use constants::*;

pub use capstone::Capstone;

/// An opaque reference to a capstone engine.
///
/// bindgen by default used this type name everywhere, so it is easier to leave it with a confusing
/// name.
///
/// It should not be exported, rust's new visibility rules make tackling this not immediately
/// obvious
#[allow(non_camel_case_types)]
type csh = libc::size_t;

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use super::*;

    static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

    #[test]
    fn test_x86_simple() {
        match capstone::Capstone::new(constants::CsArch::ARCH_X86, constants::CsMode::MODE_64) {
            Ok(cs) => {
                match cs.disasm(CODE, 0x1000, 0) {
                    Ok(insns) => {
                        assert_eq!(insns.len(), 2);
                        let is: Vec<_> = insns.iter().collect();
                        assert_eq!(is[0].mnemonic().unwrap(), "push");
                        assert_eq!(is[1].mnemonic().unwrap(), "mov");

                        assert_eq!(is[0].address, 0x1000);
                        assert_eq!(is[1].address, 0x1001);

                        assert_eq!(is[0].get_bytes(), b"\x55");
                        assert_eq!(is[1].get_bytes(), b"\x48\x8b\x05\xb8\x13\x00\x00");
                    }
                    Err(err) => assert!(false, "Couldn't disasm instructions: {}", err),
                }
            }
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_x86_names() {
        match capstone::Capstone::new(constants::CsArch::ARCH_X86, constants::CsMode::MODE_64) {
            Ok(cs) => {
                let reg_id = 1;
                match cs.reg_name(reg_id) {
                    Some(reg_name) => assert_eq!(reg_name, "ah"),
                    None => assert!(false, "Couldn't get register name"),
                }

                let insn_id = 1;
                match cs.insn_name(insn_id) {
                    Some(insn_name) => assert_eq!(insn_name, "aaa"),
                    None => assert!(false, "Couldn't get instruction name"),
                }

                assert_eq!(cs.group_name(1), Some(String::from("jump")));

                let reg_id = 6000;
                match cs.reg_name(reg_id) {
                    Some(_) => assert!(false, "invalid register worked"),
                    None => {}
                }

                let insn_id = 6000;
                match cs.insn_name(insn_id) {
                    Some(_) => assert!(false, "invalid instruction worked"),
                    None => {}
                }

                assert_eq!(cs.group_name(6000), None);
            }
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_detail_false_fail() {
        let mut cs = capstone::Capstone::new(constants::CsArch::ARCH_X86,
                                             constants::CsMode::MODE_64)
                .unwrap();
        cs.set_detail(false).unwrap();
        let insns: Vec<_> = cs.disasm(CODE, 0x1000, 0).unwrap().iter().collect();
        assert_eq!(cs.insn_belongs_to_group(&insns[0], 0),
                   Err(CsErr::CS_ERR_DETAIL));
        assert_eq!(cs.insn_belongs_to_group(&insns[1], 0),
                   Err(CsErr::CS_ERR_DETAIL));
    }

    #[test]
    fn test_detail_true() {
        let mut cs = capstone::Capstone::new(constants::CsArch::ARCH_X86,
                                             constants::CsMode::MODE_64)
                .unwrap();
        cs.set_detail(true).unwrap();
        let insns: Vec<_> = cs.disasm(CODE, 0x1000, 0).unwrap().iter().collect();
        let insn_group_ids = [CsGroupType::CS_GRP_JUMP,
                              CsGroupType::CS_GRP_CALL,
                              CsGroupType::CS_GRP_RET,
                              CsGroupType::CS_GRP_INT,
                              CsGroupType::CS_GRP_IRET];
        for insn_idx in 0..1 + 1 {
            for insn_group_id in &insn_group_ids {
                assert_eq!(cs.insn_belongs_to_group(&insns[insn_idx], *insn_group_id as u64),
                           Ok(false));
            }
        }
    }

    /// Assert instruction belongs or does not belong to groups, testing both insn_belongs_to_group
    /// and get_insn_group_ids
    fn test_x86_instruction_group_ids_helper(mnemonic_name: &str,
                                             bytes: &[u8],
                                             expected_groups: &[CsGroupType]) {
        let mut cs = capstone::Capstone::new(constants::CsArch::ARCH_X86,
                                             constants::CsMode::MODE_64)
                .expect("Failed to create capstone handle");

        // Details required to get groups information
        cs.set_detail(true).unwrap();

        // Disassemble instructions
        let insns: Vec<_> = cs.disasm(bytes, 0x1000, 0)
            .expect("Failed to disassemble")
            .iter()
            .collect();

        // Check number of instructions
        assert_eq!(insns.len(), 1, "Expected exactly 1 instruction");

        let insn = &insns[0];

        // Check mnemonic
        assert_eq!(mnemonic_name,
                   cs.insn_name(insn.get_id() as u64)
                       .expect("Failed to get instruction name"));

        // Assert expected instruction groups is a subset of computed groups
        let instruction_groups: HashSet<u8> = cs.get_insn_group_ids(&insn)
            .expect("failed to get instruction groups")
            .iter()
            .map(|&x| x)
            .collect();
        let expected_groups_u8: HashSet<u8> = expected_groups.iter().map(|&x| x as u8).collect();
        assert!(expected_groups_u8.is_subset(&instruction_groups),
                "Expected groups {:?} does NOT match computed insn groups {:?}",
                expected_groups_u8,
                instruction_groups);


        // Create sets of expected groups and unexpected groups
        let instruction_types: HashSet<CsGroupType> = [CsGroupType::CS_GRP_JUMP,
                                                       CsGroupType::CS_GRP_CALL,
                                                       CsGroupType::CS_GRP_RET,
                                                       CsGroupType::CS_GRP_INT,
                                                       CsGroupType::CS_GRP_IRET]
                .iter()
                .cloned()
                .collect();
        let expected_groups_set: HashSet<CsGroupType> =
            expected_groups.iter().map(|&x| x).collect();
        let not_belong_groups = instruction_types.difference(&expected_groups_set);

        // Assert instruction belongs to belong_groups
        for belong_group in expected_groups {
            assert_eq!(Ok(true),
                       cs.insn_belongs_to_group(&insn, *belong_group as u64),
                       "{:?} does NOT BELONG to group {:?}, but the instruction SHOULD",
                       insn,
                       *belong_group);
        }

        // Assert instruction does not belong to not_belong_groups
        for not_belong_group in not_belong_groups {
            assert_eq!(Ok(false),
                       cs.insn_belongs_to_group(&insn, *not_belong_group as u64),
                       "{:?} BELONGS to group {:?}, but the instruction SHOULD NOT",
                       insn,
                       *not_belong_group);
        }
    }

    #[test]
    fn test_instruction_group_ids() {
        let jump = CsGroupType::CS_GRP_JUMP;
        let call = CsGroupType::CS_GRP_CALL;
        let ret = CsGroupType::CS_GRP_RET;
        let int = CsGroupType::CS_GRP_INT;
        let iret = CsGroupType::CS_GRP_IRET;

        test_x86_instruction_group_ids_helper("nop", b"\x90", &[]);
        test_x86_instruction_group_ids_helper("je", b"\x74\x05", &[jump]);
        test_x86_instruction_group_ids_helper("call", b"\xe8\x28\x07\x00\x00", &[call]);
        test_x86_instruction_group_ids_helper("ret", b"\xc3", &[ret]);
        test_x86_instruction_group_ids_helper("syscall", b"\x0f\x05", &[int]);
        test_x86_instruction_group_ids_helper("iretd", b"\xcf", &[iret]);
        test_x86_instruction_group_ids_helper("sub", b"\x48\x83\xec\x08", &[]);
        test_x86_instruction_group_ids_helper("test", b"\x48\x85\xc0", &[]);
    }

    #[test]
    fn test_invalid_mode() {
        match capstone::Capstone::new(constants::CsArch::ARCH_ALL, constants::CsMode::MODE_64) {
            Ok(_) => assert!(false, "Invalid open worked"),
            Err(err) => assert!(err == constants::CsErr::CS_ERR_ARCH),
        }
    }

    #[test]
    fn test_capstone_version() {
        let (major, minor) = capstone::lib_version();
        println!("Capstone lib version: ({}, {})", major, minor);
        assert!(major > 0 && major < 100, "Invalid major version {}", major);
        assert!(minor < 500, "Invalid minor version {}", minor);
    }

    #[test]
    fn test_capstone_supports_arch() {
        let architectures = vec![CsArch::ARCH_ARM,
                                 CsArch::ARCH_ARM64,
                                 CsArch::ARCH_MIPS,
                                 CsArch::ARCH_X86,
                                 CsArch::ARCH_PPC,
                                 CsArch::ARCH_SPARC,
                                 CsArch::ARCH_SYSZ,
                                 CsArch::ARCH_XCORE,
                                 CsArch::CS_ARCH_M68K];

        println!("Supported architectures");
        for arch in architectures {
            let supports_arch = capstone::supports_arch(arch);
            println!("  {:?}: {}", arch, if supports_arch { "yes" } else { "no" });
        }
    }

    #[test]
    fn test_capstone_is_diet() {
        println!("Capstone is diet: {}", capstone::is_diet());
    }
}
