//! Bindings to the [capstone library][upstream] disassembly framework.
//!
//! This crate is a wrapper around the
//! [Capstone disassembly library](http://www.capstone-engine.org/),
//! a "lightweight multi-platform, multi-architecture disassembly framework."
//!
//! The [`Capstone`](struct.Capstone.html) struct is the main interface to the library.
//!
//! ```rust
//! extern crate capstone;
//! use capstone::prelude::*;
//!
//! const CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
//! fn main() {
//!     match Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build() {
//!         Ok(cs) => {
//!             match cs.disasm_all(CODE, 0x1000) {
//!                 Ok(insns) => {
//!                     println!("Got {} instructions", insns.len());
//!
//!                     for i in insns.iter() {
//!                         println!("{}", i);
//!                     }
//!                 },
//!                 Err(err) => {
//!                     println!("Error: {}", err)
//!                 }
//!             }
//!         },
//!         Err(err) => {
//!             println!("Error: {}", err)
//!         }
//!     }
//! }
//! ```
//!
//! Produces:
//!
//! ```no_test
//! Got 2 instructions
//! 0x1000: push rbp
//! 0x1001: mov rax, qword ptr [rip + 0x13b8]
//! ```
//!
//! [upstream]: http://capstone-engine.org/
//!

extern crate capstone_sys;

pub mod arch;
mod capstone;
mod constants;
mod error;
mod instruction;

pub use capstone::*;
pub use constants::*;
pub use instruction::*;
pub use error::*;

/// Contains items that you probably want to always import
///
/// For example:
///
/// ```
/// use capstone::prelude::*;
/// ```
pub mod prelude {
    pub use {Capstone, CsResult};
    pub use arch::{self, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode,
                   BuildsCapstoneSyntax};
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use capstone_sys::cs_group_type;
    use super::*;
    use super::arch::*;

    const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
    const ARM_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

    // Aliases for group types
    const JUMP: cs_group_type = cs_group_type::CS_GRP_JUMP;
    const CALL: cs_group_type = cs_group_type::CS_GRP_CALL;
    const RET: cs_group_type = cs_group_type::CS_GRP_RET;
    const INT: cs_group_type = cs_group_type::CS_GRP_INT;
    const IRET: cs_group_type = cs_group_type::CS_GRP_IRET;

    #[test]
    fn test_x86_simple() {
        match Capstone::new().x86().mode(x86::ArchMode::Mode64).build() {
            Ok(cs) => {
                match cs.disasm_all(X86_CODE, 0x1000) {
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
                }
            }
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_arm_simple() {
        match Capstone::new().arm().mode(arm::ArchMode::Arm).build() {
            Ok(cs) => {
                match cs.disasm_all(ARM_CODE, 0x1000) {
                    Ok(insns) => {
                        assert_eq!(insns.len(), 2);
                        let is: Vec<_> = insns.iter().collect();
                        assert_eq!(is[0].mnemonic().unwrap(), "streq");
                        assert_eq!(is[1].mnemonic().unwrap(), "strheq");

                        assert_eq!(is[0].address(), 0x1000);
                        assert_eq!(is[1].address(), 0x1004);
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
        let mut cs = Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode64)
            .build()
            .unwrap();
        cs.set_detail(false).unwrap();
        let insns: Vec<_> = cs.disasm_all(X86_CODE, 0x1000).unwrap().iter().collect();
        assert_eq!(
            cs.insn_belongs_to_group(&insns[0], 0),
            Err(Error::Capstone(CapstoneError::DetailOff))
        );
        assert_eq!(
            cs.insn_belongs_to_group(&insns[1], 0),
            Err(Error::Capstone(CapstoneError::DetailOff))
        );
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
            let insns: Vec<_> = cs.disasm_all(X86_CODE, 0x1000).unwrap().iter().collect();
            let insn_group_ids = [
                cs_group_type::CS_GRP_JUMP,
                cs_group_type::CS_GRP_CALL,
                cs_group_type::CS_GRP_RET,
                cs_group_type::CS_GRP_INT,
                cs_group_type::CS_GRP_IRET,
            ];
            for insn_idx in 0..1 + 1 {
                for insn_group_id in &insn_group_ids {
                    assert_eq!(
                        cs.insn_belongs_to_group(&insns[insn_idx], *insn_group_id as u64),
                        Ok(false)
                    );
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
        // Check mnemonic
        if has_default_syntax {
            // insn_name() does not respect current syntax
            // does not always match the internal mnemonic
            cs.insn_name(insn.id() as u64).expect(
                "Failed to get instruction name",
            );
        }
        assert_eq!(
            mnemonic_name,
            insn.mnemonic().expect("Failed to get mnemonic"),
            "Did not match contained insn.mnemonic"
        );

        // Assert instruction bytes match
        assert_eq!(bytes, insn.bytes());
    }

    /// Assert instruction belongs or does not belong to groups, testing both insn_belongs_to_group
    /// and insn_group_ids
    fn test_instruction_group_helper(
        cs: &Capstone,
        insn: &Insn,
        mnemonic_name: &str,
        bytes: &[u8],
        expected_groups: &[cs_group_type],
        has_default_syntax: bool,
    ) {
        test_instruction_helper(&cs, insn, mnemonic_name, bytes, has_default_syntax);

        // Assert expected instruction groups is a subset of computed groups through ids
        let instruction_group_ids: HashSet<u8> = cs.insn_group_ids(&insn)
            .expect("failed to get instruction groups")
            .iter()
            .map(|&x| x)
            .collect();
        let expected_groups_ids: HashSet<u8> = expected_groups.iter().map(|&x| x as u8).collect();
        assert!(
            expected_groups_ids.is_subset(&instruction_group_ids),
            "Expected groups {:?} does NOT match computed insn groups {:?} with ",
            expected_groups_ids,
            instruction_group_ids
        );

        // Assert expected instruction groups is a subset of computed groups through enum
        let instruction_groups_set: HashSet<u8> = cs.insn_group_ids(&insn)
            .expect("failed to get instruction groups")
            .iter()
            .map(|&x| x)
            .collect();
        let expected_groups_set: HashSet<u8> = expected_groups.iter().map(|&x| x as u8).collect();
        assert!(
            expected_groups_set.is_subset(&instruction_groups_set),
            "Expected groups {:?} does NOT match computed insn groups {:?}",
            expected_groups_set,
            instruction_groups_set
        );

        // Create sets of expected groups and unexpected groups
        let instruction_types: HashSet<cs_group_type> = [
            cs_group_type::CS_GRP_JUMP,
            cs_group_type::CS_GRP_CALL,
            cs_group_type::CS_GRP_RET,
            cs_group_type::CS_GRP_INT,
            cs_group_type::CS_GRP_IRET,
        ].iter()
            .cloned()
            .collect();
        let expected_groups_set: HashSet<cs_group_type> =
            expected_groups.iter().map(|&x| x).collect();
        let not_belong_groups = instruction_types.difference(&expected_groups_set);

        // Assert instruction belongs to belong_groups
        for &belong_group in expected_groups {
            assert_eq!(
                Ok(true),
                cs.insn_belongs_to_group(&insn, belong_group as u64),
                "{:?} does NOT BELONG to group {:?}, but the instruction SHOULD",
                insn,
                belong_group
            );
        }

        // Assert instruction does not belong to not_belong_groups
        for &not_belong_group in not_belong_groups {
            assert_eq!(
                Ok(false),
                cs.insn_belongs_to_group(&insn, not_belong_group as u64),
                "{:?} BELONGS to group {:?}, but the instruction SHOULD NOT",
                insn,
                not_belong_group
            );
        }

        // @todo: check read_register_ids

        // @todo: check write_register_ids
    }

    fn instructions_match_group(
        cs: &mut Capstone,
        expected_insns: &[(&str, &[u8], &[cs_group_type])],
        has_default_syntax: bool,
    ) {
        let insns_buf: Vec<u8> = expected_insns
            .iter()
            .flat_map(|&(_, bytes, _)| bytes)
            .map(|x| *x)
            .collect();

        // Details required to get groups information
        cs.set_detail(true).unwrap();


        if expected_insns.len() == 0 {
            // Input was empty, which will cause disasm_all() to fail
            return;
        }

        let insns: Vec<_> = cs.disasm_all(&insns_buf, 0x1000)
            .expect("Failed to disassemble")
            .iter()
            .collect();

        // Check number of instructions
        assert_eq!(insns.len(), expected_insns.len());

        for (insn, &(expected_mnemonic, expected_bytes, expected_groups)) in
            insns.iter().zip(expected_insns)
        {
            test_instruction_group_helper(
                &cs,
                insn,
                expected_mnemonic,
                expected_bytes,
                expected_groups,
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


        if expected_insns.len() == 0 {
            // Input was empty, which will cause disasm_all() to fail
            return;
        }

        let insns: Vec<_> = cs.disasm_all(&insns_buf, 0x1000)
            .expect("Failed to disassemble")
            .iter()
            .collect();

        // Check number of instructions
        assert_eq!(insns.len(), expected_insns.len());

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

    #[test]
    fn test_instruction_group_ids() {
        let expected_insns: &[(&str, &[u8], &[cs_group_type])] =
            &[
                ("nop", b"\x90", &[]),
                ("je", b"\x74\x05", &[JUMP]),
                ("call", b"\xe8\x28\x07\x00\x00", &[CALL]),
                ("ret", b"\xc3", &[RET]),
                ("syscall", b"\x0f\x05", &[INT]),
                ("iretd", b"\xcf", &[IRET]),
                ("sub", b"\x48\x83\xec\x08", &[]),
                ("test", b"\x48\x85\xc0", &[]),
                ("mov", b"\x48\x8b\x05\x95\x4a\x4d\x00", &[]),
                ("mov", b"\xb9\x04\x02\x00\x00", &[]),
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

        let extra_mode = extra_mode.iter().map(|x| *x);
        let mut cs_raw = Capstone::new_raw(arch, mode, extra_mode, endian).unwrap();

        instructions_match(&mut cs_raw, expected_insns.as_slice(), true);
        instructions_match(cs, expected_insns.as_slice(), true);
    }

    #[test]
    fn test_syntax() {
        let expected_insns: &[(&str, &str, &[u8], &[cs_group_type])] =
            &[
                ("nop", "nop", b"\x90", &[]),
                ("je", "je", b"\x74\x05", &[JUMP]),
                ("call", "callq", b"\xe8\x28\x07\x00\x00", &[CALL]),
                ("ret", "retq", b"\xc3", &[RET]),
                ("syscall", "syscall", b"\x0f\x05", &[INT]),
                ("iretd", "iretl", b"\xcf", &[IRET]),
                ("sub", "subq", b"\x48\x83\xec\x08", &[]),
                ("test", "testq", b"\x48\x85\xc0", &[]),
                ("mov", "movq", b"\x48\x8b\x05\x95\x4a\x4d\x00", &[]),
                ("mov", "movl", b"\xb9\x04\x02\x00\x00", &[]),
            ];

        let expected_insns_intel: Vec<(&str, &[u8], &[cs_group_type])> = expected_insns
            .iter()
            .map(|&(mnemonic, _, bytes, groups)| (mnemonic, bytes, groups))
            .collect();
        let expected_insns_att: Vec<(&str, &[u8], &[cs_group_type])> = expected_insns
            .iter()
            .map(|&(_, mnemonic, bytes, groups)| (mnemonic, bytes, groups))
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

    #[test]
    fn test_invalid_mode() {
        if let Err(err) = Capstone::new_raw(Arch::PPC, Mode::Thumb, NO_EXTRA_MODE, None) {
            assert_eq!(err, Error::Capstone(CapstoneError::InvalidMode));
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
                ("addiupc", b"\xec\x80\x00\x19"),
                ("align", b"\x7c\x43\x22\xa0"),
            ],
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
}
