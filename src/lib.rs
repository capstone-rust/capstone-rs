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
                    },
                    Err(err) => {
                        assert!(false, "Couldn't disasm instructions: {}", err)
                    }
                }
            },
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

                let reg_id = 6000;
                match cs.reg_name(reg_id) {
                    Some(_) => assert!(false, "invalid register worked"),
                    None => {},
                }

                let insn_id = 6000;
                match cs.insn_name(insn_id) {
                    Some(_) => assert!(false, "invalid instruction worked"),
                    None => {},
                }
            },
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_invalid_mode() {
        match capstone::Capstone::new(constants::CsArch::ARCH_ALL, constants::CsMode::MODE_64) {
            Ok(_) => { assert!(false, "Invalid open worked") },
            Err(err) => { assert!(err == constants::CsErr::CS_ERR_ARCH) },
        }
    }

    #[test]
    fn test_capstone_version() {
        let (major, minor) = capstone::lib_version();
        println!("Capstone lib version: ({}, {})", major, minor);
        assert!(major > 0 && major < 100, "Invalid major version {}", major);
        assert!(minor < 500, "Invalid minor version {}", minor);
    }
}
