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
type csh = libc::c_ulong;

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
                        assert!(false, format!("Couldn't disasm instructions: {}", err.to_string()))
                    }
                }
                let reg_id = 1;
                match cs.reg_name(reg_id) {
                    Ok(reg_name) => assert_eq!(reg_name, "ah"),
                    Err(err) => assert!(false, format!("Couldn't get register name: {}", err.to_string())),
                }

                let insn_id = 1;
                match cs.insn_name(insn_id) {
                    Ok(insn_name) => assert_eq!(insn_name, "aaa"),
                    Err(err) => assert!(false, format!("Couldn't get instruction name: {}", err.to_string())),
                }
            }
            Err(e) => {
                assert!(false, format!("Couldn't create a cs engine: {}", e.to_string()));
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
}
