//! Bindings to the [capstone library][upstream] disassembly framework.
//!
//! ```rust
//! extern crate capstone;
//! const CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
//! fn main() {
//!     match capstone::Capstone::new(capstone::Arch::X86) {
//!         Ok(cs) => {
//!             match cs.disasm(CODE, 0x1000) {
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
//! **NOTE** if you want to compile for a different target, you should use the `build_capstone` feature.
//!
//! [upstream]: http://capstone-engine.org/
//!

extern crate libc;
extern crate capstone_sys;

mod capstone;
pub mod instruction;
pub mod error;

pub use capstone::*;

#[cfg(test)]
mod test {
    use super::{capstone, error};
    const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
    const ARM_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

     #[test]
     fn test_x86_simple() {
         match capstone::Capstone::new(capstone::Arch::X86) {
             Ok(cs) => {
                 match cs.disasm(X86_CODE, 0x1000) {
                     Ok(insns) => {
                         assert_eq!(insns.len(), 2);
                         let is: Vec<_> = insns.iter().collect();
                         assert_eq!(is[0].mnemonic().unwrap(), "push");
                         assert_eq!(is[1].mnemonic().unwrap(), "mov");

                         assert_eq!(is[0].address(), 0x1000);
                         assert_eq!(is[1].address(), 0x1001);
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
    fn test_arm_simple() {
        match capstone::Capstone::new(capstone::Arch::ARM) {
            Ok(cs) => {
                match cs.disasm(ARM_CODE, 0x1000) {
                    Ok(insns) => {
                        assert_eq!(insns.len(), 2);
                        let is: Vec<_> = insns.iter().collect();
                        assert_eq!(is[0].mnemonic().unwrap(), "streq");
                        assert_eq!(is[1].mnemonic().unwrap(), "strheq");

                        assert_eq!(is[0].address(), 0x1000);
                        assert_eq!(is[1].address(), 0x1004);
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
         match capstone::Capstone::new(capstone::Arch::X86) {
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
        match capstone::Capstone::new(capstone::Arch::ALL) {
            Ok(_) => assert!(false, "Invalid open worked"),
            Err(err) => {
                match err {
                    error::Err::Cs(err) => assert!(err == error::CsErr::Arch),
                    _ => assert!(false),
                }
            }
        }
    }
}
