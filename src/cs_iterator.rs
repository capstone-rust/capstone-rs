use std::ptr;
use libc;

use csh;
use instruction::Insn;
use capstone::CsResult;
use constants::*;
use ffi::{cs_disasm_iter, cs_errno, cs_malloc, cs_free};

/// Lazy iterator that decompiles as it walks the code
pub struct CsIterator<'a> {
    csh: &'a csh,
    code: &'a [u8],
    addr: u64,
    ptr: *mut Insn,
}

impl<'a> CsIterator<'a> {
    pub fn new(handle: &'a u64, code: &'a [u8], addr: u64) -> CsIterator<'a> {
        CsIterator {
            csh: handle,
            code: code,
            addr: addr,
            ptr: unsafe { cs_malloc(*handle) },
        }

    }
}

impl<'a> Drop for CsIterator<'a> {
    fn drop(&mut self) {
        unsafe { cs_free(self.ptr, 1) };
    }
}

impl<'a> Iterator for CsIterator<'a> {
    type Item = CsResult<Insn>;

    fn next(&mut self) -> Option<CsResult<Insn>> {
        let mut size = self.code.len() as libc::size_t;
        // We have to manually fix up the code pointer
        let mut code_ptr = self.code.as_ptr();
        let res = unsafe { cs_disasm_iter(*self.csh,
                                 &mut code_ptr,
                                 &mut size,
                                 &mut self.addr,
                                 self.ptr) };
        if res {
            Some(Ok(unsafe { ptr::read(self.ptr) }))
        } else {
            let err = unsafe { cs_errno(*self.csh) };
            if err == CsErr::CS_ERR_OK {
                None
            } else {
                Some(Err(err))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use constants;
    use capstone;
    static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

    #[test]
    fn test_x86_simple() {
        match capstone::Capstone::new(constants::CsArch::ARCH_X86, constants::CsMode::MODE_64) {
            Ok(cs) => {
                for insn in cs.disasm_iter(CODE, 0x1000) {
                    // assert_eq!(insns.len(), 2);
                    // let is: Vec<_> = insns.iter().collect();
                    // assert_eq!(is[0].mnemonic().unwrap(), "push");
                    // assert_eq!(is[1].mnemonic().unwrap(), "mov");

                    // assert_eq!(is[0].address, 0x1000);
                    // assert_eq!(is[1].address, 0x1001);
                }
            }
            Err(e) => {
                assert!(false, format!("Couldn't create a cs engine: {}", e.to_string()));
            }
        }
    }
}
