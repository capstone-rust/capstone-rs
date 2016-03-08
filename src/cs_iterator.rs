use std::ptr;
use libc;

use csh;
use instruction::Insn;
use capstone::CsResult;
use constants::*;
use ffi::{cs_disasm_iter, cs_errno};

/// Lazy iterator that decompiles as it walks the code
pub struct CsIterator<'a> {
    csh: &'a csh,
    code: &'a [u8],
    addr: u64,
}

impl<'a> CsIterator<'a> {
    pub fn new(handle: &'a csh, code: &'a [u8], addr: u64) -> CsIterator<'a> {
        CsIterator {
            csh: handle,
            code: code,
            addr: addr
        }

    }
}

impl<'a> Iterator for CsIterator<'a> {
    type Item = CsResult<Insn>;

    fn next(&mut self) -> Option<CsResult<Insn>> {
        let mut ptr: *const Insn = ptr::null();
        let mut size = self.code.len() as libc::size_t;
        let res = cs_disasm_iter(self.csh,
                                 &mut self.code,
                                 &mut size,
                                 self.addr,
                                 &mut ptr);
        if res {
            Some(Ok(unsafe { ptr::read(ptr) }))
        } else {
            let err = cs_errno(self.csh);
            if err == CsErr::CS_ERR_OK {
                None
            } else {
                Some(Err(err))
            }
        }
    }
}
