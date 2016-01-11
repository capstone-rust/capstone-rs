use libc;
use std::ptr;
use constants::*;
use ffi::{cs_close,cs_open,cs_disasm};
use csh;

use instruction::{Insn,Instructions};

pub struct Capstone {
    csh: csh, // Opaque handle to cs_engine
}

impl Capstone {
    pub fn new(arch: CsArch, mode: CsMode) -> Option<Capstone> {
        let mut handle = 0;
        if let CsErr::CS_ERR_OK = unsafe { cs_open(arch, mode, &mut handle) } {
            Some(Capstone {
                csh: handle
            })
        } else {
            None
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: isize) -> Option<Instructions> {
        let mut ptr: *const Insn = ptr::null();
        let insn_count = unsafe { cs_disasm(self.csh, code.as_ptr(), code.len() as libc::size_t,
                                            addr, count as libc::size_t, &mut ptr) };
        if insn_count == 0 {
            // TODO  On failure, call cs_errno() for error code.
            return None
        }

        Some(Instructions::from_raw_parts(ptr, insn_count as isize))
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
