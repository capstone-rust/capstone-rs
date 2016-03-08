use libc;
use std::ptr;
use std::ffi::CStr;
use constants::*;
use csh;
use ffi::{cs_close, cs_open, cs_disasm, cs_reg_name, cs_insn_name, cs_errno};
use instruction::{Insn, Instructions};
use cs_iterator::CsIterator;

pub struct Capstone {
    csh: csh, // Opaque handle to cs_engine
}

pub type CsResult<T> = Result<T, CsErr>;

impl Capstone {
    pub fn new(arch: CsArch, mode: CsMode) -> CsResult<Capstone> {
        let mut handle = 0;
        let err = unsafe { cs_open(arch, mode, &mut handle) };

        if CsErr::CS_ERR_OK == err {
            Ok(Capstone { csh: handle })
        } else {
            Err(err)
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: isize) -> CsResult<Instructions> {
        let mut ptr: *const Insn = ptr::null();
        let insn_count = unsafe {
            cs_disasm(self.csh,
                      code.as_ptr(),
                      code.len() as libc::size_t,
                      addr,
                      count as libc::size_t,
                      &mut ptr)
        };
        if insn_count == 0 {
            return Err(unsafe { cs_errno(self.csh) })
        }

        Ok(Instructions::from_raw_parts(ptr, insn_count as isize))
    }

    /// Returns a CsIterator which lazily fetches the next instruction
    ///
    /// Note that because it's lazy, it doesn't guarantee that all the instructions are valid, and
    /// as a result the Iterator itself yields CsResult<Instruction>
    pub fn disasm_iter<'a>(&'a self, code: &'a [u8], addr: u64) -> CsIterator<'a> {
        CsIterator::new(&self.csh, code, addr)
    }

    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_reg_name(self.csh, reg_id as libc::size_t);
            if _reg_name == ptr::null() {
                return None
            }

            CStr::from_ptr(_reg_name).to_string_lossy().into_owned()
        };

        Some(reg_name)
    }

    pub fn insn_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_insn_name(self.csh, reg_id as libc::size_t);
            if _reg_name == ptr::null() {
                return None
            }

            CStr::from_ptr(_reg_name).to_string_lossy().into_owned()
        };

        Some(reg_name)
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
