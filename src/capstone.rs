use libc;
use std::ptr;
use std::ffi::CStr;
use constants::*;
use ffi::{cs_close, cs_open, cs_disasm, cs_reg_name, cs_insn_name};
use instruction::{Insn, Instructions};

pub struct Capstone {
    csh: csh, // Opaque handle to cs_engine
}

impl Capstone {
    pub fn new(arch: CsArch, mode: CsMode) -> Option<Capstone> {
        let mut handle = 0;
        if let CsErr::CS_ERR_OK = unsafe { cs_open(arch, mode, &mut handle) } {
            Some(Capstone { csh: handle })
        } else {
            None
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: isize) -> Option<Instructions> {
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
            // TODO  On failure, call cs_errno() for error code.
            return None;
        }

        Some(Instructions::from_raw_parts(ptr, insn_count as isize))
    }

    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_reg_name(self.csh, reg_id as libc::size_t);
            if _reg_name == ptr::null() {
                return None;
            }

            CStr::from_ptr(_reg_name).to_string_lossy().into_owned()
        };

        Some(reg_name)
    }

    pub fn insn_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_insn_name(self.csh, reg_id as libc::size_t);
            if _reg_name == ptr::null() {
                return None;
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
