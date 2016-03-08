use libc;
use std::ptr;
use std::ffi::CStr;
use constants::*;
use csh;
use ffi::{cs_close, cs_open, cs_disasm, cs_reg_name, cs_insn_name, cs_errno};
use instruction::{Insn, Instructions};

/// An instance of the capstone disassembler
pub struct Capstone {
    csh: csh, // Opaque handle to cs_engine
}

pub type CsResult<T> = Result<T, CsErr>;

impl Capstone {
    /// Create a new instance of the decompiler
    ///
    /// ```
    /// use capstone::Capstone;
    /// use capstone::constants::*;
    /// let cs = Capstone::new(CsArch::ARCH_X86, CsMode::MODE_64);
    /// assert!(cs.is_ok());
    /// ```
    pub fn new(arch: CsArch, mode: CsMode) -> CsResult<Capstone> {
        let mut handle = 0;
        let err = unsafe { cs_open(arch, mode, &mut handle) };

        if CsErr::CS_ERR_OK == err {
            Ok(Capstone { csh: handle })
        } else {
            Err(err)
        }
    }

    /// Disassemble a &[u8] full of instructions
    ///
    /// Pass count = 0 to disassemble all instructions in the buffer
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

    /// Convert a reg_id to a String naming the register
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

    /// Convert an instruction_id to a String naming the instruction
    pub fn insn_name(&self, insn_id: u64) -> Option<String> {
        let insn_name = unsafe {
            let _insn_name = cs_insn_name(self.csh, insn_id as libc::size_t);
            if _insn_name == ptr::null() {
                return None
            }

            CStr::from_ptr(_insn_name).to_string_lossy().into_owned()
        };

        Some(insn_name)
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
