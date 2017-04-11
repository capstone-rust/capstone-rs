use libc;
use std::ptr;
use std::ffi::CStr;
use constants::*;
use csh;
use ffi;
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
        let err = unsafe { ffi::cs_open(arch, mode, &mut handle) };

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
            ffi::cs_disasm(self.csh,
                      code.as_ptr(),
                      code.len() as libc::size_t,
                      addr,
                      count as libc::size_t,
                      &mut ptr)
        };
        if insn_count == 0 {
            return self.get_error_result();
        }

        Ok(unsafe { Instructions::from_raw_parts(ptr, insn_count as isize) })
    }

    /// Get error CsResult based on current errno
    fn get_error_result(&self) ->CsResult<Instructions> {
        Err(unsafe { ffi::cs_errno(self.csh) })
    }

    /// Convert a reg_id to a String naming the register
    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = ffi::cs_reg_name(self.csh, reg_id as libc::c_uint);
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
            let _insn_name = ffi::cs_insn_name(self.csh, insn_id as libc::c_uint);
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
        unsafe { ffi::cs_close(&mut self.csh) };
    }
}

/// Return tuple (major, minor) indicating the version of the capstone C library
pub fn lib_version() -> (u32, u32) {
    let mut major: libc::c_int = 0;
    let mut minor: libc::c_int = 0;
    let major_ptr: *mut libc::c_int = &mut major;
    let minor_ptr: *mut libc::c_int = &mut minor;

    let _ = unsafe { ffi::cs_version(major_ptr, minor_ptr) };

    (major as u32, minor as u32)
}
