use libc;
use std::collections::HashMap;
use std::ptr;
use std::ffi::CStr;
use constants::*;
use csh;
use ffi;
use instruction::{Insn, Instructions};


/// An instance of the capstone disassembler
pub struct Capstone {
    csh: csh, // Opaque handle to cs_engine
    cs_option_state: HashMap<CsOptType, libc::size_t>, // maintains state set with cs_option
}

pub type CsResult<T> = Result<T, CsErr>;

impl Capstone {
    /// Create a new instance of the disassembler
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
            let mut opt_state: HashMap<CsOptType, libc::size_t> = HashMap::new();
            opt_state.insert(CsOptType::CS_OPT_SYNTAX, CsOptValueSyntax::CS_OPT_SYNTAX_DEFAULT as libc::size_t);
            opt_state.insert(CsOptType::CS_OPT_DETAIL, CsOptValueBool::CS_OPT_OFF as libc::size_t);
            opt_state.insert(CsOptType::CS_OPT_MODE, mode as libc::size_t);
            opt_state.insert(CsOptType::CS_OPT_MEM, 0);
            opt_state.insert(CsOptType::CS_OPT_SKIPDATA, CsOptValueBool::CS_OPT_OFF as libc::size_t);

            Ok(Capstone {
                csh: handle,
                cs_option_state: opt_state,
            })
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
    fn get_error_result<T>(&self) ->CsResult<T> {
        Err(unsafe { ffi::cs_errno(self.csh) })
    }

    /// Set disassembling option at runtime
    /// Acts as a safe wrapper around capstone's cs_option
    fn set_cs_option(&mut self, option_type: CsOptType, option_value: libc::size_t) -> CsResult<()> {
        let err = unsafe {
            ffi::cs_option(self.csh, option_type, option_value)
        };

        if CsErr::CS_ERR_OK == err {
            self.cs_option_state.insert(option_type, option_value);
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Enable generate details about disassembled instructions
    pub fn set_detail(&mut self, enable_detail: bool) -> CsResult<()> {
        let option_value: libc::size_t = CsOptValueBool::from(enable_detail) as libc::size_t;
        self.set_cs_option(CsOptType::CS_OPT_DETAIL, option_value)
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

    /// Convert an instruction id to a String indicating the group
    pub fn group_name(&self, group_id: u64) -> Option<String> {
        let group_name = unsafe {
            let _group_name = ffi::cs_group_name(self.csh, group_id as libc::c_uint);
            if _group_name == ptr::null() {
                return None
            }

            CStr::from_ptr(_group_name).to_string_lossy().into_owned()
        };

        Some(group_name)
    }

    /// Returns whether instruction groups may be queried
    fn is_insn_group_valid(&self, insn: &Insn) -> CsResult<()> {
        /* CS_OPT_DETAIL is initialized in constructor */
        if *self.cs_option_state.get(&CsOptType::CS_OPT_DETAIL).unwrap() ==
            CsOptValueBool::CS_OPT_OFF as libc::size_t {
            Err(CsErr::CS_ERR_DETAIL)
        } else if insn.get_id() == 0 {
            Err(CsErr::CS_ERR_SKIPDATA)
        } else if is_diet() {
            Err(CsErr::CS_ERR_DIET)
        } else {
            Ok(())
        }
    }

    /// Returns whether the instruction belongs to the group wth id
    pub fn insn_belongs_to_group(&self, insn: &Insn, group_id: u64) -> CsResult<bool> {
        if let Err(e) = self.is_insn_group_valid(insn) {
            return Err(e);
        }

        Ok(unsafe {
            ffi::cs_insn_group(self.csh, insn as *const Insn, group_id as libc::c_uint)
        })
    }


    /// Returns groups to which an instruction belongs
    pub fn get_insn_group_ids(&self, insn: &Insn) -> CsResult<&[u8]> {
        if let Err(e) = self.is_insn_group_valid(insn) {
            return Err(e);
        }

        let groups = unsafe { (*insn.detail).get_groups() };
        Ok(groups)
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

/// Determine if capstone library supports given architecture
pub fn supports_arch(arch: CsArch) -> bool {
    unsafe { ffi::cs_support(arch as libc::c_int) }
}

/// Determine if capstone library was compiled in diet mode
pub fn is_diet() -> bool {
    const CS_SUPPORT_DIET: libc::c_int = ((CsArch::ARCH_ALL as libc::c_int) + 1);
    unsafe { ffi::cs_support(CS_SUPPORT_DIET as libc::c_int) }
}
