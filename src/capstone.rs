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

#[must_use]
pub type CsResult<T> = Result<T, CsErr>;

impl Capstone {
    /// Creates a new instance of the disassembler.
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
            opt_state.insert(CsOptType::CS_OPT_SYNTAX,
                             CsOptValueSyntax::CS_OPT_SYNTAX_DEFAULT as libc::size_t);
            opt_state.insert(CsOptType::CS_OPT_DETAIL,
                             CsOptValueBool::CS_OPT_OFF as libc::size_t);
            opt_state.insert(CsOptType::CS_OPT_MODE, mode as libc::size_t);
            opt_state.insert(CsOptType::CS_OPT_MEM, 0);
            opt_state.insert(CsOptType::CS_OPT_SKIPDATA,
                             CsOptValueBool::CS_OPT_OFF as libc::size_t);

            Ok(Capstone {
                   csh: handle,
                   cs_option_state: opt_state,
               })
        } else {
            Err(err)
        }
    }

    // @todo: change `count` to a `Option<usize>` and use a safe cast
    /// Disassembles a `&[u8]` full of instructions.
    ///
    /// Pass `count = 0` to disassemble all instructions in the buffer.
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
            return self.error_result();
        }

        Ok(unsafe { Instructions::from_raw_parts(ptr, insn_count as isize) })
    }

    /// Returns an `CsResult::Err` based on current errno.
    fn error_result<T>(&self) -> CsResult<T> {
        Err(unsafe { ffi::cs_errno(self.csh) })
    }

    /// Sets disassembling options at runtime.
    ///
    /// Acts as a safe wrapper around capstone's `cs_option`.
    fn set_cs_option(&mut self,
                     option_type: CsOptType,
                     option_value: libc::size_t)
                     -> CsResult<()> {
        let err = unsafe { ffi::cs_option(self.csh, option_type, option_value) };

        if CsErr::CS_ERR_OK == err {
            self.cs_option_state.insert(option_type, option_value);
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Controls whether to capstone will generate extra details about disassembled instructions.
    ///
    /// Pass `true` to enable detail or `false` to disable detail.
    pub fn set_detail(&mut self, enable_detail: bool) -> CsResult<()> {
        let option_value: libc::size_t = CsOptValueBool::from(enable_detail) as libc::size_t;
        self.set_cs_option(CsOptType::CS_OPT_DETAIL, option_value)
    }

    // @todo: use a type alias for reg_ids
    /// Converts a register id `reg_id` to a `String` containing the register name.
    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = ffi::cs_reg_name(self.csh, reg_id as libc::c_uint);
            if _reg_name == ptr::null() {
                return None;
            }

            CStr::from_ptr(_reg_name).to_string_lossy().into_owned()
        };

        Some(reg_name)
    }

    /// Converts an instruction id `insn_id` to a `String` containing the instruction name.
    pub fn insn_name(&self, insn_id: u64) -> Option<String> {
        let insn_name = unsafe {
            let _insn_name = ffi::cs_insn_name(self.csh, insn_id as libc::c_uint);
            if _insn_name == ptr::null() {
                return None;
            }

            CStr::from_ptr(_insn_name).to_string_lossy().into_owned()
        };

        Some(insn_name)
    }

    /// Converts a group id `group_id` to a `String` containing the group name.
    pub fn group_name(&self, group_id: u64) -> Option<String> {
        let group_name = unsafe {
            let _group_name = ffi::cs_group_name(self.csh, group_id as libc::c_uint);
            if _group_name == ptr::null() {
                return None;
            }

            CStr::from_ptr(_group_name)
                .to_string_lossy()
                .into_owned()
        };

        Some(group_name)
    }

    /// Returns the current error from not enabling `CS_OPT_DETAIL`.
    fn detail_required_error(&self) -> Option<CsErr> {
        if *self.cs_option_state
                .get(&CsOptType::CS_OPT_DETAIL)
                .unwrap() == CsOptValueBool::CS_OPT_OFF as libc::size_t {
            Some(CsErr::CS_ERR_DETAIL)
        } else {
            None
        }
    }

    /// Returns the current error that could arise from enabling `CS_ERR_SKIPDATA`.
    fn skipdata_error(insn: &Insn) -> Option<CsErr> {
        if insn.id() == 0 {
            Some(CsErr::CS_ERR_SKIPDATA)
        } else {
            None
        }
    }

    /// Returns the error that could arise from capstone being compiled in diet mode.
    fn is_diet_error() -> Option<CsErr> {
        if Self::is_diet() {
            Some(CsErr::CS_ERR_DIET)
        } else {
            None
        }
    }

    /// Returns an error that could arise from querying instruction groups.
    ///
    /// Returns `Ok` if there is no error, or `Err` otherwise.
    fn is_insn_group_valid(&self, insn: &Insn) -> CsResult<()> {
        if let Some(err) = self.detail_required_error() {
            Err(err)
        } else if let Some(err) = Self::skipdata_error(insn) {
            Err(err)
        } else if let Some(err) = Self::is_diet_error() {
            Err(err)
        } else {
            Ok(())
        }
    }

    /// Returns whether the instruction `insn` belongs to the group with id `group_id`.
    pub fn insn_belongs_to_group(&self, insn: &Insn, group_id: u64) -> CsResult<bool> {
        if let Err(e) = self.is_insn_group_valid(insn) {
            return Err(e);
        }

        Ok(unsafe { ffi::cs_insn_group(self.csh, insn as *const Insn, group_id as libc::c_uint) })
    }


    /// Returns groups ids to which an instruction belongs.
    pub fn insn_group_ids(&self, insn: &Insn) -> CsResult<&[u8]> {
        if let Err(e) = self.is_insn_group_valid(insn) {
            return Err(e);
        }

        let group_ids = unsafe { (*insn.detail()).groups_ids() };
        Ok(group_ids)
    }

    /// Returns groups to which an instruction belongs.
    pub fn insn_groups(&self, insn: &Insn) -> CsResult<Vec<CsGroupType>> {
        if let Err(e) = self.is_insn_group_valid(insn) {
            return Err(e);
        }

        let groups = unsafe { (*insn.detail()).groups() };
        Ok(groups)
    }

    /// Returns whether read or write registers may be queried.
    ///
    /// Returns `Ok` if there is no error, or `Err` otherwise.
    fn is_reg_read_write_valid(&self, insn: &Insn) -> CsResult<()> {
        if let Some(err) = Self::skipdata_error(insn) {
            Err(err)
        } else if let Some(err) = Self::is_diet_error() {
            Err(err)
        } else {
            Ok(())
        }
    }

    // @todo: make public
    /// Checks if an instruction implicitly reads a register with id `reg_id`.
    #[allow(dead_code)]
    fn register_id_is_read(&self, insn: &Insn, reg_id: u64) -> CsResult<bool> {
        if let Err(e) = self.is_reg_read_write_valid(insn) {
            return Err(e);
        }

        Ok(unsafe { ffi::cs_reg_read(self.csh, insn as *const Insn, reg_id as libc::c_uint) })
    }

    // @todo: make public
    #[allow(dead_code)]
    /// Returns list of ids of registers that are implicitly read by instruction `insn`.
    fn read_registers(&self, insn: &Insn) -> CsResult<&[u8]> {
        if let Err(e) = self.is_reg_read_write_valid(insn) {
            return Err(e);
        }

        let reg_read_ids = unsafe { (*insn.detail()).regs_read_ids() };
        Ok(reg_read_ids)
    }

    // @todo: make public
    /// Checks if an instruction implicitly writes to a register with id `reg_id`.
    #[allow(dead_code)]
    fn register_is_written(&self, insn: &Insn, reg_id: u64) -> CsResult<bool> {
        if let Err(e) = self.is_reg_read_write_valid(insn) {
            return Err(e);
        }

        Ok(unsafe { ffi::cs_reg_write(self.csh, insn as *const Insn, reg_id as libc::c_uint) })
    }

    // @todo: make public
    #[allow(dead_code)]
    /// Returns a list of ids of registers that are implicitly written to by the instruction `insn`.
    fn write_registers(&self, insn: &Insn) -> CsResult<&[u8]> {
        if let Err(e) = self.is_reg_read_write_valid(insn) {
            return Err(e);
        }

        let reg_write_ids = unsafe { (*insn.detail()).regs_write_ids() };
        Ok(reg_write_ids)
    }

    /// Returns a tuple (major, minor) indicating the version of the capstone C library.
    pub fn lib_version() -> (u32, u32) {
        let mut major: libc::c_int = 0;
        let mut minor: libc::c_int = 0;
        let major_ptr: *mut libc::c_int = &mut major;
        let minor_ptr: *mut libc::c_int = &mut minor;

        // We can ignore the "hexical" version returned by capstone because we already have the
        // major and minor versions
        let _ = unsafe { ffi::cs_version(major_ptr, minor_ptr) };

        (major as u32, minor as u32)
    }

    /// Returns whether the capstone library supports a given architecture.
    pub fn supports_arch(arch: CsArch) -> bool {
        unsafe { ffi::cs_support(arch as libc::c_int) }
    }

    /// Returns whether the capstone library was compiled in diet mode.
    pub fn is_diet() -> bool {
        unsafe { ffi::cs_support(::constants::CS_SUPPORT_DIET as libc::c_int) }
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { ffi::cs_close(&mut self.csh) };
    }
}
