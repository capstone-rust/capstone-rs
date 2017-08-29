use libc;
use std::collections::HashMap;
use std::convert::From;
use std::ffi::CStr;
use std::mem;
use error::*;
use capstone_sys::*;
use constants::{Arch, Mode, OptValue};
use instruction::{Insn, Instructions, Detail};


/// An instance of the capstone disassembler
pub struct Capstone {
    csh: csh, // Opaque handle to cs_engine
    cs_option_state: HashMap<cs_opt_type, libc::size_t>, // maintains state set with cs_option
    _arch: Arch,
}

impl Capstone {
    /// Create a new instance of the decompiler.
    ///
    /// ```
    /// use capstone::{Arch, Capstone, Mode};
    /// let cs = Capstone::new(Arch::X86, Mode::Mode64);
    /// assert!(cs.is_ok());
    /// ```
    pub fn new(arch: Arch, mode: Mode) -> CsResult<Capstone> {
        let mut handle = 0;
        let csarch: cs_arch = arch.into();
        let csmode: cs_mode = mode.into();
        let err = unsafe { cs_open(csarch, csmode, &mut handle) };

        if cs_err::CS_ERR_OK == err {
            let mut opt_state: HashMap<cs_opt_type, libc::size_t> = HashMap::new();
            opt_state.insert(cs_opt_type::CS_OPT_SYNTAX,
                             CS_OPT_SYNTAX_DEFAULT as libc::size_t);
            opt_state.insert(cs_opt_type::CS_OPT_DETAIL,
                             cs_opt_value::CS_OPT_OFF as libc::size_t);
            opt_state.insert(cs_opt_type::CS_OPT_MODE, mode as libc::size_t);
            opt_state.insert(cs_opt_type::CS_OPT_MEM, 0);
            opt_state.insert(cs_opt_type::CS_OPT_SKIPDATA,
                             cs_opt_value::CS_OPT_OFF as libc::size_t);

            Ok(Capstone {
                   csh: handle,
                   cs_option_state: opt_state,
                   _arch: arch,
               })
        } else {
            Err(err.into())
        }
    }

    #[inline]
    fn set_option(&self, opt_type: cs_opt_type, value: usize) -> CsResult<()> {
        let err = unsafe { cs_option(self.csh, opt_type, value) };
        if cs_err::CS_ERR_OK == err {
            Ok(())
        } else {
            Err(Error::from(err))
        }
    }

    /// Disassemble all instructions in buffer
    pub fn disasm_all(&self, code: &[u8], addr: u64) -> CsResult<Instructions> {
        self.disasm(code, addr, 0)
    }

    /// Disassemble `count` instructions in `code`
    pub fn disasm_count(&self, code: &[u8], addr: u64, count: usize) -> CsResult<Instructions> {
        if count == 0 {
            return Err(Error::CustomError("Invalid dissasemble count; must be > 0"));
        }
        self.disasm(code, addr, count)
    }

    /// Disassembles a `&[u8]` full of instructions.
    ///
    /// Pass `count = 0` to disassemble all instructions in the buffer.
    fn disasm(&self, code: &[u8], addr: u64, count: usize) -> CsResult<Instructions> {
        let mut ptr: *mut cs_insn = unsafe { mem::zeroed() };
        let insn_count = unsafe {
            cs_disasm(self.csh,
                           code.as_ptr(),
                           code.len() as libc::size_t,
                           addr,
                           count as libc::size_t,
                           &mut ptr)
        };
        if insn_count == 0 {
            return self.error_result();
        }
        Ok(unsafe {
            Instructions::from_raw_parts(ptr, insn_count as isize)
        })
    }

    /// Sets the engine's disassembly mode.
    /// Be careful, various combinations of modes aren't supported
    /// See the capstone-sys documentation for more information.
    pub fn set_mode(&mut self, modes: &[Mode]) -> CsResult<()> {
        let mut value: usize = 0;
        for mode in modes {
            let mode = cs_mode::from(*mode);
            value |= mode as usize;
        }
        self.set_option(cs_opt_type::CS_OPT_MODE, value)
    }

    /// Set the X86 assembly to AT&T style (has no effect on other platforms)
    pub fn att(&self) {
        self.set_option(
            cs_opt_type::CS_OPT_SYNTAX,
            cs_opt_value::CS_OPT_SYNTAX_ATT as usize,
        ).unwrap()
    }

    /// Set the X86 assembly to Intel style (default)
    pub fn intel(&self) {
        self.set_option(
            cs_opt_type::CS_OPT_SYNTAX,
            cs_opt_value::CS_OPT_SYNTAX_INTEL as usize,
        ).unwrap()
    }

    /// Returns an `CsResult::Err` based on current errno.
    fn error_result<T>(&self) -> CsResult<T> {
        Err(unsafe { cs_errno(self.csh) }.into())
    }

    /// Sets disassembling options at runtime.
    ///
    /// Acts as a safe wrapper around capstone's `cs_option`.
    fn set_cs_option(&mut self,
                     option_type: cs_opt_type,
                     option_value: libc::size_t)
                     -> CsResult<()> {
        let err = unsafe { cs_option(self.csh, option_type, option_value) };

        if cs_err::CS_ERR_OK == err {
            self.cs_option_state.insert(option_type, option_value);
            Ok(())
        } else {
            Err(err.into())
        }
    }

    /// Controls whether to capstone will generate extra details about disassembled instructions.
    ///
    /// Pass `true` to enable detail or `false` to disable detail.
    pub fn set_detail(&mut self, enable_detail: bool) -> CsResult<()> {
        let option_value: libc::size_t = OptValue::from(enable_detail).0 as libc::size_t;
        self.set_cs_option(cs_opt_type::CS_OPT_DETAIL, option_value)
    }

    // @todo: use a type alias for reg_ids
    /// Converts a register id `reg_id` to a `String` containing the register name.
    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_reg_name(self.csh, reg_id as libc::c_uint);
            if _reg_name.is_null() {
                return None;
            }

            CStr::from_ptr(_reg_name).to_string_lossy().into_owned()
        };

        Some(reg_name)
    }

    /// Converts an instruction id `insn_id` to a `String` containing the instruction name.
    pub fn insn_name(&self, insn_id: u64) -> Option<String> {
        let insn_name = unsafe {
            let _insn_name = cs_insn_name(self.csh, insn_id as libc::c_uint);
            if _insn_name.is_null() {
                return None;
            }
            CStr::from_ptr(_insn_name).to_string_lossy().into_owned()
        };

        Some(insn_name)
    }

    /// Converts a group id `group_id` to a `String` containing the group name.
    pub fn group_name(&self, group_id: u64) -> Option<String> {
        let group_name = unsafe {
            let _group_name = cs_group_name(self.csh, group_id as libc::c_uint);
            if _group_name.is_null() {
                return None;
            }

            CStr::from_ptr(_group_name)
                .to_string_lossy()
                .into_owned()
        };

        Some(group_name)
    }

    /// Returns `Detail` structure for a given instruction
    ///
    /// Requires:
    /// 1. Instruction was created with detail enabled
    /// 2. Skipdata is disabled
    /// 3. Capstone was not compiled in diet mode
    fn insn_detail<'s, 'i: 's>(&'s self, insn: &'i Insn) -> CsResult<Detail<'i>> {
       if self.cs_option_state[&cs_opt_type::CS_OPT_DETAIL] == cs_opt_value::CS_OPT_OFF as libc::size_t {
           Err(Error::Capstone(CapstoneError::DetailOff))
       } else if insn.id() == 0 {
           Err(Error::Capstone(CapstoneError::IrrelevantDataInSkipData))
       } else if Self::is_diet() {
           Err(Error::Capstone(CapstoneError::IrrelevantDataInDiet))
       } else {
           Ok(unsafe { insn.detail() })
       }
    }

    /// Returns whether the instruction `insn` belongs to the group with id `group_id`.
    pub fn insn_belongs_to_group(&self, insn: &Insn, group_id: u64) -> CsResult<bool> {
        self.insn_detail(insn)?;
        Ok(unsafe { cs_insn_group(self.csh, &insn.0 as *const cs_insn, group_id as libc::c_uint) })
    }


    /// Returns groups ids to which an instruction belongs.
    pub fn insn_groups<'i>(&self, insn: &'i Insn) -> CsResult<&'i [u8]> {
        let detail = self.insn_detail(insn)?;
        let group_ids: &'i [libc::uint8_t] = unsafe { mem::transmute(detail.groups()) };
        Ok(group_ids)
    }

    /// Checks if an instruction implicitly reads a register with id `reg_id`.
    pub fn register_id_is_read(&self, insn: &Insn, reg_id: u64) -> CsResult<bool> {
        self.insn_detail(insn)?;
        Ok(unsafe { cs_reg_read(self.csh, &insn.0 as *const cs_insn, reg_id as libc::c_uint) })
    }

    /// Returns list of ids of registers that are implicitly read by instruction `insn`.
    pub fn read_registers<'i>(&self, insn: &'i Insn) -> CsResult<&'i [u8]> {
        let detail = self.insn_detail(insn)?;
        let reg_read_ids: &'i [libc::uint8_t] = unsafe { mem::transmute(detail.regs_read()) };
        Ok(reg_read_ids)
    }

    /// Checks if an instruction implicitly writes to a register with id `reg_id`.
    pub fn register_is_written(&self, insn: &Insn, reg_id: u64) -> CsResult<bool> {
        self.insn_detail(insn)?;
        Ok(unsafe { cs_reg_write(self.csh, &insn.0 as *const cs_insn, reg_id as libc::c_uint) })
    }

    /// Returns a list of ids of registers that are implicitly written to by the instruction `insn`.
    pub fn write_registers<'i>(&self, insn: &'i Insn) -> CsResult<&'i [u8]> {
        let detail = self.insn_detail(insn)?;
        let reg_write_ids: &'i [libc::uint8_t] = unsafe { mem::transmute(detail.regs_write()) };
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
        let _ = unsafe { cs_version(major_ptr, minor_ptr) };

        (major as u32, minor as u32)
    }

    /// Returns whether the capstone library supports a given architecture.
    pub fn supports_arch(arch: Arch) -> bool {
        unsafe { cs_support(arch as libc::c_int) }
    }

    /// Returns whether the capstone library was compiled in diet mode.
    pub fn is_diet() -> bool {
        unsafe { cs_support(CS_SUPPORT_DIET as libc::c_int) }
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
