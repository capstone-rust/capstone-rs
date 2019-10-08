use alloc::string::{String, ToString};
use core::convert::From;
use core::marker::PhantomData;
use core::mem;

use libc::{c_int, c_uint, c_void};

use crate::arch::CapstoneBuilder;
use capstone_sys::cs_opt_value::*;
use capstone_sys::*;
use crate::constants::{Arch, Endian, ExtraMode, Mode, OptValue, Syntax};
use crate::error::*;
use crate::ffi::str_from_cstr_ptr;
use crate::instruction::{
    Insn, InsnDetail, InsnGroupId, InsnId, InsnRegsAccess, Instructions, RegId,
};


/// An instance of the capstone disassembler
#[derive(Debug)]
pub struct Capstone {
    /// Opaque handle to cs_engine
    /// Stored as a pointer to ensure `Capstone` is `!Send`/`!Sync`
    csh: *mut c_void,

    /// Internal mode bitfield
    mode: cs_mode,

    /// Internal endian bitfield
    endian: cs_mode,

    /// Syntax
    syntax: cs_opt_value::Type,

    /// Internal extra mode bitfield
    extra_mode: cs_mode,

    /// Whether to get extra details when disassembling
    detail_enabled: bool,

    /// Whether to skipdata when disassembling
    skipdata_enabled: bool,

    /// We *must* set `mode`, `extra_mode`, and `endian` at once because `capstone`
    /// handles them inside the arch-specific handler. We store the bitwise OR of these flags that
    /// can be passed directly to `cs_option()`.
    raw_mode: cs_mode,

    /// Architecture
    arch: Arch,
}

/// Defines a setter on `Capstone` that speculatively changes the arch-specific mode (which
/// includes `mode`, `endian`, and `extra_mode`). The setter takes a `capstone-rs` type and changes
/// the internal `capstone-sys` type.
macro_rules! define_set_mode {
    (
        $( #[$func_attr:meta] )*
        => $($visibility:ident)*, $fn_name:ident,
            $opt_type:ident, $param_name:ident : $param_type:ident ;
        $cs_base_type:ident
    ) => {
        $( #[$func_attr] )*
        $($visibility)* fn $fn_name(&mut self, $param_name: $param_type) -> CsResult<()> {
            let old_val = self.$param_name;
            self.$param_name = $cs_base_type::from($param_name);

            let old_raw_mode = self.raw_mode;
            let new_raw_mode = self.update_raw_mode();

            let result = self._set_cs_option(
                cs_opt_type::$opt_type,
                new_raw_mode.0 as usize,
            );

            if result.is_err() {
                // On error, restore old values
                self.raw_mode = old_raw_mode;
                self.$param_name = old_val;
            }

            result
        }
    }
}

/// Represents that no extra modes are enabled. Can be passed to `Capstone::new_raw()` as the
/// `extra_mode` argument.
pub static NO_EXTRA_MODE: EmptyExtraModeIter = EmptyExtraModeIter(PhantomData);

/// Represents an empty set of `ExtraMode`.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct EmptyExtraModeIter(PhantomData<()>);

impl Iterator for EmptyExtraModeIter {
    type Item = ExtraMode;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl Capstone {
    /// Create a new instance of the decompiler using the builder pattern interface.
    /// This is the recommended interface to `Capstone`.
    ///
    /// ```
    /// use capstone::prelude::*;
    /// let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build();
    /// ```
    pub fn new() -> CapstoneBuilder {
        CapstoneBuilder::new()
    }

    /// Create a new instance of the decompiler using the "raw" interface.
    /// The user must ensure that only sensible `Arch`/`Mode` combinations are used.
    ///
    /// ```
    /// use capstone::{Arch, Capstone, NO_EXTRA_MODE, Mode};
    /// let cs = Capstone::new_raw(Arch::X86, Mode::Mode64, NO_EXTRA_MODE, None);
    /// assert!(cs.is_ok());
    /// ```
    pub fn new_raw<T: Iterator<Item = ExtraMode>>(
        arch: Arch,
        mode: Mode,
        extra_mode: T,
        endian: Option<Endian>,
    ) -> CsResult<Capstone> {
        let mut handle: csh = 0;
        let csarch: cs_arch = arch.into();
        let csmode: cs_mode = mode.into();

        // todo(tmfink): test valid modes at run time (or modify upstream capstone)

        let endian = match endian {
            Some(endian) => cs_mode::from(endian),
            None => cs_mode(0),
        };
        let extra_mode = Self::extra_mode_value(extra_mode);

        let combined_mode = csmode | endian | extra_mode;
        let err = unsafe { cs_open(csarch, combined_mode, &mut handle) };

        if cs_err::CS_ERR_OK == err {
            let syntax = CS_OPT_SYNTAX_DEFAULT;
            let raw_mode = cs_mode(0);
            let detail_enabled = false;
            let skipdata_enabled = detail_enabled;

            let mut cs = Capstone {
                csh: handle as *mut c_void,
                syntax,
                endian,
                mode: csmode,
                extra_mode,
                detail_enabled,
                skipdata_enabled,
                raw_mode,
                arch,
            };
            cs.update_raw_mode();
            Ok(cs)
        } else {
            Err(err.into())
        }
    }

    /// Disassemble all instructions in buffer
    pub fn disasm_all<'a>(&'a self, code: &[u8], addr: u64) -> CsResult<Instructions<'a>> {
        self.disasm(code, addr, 0)
    }

    /// Disassemble `count` instructions in `code`
    pub fn disasm_count<'a>(
        &'a self,
        code: &[u8],
        addr: u64,
        count: usize,
    ) -> CsResult<Instructions<'a>> {
        if count == 0 {
            return Err(Error::CustomError("Invalid dissasemble count; must be > 0"));
        }
        self.disasm(code, addr, count)
    }

    /// Disassembles a `&[u8]` full of instructions.
    ///
    /// Pass `count = 0` to disassemble all instructions in the buffer.
    fn disasm<'a>(&'a self, code: &[u8], addr: u64, count: usize) -> CsResult<Instructions<'a>> {
        let mut ptr: *mut cs_insn = unsafe { mem::zeroed() };
        let insn_count = unsafe {
            cs_disasm(
                self.csh(),
                code.as_ptr(),
                code.len() as usize,
                addr,
                count as usize,
                &mut ptr,
            )
        };
        if insn_count == 0 {
            match self.error_result() {
                Ok(_) => Ok(Instructions::new_empty()),
                Err(err) => Err(err),
            }
        } else {
            Ok(unsafe { Instructions::from_raw_parts(ptr, insn_count) })
        }
    }

    /// Returns csh handle
    #[inline]
    fn csh(&self) -> csh {
        self.csh as csh
    }

    /// Returns the raw mode value, which is useful for debugging
    #[allow(dead_code)]
    pub(crate) fn raw_mode(&self) -> cs_mode {
        self.raw_mode
    }

    /// Update `raw_mode` with the bitwise OR of `mode`, `extra_mode`, and `endian`.
    ///
    /// Returns the new `raw_mode`.
    fn update_raw_mode(&mut self) -> cs_mode {
        self.raw_mode = self.mode | self.extra_mode | self.endian;
        self.raw_mode
    }

    /// Return the integer value used by capstone to represent the set of extra modes
    fn extra_mode_value<T: Iterator<Item = ExtraMode>>(extra_mode: T) -> cs_mode {
        // Bitwise OR extra modes
        extra_mode.fold(cs_mode(0), |acc, x| acc | cs_mode::from(x))
    }

    /// Set extra modes in addition to normal `mode`
    pub fn set_extra_mode<T: Iterator<Item = ExtraMode>>(&mut self, extra_mode: T) -> CsResult<()> {
        let old_val = self.extra_mode;

        self.extra_mode = Self::extra_mode_value(extra_mode);

        let old_mode = self.raw_mode;
        let new_mode = self.update_raw_mode();
        let result = self._set_cs_option(cs_opt_type::CS_OPT_MODE, new_mode.0 as usize);

        if result.is_err() {
            // On error, restore old values
            self.raw_mode = old_mode;
            self.extra_mode = old_val;
        }

        result
    }

    /// Set the assembly syntax (has no effect on some platforms)
    pub fn set_syntax(&mut self, syntax: Syntax) -> CsResult<()> {
        // Todo(tmfink) check for valid syntax
        let syntax_int = cs_opt_value::Type::from(syntax);
        let result = self._set_cs_option(cs_opt_type::CS_OPT_SYNTAX, syntax_int as usize);

        if result.is_ok() {
            self.syntax = syntax_int;
        }

        result
    }

    define_set_mode!(
    /// Set the endianness (has no effect on some platforms).
    => pub, set_endian, CS_OPT_MODE, endian : Endian; cs_mode);
    define_set_mode!(
    /// Sets the engine's disassembly mode.
    /// Be careful, various combinations of modes aren't supported
    /// See the capstone-sys documentation for more information.
    => pub, set_mode, CS_OPT_MODE, mode : Mode; cs_mode);

    /// Returns a `CsResult` based on current `errno`.
    /// If the `errno` is `CS_ERR_OK`, then `Ok(())` is returned. Otherwise, the error is returned.
    fn error_result(&self) -> CsResult<()> {
        let errno = unsafe { cs_errno(self.csh()) };
        if errno == cs_err::CS_ERR_OK {
            Ok(())
        } else {
            Err(errno.into())
        }
    }

    /// Sets disassembling options at runtime.
    ///
    /// Acts as a safe wrapper around capstone's `cs_option`.
    fn _set_cs_option(&mut self, option_type: cs_opt_type, option_value: usize) -> CsResult<()> {
        let err = unsafe { cs_option(self.csh(), option_type, option_value) };

        if cs_err::CS_ERR_OK == err {
            Ok(())
        } else {
            Err(err.into())
        }
    }

    /// Controls whether to capstone will generate extra details about disassembled instructions.
    ///
    /// Pass `true` to enable detail or `false` to disable detail.
    pub fn set_detail(&mut self, enable_detail: bool) -> CsResult<()> {
        let option_value: usize = OptValue::from(enable_detail).0 as usize;
        let result = self._set_cs_option(cs_opt_type::CS_OPT_DETAIL, option_value);

        // Only update internal state on success
        if result.is_ok() {
            self.detail_enabled = enable_detail;
        }

        result
    }

    /// Controls whether capstone will skip over invalid or data instructions.
    ///
    /// Pass `true` to enable skipdata or `false` to disable skipdata.
    pub fn set_skipdata(&mut self, enable_skipdata: bool) -> CsResult<()> {
        let option_value: usize = OptValue::from(enable_skipdata).0 as usize;
        let result = self._set_cs_option(cs_opt_type::CS_OPT_SKIPDATA, option_value);

        // Only update internal state on success
        if result.is_ok() {
            self.skipdata_enabled = enable_skipdata;
        }

        result
    }

    /// Converts a register id `reg_id` to a `String` containing the register name.
    pub fn reg_name(&self, reg_id: RegId) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_reg_name(self.csh(), c_uint::from(reg_id.0));
            str_from_cstr_ptr(_reg_name)?.to_string()
        };

        Some(reg_name)
    }

    /// Converts an instruction id `insn_id` to a `String` containing the instruction name.
    ///
    /// Note: This function ignores the current syntax and uses the default syntax.
    pub fn insn_name(&self, insn_id: InsnId) -> Option<String> {
        let insn_name = unsafe {
            let _insn_name = cs_insn_name(self.csh(), insn_id.0 as c_uint);
            str_from_cstr_ptr(_insn_name)?.to_string()
        };

        Some(insn_name)
    }

    /// Converts a group id `group_id` to a `String` containing the group name.
    pub fn group_name(&self, group_id: InsnGroupId) -> Option<String> {
        let group_name = unsafe {
            let _group_name = cs_group_name(self.csh(), c_uint::from(group_id.0));
            str_from_cstr_ptr(_group_name)?.to_string()
        };

        Some(group_name)
    }

    /// Returns `Detail` structure for a given instruction
    ///
    /// Requires:
    ///
    /// 1. Instruction was created with detail enabled
    /// 2. Skipdata is disabled
    /// 3. Capstone was not compiled in diet mode
    pub fn insn_detail<'s, 'i: 's>(&'s self, insn: &'i Insn) -> CsResult<InsnDetail<'i>> {
        if !self.detail_enabled {
            Err(Error::DetailOff)
        } else if insn.id().0 == 0 {
            Err(Error::IrrelevantDataInSkipData)
        } else if Self::is_diet() {
            Err(Error::IrrelevantDataInDiet)
        } else {
            Ok(unsafe { insn.detail(self.arch) })
        }
    }

    /// Returns `RegsAccess` structure for a given instruction
    ///
    /// Requires:
    ///
    /// 1. Instruction was created with detail enabled
    /// 2. Skipdata is disabled
    /// 3. Capstone was not compiled in diet mode
    pub fn insn_regs_access<'s, 'i: 's>(&'s self, insn: &'i Insn) -> CsResult<InsnRegsAccess> {
        if !self.detail_enabled {
            Err(Error::DetailOff)
        } else if insn.id().0 == 0 {
            Err(Error::IrrelevantDataInSkipData)
        } else if Self::is_diet() {
            Err(Error::IrrelevantDataInDiet)
        } else {
            Ok(unsafe { insn.regs_access(self.csh()) })
        }
    }

    /// Returns a tuple (major, minor) indicating the version of the capstone C library.
    pub fn lib_version() -> (u32, u32) {
        let mut major: c_int = 0;
        let mut minor: c_int = 0;
        let major_ptr: *mut c_int = &mut major;
        let minor_ptr: *mut c_int = &mut minor;

        // We can ignore the "hexical" version returned by capstone because we already have the
        // major and minor versions
        let _ = unsafe { cs_version(major_ptr, minor_ptr) };

        (major as u32, minor as u32)
    }

    /// Returns whether the capstone library supports a given architecture.
    pub fn supports_arch(arch: Arch) -> bool {
        unsafe { cs_support(arch as c_int) }
    }

    /// Returns whether the capstone library was compiled in diet mode.
    pub fn is_diet() -> bool {
        unsafe { cs_support(CS_SUPPORT_DIET as c_int) }
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh()) };
    }
}
