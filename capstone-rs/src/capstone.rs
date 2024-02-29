use alloc::string::{String, ToString};
use core::convert::From;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;

use libc::{c_int, c_void};

use capstone_sys::*;

use crate::arch::ArchTag;
use crate::constants::{Arch, Endian, ExtraMode, Mode, OptValue};
use crate::error::*;
use crate::ffi::str_from_cstr_ptr;
use crate::instruction::{Insn, InsnDetail, Instructions};

/// An instance of the capstone disassembler.
///
/// The generic type parameter `A` is called the "architecture tag" and it allows you to specify the target architecture
/// of the disassembler. For example, a Capstone disassembler that disassembles x86 and x86_64 code has the type
/// `Capstone<X86ArchTag>`. For the full list of architecture tags, please refer to the "implementors" section of the
/// [`ArchTag`] trait.
///
/// If the target architecture is unknown at compile time, you can use the special architecture tag [`DynamicArchTag`].
///
/// [`DynamicArchTag`]: ./arch/struct.DynamicArchTag.html
///
/// Create with an instance with [`.new()`](Self::new) and disassemble bytes with [`.disasm_all()`](Self::disasm_all).
pub struct Capstone<A: ArchTag> {
    /// Opaque handle to cs_engine
    /// Stored as a pointer to ensure `Capstone` is `!Send`/`!Sync`
    csh: *mut c_void,

    /// Internal mode bitfield
    mode: cs_mode,

    /// Internal endian bitfield
    endian: cs_mode,

    /// Syntax
    syntax: cs_opt_value,

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

    _arch_tag: PhantomData<A>,
}

impl<A: ArchTag> Debug for Capstone<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Capstone")
            .field("csh", &self.csh)
            .field("mode", &self.mode)
            .field("endian", &self.endian)
            .field("syntax", &self.syntax)
            .field("extra_mode", &self.extra_mode)
            .field("detail_enabled", &self.detail_enabled)
            .field("skipdata_enabled", &self.skipdata_enabled)
            .field("raw_mode", &self.raw_mode)
            .field("arch", &self.arch)
            .finish()
    }
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

impl<A: ArchTag> Capstone<A> {
    /// Create a new instance of the decompiler using the builder pattern interface.
    /// This is the recommended interface to `Capstone`.
    ///
    /// ```
    /// use capstone::arch::x86::X86ArchTag;
    /// use capstone::prelude::*;
    /// let cs = Capstone::<X86ArchTag>::new().mode(arch::x86::ArchMode::Mode32).build();
    /// ```
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> A::Builder {
        A::Builder::default()
    }

    /// Create a new instance of the decompiler using the "raw" interface. The user must ensure that only sensible
    /// [`Arch`] / [`Mode`] combinations are used.
    ///
    /// This function will return an `Err` value if the given [`Arch`], [`Mode`], or extra modes are invalid for the
    /// disassembler's target architecture specified by `A`.
    ///
    /// ```
    /// use capstone::{Arch, Capstone, NO_EXTRA_MODE, Mode};
    /// use capstone::arch::DynamicArchTag;
    /// let cs = Capstone::<DynamicArchTag>::new_raw(Arch::X86, Mode::Mode64, NO_EXTRA_MODE, None);
    /// assert!(cs.is_ok());
    /// ```
    pub fn new_raw<T: Iterator<Item = ExtraMode>>(
        arch: Arch,
        mode: Mode,
        extra_mode: T,
        endian: Option<Endian>,
    ) -> CsResult<Self> {
        if !A::support_arch(arch) {
            return Err(Error::UnsupportedArch);
        }

        let mut handle: csh = 0;
        let csarch: cs_arch = arch.into();
        let csmode: cs_mode = mode.into();

        // todo(tmfink): test valid modes at run time (or modify upstream capstone)

        let endian = match endian {
            Some(endian) => cs_mode::from(endian),
            None => cs_mode(0),
        };
        let extra_mode = extra_mode_value(extra_mode);

        let combined_mode = csmode | endian | extra_mode;
        let err = unsafe { cs_open(csarch, combined_mode, &mut handle) };

        if cs_err::CS_ERR_OK == err {
            let syntax = cs_opt_value::CS_OPT_SYNTAX_DEFAULT;
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
                _arch_tag: PhantomData::default(),
            };
            cs.update_raw_mode();
            Ok(cs)
        } else {
            Err(err.into())
        }
    }

    /// Disassemble all instructions in buffer.
    ///
    /// ```
    /// # use capstone::prelude::*;
    /// # use capstone::arch::x86::X86ArchTag;
    /// # let cs = Capstone::<X86ArchTag>::new().mode(arch::x86::ArchMode::Mode32).build().unwrap();
    /// cs.disasm_all(b"\x90", 0x1000).unwrap();
    /// ```
    pub fn disasm_all<'a>(&'a self, code: &[u8], addr: u64) -> CsResult<Instructions<'a, A>> {
        self.disasm(code, addr, 0)
    }

    /// Disassemble `count` instructions in `code`.
    pub fn disasm_count<'a>(
        &'a self,
        code: &[u8],
        addr: u64,
        count: usize,
    ) -> CsResult<Instructions<'a, A>> {
        if count == 0 {
            return Err(Error::CustomError("Invalid dissasemble count; must be > 0"));
        }
        self.disasm(code, addr, count)
    }

    /// Disassembles a `&[u8]` full of instructions.
    ///
    /// Pass `count = 0` to disassemble all instructions in the buffer.
    fn disasm<'a>(&'a self, code: &[u8], addr: u64, count: usize) -> CsResult<Instructions<'a, A>> {
        // SAFETY NOTE: `cs_disasm()` will write the error state into the
        // `struct cs_struct` (true form of the `self.csh`) `errnum` field.
        // CLAIM: since:
        // - `Capstone` is not `Send`/`Sync`
        // - The mutation is done through a `*mut c_void` (not through a const reference)
        // it *should* be safe to accept `&self` (instead of `&mut self`) in this method.

        let mut ptr: *mut cs_insn = core::ptr::null_mut();
        let insn_count =
            unsafe { cs_disasm(self.csh(), code.as_ptr(), code.len(), addr, count, &mut ptr) };
        if insn_count == 0 {
            match self.error_result() {
                Ok(_) => Ok(Instructions::new_empty()),
                Err(err) => Err(err),
            }
        } else {
            Ok(unsafe { Instructions::from_raw_parts(ptr, insn_count) })
        }
    }

    /// Returns csh handle.
    #[inline]
    fn csh(&self) -> csh {
        self.csh as csh
    }

    /// Returns the raw mode value, which is useful for debugging.
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

    /// Set extra modes in addition to normal `mode`.
    pub fn set_extra_mode<T: Iterator<Item = A::ExtraMode>>(
        &mut self,
        extra_mode: T,
    ) -> CsResult<()> {
        let old_val = self.extra_mode;

        self.extra_mode = extra_mode_value(extra_mode.map(|x| x.into()));

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

    /// Set the assembly syntax (has no effect on some platforms).
    pub fn set_syntax(&mut self, syntax: A::Syntax) -> CsResult<()> {
        // Todo(tmfink) check for valid syntax
        let syntax_int = cs_opt_value::from(syntax.into());
        let result = self._set_cs_option(cs_opt_type::CS_OPT_SYNTAX, syntax_int.0 as usize);

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

    /// Controls whether capstone should generate extra details about disassembled instructions.
    ///
    /// Pass `true` to enable detail or `false` to disable detail.
    pub fn set_detail(&mut self, enable_detail: bool) -> CsResult<()> {
        let option_value: usize = OptValue::from(enable_detail).0 .0 as usize;
        let result = self._set_cs_option(cs_opt_type::CS_OPT_DETAIL, option_value);

        // Only update internal state on success
        if result.is_ok() {
            self.detail_enabled = enable_detail;
        }

        result
    }

    /// Controls whether capstone should skip over invalid or data instructions.
    ///
    /// Pass `true` to enable skipdata or `false` to disable skipdata.
    pub fn set_skipdata(&mut self, enable_skipdata: bool) -> CsResult<()> {
        let option_value: usize = OptValue::from(enable_skipdata).0 .0 as usize;
        let result = self._set_cs_option(cs_opt_type::CS_OPT_SKIPDATA, option_value);

        // Only update internal state on success
        if result.is_ok() {
            self.skipdata_enabled = enable_skipdata;
        }

        result
    }

    /// Converts a register id `reg_id` to a `String` containing the register name.
    /// Unavailable in Diet mode.
    pub fn reg_name(&self, reg_id: A::RegId) -> Option<String> {
        if cfg!(feature = "full") {
            let reg_name = unsafe {
                let _reg_name = cs_reg_name(self.csh(), reg_id.into().0 as libc::c_uint);
                str_from_cstr_ptr(_reg_name)?.to_string()
            };
            Some(reg_name)
        } else {
            None
        }
    }

    /// Converts an instruction id `insn_id` to a `String` containing the instruction name.
    /// Unavailable in Diet mode.
    /// Note: This function ignores the current syntax and uses the default syntax.
    pub fn insn_name(&self, insn_id: A::InsnId) -> Option<String> {
        if cfg!(feature = "full") {
            let insn_name = unsafe {
                let _insn_name = cs_insn_name(self.csh(), insn_id.into().0 as libc::c_uint);
                str_from_cstr_ptr(_insn_name)?.to_string()
            };

            Some(insn_name)
        } else {
            None
        }
    }

    /// Converts a group id `group_id` to a `String` containing the group name.
    /// Unavailable in Diet mode.
    pub fn group_name(&self, group_id: A::InsnGroupId) -> Option<String> {
        if cfg!(feature = "full") {
            let group_name = unsafe {
                let _group_name = cs_group_name(self.csh(), group_id.into().0 as libc::c_uint);
                str_from_cstr_ptr(_group_name)?.to_string()
            };

            Some(group_name)
        } else {
            None
        }
    }

    /// Returns `Detail` structure for a given instruction.
    ///
    /// Requires:
    ///
    /// 1. Instruction was created with details enabled.
    /// 2. Skipdata is disabled.
    pub fn insn_detail<'s, 'i: 's>(&'s self, insn: &'i Insn<A>) -> CsResult<InsnDetail<'i, A>> {
        if !self.detail_enabled {
            Err(Error::DetailOff)
        } else if insn.id().0 == 0 {
            Err(Error::IrrelevantDataInSkipData)
        } else {
            Ok(unsafe { insn.detail(self.arch) })
        }
    }
}

impl<A: ArchTag> Drop for Capstone<A> {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh()) };
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

/// Return the integer value used by capstone to represent the set of extra modes
fn extra_mode_value<T: Iterator<Item = ExtraMode>>(extra_mode: T) -> cs_mode {
    // Bitwise OR extra modes
    extra_mode.fold(cs_mode(0), |acc, x| acc | cs_mode::from(x))
}
