use libc;
use std::ptr;
use std::ffi::CStr;
use error::*;
use capstone_sys::*;
use capstone_sys::cs_arch::*;
use capstone_sys::cs_mode::*;
use capstone_sys;
use instruction::Instructions;

/// An instance of the capstone disassembler
pub struct Capstone {
    csh: capstone_sys::csh,
    _arch: Arch,
}

/// Define an `enum` that corresponds to a capstone enum
///
/// The different `From` implementations can be disabled by using the cfg attribute
macro_rules! define_cs_enum_wrapper {
    ( [
        $( #[$enum_attr:meta] )*
        => $rust_enum:ident = $cs_enum:ident,
        $( #[$cs_to_rust_attrs:meta] )*
        ,
        $( #[$rust_to_cs_attrs:meta] )*
      ]
      $( $( #[$attr:meta] )*
      => $rust_variant:ident = $cs_variant:tt; )* ) => {

        $( #[$enum_attr] )*
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub enum $rust_enum {
            $(
                $( #[$attr] )*
                $rust_variant,
            )*
        }

        $( #[$cs_to_rust_attrs] )*
        impl From<$cs_enum> for $rust_enum {
            fn from(other: $cs_enum) -> Self {
                match other {
                    $(
                        $cs_enum::$cs_variant => $rust_enum::$rust_variant,
                    )*
                }
            }
        }

        $( #[$rust_to_cs_attrs] )*
        impl From<$rust_enum> for $cs_enum {
            fn from(other: $rust_enum) -> Self {
                match other {
                    $(
                        $rust_enum::$rust_variant => $cs_variant,
                    )*
                }
            }
        }
    }
}

define_cs_enum_wrapper!(
    [
        /// Architectures for the disassembler
        => Arch = cs_arch,
        ,
    ]
    /// ARM (Advanced RISC Machine)
    => ARM = CS_ARCH_ARM;
    /// ARM 64-bit (also known as AArch64)
    => ARM64 = CS_ARCH_ARM64;
    /// MIPS
    => MIPS = CS_ARCH_MIPS;
    /// x86 family (includes 16, 32, and 64 bit modes)
    => X86 = CS_ARCH_X86;
    /// PowerPC
    => PPC = CS_ARCH_PPC;
    /// SPARC
    => SPARC = CS_ARCH_SPARC;
    /// System z
    => SYSZ = CS_ARCH_SYSZ;
    /// XCore
    => XCORE = CS_ARCH_XCORE;
    => MAX = CS_ARCH_MAX;
    /// used for `cs_support()`
    => ALL = CS_ARCH_ALL;
);

define_cs_enum_wrapper!(
    [
        /// Disassembler modes
        => Mode = cs_mode,
        #[cfg(other)]
        ,
    ]
    /// little-endian mode (default mode)
    => LittleEndian = CS_MODE_LITTLE_ENDIAN;
    /// 32-bit ARM
    => Arm32 = CS_MODE_ARM;
    /// 16-bit mode (X86)
    => Mode16 = CS_MODE_16;
    /// 32-bit mode (X86)
    => Mode32 = CS_MODE_32;
    /// 64-bit mode (X86, PPC)
    => Mode64 = CS_MODE_64;
    /// ARM's Thumb mode, including Thumb-2
    => Thumb = CS_MODE_THUMB;
    /// ARM's Cortex-M series
    => MClass = CS_MODE_MCLASS;
    /// ARMv8 A32 encodings for ARM
    => V8 = CS_MODE_V8;
    /// MicroMips mode (MIPS)
    => Micro = CS_MODE_MICRO;
    /// Mips III ISA
    => Mips3 = CS_MODE_MIPS3;
    /// Mips32r6 ISA
    => Mips32R6 = CS_MODE_MIPS32R6;
    /// General Purpose Registers are 64-bit wide (MIPS)
    => MipsGP64 = CS_MODE_MIPSGP64;
    /// SparcV9 mode (Sparc)
    => V9 = CS_MODE_V9;
    /// big-endian mode
    => BigEndian = CS_MODE_BIG_ENDIAN;
    /// Mips32 ISA (Mips)
    => Mips32 = CS_MODE_MIPS32;
    /// Mips64 ISA (Mips)
    => Mips64 = CS_MODE_MIPS64;
);

impl Capstone {
    /// Create a new instance of the decompiler. Defaults to 64-bit little-endian mode.
    ///
    /// ```
    /// use capstone3::{Arch, Capstone};
    /// let cs = Capstone::new(Arch::X86);
    /// assert!(cs.is_ok());
    /// ```
    pub fn new(arch: Arch) -> Result<Capstone> {
        let mut handle: capstone_sys::csh = 0;
        let csarch: cs_arch = arch.into();
        let csmode = CS_MODE_LITTLE_ENDIAN;
        let err = unsafe { cs_open(csarch, csmode, &mut handle) };
        // this can be put into a macro, cs_try, but i guess who cares
        if cs_err::CS_ERR_OK == err {
            Ok(Capstone { csh: handle, _arch: arch })
        } else {
            Err(Error::from(err))
        }
    }

    #[inline]
    fn set_option(&self, opt_type: cs_opt_type, value: usize) -> Result<()> {
        let err = unsafe {
            cs_option(self.csh, opt_type, value)
        };
        if cs_err::CS_ERR_OK == err {
            Ok(())
        } else {
            Err(Error::from(err))
        }
    }

    /// Set the disassembly engine to use detail mode
    pub fn detail(&self) -> Result<()> {
        self.set_option(cs_opt_type::CS_OPT_DETAIL, cs_opt_value::CS_OPT_ON as libc::size_t)
    }

    /// Sets the engine's disassembly mode.
    /// Be careful, various combinations of modes aren't supported
    /// See the capstone-sys documentation for more information.
    pub fn mode(&mut self, modes: &[Mode]) -> Result<()> {
        let mut value: usize = 0;
        for mode in modes {
            let mode = cs_mode::from(*mode);
            value |= mode as usize;
        }
        self.set_option(cs_opt_type::CS_OPT_MODE, value)
    }

    /// Set the X86 assembly to AT&T style (has no effect on other platforms)
    pub fn att(&self) {
        self.set_option(cs_opt_type::CS_OPT_SYNTAX, cs_opt_value::CS_OPT_SYNTAX_ATT as usize).unwrap()
    }

    /// Set the X86 assembly to Intel style (default)
    pub fn intel(&self) {
        self.set_option(cs_opt_type::CS_OPT_SYNTAX, cs_opt_value::CS_OPT_SYNTAX_INTEL as usize).unwrap()
    }

    /// Disassemble a &[u8] `buffer` full of instructions
    ///
    /// Disassembles all instructions in `code`. If you want to disassemble less, then pass a smaller slice :]
    pub fn disassemble(&self, buffer: &[u8], addr: u64) -> Result<Instructions> {
        let mut ptr: *mut capstone_sys::cs_insn = ptr::null_mut();
        let insn_count = unsafe {
            cs_disasm(self.csh,
                      buffer.as_ptr(),
                      buffer.len() as libc::size_t,
                      addr,
                      0 as libc::size_t,
                      &mut ptr)
        };
        if insn_count == 0 {
            // we can just simply not have found instructions in the buffer; this isn't an error
            // so we just return an empty instructions
            // I worry this will explode when freeing, we need a better api to just convert to a
            // straight vector
            let err = unsafe { cs_errno(self.csh) };
            if err != cs_err::CS_ERR_OK {
                return Err(Error::from(err))
            }
        }
        Ok(unsafe { Instructions::from_raw_parts(ptr, insn_count as isize) })
    }

    /// Convert a reg_id to a String naming the register
    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_reg_name(self.csh, reg_id as libc::c_uint);
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
            let _insn_name = cs_insn_name(self.csh, insn_id as libc::c_uint);
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
