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

/// Architectures for the disassembler
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum Arch {
    ARM,
    ARM64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSZ,
    XCORE,
    MAX,
    /// used for `cs_support()`
    ALL,
}

impl Arch {
    pub fn to_cs_arch(&self) -> cs_arch {
        use Arch::*;
        match *self {
            ARM => CS_ARCH_ARM,
            ARM64 => CS_ARCH_ARM64,
            MIPS => CS_ARCH_MIPS,
            X86 => CS_ARCH_X86,
            PPC => CS_ARCH_PPC,
            SPARC => CS_ARCH_SPARC,
            SYSZ => CS_ARCH_SYSZ,
            XCORE => CS_ARCH_XCORE,
            MAX => CS_ARCH_MAX,
            ALL => CS_ARCH_ALL,
        }
    }
}

/// Disassembler modes
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum Mode {
    /// little-endian mode (default mode)
    LittleEndian,
    /// 32-bit ARM
    Arm32,
    /// 16-bit mode (X86)
    Mode16,
    /// 32-bit mode (X86)
    Mode32,
    /// 64-bit mode (X86, PPC)
    Mode64,
    /// ARM's Thumb mode, including Thumb-2
    Thumb,
    /// ARM's Cortex-M series
    MClass,
    /// ARMv8 A32 encodings for ARM
    V8,
    /// MicroMips mode (MIPS)
    Micro,
    /// Mips III ISA
    Mips3,
    /// Mips32r6 ISA
    Mips32R6,
    /// General Purpose Registers are 64-bit wide (MIPS)
    MipsGP64,
    /// SparcV9 mode (Sparc)
    V9,
    /// big-endian mode
    BigEndian,
    /// Mips32 ISA (Mips)
    Mips32,
    /// Mips64 ISA (Mips)
    Mips64,
}

impl Mode {
    pub fn to_cs_mode(&self) -> capstone_sys::cs_mode {
        use Mode::*;
        match *self {
            LittleEndian => CS_MODE_LITTLE_ENDIAN,
            Arm32 => CS_MODE_ARM,
            Mode16 => CS_MODE_16,
            Mode32 => CS_MODE_32,
            Mode64 => CS_MODE_64,
            Thumb => CS_MODE_THUMB,
            MClass => CS_MODE_MCLASS,
            V8 => CS_MODE_V8,
            Micro => CS_MODE_MICRO,
            Mips3 => CS_MODE_MIPS3,
            Mips32R6 => CS_MODE_MIPS32R6,
            MipsGP64 => CS_MODE_MIPSGP64,
            V9 => CS_MODE_V9,
            BigEndian => CS_MODE_BIG_ENDIAN,
            Mips32 => CS_MODE_MIPS32,
            Mips64 => CS_MODE_MIPS64,
        }
    }
}

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
        let csarch = arch.to_cs_arch();
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
            value |= mode.to_cs_mode() as usize;
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
