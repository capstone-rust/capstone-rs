use std::convert::From;
use std::ffi::CStr;
use std::fmt;
use ffi::cs_strerror;
use libc;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Architectures for the disassembler
///
/// Corresponds to the Capstone type `cs_arch`.
pub enum CsArch {
    ARCH_ARM = 0, // ARM architecture (including Thumb, Thumb-2)
    ARCH_ARM64, // ARM-64, also called AArch64
    ARCH_MIPS, // Mips architecture
    ARCH_X86, // X86 architecture (including x86 & x86-64)
    ARCH_PPC, // PowerPC architecture
    ARCH_SPARC, // Sparc architecture
    ARCH_SYSZ, // SystemZ architecture
    ARCH_XCORE, // XCore architecture
    CS_ARCH_M68K, // 68K architecture
    ARCH_MAX,
    ARCH_ALL = 0xFFFF, // All architectures - for cs_support()
}

pub const CS_SUPPORT_DIET: libc::c_int = (CsArch::ARCH_ALL as libc::c_int) + 1;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Disassembler modes
///
/// Corresponds to the Capstone type `cs_mode`.
pub enum CsMode {
    MODE_LITTLE_ENDIAN = 0, // little-endian mode (default mode)
    // MODE_ARM = 0,    // 32-bit ARM
    MODE_16 = 1 << 1, // 16-bit mode (X86)
    MODE_32 = 1 << 2, // 32-bit mode (X86)
    MODE_64 = 1 << 3, // 64-bit mode (X86, PPC)
    MODE_THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    MODE_MCLASS = 1 << 5, // ARM's Cortex-M series
    MODE_V8 = 1 << 6, // ARMv8 A32 encodings for ARM
    // MODE_MICRO = 1 << 4, // MicroMips mode (MIPS)
    // MODE_MIPS3 = 1 << 5, // Mips III ISA
    // MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA
    // MODE_MIPSGP64 = 1 << 7, // General Purpose Registers are 64-bit wide (MIPS)
    // MODE_V9 = 1 << 4, // SparcV9 mode (Sparc)
    MODE_BIG_ENDIAN = 1 << 31, /* big-endian mode
                                * MODE_MIPS32 = CsMode::MODE_32,    // Mips32 ISA (Mips)
                                * MODE_MIPS64 = CsMode::MODE_64,    // Mips64 ISA (Mips) */
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Error states returned by various disassembler features
///
/// Corresponds to the Capstone type `cs_err`.
pub enum CsErr {
    CS_ERR_OK = 0, // No error: everything was fine
    CS_ERR_MEM, // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    CS_ERR_ARCH, // Unsupported architecture: cs_open()
    CS_ERR_HANDLE, // Invalid handle: cs_op_count(), cs_op_index()
    CS_ERR_CSH, // Invalid csh argument: cs_close(), cs_errno(), cs_option()
    CS_ERR_MODE, // Invalid/unsupported mode: cs_open()
    CS_ERR_OPTION, // Invalid/unsupported option: cs_option()
    CS_ERR_DETAIL, // Information is unavailable because detail option is OFF
    CS_ERR_MEMSETUP, // Dynamic memory management uninitialized (see CS_OPT_MEM)
    CS_ERR_VERSION, // Unsupported version (bindings)
    CS_ERR_DIET, // Access irrelevant data in "diet" engine
    CS_ERR_SKIPDATA, // Access irrelevant data for "data" instruction in SKIPDATA mode
    CS_ERR_X86_ATT, // X86 AT&T syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_INTEL, // X86 Intel syntax is unsupported (opt-out at compile time)
}

impl fmt::Display for CsErr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s = unsafe {
            let err = cs_strerror(*self);
            CStr::from_ptr(err).to_string_lossy().into_owned()
        };
        write!(fmt, "{}", s)
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Runtime option for the disassembled engine
///
/// Corresponds to the Capstone type `cs_opt_type`.
pub enum CsOptType {
    CS_OPT_INVALID = 0, // No option specified
    CS_OPT_SYNTAX, // Assembly output syntax
    CS_OPT_DETAIL, // Break down instruction structure into details
    CS_OPT_MODE, // Change engine's mode at run-time
    CS_OPT_MEM, // User-defined dynamic memory related functions
    CS_OPT_SKIPDATA, // Skip data when disassembling. Then engine is in SKIPDATA mode.
}

// The cs_opt_value C enum is partitioned into CsOptValueBool and CsOptValueSyntax Rust enums
// because Rust enum variants must have unique discriminant values

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Boolean runtime option values corresponding to CsOptType
///
/// Corresponds to a subset of the Capstone type `cs_opt_value`.
pub enum CsOptValueBool {
    CS_OPT_OFF = 0, // Turn OFF an option - default option of CS_OPT_DETAIL, CS_OPT_SKIPDATA.
    CS_OPT_ON = 3, // Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
}

impl From<bool> for CsOptValueBool {
    fn from(value: bool) -> Self {
        if value {
            CsOptValueBool::CS_OPT_ON
        } else {
            CsOptValueBool::CS_OPT_OFF
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Runtime option values corresponding to `CsOptType::CS_OPT_SYNTAX`
///
/// Corresponds to a subset of the Capstone type `cs_opt_value`.
pub enum CsOptValueSyntax {
    CS_OPT_SYNTAX_DEFAULT = 0, // Default asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_INTEL, // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_ATT, // X86 ATT asm syntax (CS_OPT_SYNTAX).
    CS_OPT_SYNTAX_NOREGNAME, // Prints register name with only number (CS_OPT_SYNTAX)
}

#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Runtime option values corresponding to all possible `CsOptType`
///
/// Corresponds to the Capstone type `cs_opt_value`.
pub enum CsOptValue {
    Bool(CsOptValueBool),
    Syntax(CsOptValueSyntax),
}

impl Into<libc::size_t> for CsOptValue {
    fn into(self) -> libc::size_t {
        match self {
            CsOptValue::Bool(b) => b as libc::size_t,
            CsOptValue::Syntax(s) => s as libc::size_t,
        }
    }
}


enum_from_primitive! {
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone,Copy,PartialEq,Eq,Debug,Hash)]
/// Common instruction groups
///
/// Corresponds to Capstone's `cs_group_type`.
pub enum CsGroupType {
    CS_GRP_INVALID = 0, // uninitialized/invalid group.
    CS_GRP_JUMP, // all jump instructions (conditional+direct+indirect jumps)
    CS_GRP_CALL, // all call instructions
    CS_GRP_RET, // all return instructions
    CS_GRP_INT, // all interrupt instructions (int+syscall)
    CS_GRP_IRET, // all interrupt return instructions
}
}
