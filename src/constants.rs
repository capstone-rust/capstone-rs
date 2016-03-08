use std::ffi::CStr;
use ffi::cs_strerror;

#[repr(C)]
pub enum CsArch {
    ARCH_ARM = 0, // ARM architecture (including Thumb, Thumb-2)
    ARCH_ARM64, // ARM-64, also called AArch64
    ARCH_MIPS, // Mips architecture
    ARCH_X86, // X86 architecture (including x86 & x86-64)
    ARCH_PPC, // PowerPC architecture
    ARCH_SPARC, // Sparc architecture
    ARCH_SYSZ, // SystemZ architecture
    ARCH_XCORE, // XCore architecture
    ARCH_MAX,
    ARCH_ALL = 0xFFFF, // All architectures - for cs_support()
}

#[repr(C)]
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
#[derive(Clone,Copy)]
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

impl ToString for CsErr {
    fn to_string(&self) -> String {
        unsafe {
            let err = cs_strerror(*self);
            CStr::from_ptr(err).to_string_lossy().into_owned()
        }
    }
}
