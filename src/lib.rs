#![feature(libc)]
#![feature(core)]
#![feature(debug_builders)]
extern crate libc;

use std::ptr;
use std::mem;
use std::slice;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Error};

use std::io;
use std::str;
use std::intrinsics;
use std::io::Write;

#[repr(C)]
pub enum CsArch {
    ARCH_ARM = 0,    // ARM architecture (including Thumb, Thumb-2)
    ARCH_ARM64,      // ARM-64, also called AArch64
    ARCH_MIPS,       // Mips architecture
    ARCH_X86,        // X86 architecture (including x86 & x86-64)
    ARCH_PPC,        // PowerPC architecture
    ARCH_SPARC,      // Sparc architecture
    ARCH_SYSZ,       // SystemZ architecture
    ARCH_XCORE,      // XCore architecture
    ARCH_MAX,
    ARCH_ALL = 0xFFFF, // All architectures - for cs_support()
}

#[repr(C)]
pub enum CsMode {
    MODE_LITTLE_ENDIAN = 0,  // little-endian mode (default mode)
    // MODE_ARM = 0,    // 32-bit ARM
    MODE_16 = 1 << 1,    // 16-bit mode (X86)
    MODE_32 = 1 << 2,    // 32-bit mode (X86)
    MODE_64 = 1 << 3,    // 64-bit mode (X86, PPC)
    MODE_THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    MODE_MCLASS = 1 << 5,    // ARM's Cortex-M series
    MODE_V8 = 1 << 6,    // ARMv8 A32 encodings for ARM
    // MODE_MICRO = 1 << 4, // MicroMips mode (MIPS)
    // MODE_MIPS3 = 1 << 5, // Mips III ISA
    // MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA
    // MODE_MIPSGP64 = 1 << 7, // General Purpose Registers are 64-bit wide (MIPS)
    // MODE_V9 = 1 << 4, // SparcV9 mode (Sparc)
    MODE_BIG_ENDIAN = 1 << 31,   // big-endian mode
    // MODE_MIPS32 = CsMode::MODE_32,    // Mips32 ISA (Mips)
    // MODE_MIPS64 = CsMode::MODE_64,    // Mips64 ISA (Mips)
}

#[repr(C)]
enum CsErr {
    CS_ERR_OK = 0,   // No error: everything was fine
    CS_ERR_MEM,      // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    CS_ERR_ARCH,     // Unsupported architecture: cs_open()
    CS_ERR_HANDLE,   // Invalid handle: cs_op_count(), cs_op_index()
    CS_ERR_CSH,      // Invalid csh argument: cs_close(), cs_errno(), cs_option()
    CS_ERR_MODE,     // Invalid/unsupported mode: cs_open()
    CS_ERR_OPTION,   // Invalid/unsupported option: cs_option()
    CS_ERR_DETAIL,   // Information is unavailable because detail option is OFF
    CS_ERR_MEMSETUP, // Dynamic memory management uninitialized (see CS_OPT_MEM)
    CS_ERR_VERSION,  // Unsupported version (bindings)
    CS_ERR_DIET,     // Access irrelevant data in "diet" engine
    CS_ERR_SKIPDATA, // Access irrelevant data for "data" instruction in SKIPDATA mode
    CS_ERR_X86_ATT,  // X86 AT&T syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_INTEL, // X86 Intel syntax is unsupported (opt-out at compile time)
}

type csh = libc::size_t;
#[link(name = "capstone")]
extern "C" {
    fn cs_open(arch: CsArch, mode: CsMode, handle: *mut csh) -> CsErr;
    fn cs_close(handle: *mut csh) -> CsErr;
    fn cs_disasm(handle: csh, code: *const u8, code_size: isize,
                 address: u64, count: isize, insn: &mut *const Insn) -> isize;
    fn cs_disasm_ex(handle: csh, code: *const u8, code_size: isize,
                    address: u64, count: isize, insn: &mut *const Insn) -> isize;
}

pub struct Capstone {
    csh: libc::size_t, // Opaque handle to cs_engine
}

// Using an actual slice is causing issues with auto deref, instead implement a custom iterator and
// drop trait
pub struct Instructions {
    ptr: *const Insn,
    len: isize,
}

impl Instructions {
    fn from_raw_parts(ptr: *const Insn, len: isize) -> Instructions {
        Instructions {
            ptr: ptr,
            len: len,
        }
    }

    pub fn len(&self) -> isize {
        self.len
    }

    pub fn iter(&self) -> InstructionIterator {
        InstructionIterator { insns: &self, cur: 0 }
    }
}

pub struct InstructionIterator<'a> {
    insns: &'a Instructions,
    cur: isize,
}

impl<'a> Iterator for InstructionIterator<'a> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        if self.cur == self.insns.len {
            None
        } else {
            let obj = unsafe { intrinsics::offset(self.insns.ptr, self.cur) };
            self.cur += 1;
            Some(unsafe { *obj })
        }
    }
}

impl Capstone {
    pub fn new(arch: CsArch, mode: CsMode) -> Option<Capstone> {
        let mut handle: libc::size_t = 0;
        if let CsErr::CS_ERR_OK = unsafe { cs_open(arch, mode, &mut handle) } {
            Some(Capstone {
                csh: handle
            })
        } else {
            None
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: isize) -> Option<Instructions> {
        let mut ptr: *const Insn = ptr::null();
        let insn_count = unsafe { cs_disasm(self.csh, code.as_ptr(), code.len() as isize, addr, count, &mut ptr) };
        if insn_count == 0 {
            // TODO  On failure, call cs_errno() for error code.
            return None
        }

        Some(Instructions::from_raw_parts(ptr, insn_count))
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}

#[repr(C)]
#[derive(Copy)]
pub struct Insn {
    id: ::libc::c_uint,
    pub address: u64,
    pub size: u16,
    pub bytes: [u8; 16usize],
    pub mnemonic: [::libc::c_char; 32usize],
    pub op_str: [::libc::c_char; 160usize],
    detail: *mut libc::c_void, // Opaque cs_detail
}

impl Insn {
    pub fn mnemonic(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.mnemonic.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    pub fn op_str(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.op_str.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }
}

impl Debug for Insn {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        fmt.debug_struct("Insn")
            .field("address", &self.address)
            .field("size", &self.size)
            .field("mnemonic", &self.mnemonic())
            .field("op_str", &self.op_str())
            .finish()
    }
}
