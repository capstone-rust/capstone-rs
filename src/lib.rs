#![feature(libc)]
#![feature(core)]
#![feature(debug_builders)]
extern crate libc;

pub mod instruction;
pub mod constants;

pub use constants::{CsArch, CsMode};
use constants::{CsErr};

pub use instruction::*;

use std::ptr;

// bindgen by default used this type name everywhere, it is easier to leave it alone.
#[allow(non_camel_case_types)]
type csh = libc::size_t;

#[allow(dead_code)]
#[link(name = "capstone")]
extern "C" {
    fn cs_open(arch: CsArch, mode: CsMode, handle: *mut csh) -> CsErr;
    fn cs_close(handle: *mut csh) -> CsErr;
    fn cs_disasm(handle: csh, code: *const u8, code_size: libc::size_t,
                 address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
    fn cs_disasm_ex(handle: csh, code: *const u8, code_size: libc::size_t,
                    address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
}

pub struct Capstone {
    csh: libc::size_t, // Opaque handle to cs_engine
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
        let insn_count = unsafe { cs_disasm(self.csh, code.as_ptr(), code.len() as libc::size_t,
                                            addr, count as libc::size_t, &mut ptr) };
        if insn_count == 0 {
            // TODO  On failure, call cs_errno() for error code.
            return None
        }

        Some(Instructions::from_raw_parts(ptr, insn_count as isize))
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
