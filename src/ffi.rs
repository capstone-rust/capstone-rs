use libc;
use instruction::Insn;
use constants::{CsArch, CsMode, CsErr};
use csh;

#[allow(dead_code)]
#[link(name = "capstone")]
extern "C" {
    pub fn cs_open(arch: CsArch, mode: CsMode, handle: *mut csh) -> CsErr;
    pub fn cs_close(handle: *mut csh) -> CsErr;
    pub fn cs_disasm(handle: csh, code: *const u8, code_size: libc::size_t,
                     address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
    pub fn cs_disasm_ex(handle: csh, code: *const u8, code_size: libc::size_t,
                        address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
    pub fn cs_free(insn: *const Insn, count: libc::size_t);
}

