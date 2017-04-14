use libc;
use instruction::Insn;
use constants::{CsArch, CsMode, CsErr, CsOptType};
use csh;

#[allow(dead_code)]
#[link(name = "capstone")]
extern "C" {
    pub fn cs_version(major: *mut libc::c_int, minor: *mut libc::c_int) -> libc::c_uint;
    pub fn cs_support(query: libc::c_int) -> bool;
    pub fn cs_open(arch: CsArch, mode: CsMode, handle: *mut csh) -> CsErr;
    pub fn cs_close(handle: *mut csh) -> CsErr;
    pub fn cs_disasm(handle: csh,
                     code: *const u8,
                     code_size: libc::size_t,
                     address: u64,
                     count: libc::size_t,
                     insn: &mut *const Insn)
                     -> libc::size_t;
    pub fn cs_free(insn: *const Insn, count: libc::size_t);
    pub fn cs_reg_name(handle: csh, reg_id: libc::c_uint) -> *const libc::c_char;
    pub fn cs_insn_name(handle: csh, insn_id: libc::c_uint) -> *const libc::c_char;
    pub fn cs_group_name(handle: csh, group_id: libc::c_uint) -> *const libc::c_char;
    pub fn cs_insn_group(handle: csh, cs_insn: *const Insn, group_id: libc::c_uint) -> bool;
    pub fn cs_reg_read(handle: csh, cs_insn: *const Insn, reg_id: libc::c_uint) -> bool;
    pub fn cs_reg_write(handle: csh, cs_insn: *const Insn, reg_id: libc::c_uint) -> bool;
    pub fn cs_option(handle: csh, option_type: CsOptType, value: libc::size_t) -> CsErr;
    pub fn cs_errno(handle: csh) -> CsErr;
    pub fn cs_strerror(err: CsErr) -> *const libc::c_char;
}
