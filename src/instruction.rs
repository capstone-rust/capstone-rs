extern crate libc;
extern crate num;
use std::ptr;
use std::str;
use std::ffi::CStr;
use std::fmt::{Display, Debug, Formatter, Error};
use ffi::cs_free;
use num::FromPrimitive;
use constants::*;

/// Representation of the array of instructions returned by disasm
pub struct Instructions {
    ptr: *const Insn,
    len: isize,
}

impl Instructions {
    pub unsafe fn from_raw_parts(ptr: *const Insn, len: isize) -> Instructions {
        Instructions { ptr: ptr, len: len }
    }

    pub fn len(&self) -> isize {
        self.len
    }

    pub fn iter(&self) -> InstructionIterator {
        InstructionIterator {
            insns: &self,
            cur: 0,
        }
    }
}

impl Drop for Instructions {
    fn drop(&mut self) {
        unsafe {
            cs_free(self.ptr, self.len as libc::size_t);
        }
    }
}

/// An iterator over the instructions returned by disasm
///
/// This is currently the only supported interface for reading them.
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
            let obj = unsafe { self.insns.ptr.offset(self.cur) };
            self.cur += 1;
            Some(unsafe { ptr::read(obj) })
        }
    }
}

#[repr(C)]
/// A logical instruction disassembled by capstone
pub struct Insn {
    id: ::libc::c_uint,
    pub address: u64,
    pub size: u16,
    bytes: [u8; 16usize],
    mnemonic: [::libc::c_char; 32usize],
    op_str: [::libc::c_char; 160usize],
    detail: *mut CsDetail,
}

impl Insn {
    /// The mnemonic for the instruction
    pub fn mnemonic(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.mnemonic.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// The operand string associated with the instruction
    pub fn op_str(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.op_str.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// Access instruction id
    pub fn id(&self) -> libc::c_uint {
        self.id
    }

    /// Access instruction bytes
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[0..(self.size as usize)]
    }

    // Should be private, but then we could not access it from other modules
    #[doc(hidden)]
    /// Returns instruction details
    pub fn detail(&self) -> *mut CsDetail {
        self.detail
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

impl Display for Insn {
    #[allow(unused_must_use)]
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        write!(fmt, "{:#x}: ", self.address);
        if let Some(mnemonic) = self.mnemonic() {
            write!(fmt, "{} ", mnemonic);
            if let Some(op_str) = self.op_str() {
                write!(fmt, "{}", op_str);
            }
        }
        Ok(())
    }
}

#[repr(C)]
/// Represents details for instruction
///
/// Only available if disassembled with details.
pub struct CsDetail {
    regs_read: [u8; 12usize], // list of implicit registers read by this insn
    regs_read_count: u8, // number of implicit registers read by this insn
    regs_write: [u8; 20usize], // list of implicit registers modified by this insn
    regs_write_count: u8, // number of implicit registers modified by this insn
    groups: [u8; 8usize], // list of group this instruction belong to
    groups_count: u8, // number of groups this insn belongs to
}

impl CsDetail {
    /// Return ids of implicit read registers
    pub fn regs_read_ids(&self) -> &[u8] {
        &self.regs_read[..self.regs_read_count as usize]
    }

    /// Return ids of implicit write registers
    pub fn regs_write_ids(&self) -> &[u8] {
        &self.regs_write[..self.regs_write_count as usize]
    }

    /// Return ids of instruction groups to which instructions belong
    pub fn groups_ids(&self) -> &[u8] {
        &self.groups[..self.groups_count as usize]
    }

    /// Return architecture-independent instruction groups
    pub fn groups(&self) -> Vec<CsGroupType> {
        // Ignore integer values for which there is no CsGroupType because they are
        // architecture-specific
        self.groups_ids()
            .iter()
            .filter_map(|&x| CsGroupType::from_u8(x))
            .collect()
    }
}
