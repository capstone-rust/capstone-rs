extern crate libc;
use std::ptr;
use std::str;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Error};
use ffi::cs_free;

/// Representation of the array of instructions returned by disasm
pub struct Instructions {
    ptr: *const Insn,
    len: isize,
}

impl Instructions {
    pub unsafe fn from_raw_parts(ptr: *const Insn, len: isize) -> Instructions {
        Instructions {
            ptr: ptr,
            len: len,
        }
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
    pub bytes: [u8; 16usize],
    pub mnemonic: [::libc::c_char; 32usize],
    pub op_str: [::libc::c_char; 160usize],
    detail: *mut libc::c_void, // Opaque cs_detail
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
