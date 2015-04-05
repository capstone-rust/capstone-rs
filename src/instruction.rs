extern crate libc;
use std::intrinsics;
use std::ptr;
use std::str;
use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Error};

// Using an actual slice is causing issues with auto deref, instead implement a custom iterator and
// drop trait
pub struct Instructions {
    ptr: *const Insn,
    len: isize,
}

impl Instructions {
    // This method really shouldn't be public, but it was unclear how to make it visible in lib.rs
    // but not globally visible.
    pub fn from_raw_parts(ptr: *const Insn, len: isize) -> Instructions {
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
            Some(unsafe { ptr::read(obj) })
        }
    }
}

#[repr(C)]
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
