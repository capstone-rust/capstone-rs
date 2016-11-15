extern crate libc;
use std::ptr;
use std::str;
use std::ffi::CStr;
use std::fmt::{self, Display, Debug, Formatter, Error};
use capstone_sys::{cs_free, cs_insn, cs_detail};

/// Representation of the array of instructions returned by disasm
#[derive(Debug)]
pub struct Instructions {
    ptr: *mut cs_insn,
    len: isize,
}

impl Instructions {
    pub unsafe fn from_raw_parts(ptr: *mut cs_insn, len: isize) -> Instructions {
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

    pub fn is_empty(&self) -> bool {
        self.len == 0
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
            Some(unsafe { Insn::from(ptr::read(obj)) })
        }
    }
}

/// A wrapper for the raw capstone-sys instruction
pub struct Insn(cs_insn);

/// A wrapper for the raw capstone-sys detail struct, which contains register information in addition
/// to architecture specific information (not implemented in capstone-sys yet)
pub struct Detail(cs_detail);

use std::convert::From;

impl From<cs_insn> for Insn {
    fn from(insn: cs_insn) -> Self {
        Insn (insn)
    }
}

impl From<cs_detail> for Detail{
    fn from(detail: cs_detail) -> Self {
        Detail (detail)
    }
}

impl Insn {
    /// The mnemonic for the instruction
    pub fn mnemonic(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.0.mnemonic.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// The operand string associated with the instruction
    pub fn op_str(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.0.op_str.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// Size of instruction (in bytes)
    pub fn len (&self) -> usize {
        self.0.size as usize
    }

    pub fn address (&self) -> u64 {
        self.0.address as u64
    }

    /// Byte-level representation of the instruction
    pub fn bytes (&self) -> &[u8] {
        &self.0.bytes[..self.len()]
    }

    /// Returns the detail object, if there is one.
    ///
    /// Be careful this is still in early stages and largely untested with various `cs_option` and
    /// architecture matrices
    pub fn detail (&self) -> Option<Detail> {
        if self.0.detail.is_null() {
            None
        } else {
            Some(Detail::from(unsafe { ptr::read(self.0.detail) }))
        }
    }
}

impl Debug for Insn {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        fmt.debug_struct("Insn")
            .field("address", &self.address())
            .field("len", &self.len())
            .field("bytes", &self.bytes())
            .field("mnemonic", &self.mnemonic())
            .field("op_str", &self.op_str())
            .finish()
    }
}

impl Display for Insn {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "{:#x}: ", self.address())?;
        if let Some(mnemonic) = self.mnemonic() {
            write!(fmt, "{} ", mnemonic)?;
            if let Some(op_str) = self.op_str() {
                write!(fmt, "{}", op_str)?;
            }
        }
        Ok(())
    }
}

impl Detail {
    /// list of implicit registers read by this insn
    pub fn regs_read(&self) -> &[libc::uint8_t; 12] {
        &self.0.regs_read
    }
    /// number of implicit registers read by this insn
    pub fn regs_read_count(&self) -> libc::uint8_t {
        self.0.regs_read_count
    }
    /// list of implicit registers modified by this insn
    pub fn regs_write(&self) -> &[libc::uint8_t; 20] {
        &self.0.regs_write
    }
    /// number of implicit registers modified by this insn
    pub fn regs_write_count(&self) -> libc::uint8_t {
        self.0.regs_write_count
    }
    /// list of group this instruction belong to
    pub fn groups(&self) -> &[libc::uint8_t; 8] {
        &self.0.groups
    }
    /// number of groups this insn belongs to
    pub fn groups_count(&self) -> libc::uint8_t {
        self.0.groups_count
    }

}

impl Debug for Detail {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.debug_struct("Detail")
            .field("regs_read", &self.regs_read())
            .field("regs_read_count", &self.regs_read_count())
            .field("regs_write", &self.regs_write())
            .field("regs_write_count", &self.regs_write_count())
            .field("groups", &self.groups())
            .field("groups_count", &self.groups_count())
            .finish()
    }
}

impl Display for Instructions {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        for sym in self.iter() {
            write!(fmt, "{:x}:\t", sym.address())?;
            for byte in sym.bytes() {
                write!(fmt, " {:02x}", byte)?;
            }
            let remainder = 16*3 - (sym.bytes().len())*3;
            for _ in 0..remainder {
                write!(fmt, " ")?;
            }
            if let Some(mnemonic) = sym.mnemonic() {
                write!(fmt, " {}", mnemonic)?;
                if let Some(op_str) = sym.op_str() {
                    write!(fmt, " {}", op_str)?;
                }
            }
            write!(fmt, "\n")?;
        }
        Ok(())
    }
}
