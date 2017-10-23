extern crate libc;

use std::ffi::CStr;
use std::ptr;
use std::str;
use std::fmt::{self, Debug, Display, Error, Formatter};
use capstone_sys::*;

/// Representation of the array of instructions returned by disasm
#[derive(Debug)]
pub struct Instructions {
    ptr: *mut cs_insn,
    len: isize,
}

impl Instructions {
    pub unsafe fn from_raw_parts(ptr: *mut cs_insn, len: isize) -> Instructions {
        Instructions { ptr: ptr, len: len }
    }

    pub fn len(&self) -> isize {
        self.len
    }

    pub fn iter(&self) -> InstructionIterator {
        InstructionIterator {
            insns: self,
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
            Some(unsafe { Insn(ptr::read(obj)) })
        }
    }
}

/// A wrapper for the raw capstone-sys instruction
pub struct Insn(pub(crate) cs_insn);

/// Contains extra information about an instruction such as register reads in
/// addition to architecture-specific information
pub struct Detail<'a>(pub(crate) &'a cs_detail);

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

    /// Access instruction id
    pub fn id(&self) -> libc::c_uint {
        self.0.id
    }

    /// Size of instruction (in bytes)
    fn len(&self) -> usize {
        self.0.size as usize
    }

    /// Instruction address
    pub fn address(&self) -> u64 {
        self.0.address as u64
    }

    /// Byte-level representation of the instruction
    pub fn bytes(&self) -> &[u8] {
        &self.0.bytes[..self.len()]
    }

    /// Returns the `Detail` object, if there is one. It is up to the caller to determine
    /// the pre-conditions are satisfied.
    ///
    /// Be careful this is still in early stages and largely untested with various `cs_option` and
    /// architecture matrices
    pub(crate) unsafe fn detail(&self) -> Detail {
        Detail(&*self.0.detail)
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

impl<'a> Detail<'a> {
    /// Returns the implicit read registers
    pub fn regs_read(&self) -> &[libc::uint8_t] {
        &(*self.0).regs_read[..self.regs_read_count() as usize]
    }

    /// Returns the number of implicit read registers
    pub fn regs_read_count(&self) -> libc::uint8_t {
        (*self.0).regs_read_count
    }

    /// Returns the implicit write registers
    pub fn regs_write(&self) -> &[libc::uint8_t] {
        &(*self.0).regs_write[..self.regs_write_count() as usize]
    }

    /// Returns the number of implicit write registers
    pub fn regs_write_count(&self) -> libc::uint8_t {
        (*self.0).regs_write_count
    }

    /// Returns the groups to which this instruction belongs
    pub fn groups(&'a self) -> &'a [libc::uint8_t] {
        &(*self.0).groups[..self.groups_count() as usize]
    }

    /// Returns the number groups to which this instruction belongs
    pub fn groups_count(&self) -> libc::uint8_t {
        (*self.0).groups_count
    }
}

impl<'a> Debug for Detail<'a> {
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
        for instruction in self.iter() {
            write!(fmt, "{:x}:\t", instruction.address())?;
            for byte in instruction.bytes() {
                write!(fmt, " {:02x}", byte)?;
            }
            let remainder = 16 * 3 - (instruction.bytes().len()) * 3;
            for _ in 0..remainder {
                write!(fmt, " ")?;
            }
            if let Some(mnemonic) = instruction.mnemonic() {
                write!(fmt, " {}", mnemonic)?;
                if let Some(op_str) = instruction.op_str() {
                    write!(fmt, " {}", op_str)?;
                }
            }
            write!(fmt, "\n")?;
        }
        Ok(())
    }
}
