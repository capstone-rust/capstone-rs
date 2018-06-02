use arch::ArchDetail;
use capstone_sys::*;
use constants::Arch;
use std::ffi::CStr;
use std::fmt::{self, Debug, Display, Error, Formatter};
use std::marker::PhantomData;
use std::slice;
use std::str;

/// Representation of the array of instructions returned by disasm
#[derive(Debug)]
pub struct Instructions<'a>(&'a mut [cs_insn]);

/// Integer type used in `InsnId`
pub type InsnIdInt = u32;

/// Represents an instruction id, which may architecture-specific.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct InsnId(pub InsnIdInt);

/// Integer type used in `InsnGroupId`
pub type InsnGroupIdInt = u8;

/// Represents the group an instruction belongs to, which may be architecture-specific.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct InsnGroupId(pub InsnGroupIdInt);

/// Integer type used in `RegId`
pub type RegIdInt = u16;

/// Represents an register id, which is architecture-specific.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegId(pub RegIdInt);

impl<'a> Instructions<'a> {
    pub(crate) unsafe fn from_raw_parts(ptr: *mut cs_insn, len: usize) -> Instructions<'a> {
        Instructions(slice::from_raw_parts_mut(ptr, len))
    }

    pub(crate) fn new_empty() -> Instructions<'a> {
        Instructions(&mut [])
    }

    /// Get number of instructions
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterator over instructions
    pub fn iter(&'a self) -> InstructionIterator<'a> {
        let iter = self.0.iter();
        InstructionIterator(iter)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> Drop for Instructions<'a> {
    fn drop(&mut self) {
        if !self.is_empty() {
            unsafe {
                cs_free(self.0.as_mut_ptr(), self.len());
            }
        }
    }
}

/// impl Iterator (and variants) for a type that wraps slice::iterator
///
/// Implements Iterator, ExactSizeIterator, and DoubleEndedIterator
macro_rules! impl_SliceIterator_wrapper {
    (
        impl <$( $lifetime:tt ),*> Iterator for $iterator:ty {
            type Item = $item:ty;
            [ $next:expr ]
        }
    ) => {
        impl <$( $lifetime ),*> Iterator for $iterator {
            type Item = $item;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                self.0.next().map($next)
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }

            #[inline]
            fn count(self) -> usize {
                self.0.count()
            }
        }

        impl<'a> ExactSizeIterator for $iterator {
            #[inline]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl<'a> DoubleEndedIterator for $iterator {
            #[inline]
            fn next_back(&mut self) -> Option<Self::Item> {
                self.0.next_back().map($next)
            }
        }
    }
}

/// An iterator over the instructions returned by disasm
///
/// This is currently the only supported interface for reading them.
pub struct InstructionIterator<'a>(slice::Iter<'a, cs_insn>);

impl_SliceIterator_wrapper!(
    impl<'a> Iterator for InstructionIterator<'a> {
        type Item = Insn<'a>;
        [
            |x| Insn { insn: *x, _marker: PhantomData }
        ]
    }
);

/// A wrapper for the raw capstone-sys instruction
pub struct Insn<'a> {
    /// Inner `cs_insn`
    pub(crate) insn: cs_insn,

    /// Adds lifetime
    pub(crate) _marker: PhantomData<&'a InsnDetail<'a>>,
}

/// Contains extra information about an instruction such as register reads in
/// addition to architecture-specific information
pub struct InsnDetail<'a>(pub(crate) &'a cs_detail, pub(crate) Arch);

impl<'a> Insn<'a> {
    /// The mnemonic for the instruction
    pub fn mnemonic(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.insn.mnemonic.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// The operand string associated with the instruction
    pub fn op_str(&self) -> Option<&str> {
        let cstr = unsafe { CStr::from_ptr(self.insn.op_str.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// Access instruction id
    pub fn id(&self) -> InsnId {
        InsnId(self.insn.id)
    }

    /// Size of instruction (in bytes)
    fn len(&self) -> usize {
        self.insn.size as usize
    }

    /// Instruction address
    pub fn address(&self) -> u64 {
        self.insn.address as u64
    }

    /// Byte-level representation of the instruction
    pub fn bytes(&self) -> &[u8] {
        &self.insn.bytes[..self.len()]
    }

    /// Returns the `Detail` object, if there is one. It is up to the caller to determine
    /// the pre-conditions are satisfied.
    ///
    /// Be careful this is still in early stages and largely untested with various `cs_option` and
    /// architecture matrices
    pub(crate) unsafe fn detail(&self, arch: Arch) -> InsnDetail {
        InsnDetail(&*self.insn.detail, arch)
    }
}

impl<'a> Debug for Insn<'a> {
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

impl<'a> Display for Insn<'a> {
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

/// Iterator over registers ids
#[derive(Debug, Clone)]
pub struct RegsIter<'a, T: 'a + Into<RegIdInt> + Copy>(slice::Iter<'a, T>);

impl<'a, T: 'a + Into<RegIdInt> + Copy> Iterator for RegsIter<'a, T> {
    type Item = RegId;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| RegId((*x).into()))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.0.count()
    }
}

impl<'a, T: 'a + Into<RegIdInt> + Copy> ExactSizeIterator for RegsIter<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a, T: 'a + Into<RegIdInt> + Copy> DoubleEndedIterator for RegsIter<'a, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(|x| RegId((*x).into()))
    }
}

/// Iterator over instruction group ids
#[derive(Debug, Clone)]
pub struct InsnGroupIter<'a>(slice::Iter<'a, InsnGroupIdInt>);

impl_SliceIterator_wrapper!(
    impl<'a> Iterator for InsnGroupIter<'a> {
        type Item = InsnGroupId;

        [
            |x| InsnGroupId(*x as InsnGroupIdInt)
        ]
    }
);

impl<'a> InsnDetail<'a> {
    /// Returns the implicit read registers
    pub fn regs_read(&self) -> RegsIter<u8> {
        RegsIter((*self.0).regs_read[..self.regs_read_count() as usize].iter())
    }

    /// Returns the number of implicit read registers
    pub fn regs_read_count(&self) -> u8 {
        (*self.0).regs_read_count
    }

    /// Returns the implicit write registers
    pub fn regs_write(&self) -> RegsIter<u8> {
        RegsIter((*self.0).regs_write[..self.regs_write_count() as usize].iter())
    }

    /// Returns the number of implicit write registers
    pub fn regs_write_count(&self) -> u8 {
        (*self.0).regs_write_count
    }

    /// Returns the groups to which this instruction belongs
    pub fn groups(&self) -> InsnGroupIter {
        InsnGroupIter((*self.0).groups[..self.groups_count() as usize].iter())
    }

    /// Returns the number groups to which this instruction belongs
    pub fn groups_count(&self) -> u8 {
        (*self.0).groups_count
    }

    /// Architecture-specific detail
    pub fn arch_detail(&self) -> ArchDetail {
        macro_rules! def_arch_detail_match {
            (
                $( [ $ARCH:ident, $detail:ident, $insn_detail:ident, $arch:ident ] )*
            ) => {
                use self::ArchDetail::*;
                use Arch::*;
                $( use arch::$arch::$insn_detail; )*

                return match self.1 {
                    $(
                        $ARCH => {
                            $detail($insn_detail(unsafe { &self.0.__bindgen_anon_1.$arch }))
                        }
                    )*
                    _ => panic!("Unsupported detail arch"),
                }
            }
        }
        def_arch_detail_match!(
            [ARM, ArmDetail, ArmInsnDetail, arm]
            [ARM64, Arm64Detail, Arm64InsnDetail, arm64]
            [MIPS, MipsDetail, MipsInsnDetail, mips]
            [PPC, PpcDetail, PpcInsnDetail, ppc]
            [SPARC, SparcDetail, SparcInsnDetail, sparc]
            [X86, X86Detail, X86InsnDetail, x86]
            [XCORE, XcoreDetail, XcoreInsnDetail, xcore]
        );
    }
}

impl<'a> Debug for InsnDetail<'a> {
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

impl<'a> Display for Instructions<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        for instruction in self.iter() {
            write!(fmt, "{:x}:\t", instruction.address())?;
            for byte in instruction.bytes() {
                write!(fmt, " {:02x}", byte)?;
            }
            let remainder = 16 * 3 - instruction.bytes().len() * 3;
            for _ in 0..remainder {
                write!(fmt, " ")?;
            }
            if let Some(mnemonic) = instruction.mnemonic() {
                write!(fmt, " {}", mnemonic)?;
                if let Some(op_str) = instruction.op_str() {
                    write!(fmt, " {}", op_str)?;
                }
            }
            writeln!(fmt)?;
        }
        Ok(())
    }
}
