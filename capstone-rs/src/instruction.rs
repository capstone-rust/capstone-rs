use alloc::{self, boxed::Box};
use core::convert::{TryFrom, TryInto};
use core::fmt::{self, Debug, Display, Error, Formatter};
use core::marker::PhantomData;
use core::ops::Deref;
use core::slice;
use core::str;

use capstone_sys::*;

use crate::arch::ArchDetail;
use crate::constants::Arch;

#[cfg(feature = "full")]
use crate::ffi::str_from_cstr_ptr;

/// Represents a slice of [`Insn`] returned by [`Capstone`](crate::Capstone) `disasm*()` methods.
///
/// To access inner [`&[Insn]`](Insn), use [`.as_ref()`](AsRef::as_ref).
/// ```
/// # use capstone::Instructions;
/// # use capstone::prelude::*;
/// # let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build().unwrap();
/// let insns: Instructions = cs.disasm_all(b"\x55\x48\x8b\x05", 0x1000).unwrap();
/// for insn in insns.as_ref() {
///     println!("{}", insn);
/// }
/// ```
#[derive(Debug)]
pub struct Instructions<'a>(&'a mut [cs_insn]);

/// Integer type used in `InsnId`
pub type InsnIdInt = u32;

/// Represents an instruction id, which may be architecture-specific.
///
/// To translate to a human-readable name, see [`Capstone::insn_name()`](crate::Capstone::insn_name).
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct InsnId(pub InsnIdInt);

/// Integer type used in `InsnGroupId`
pub type InsnGroupIdInt = u8;

/// Represents the group an instruction belongs to, which may be architecture-specific.
///
/// To translate to a human-readable name, see [`Capstone::group_name()`](crate::Capstone::group_name).
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct InsnGroupId(pub InsnGroupIdInt);

pub use capstone_sys::cs_group_type as InsnGroupType;

/// Integer type used in `RegId`
pub type RegIdInt = u16;

/// Represents an register id, which is architecture-specific.
///
/// To translate to a human-readable name, see [`Capstone::reg_name()`](crate::Capstone::reg_name).
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct RegId(pub RegIdInt);

impl RegId {
    /// Invalid Register
    pub const INVALID_REG: Self = Self(0);
}

impl core::convert::From<u32> for RegId {
    fn from(v: u32) -> RegId {
        RegId(v.try_into().ok().unwrap_or(Self::INVALID_REG.0))
    }
}

/// Represents how the register is accessed.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum RegAccessType {
    /// Operand read from memory or register.
    ReadOnly,
    /// Operand write from memory or register.
    WriteOnly,
    /// Operand read and write from memory or register.
    ReadWrite,
}

impl RegAccessType {
    /// Returns whether the instruction reads from the operand.
    ///
    /// Note that an instruction may read and write to the register
    /// simultaneously. In this case, the operand is also considered as
    /// readable.
    pub fn is_readable(self) -> bool {
        self == RegAccessType::ReadOnly || self == RegAccessType::ReadWrite
    }

    /// Returns whether the instruction writes from the operand.
    ///
    /// Note that an instruction may read and write to the register
    /// simultaneously. In this case, the operand is also considered as
    /// writable.
    pub fn is_writable(self) -> bool {
        self == RegAccessType::WriteOnly || self == RegAccessType::ReadWrite
    }
}

impl TryFrom<cs_ac_type> for RegAccessType {
    type Error = ();

    fn try_from(access: cs_ac_type) -> Result<Self, Self::Error> {
        // Check for flags other than CS_AC_READ or CS_AC_WRITE.
        let unknown_flag_mask = !(CS_AC_READ | CS_AC_WRITE).0;
        if (access.0 & unknown_flag_mask) != 0 {
            return Err(());
        }

        let is_readable = (access & CS_AC_READ).0 != 0;
        let is_writable = (access & CS_AC_WRITE).0 != 0;
        match (is_readable, is_writable) {
            (true, false) => Ok(RegAccessType::ReadOnly),
            (false, true) => Ok(RegAccessType::WriteOnly),
            (true, true) => Ok(RegAccessType::ReadWrite),
            _ => Err(()),
        }
    }
}

impl<'a> Instructions<'a> {
    pub(crate) unsafe fn from_raw_parts(ptr: *mut cs_insn, len: usize) -> Instructions<'a> {
        Instructions(slice::from_raw_parts_mut(ptr, len))
    }

    pub(crate) fn new_empty() -> Instructions<'a> {
        Instructions(&mut [])
    }
}

impl<'a> core::ops::Deref for Instructions<'a> {
    type Target = [Insn<'a>];

    #[inline]
    fn deref(&self) -> &[Insn<'a>] {
        // SAFETY: `cs_insn` has the same memory layout as `Insn`
        unsafe { &*(self.0 as *const [cs_insn] as *const [Insn]) }
    }
}

impl<'a> AsRef<[Insn<'a>]> for Instructions<'a> {
    #[inline]
    fn as_ref(&self) -> &[Insn<'a>] {
        self.deref()
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

/// A single disassembled CPU instruction.
///
/// # Detail
///
/// To learn how to get more instruction details, see [`InsnDetail`].
#[repr(transparent)]
pub struct Insn<'a> {
    /// Inner `cs_insn`
    pub(crate) insn: cs_insn,

    /// Adds lifetime
    pub(crate) _marker: PhantomData<&'a InsnDetail<'a>>,
}

/// Contains architecture-independent details about an [`Insn`].
///
/// To get more detail about the instruction, enable extra details for the
/// [`Capstone`](crate::Capstone) instance with
/// [`Capstone::set_detail(True)`](crate::Capstone::set_detail) and use
/// [`Capstone::insn_detail()`](crate::Capstone::insn_detail).
///
/// ```
/// # use capstone::Instructions;
/// # use capstone::prelude::*;
/// let cs = Capstone::new()
///     .x86()
///     .mode(arch::x86::ArchMode::Mode32)
///     .detail(true) // needed to enable detail
///     .build()
///     .unwrap();
/// let insns = cs.disasm_all(b"\x90", 0x1000).unwrap();
/// for insn in insns.as_ref() {
///     println!("{}", insn);
///     let insn_detail: InsnDetail = cs.insn_detail(insn).unwrap();
///     println!("    {:?}", insn_detail.groups());
/// }
/// ```
///
/// # Arch-specific detail
///
/// To get additional architecture-specific information, use the
/// [`.arch_detail()`](Self::arch_detail) method to get an `ArchDetail` enum.
///
pub struct InsnDetail<'a>(pub(crate) &'a cs_detail, pub(crate) Arch);

#[allow(clippy::len_without_is_empty)]
impl<'a> Insn<'a> {
    /// Create an `Insn` from a raw pointer to a [`capstone_sys::cs_insn`].
    ///
    /// This function serves to allow integration with libraries which generate `capstone_sys::cs_insn`'s internally.
    ///
    /// # Safety
    ///
    /// Note that this function is unsafe, and assumes that you know what you are doing. In
    /// particular, it generates a lifetime for the `Insn` from nothing, and that lifetime is in
    /// no-way actually tied to the cs_insn itself. It is the responsibility of the caller to
    /// ensure that the resulting `Insn` lives only as long as the `cs_insn`. This function
    /// assumes that the pointer passed is non-null and a valid `cs_insn` pointer.
    ///
    /// The caller is fully responsible for the backing allocations lifetime, including freeing.
    pub unsafe fn from_raw(insn: *const cs_insn) -> Self {
        Self {
            insn: core::ptr::read(insn),
            _marker: PhantomData,
        }
    }

    /// The mnemonic for the instruction.
    /// Unavailable in Diet mode.
    #[inline]
    pub fn mnemonic(&self) -> Option<&str> {
        if cfg!(feature = "full") {
            unsafe { str_from_cstr_ptr(self.insn.mnemonic.as_ptr()) }
        } else {
            None
        }
    }

    /// The operand string associated with the instruction.
    /// Unavailable in Diet mode.
    #[inline]
    pub fn op_str(&self) -> Option<&str> {
        if cfg!(feature = "full") {
            unsafe { str_from_cstr_ptr(self.insn.op_str.as_ptr()) }
        } else {
            None
        }
    }

    /// Access instruction id
    #[inline]
    pub fn id(&self) -> InsnId {
        InsnId(self.insn.id)
    }

    /// Size of instruction (in bytes)
    #[inline]
    pub fn len(&self) -> usize {
        self.insn.size as usize
    }

    /// Instruction address
    #[inline]
    pub fn address(&self) -> u64 {
        self.insn.address as u64
    }

    /// Byte-level representation of the instruction
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.insn.bytes[..self.len()]
    }

    /// Returns the `Detail` object, if there is one. It is up to the caller to determine
    /// the pre-conditions are satisfied.
    ///
    /// Be careful this is still in early stages and largely untested with various `cs_option` and
    /// architecture matrices
    ///
    /// # Safety
    /// The [`cs_insn::detail`] pointer must be valid and non-null.
    #[inline]
    pub(crate) unsafe fn detail(&self, arch: Arch) -> InsnDetail {
        InsnDetail(&*self.insn.detail, arch)
    }
}

impl<'a> From<&Insn<'_>> for OwnedInsn<'a> {
    // SAFETY: assumes that `cs_detail` struct transitively only contains owned
    // types and no pointers, including the union over the architecture-specific
    // types.
    fn from(insn: &Insn<'_>) -> Self {
        let mut new = unsafe { <*const cs_insn>::read(&insn.insn as _) };
        new.detail = if new.detail.is_null() {
            new.detail
        } else {
            unsafe {
                let new_detail = Box::new(*new.detail);
                Box::into_raw(new_detail)
            }
        };
        Self {
            insn: new,
            _marker: PhantomData,
        }
    }
}

/// SAFETY:
/// 1. [`OwnedInsn`] and [`Insn`] must be `#repr(transparent)` of [`cs_insn`]
/// 2. all [`Insn`] methods must be safe to perform for an [`OwnedInsn`]
impl<'a> Deref for OwnedInsn<'a> {
    type Target = Insn<'a>;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.insn as *const cs_insn as *const Insn) }
    }
}

/// A single disassembled CPU instruction that lives on the Rust heap.
///
/// # Detail
///
/// To learn how to get more instruction details, see [`InsnDetail`].
pub struct OwnedInsn<'a> {
    /// Inner cs_insn
    pub(crate) insn: cs_insn,

    /// Adds lifetime
    pub(crate) _marker: PhantomData<&'a InsnDetail<'a>>,
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

impl<'a> Drop for OwnedInsn<'a> {
    fn drop(&mut self) {
        if let Some(ptr) = core::ptr::NonNull::new(self.insn.detail) {
            unsafe { drop(Box::from_raw(ptr.as_ptr())) }
        }
    }
}

impl<'a> Debug for OwnedInsn<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        Debug::fmt(&self.deref(), fmt)
    }
}

impl<'a> Display for OwnedInsn<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.deref(), fmt)
    }
}

/// Iterator over instruction group ids
#[derive(Debug, Clone)]
pub struct InsnGroupIter<'a>(slice::Iter<'a, InsnGroupIdInt>);

impl<'a> InsnDetail<'a> {
    #[cfg(feature = "full")]
    /// Returns the implicit read registers
    pub fn regs_read(&self) -> &[RegId] {
        unsafe {
            &*(&self.0.regs_read[..self.0.regs_read_count as usize] as *const [RegIdInt]
                as *const [RegId])
        }
    }

    #[cfg(feature = "full")]
    /// Returns the implicit write registers
    pub fn regs_write(&self) -> &[RegId] {
        unsafe {
            &*(&self.0.regs_write[..self.0.regs_write_count as usize] as *const [RegIdInt]
                as *const [RegId])
        }
    }

    #[cfg(feature = "full")]
    /// Returns the groups to which this instruction belongs
    pub fn groups(&self) -> &[InsnGroupId] {
        unsafe {
            &*(&self.0.groups[..self.0.groups_count as usize] as *const [InsnGroupIdInt]
                as *const [InsnGroupId])
        }
    }

    /// Architecture-specific detail
    pub fn arch_detail(&self) -> ArchDetail {
        macro_rules! def_arch_detail_match {
            (
                $( [ $ARCH:ident, $detail:ident, $insn_detail:ident, $arch:ident ] )*
            ) => {
                use self::ArchDetail::*;
                use crate::Arch::*;
                $( use crate::arch::$arch::$insn_detail; )*

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
            [EVM, EvmDetail, EvmInsnDetail, evm]
            [M680X, M680xDetail, M680xInsnDetail, m680x]
            [M68K, M68kDetail, M68kInsnDetail, m68k]
            [MIPS, MipsDetail, MipsInsnDetail, mips]
            [PPC, PpcDetail, PpcInsnDetail, ppc]
            [RISCV, RiscVDetail, RiscVInsnDetail, riscv]
            [SPARC, SparcDetail, SparcInsnDetail, sparc]
            [TMS320C64X, Tms320c64xDetail, Tms320c64xInsnDetail, tms320c64x]
            [X86, X86Detail, X86InsnDetail, x86]
            [XCORE, XcoreDetail, XcoreInsnDetail, xcore]
        );
    }
}

#[cfg(feature = "full")]
impl<'a> Debug for InsnDetail<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.debug_struct("Detail")
            .field("regs_read", &self.regs_read())
            .field("regs_write", &self.regs_write())
            .field("groups", &self.groups())
            .finish()
    }
}

#[cfg(not(feature = "full"))]
impl<'a> Debug for InsnDetail<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.debug_struct("Detail").finish()
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_invalid_reg_access() {
        assert_eq!(RegAccessType::try_from(cs_ac_type(1337)), Err(()));
    }
}
