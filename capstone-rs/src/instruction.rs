use alloc::{self, boxed::Box};
use core::convert::{TryFrom, TryInto};
use core::fmt::{self, Debug, Display, Error, Formatter};
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;
use core::slice;
use core::str;

use capstone_sys::*;

use crate::arch::ArchTag;
use crate::constants::Arch;

use crate::ffi::str_from_cstr_ptr;

/// Represents a slice of [`Insn`] returned by [`Capstone`](crate::Capstone) `disasm*()` methods.
///
/// To access inner [`&[Insn]`](Insn), use [`.as_ref()`](AsRef::as_ref).
/// ```
/// # use capstone::arch::x86::X86ArchTag;
/// # use capstone::prelude::*;
/// # let cs = Capstone::<X86ArchTag>::new().mode(arch::x86::ArchMode::Mode32).build().unwrap();
/// let insns = cs.disasm_all(b"\x55\x48\x8b\x05", 0x1000).unwrap();
/// for insn in insns.as_ref() {
///     println!("{}", insn);
/// }
/// ```
pub struct Instructions<'a, A: ArchTag>(&'a mut [cs_insn], PhantomData<A>);

impl<'a, A: ArchTag> Instructions<'a, A> {
    fn new(insns: &'a mut [cs_insn]) -> Self {
        Self(insns, PhantomData::default())
    }
}

impl<'a, A: ArchTag> Debug for Instructions<'a, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Instructions").field(&self.0).finish()
    }
}

/// Integer type used in `InsnId`
pub type InsnIdInt = u32;

/// Represents an instruction id, which may be architecture-specific.
///
/// To translate to a human-readable name, see [`Capstone::insn_name()`](crate::Capstone::insn_name).
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct InsnId(pub InsnIdInt);

macro_rules! define_arch_insn_conversions {
    ( $( [ $arch:ident, $arch_insn:ident ] ),+ $(,)? ) => {
        $(
            impl From<$crate::arch::$arch::$arch_insn> for InsnId {
                fn from(arch_insn: $crate::arch::$arch::$arch_insn) -> Self {
                    Self(arch_insn as InsnIdInt)
                }
            }
        )+
    };
}

define_arch_insn_conversions![
    [arm, ArmInsn],
    [arm64, Arm64Insn],
    [evm, EvmInsn],
    [m68k, M68kInsn],
    [m680x, M680xInsn],
    [mips, MipsInsn],
    [ppc, PpcInsn],
    [riscv, RiscVInsn],
    [sparc, SparcInsn],
    [sysz, SyszInsn],
    [tms320c64x, Tms320c64xInsn],
    [x86, X86Insn],
    [xcore, XcoreInsn],
];

/// Integer type used in `InsnGroupId`
pub type InsnGroupIdInt = u8;

/// Represents the group an instruction belongs to, which may be architecture-specific.
///
/// To translate to a human-readable name, see [`Capstone::group_name()`](crate::Capstone::group_name).
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct InsnGroupId(pub InsnGroupIdInt);

impl InsnGroupId {
    pub const INVALID_GROUP: Self = Self(0);
}

impl From<u32> for InsnGroupId {
    fn from(value: u32) -> Self {
        Self(value.try_into().ok().unwrap_or(Self::INVALID_GROUP.0))
    }
}

macro_rules! define_arch_grp_id_conversions {
    ( $( [ $arch:ident, $arch_insn_grp:ident ] ),+ $(,)? ) => {
        $(
            impl From<$crate::arch::$arch::$arch_insn_grp> for InsnGroupId {
                fn from(arch_insn_grp: $crate::arch::$arch::$arch_insn_grp) -> Self {
                    Self(arch_insn_grp.0 as InsnGroupIdInt)
                }
            }

            impl From<InsnGroupId> for $crate::arch::$arch::$arch_insn_grp {
                fn from(insn_grp: InsnGroupId) -> Self {
                    Self(insn_grp.0 as _)
                }
            }
        )+
    };
}

define_arch_grp_id_conversions![
    [arm, ArmInsnGroup],
    [arm64, Arm64InsnGroup],
    [evm, EvmInsnGroup],
    [m68k, M68kInsnGroup],
    [m680x, M680xInsnGroup],
    [mips, MipsInsnGroup],
    [ppc, PpcInsnGroup],
    [riscv, RiscVInsnGroup],
    [sparc, SparcInsnGroup],
    [sysz, SyszInsnGroup],
    [tms320c64x, Tms320c64xInsnGroup],
    [x86, X86InsnGroup],
    [xcore, XcoreInsnGroup],
];

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

impl From<RegIdInt> for RegId {
    fn from(value: RegIdInt) -> Self {
        Self(value)
    }
}

impl From<RegId> for RegIdInt {
    fn from(value: RegId) -> Self {
        value.0
    }
}

macro_rules! define_arch_reg_conversions {
    ( $( [ $arch:ident, $arch_reg:ident ] ),+ $(,)? ) => {
        $(
            impl From<$crate::arch::$arch::$arch_reg> for RegId {
                fn from(arch_reg: $crate::arch::$arch::$arch_reg) -> Self {
                    Self(arch_reg.0 as _)
                }
            }

            impl From<RegId> for $crate::arch::$arch::$arch_reg {
                fn from(reg_id: RegId) -> Self {
                    Self(reg_id.0 as _)
                }
            }
        )+
    };
}

define_arch_reg_conversions![
    [arm, ArmReg],
    [arm64, Arm64Reg],
    [m68k, M68kReg],
    [m680x, M680xReg],
    [mips, MipsReg],
    [ppc, PpcReg],
    [riscv, RiscVReg],
    [sparc, SparcReg],
    [sysz, SyszReg],
    [tms320c64x, Tms320c64xReg],
    [x86, X86Reg],
    [xcore, XcoreReg],
];

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
        let unknown_flag_mask = !(cs_ac_type::CS_AC_READ | cs_ac_type::CS_AC_WRITE).0;
        if (access.0 & unknown_flag_mask) != 0 {
            return Err(());
        }

        let is_readable = (access & cs_ac_type::CS_AC_READ).0 != 0;
        let is_writable = (access & cs_ac_type::CS_AC_WRITE).0 != 0;
        match (is_readable, is_writable) {
            (true, false) => Ok(RegAccessType::ReadOnly),
            (false, true) => Ok(RegAccessType::WriteOnly),
            (true, true) => Ok(RegAccessType::ReadWrite),
            _ => Err(()),
        }
    }
}

impl<'a, A: ArchTag> Instructions<'a, A> {
    pub(crate) unsafe fn from_raw_parts(ptr: *mut cs_insn, len: usize) -> Instructions<'a, A> {
        Instructions::new(slice::from_raw_parts_mut(ptr, len))
    }

    pub(crate) fn new_empty() -> Instructions<'a, A> {
        Instructions::new(&mut [])
    }
}

impl<'a, A: ArchTag> Deref for Instructions<'a, A> {
    type Target = [Insn<'a, A>];

    #[inline]
    fn deref(&self) -> &[Insn<'a, A>] {
        // SAFETY: `cs_insn` has the same memory layout as `Insn`
        unsafe { &*(self.0 as *const [cs_insn] as *const [Insn<'a, A>]) }
    }
}

impl<'a, A: ArchTag> AsRef<[Insn<'a, A>]> for Instructions<'a, A> {
    #[inline]
    fn as_ref(&self) -> &[Insn<'a, A>] {
        self.deref()
    }
}

impl<'a, A: ArchTag> Drop for Instructions<'a, A> {
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
pub struct Insn<'a, A: ArchTag> {
    /// Inner `cs_insn`
    pub(crate) insn: cs_insn,

    /// Adds lifetime
    pub(crate) _marker: PhantomData<&'a InsnDetail<'a, A>>,
}

/// Contains architecture-independent details about an [`Insn`].
///
/// To get more detail about the instruction, enable extra details for the
/// [`Capstone`](crate::Capstone) instance with
/// [`Capstone::set_detail(True)`](crate::Capstone::set_detail) and use
/// [`Capstone::insn_detail()`](crate::Capstone::insn_detail).
///
/// ```
/// # use capstone::arch::x86::X86ArchTag;
/// # use capstone::prelude::*;
/// let cs = Capstone::<X86ArchTag>::new()
///     .mode(arch::x86::ArchMode::Mode32)
///     .detail(true) // needed to enable detail
///     .build()
///     .unwrap();
/// let insns = cs.disasm_all(b"\x90", 0x1000).unwrap();
/// for insn in insns.as_ref() {
///     println!("{}", insn);
///     let insn_detail = cs.insn_detail(insn).unwrap();
///     println!("    {:?}", insn_detail.groups().collect::<Vec<_>>());
/// }
/// ```
///
/// # Arch-specific detail
///
/// To get additional architecture-specific information, use the
/// [`.arch_detail()`](Self::arch_detail) method to get an `ArchDetail` enum.
///
pub struct InsnDetail<'a, A: ArchTag>(pub(crate) &'a cs_detail, pub(crate) Arch, PhantomData<A>);

impl<'a, A: ArchTag> InsnDetail<'a, A> {
    fn new(detail: &'a cs_detail, arch: Arch) -> Self {
        Self(detail, arch, PhantomData::default())
    }
}

#[allow(clippy::len_without_is_empty)]
impl<'a, A: ArchTag> Insn<'a, A> {
    /// Create an `Insn` from a raw pointer to a [`capstone_sys::cs_insn`].
    ///
    /// This function serves to allow integration with libraries which generate `capstone_sys::cs_insn`'s internally.
    ///
    /// # Safety
    ///
    /// Note that this function is unsafe, and assumes that you know what you are doing. In
    /// particular, it generates a lifetime for the `Insn` from nothing, and that lifetime is in
    /// no-way actually tied to the cs_insn itself. It is the responsibility of the caller to
    /// ensure that:
    /// - The resulting `Insn` does not outlive the given `cs_insn` object.
    /// - The pointer passed in as `insn` is non-null and is a valid pointer to a `cs_insn` object.
    /// - The architecture of the instruction matches the architecture specified by the architecture tag `A`.
    ///
    /// The caller is fully responsible for the backing allocations lifetime, including freeing.
    pub unsafe fn from_raw(insn: NonNull<cs_insn>) -> Self {
        Self {
            insn: core::ptr::read(insn.as_ptr()),
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

    /// Access instruction id.
    #[inline]
    pub fn id(&self) -> InsnId {
        InsnId(self.insn.id)
    }

    /// Size of instruction (in bytes).
    #[inline]
    pub fn len(&self) -> usize {
        self.insn.size as usize
    }

    /// Instruction address.
    #[inline]
    pub fn address(&self) -> u64 {
        self.insn.address
    }

    /// Byte-level representation of the instruction.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.insn.bytes[..self.len()]
    }

    /// Returns the `Detail` object, if there is one. It is up to the caller to determine
    /// the pre-conditions are satisfied.
    ///
    /// Be careful this is still in early stages and largely untested with various `cs_option` and
    /// architecture matrices.
    ///
    /// # Safety
    /// The [`cs_insn::detail`] pointer must be valid and non-null.
    #[inline]
    pub(crate) unsafe fn detail(&self, arch: Arch) -> InsnDetail<'_, A> {
        InsnDetail::new(&*self.insn.detail, arch)
    }
}

impl<'a, A: ArchTag> From<&Insn<'_, A>> for OwnedInsn<'a, A> {
    // SAFETY: assumes that `cs_detail` struct transitively only contains owned
    // types and no pointers, including the union over the architecture-specific
    // types.
    fn from(insn: &Insn<'_, A>) -> Self {
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
impl<'a, A: ArchTag> Deref for OwnedInsn<'a, A> {
    type Target = Insn<'a, A>;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.insn as *const cs_insn as *const Insn<'a, A>) }
    }
}

/// A single disassembled CPU instruction that lives on the Rust heap.
///
/// # Detail
///
/// To learn how to get more instruction details, see [`InsnDetail`].
pub struct OwnedInsn<'a, A: ArchTag> {
    /// Inner cs_insn
    pub(crate) insn: cs_insn,

    /// Adds lifetime
    pub(crate) _marker: PhantomData<&'a InsnDetail<'a, A>>,
}

impl<'a, A: ArchTag> Debug for Insn<'a, A> {
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

impl<'a, A: ArchTag> Display for Insn<'a, A> {
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

impl<'a, A: ArchTag> Drop for OwnedInsn<'a, A> {
    fn drop(&mut self) {
        if let Some(ptr) = core::ptr::NonNull::new(self.insn.detail) {
            unsafe { drop(Box::from_raw(ptr.as_ptr())) }
        }
    }
}

impl<'a, A: ArchTag> Debug for OwnedInsn<'a, A> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        Debug::fmt(&self.deref(), fmt)
    }
}

impl<'a, A: ArchTag> Display for OwnedInsn<'a, A> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.deref(), fmt)
    }
}

/// Iterator over instruction group ids
#[derive(Debug, Clone)]
pub struct InsnGroupIter<'a>(slice::Iter<'a, InsnGroupIdInt>);

impl<'a, A: ArchTag> InsnDetail<'a, A> {
    #[cfg(feature = "full")]
    /// Returns the implicit read registers
    pub fn regs_read(&self) -> impl Iterator<Item = A::RegId> + '_ {
        self.0.regs_read[..self.0.regs_read_count as usize]
            .iter()
            .map(|raw_reg| A::RegId::from(RegId(*raw_reg)))
    }

    #[cfg(feature = "full")]
    /// Returns the implicit write registers
    pub fn regs_write(&self) -> impl Iterator<Item = A::RegId> + '_ {
        self.0.regs_write[..self.0.regs_write_count as usize]
            .iter()
            .map(|raw_reg| A::RegId::from(RegId(*raw_reg)))
    }

    #[cfg(feature = "full")]
    /// Returns the groups to which this instruction belongs
    pub fn groups(&self) -> impl Iterator<Item = A::InsnGroupId> + '_ {
        self.0.groups[..self.0.groups_count as usize]
            .iter()
            .map(|raw_grp| A::InsnGroupId::from(InsnGroupId(*raw_grp)))
    }

    /// Architecture-specific detail
    pub fn arch_detail(&self) -> A::InsnDetail<'_> {
        A::InsnDetail::from(self)
    }
}

#[cfg(feature = "full")]
impl<'a, A: ArchTag> Debug for InsnDetail<'a, A>
where
    A::RegId: Debug,
    A::InsnGroupId: Debug,
{
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.debug_struct("Detail")
            .field("regs_read", &self.regs_read().collect::<Vec<_>>())
            .field("regs_write", &self.regs_write().collect::<Vec<_>>())
            .field("groups", &self.groups().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(not(feature = "full"))]
impl<'a> Debug for InsnDetail<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.debug_struct("Detail").finish()
    }
}

impl<'a, A: ArchTag> Display for Instructions<'a, A> {
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
