use alloc::{self, boxed::Box};
use core::convert::TryFrom;
use core::fmt::{self, Debug, Display, Error, Formatter};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::slice;
use core::str;

use capstone_sys::*;

use crate::arch::ArchDetail;
use crate::constants::Arch;

use crate::ffi::str_from_cstr_ptr;
use crate::{RegsAccessBuf, REGS_ACCESS_BUF_LEN};

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

/// Represents how the operand is accessed.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum AccessType {
    /// Operand read from memory or register.
    ReadOnly,
    /// Operand write from memory or register.
    WriteOnly,
    /// Operand read and write from memory or register.
    ReadWrite,
}

impl AccessType {
    /// Returns whether the instruction reads from the operand.
    ///
    /// Note that an instruction may read and write to the register
    /// simultaneously. In this case, the operand is also considered as
    /// readable.
    pub fn is_readable(self) -> bool {
        self == AccessType::ReadOnly || self == AccessType::ReadWrite
    }

    /// Returns whether the instruction writes from the operand.
    ///
    /// Note that an instruction may read and write to the register
    /// simultaneously. In this case, the operand is also considered as
    /// writable.
    pub fn is_writable(self) -> bool {
        self == AccessType::WriteOnly || self == AccessType::ReadWrite
    }
}

impl TryFrom<cs_ac_type> for AccessType {
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
            (true, false) => Ok(AccessType::ReadOnly),
            (false, true) => Ok(AccessType::WriteOnly),
            (true, true) => Ok(AccessType::ReadWrite),
            _ => Err(()),
        }
    }
}

/// Previously the enum was called RegAccessType, see issue #135
/// Maintain compatibility with legacy code
pub type RegAccessType = AccessType;

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

impl Drop for Instructions<'_> {
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

pub(crate) struct RWRegsAccessBuf {
    pub(crate) read_buf: RegsAccessBuf,
    pub(crate) write_buf: RegsAccessBuf,
}

impl RWRegsAccessBuf {
    pub(crate) fn new() -> Self {
        Self {
            read_buf: [MaybeUninit::uninit(); REGS_ACCESS_BUF_LEN],
            write_buf: [MaybeUninit::uninit(); REGS_ACCESS_BUF_LEN],
        }
    }
}

/// Contains partially initialized buffer of registers
#[cfg_attr(not(feature = "full"), allow(dead_code))]
pub(crate) struct PartialInitRegsAccess {
    pub(crate) regs_buf: Box<RWRegsAccessBuf>,
    pub(crate) read_len: u16,
    pub(crate) write_len: u16,
}

// make sure len fields can be stored as u16
static_assertions::const_assert!(crate::REGS_ACCESS_BUF_LEN <= u16::MAX as usize);

#[cfg_attr(not(feature = "full"), allow(dead_code))]
impl PartialInitRegsAccess {
    unsafe fn maybeuninit_slice_to_slice(buf: &[MaybeUninit<RegId>]) -> &[RegId] {
        &*(buf as *const [MaybeUninit<RegId>] as *const [RegId])
    }

    pub(crate) fn read(&self) -> &[RegId] {
        unsafe {
            Self::maybeuninit_slice_to_slice(&self.regs_buf.read_buf[..self.read_len as usize])
        }
    }

    pub(crate) fn write(&self) -> &[RegId] {
        unsafe {
            Self::maybeuninit_slice_to_slice(&self.regs_buf.write_buf[..self.write_len as usize])
        }
    }
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
pub struct InsnDetail<'a> {
    pub(crate) detail: &'a cs_detail,
    pub(crate) arch: Arch,

    #[cfg_attr(not(feature = "full"), allow(dead_code))]
    partial_init_regs_access: Option<PartialInitRegsAccess>,
}

#[allow(clippy::len_without_is_empty)]
impl Insn<'_> {
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
        self.insn.address
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
    pub(crate) unsafe fn detail(
        &self,
        arch: Arch,
        partial_init_regs_access: Option<PartialInitRegsAccess>,
    ) -> InsnDetail<'_> {
        InsnDetail {
            detail: &*self.insn.detail,
            arch,
            partial_init_regs_access,
        }
    }
}

impl From<&Insn<'_>> for OwnedInsn<'_> {
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

impl Debug for Insn<'_> {
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

impl Display for Insn<'_> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "{:#x}:", self.address())?;
        if let Some(mnemonic) = self.mnemonic() {
            write!(fmt, " {mnemonic}")?;
            if let Some(op_str) = self.op_str() {
                if !op_str.is_empty() {
                    write!(fmt, " {op_str}")?;
                }
            }
        }
        Ok(())
    }
}

impl Drop for OwnedInsn<'_> {
    fn drop(&mut self) {
        if let Some(ptr) = core::ptr::NonNull::new(self.insn.detail) {
            unsafe { drop(Box::from_raw(ptr.as_ptr())) }
        }
    }
}

impl Debug for OwnedInsn<'_> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        Debug::fmt(&self.deref(), fmt)
    }
}

impl Display for OwnedInsn<'_> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.deref(), fmt)
    }
}

impl InsnDetail<'_> {
    #[cfg(feature = "full")]
    /// Returns the read registers
    pub fn regs_read(&self) -> &[RegId] {
        if let Some(partial) = self.partial_init_regs_access.as_ref() {
            partial.read()
        } else {
            unsafe {
                &*(&self.detail.regs_read[..self.detail.regs_read_count as usize]
                    as *const [RegIdInt] as *const [RegId])
            }
        }
    }

    #[cfg(feature = "full")]
    /// Returns the written to registers
    pub fn regs_write(&self) -> &[RegId] {
        if let Some(partial) = self.partial_init_regs_access.as_ref() {
            partial.write()
        } else {
            unsafe {
                &*(&self.detail.regs_write[..self.detail.regs_write_count as usize]
                    as *const [RegIdInt] as *const [RegId])
            }
        }
    }

    #[cfg(feature = "full")]
    /// Returns the groups to which this instruction belongs
    pub fn groups(&self) -> &[InsnGroupId] {
        unsafe {
            &*(&self.detail.groups[..self.detail.groups_count as usize] as *const [InsnGroupIdInt]
                as *const [InsnGroupId])
        }
    }

    /// Architecture-specific detail
    pub fn arch_detail(&self) -> ArchDetail {
        macro_rules! def_arch_detail_match {
            (
                $( [ $ARCH:ident, $detail:ident, $insn_detail:ident, $arch:ident, $feature:literal ] )*
            ) => {
                use self::ArchDetail::*;
                use crate::Arch::*;
                $(
                    #[cfg(feature = $feature)]
                    use crate::arch::$arch::$insn_detail;
                )*

                return match self.arch {
                    $(
                        #[cfg(feature = $feature)]
                        $ARCH => {
                            $detail($insn_detail(unsafe { &self.detail.__bindgen_anon_1.$arch }))
                        }
                    )*,
                    // handle disabled archs if not all archs are enabled
                    #[allow(unreachable_patterns)]
                    _ => panic!("Cannot convert to arch-specific detail of disabled arch ")
                }
            }
        }
        def_arch_detail_match!(
            [ARM, ArmDetail, ArmInsnDetail, arm, "arch_arm"]
            [ARM64, Arm64Detail, Arm64InsnDetail, arm64, "arch_arm64"]
            [BPF, BpfDetail, BpfInsnDetail, bpf, "arch_bpf"]
            [EVM, EvmDetail, EvmInsnDetail, evm, "arch_evm"]
            [M680X, M680xDetail, M680xInsnDetail, m680x, "arch_m680x"]
            [M68K, M68kDetail, M68kInsnDetail, m68k, "arch_m68k"]
            [MIPS, MipsDetail, MipsInsnDetail, mips, "arch_mips"]
            [MOS65XX, Mos65xxDetail, Mos65xxInsnDetail, mos65xx, "arch_mos65xx"]
            [PPC, PpcDetail, PpcInsnDetail, ppc, "arch_powerpc"]
            [RISCV, RiscVDetail, RiscVInsnDetail, riscv, "arch_riscv"]
            [SH, ShDetail, ShInsnDetail, sh, "arch_sh"]
            [SPARC, SparcDetail, SparcInsnDetail, sparc, "arch_sparc"]
            [SYSZ, SysZDetail, SysZInsnDetail, sysz, "arch_sysz"]
            [TMS320C64X, Tms320c64xDetail, Tms320c64xInsnDetail, tms320c64x, "arch_tms320c64x"]
            [TRICORE, TriCoreDetail, TriCoreInsnDetail, tricore, "arch_tricore"]
            [X86, X86Detail, X86InsnDetail, x86, "arch_x86"]
            [XCORE, XcoreDetail, XcoreInsnDetail, xcore, "arch_xcore"]
        );
    }
}

#[cfg(feature = "full")]
impl Debug for InsnDetail<'_> {
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

impl Display for Instructions<'_> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        for instruction in self.iter() {
            write!(fmt, "{:x}:\t", instruction.address())?;
            for byte in instruction.bytes() {
                write!(fmt, " {byte:02x}")?;
            }
            let remainder = 16 * 3 - instruction.bytes().len() * 3;
            for _ in 0..remainder {
                write!(fmt, " ")?;
            }
            if let Some(mnemonic) = instruction.mnemonic() {
                write!(fmt, " {mnemonic}")?;
                if let Some(op_str) = instruction.op_str() {
                    write!(fmt, " {op_str}")?;
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
