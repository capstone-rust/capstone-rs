//! Contains sysz-specific types

pub use capstone_sys::sysz_insn_group as SyszInsnGroup;
pub use capstone_sys::sysz_insn as SyszInsn;
pub use capstone_sys::sysz_reg as SyszReg;
use capstone_sys::cs_sysz;

pub use crate::arch::arch_builder::sysz::*;
use crate::arch::ArchTag;
use crate::arch::internal::ArchTagSealed;
use crate::{Arch, InsnDetail};

pub struct SyszArchTag;

impl ArchTagSealed for SyszArchTag {}

impl ArchTag for SyszArchTag {
    type Builder = ArchCapstoneBuilder;

    type Mode = ArchMode;
    type ExtraMode = ArchExtraMode;
    type Syntax = ArchSyntax;

    type RegId = SyszReg::Type;
    type InsnId = SyszInsn;
    type InsnGroupId = SyszInsnGroup::Type;

    type InsnDetail<'a> = SyszInsnDetail<'a>;

    fn support_arch(arch: Arch) -> bool {
        arch == Arch::SYSZ
    }
}

/// Contains sysz-specific details for an instruction
pub struct SyszInsnDetail<'a>(pub(crate) &'a cs_sysz);

impl<'a, 'i> From<&'i InsnDetail<'a, SyszArchTag>> for SyszInsnDetail<'a> {
    fn from(value: &'i InsnDetail<'a, SyszArchTag>) -> Self {
        Self(unsafe { &value.0.__bindgen_anon_1.sysz })
    }
}
