//! Contains sysz-specific types

use capstone_sys::{cs_sysz, cs_sysz_op, sysz_op_mem, sysz_op_type};

pub use capstone_sys::sysz_cc as SyszCC;
pub use capstone_sys::sysz_insn as SyszInsn;
pub use capstone_sys::sysz_insn_group as SyszInsnGroup;
pub use capstone_sys::sysz_reg as SyszReg;

pub use crate::arch::arch_builder::sysz::*;
use crate::arch::internal::ArchTagSealed;
use crate::arch::ArchTag;
use crate::{Arch, InsnDetail};

use super::DetailsArchInsn;

pub struct SyszArchTag;

impl ArchTagSealed for SyszArchTag {}

impl ArchTag for SyszArchTag {
    type Builder = ArchCapstoneBuilder;

    type Mode = ArchMode;
    type ExtraMode = ArchExtraMode;
    type Syntax = ArchSyntax;

    type RegId = SyszReg;
    type InsnId = SyszInsn;
    type InsnGroupId = SyszInsnGroup;

    type InsnDetail<'a> = SyszInsnDetail<'a>;

    fn support_arch(arch: Arch) -> bool {
        arch == Arch::SYSZ
    }
}

/// Contains sysz-specific details for an instruction
pub struct SyszInsnDetail<'a>(pub(crate) &'a cs_sysz);

impl<'a> SyszInsnDetail<'a> {
    pub fn cc(&self) -> SyszCC {
        self.0.cc
    }

    pub fn op_count(&self) -> u8 {
        self.0.op_count
    }
}

impl<'a, 'i> From<&'i InsnDetail<'a, SyszArchTag>> for SyszInsnDetail<'a> {
    fn from(value: &'i InsnDetail<'a, SyszArchTag>) -> Self {
        Self(unsafe { &value.0.__bindgen_anon_1.sysz })
    }
}

impl_PartialEq_repr_fields!(SyszInsnDetail<'a> [ 'a ];
    cc, op_count, operands
);

#[derive(Clone, Debug, PartialEq)]
pub enum SyszOperand {
    Invalid,
    Reg(SyszReg),
    Imm(i64),
    Mem(SyszMemOp),
    AcReg,
}

impl Default for SyszOperand {
    fn default() -> Self {
        Self::Invalid
    }
}

impl<'a> From<&'a cs_sysz_op> for SyszOperand {
    fn from(value: &'a cs_sysz_op) -> Self {
        use sysz_op_type::*;

        match value.type_ {
            SYSZ_OP_INVALID => Self::Invalid,
            SYSZ_OP_REG => Self::Reg(unsafe { value.__bindgen_anon_1.reg.into() }),
            SYSZ_OP_IMM => Self::Imm(unsafe { value.__bindgen_anon_1.imm }),
            SYSZ_OP_MEM => Self::Mem(unsafe { value.__bindgen_anon_1.mem.into() }),
            SYSZ_OP_ACREG => Self::AcReg,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SyszMemOp {
    pub base: u8,
    pub index: u8,
    pub length: u64,
    pub disp: i64,
}

impl From<sysz_op_mem> for SyszMemOp {
    fn from(value: sysz_op_mem) -> Self {
        Self {
            base: value.base,
            index: value.index,
            length: value.length,
            disp: value.disp,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = SyszInsnDetail;
    Operand = SyszOperand;
    OperandIterator = SyszOperandIterator;
    OperandIteratorLife = SyszOperandIterator<'a>;
    [ pub struct SyszOperandIterator<'a>(core::slice::Iter<'a, cs_sysz_op>); ]
    cs_arch_op = cs_sysz_op;
    cs_arch = cs_sysz;
);
