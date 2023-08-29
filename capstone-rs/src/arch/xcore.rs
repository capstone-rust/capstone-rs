//! Contains xcore-specific types

use core::convert::From;

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::xcore_insn_group as XcoreInsnGroup;
pub use capstone_sys::xcore_insn as XcoreInsn;
pub use capstone_sys::xcore_reg as XcoreReg;
use capstone_sys::{cs_xcore, cs_xcore_op, xcore_op_mem, xcore_op_type};

pub use crate::arch::arch_builder::xcore::*;
use crate::arch::{ArchTag, DetailsArchInsn};
use crate::arch::internal::ArchTagSealed;
use crate::instruction::{RegId, RegIdInt};
use crate::{Arch, InsnDetail};

pub struct XcoreArchTag;

impl ArchTagSealed for XcoreArchTag {}

impl ArchTag for XcoreArchTag {
    type Builder = ArchCapstoneBuilder;

    type Mode = ArchMode;
    type ExtraMode = ArchExtraMode;
    type Syntax = ArchSyntax;

    type RegId = XcoreReg;
    type InsnId = XcoreInsn;
    type InsnGroupId = XcoreInsnGroup;

    type InsnDetail<'a> = XcoreInsnDetail<'a>;

    fn support_arch(arch: Arch) -> bool {
        arch == Arch::XCORE
    }
}

/// Contains XCORE-specific details for an instruction
pub struct XcoreInsnDetail<'a>(pub(crate) &'a cs_xcore);

impl_PartialEq_repr_fields!(XcoreInsnDetail<'a> [ 'a ];
    operands
);

impl<'a, 'i> From<&'i InsnDetail<'a, XcoreArchTag>> for XcoreInsnDetail<'a> {
    fn from(value: &'i InsnDetail<'a, XcoreArchTag>) -> Self {
        Self(unsafe { &value.0.__bindgen_anon_1.xcore })
    }
}

/// XCORE operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XcoreOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Memory
    Mem(XcoreOpMem),

    /// Invalid
    Invalid,
}

impl Default for XcoreOperand {
    fn default() -> Self {
        XcoreOperand::Invalid
    }
}

/// XCORE memory operand
#[derive(Debug, Copy, Clone)]
pub struct XcoreOpMem(pub(crate) xcore_op_mem);

impl XcoreOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(RegIdInt::from(self.0.base))
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(RegIdInt::from(self.0.index))
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp
    }

    /// Direct value
    pub fn direct(&self) -> i32 {
        self.0.direct
    }
}

impl_PartialEq_repr_fields!(XcoreOpMem;
    base, index, disp, direct
);

impl Eq for XcoreOpMem {}

impl<'a> From<&'a cs_xcore_op> for XcoreOperand {
    fn from(insn: &cs_xcore_op) -> XcoreOperand {
        match insn.type_ {
            xcore_op_type::XCORE_OP_REG => {
                XcoreOperand::Reg(unsafe { insn.__bindgen_anon_1.reg.into() })
            }
            xcore_op_type::XCORE_OP_IMM => XcoreOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            xcore_op_type::XCORE_OP_MEM => {
                XcoreOperand::Mem(XcoreOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            xcore_op_type::XCORE_OP_INVALID => XcoreOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = XcoreInsnDetail;
    Operand = XcoreOperand;
    OperandIterator = XcoreOperandIterator;
    OperandIteratorLife = XcoreOperandIterator<'a>;
    [ pub struct XcoreOperandIterator<'a>(core::slice::Iter<'a, cs_xcore_op>); ]
    cs_arch_op = cs_xcore_op;
    cs_arch = cs_xcore;
);
