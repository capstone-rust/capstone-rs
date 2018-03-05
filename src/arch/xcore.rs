//! Contains xcore-specific types

pub use arch::arch_builder::xcore::*;
use arch::DetailsArch;
use capstone_sys::{cs_xcore, cs_xcore_op, xcore_op_mem, xcore_op_type};
use instruction::{RegId, RegIdInt};
use std::convert::From;
use std::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::xcore_insn_group as XcoreInsnGroup;
pub use capstone_sys::xcore_insn as XcoreInsn;
pub use capstone_sys::xcore_reg as XcoreReg;

/// Contains XCORE-specific details for an instruction
pub struct XcoreInsnDetail<'a>(pub(crate) &'a cs_xcore);

impl_PartialEq_repr_fields!(XcoreInsnDetail<'a> [ 'a ];
    operands
);

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
        RegId(self.0.base as RegIdInt)
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(self.0.index as RegIdInt)
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

impl cmp::Eq for XcoreOpMem {}

impl<'a> From<&'a cs_xcore_op> for XcoreOperand {
    fn from(insn: &cs_xcore_op) -> XcoreOperand {
        match insn.type_ {
            xcore_op_type::XCORE_OP_REG => {
                XcoreOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
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
    [ pub struct XcoreOperandIterator<'a>(slice::Iter<'a, cs_xcore_op>); ]
    cs_arch_op = cs_xcore_op;
    cs_arch = cs_xcore;
);
