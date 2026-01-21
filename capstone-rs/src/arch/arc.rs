//! Contains arc-specific types

use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};

pub use capstone_sys::arc_insn as ArcInsn;
pub use capstone_sys::arc_reg as ArcReg;
use capstone_sys::{arc_op_type, cs_arc, cs_arc_op, cs_arc_op__bindgen_ty_1};

pub use crate::arch::arch_builder::arc::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::RegAccessType;

/// Contains arc-specific details for an instruction
pub struct ArcInsnDetail<'a>(pub(crate) &'a cs_arc);

impl_PartialEq_repr_fields!(ArcInsnDetail<'a> [ 'a ];
    operands
);

/// arc operand
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ArcOperand {
    /// Operand type
    pub op_type: ArcOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<RegAccessType>,
}

impl From<&cs_arc_op> for ArcOperand {
    fn from(op: &cs_arc_op) -> ArcOperand {
        let op_type = ArcOperandType::new(op.type_, op.__bindgen_anon_1);
        ArcOperand {
            op_type,
            access: op.access.try_into().ok(),
        }
    }
}

/// Arc operand
#[derive(Clone, Debug, PartialEq)]
pub enum ArcOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Invalid
    Invalid,
}

impl ArcOperandType {
    fn new(op_type: arc_op_type, value: cs_arc_op__bindgen_ty_1) -> ArcOperandType {
        match op_type {
            arc_op_type::ARC_OP_REG => ArcOperandType::Reg(RegId(unsafe { value.reg } as RegIdInt)),
            arc_op_type::ARC_OP_IMM => ArcOperandType::Imm(unsafe { value.imm }),
            arc_op_type::ARC_OP_INVALID => ArcOperandType::Invalid,
        }
    }
}

impl cmp::Eq for ArcOperandType {}

impl Default for ArcOperandType {
    fn default() -> Self {
        ArcOperandType::Invalid
    }
}

def_arch_details_struct!(
    InsnDetail = ArcInsnDetail;
    Operand = ArcOperand;
    OperandIterator = ArcOperandIterator;
    OperandIteratorLife = ArcOperandIterator<'a>;
    [ pub struct ArcOperandIterator<'a>(slice::Iter<'a, cs_arc_op>); ]
    cs_arch_op = cs_arc_op;
    cs_arch = cs_arc;
);
