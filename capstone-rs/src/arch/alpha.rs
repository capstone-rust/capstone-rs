//! Contains alpha-specific types

use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};

pub use capstone_sys::alpha_insn as AlphaInsn;
pub use capstone_sys::alpha_reg as AlphaReg;
use capstone_sys::{alpha_op_type, cs_alpha, cs_alpha_op, cs_alpha_op__bindgen_ty_1};

pub use crate::arch::arch_builder::alpha::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::RegAccessType;

/// Contains alpha-specific details for an instruction
pub struct AlphaInsnDetail<'a>(pub(crate) &'a cs_alpha);

impl_PartialEq_repr_fields!(AlphaInsnDetail<'a> [ 'a ];
    operands
);

/// alpha operand
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct AlphaOperand {
    /// Operand type
    pub op_type: AlphaOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<RegAccessType>,
}

impl From<&cs_alpha_op> for AlphaOperand {
    fn from(op: &cs_alpha_op) -> AlphaOperand {
        let op_type = AlphaOperandType::new(op.type_, op.__bindgen_anon_1);
        AlphaOperand {
            op_type,
            access: op.access.try_into().ok(),
        }
    }
}

/// Alpha operand
#[derive(Clone, Debug, PartialEq)]
pub enum AlphaOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Invalid
    Invalid,
}

impl AlphaOperandType {
    fn new(op_type: alpha_op_type, value: cs_alpha_op__bindgen_ty_1) -> AlphaOperandType {
        match op_type {
            alpha_op_type::ALPHA_OP_REG => {
                AlphaOperandType::Reg(RegId(unsafe { value.reg } as RegIdInt))
            }
            alpha_op_type::ALPHA_OP_IMM => AlphaOperandType::Imm(unsafe { value.imm }),
            alpha_op_type::ALPHA_OP_INVALID => AlphaOperandType::Invalid,
        }
    }
}

impl cmp::Eq for AlphaOperandType {}

impl Default for AlphaOperandType {
    fn default() -> Self {
        AlphaOperandType::Invalid
    }
}

def_arch_details_struct!(
    InsnDetail = AlphaInsnDetail;
    Operand = AlphaOperand;
    OperandIterator = AlphaOperandIterator;
    OperandIteratorLife = AlphaOperandIterator<'a>;
    [ pub struct AlphaOperandIterator<'a>(slice::Iter<'a, cs_alpha_op>); ]
    cs_arch_op = cs_alpha_op;
    cs_arch = cs_alpha;
);
