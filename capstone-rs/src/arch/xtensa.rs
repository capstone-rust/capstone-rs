//! Contains xtensa-specific types

use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};

pub use capstone_sys::xtensa_insn as XtensaInsn;
pub use capstone_sys::xtensa_reg as XtensaReg;
use capstone_sys::{
    cs_ac_type, cs_xtensa, cs_xtensa_op, cs_xtensa_op_mem, cs_xtensa_op_type,
    cs_xtensa_operand__bindgen_ty_1,
};

pub use crate::arch::arch_builder::xtensa::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::RegAccessType;

/// Contains xtensa-specific details for an instruction
pub struct XtensaInsnDetail<'a>(pub(crate) &'a cs_xtensa);

impl_PartialEq_repr_fields!(XtensaInsnDetail<'a> [ 'a ];
    operands
);

/// xtensa operand
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct XtensaOperand {
    /// Operand type
    pub op_type: XtensaOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<RegAccessType>,
}

impl From<&cs_xtensa_op> for XtensaOperand {
    fn from(op: &cs_xtensa_op) -> XtensaOperand {
        let op_type = XtensaOperandType::new(op.type_, op.__bindgen_anon_1);
        XtensaOperand {
            op_type,
            access: cs_ac_type(op.access as _).try_into().ok(),
        }
    }
}

/// Xtensa operand
#[derive(Clone, Debug, PartialEq)]
pub enum XtensaOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Memory
    Mem(XtensaOpMem),

    /// Memory register
    MemReg(RegId),

    /// Memory immediate
    MemImm(i32),

    /// L32R target
    L32R(i32),

    /// Invalid
    Invalid,
}

impl XtensaOperandType {
    fn new(op_type: u8, value: cs_xtensa_operand__bindgen_ty_1) -> XtensaOperandType {
        match op_type as cs_xtensa_op_type::Type {
            cs_xtensa_op_type::XTENSA_OP_REG => {
                XtensaOperandType::Reg(RegId(unsafe { value.reg } as RegIdInt))
            }
            cs_xtensa_op_type::XTENSA_OP_IMM => XtensaOperandType::Imm(unsafe { value.imm }),
            cs_xtensa_op_type::XTENSA_OP_MEM => {
                XtensaOperandType::Mem(XtensaOpMem(unsafe { value.mem }))
            }
            cs_xtensa_op_type::XTENSA_OP_MEM_REG => {
                XtensaOperandType::MemReg(RegId(unsafe { value.reg } as RegIdInt))
            }
            cs_xtensa_op_type::XTENSA_OP_MEM_IMM => XtensaOperandType::MemImm(unsafe { value.imm }),
            cs_xtensa_op_type::XTENSA_OP_L32R => XtensaOperandType::L32R(unsafe { value.imm }),
            _ => XtensaOperandType::Invalid,
        }
    }
}

impl cmp::Eq for XtensaOperandType {}

impl Default for XtensaOperandType {
    fn default() -> Self {
        XtensaOperandType::Invalid
    }
}

/// xtensa memory operand
#[derive(Debug, Copy, Clone)]
pub struct XtensaOpMem(pub(crate) cs_xtensa_op_mem);

impl XtensaOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Displacement/offset
    pub fn disp(&self) -> i32 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(XtensaOpMem;
    base, disp
);

impl cmp::Eq for XtensaOpMem {}

def_arch_details_struct!(
    InsnDetail = XtensaInsnDetail;
    Operand = XtensaOperand;
    OperandIterator = XtensaOperandIterator;
    OperandIteratorLife = XtensaOperandIterator<'a>;
    [ pub struct XtensaOperandIterator<'a>(slice::Iter<'a, cs_xtensa_op>); ]
    cs_arch_op = cs_xtensa_op;
    cs_arch = cs_xtensa;
);
