//! Contains loongarch-specific types

use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};

pub use capstone_sys::loongarch_insn as LoongArchInsn;
pub use capstone_sys::loongarch_reg as LoongArchReg;
use capstone_sys::{
    cs_loongarch, cs_loongarch_op, cs_loongarch_op__bindgen_ty_1, loongarch_op_mem,
    loongarch_op_type,
};

pub use crate::arch::arch_builder::loongarch::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::RegAccessType;

/// Contains loongarch-specific details for an instruction
pub struct LoongArchInsnDetail<'a>(pub(crate) &'a cs_loongarch);

impl_PartialEq_repr_fields!(LoongArchInsnDetail<'a> [ 'a ];
    operands
);

/// loongarch operand
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LoongArchOperand {
    /// Operand type
    pub op_type: LoongArchOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<RegAccessType>,
}

impl From<&cs_loongarch_op> for LoongArchOperand {
    fn from(op: &cs_loongarch_op) -> LoongArchOperand {
        let op_type = LoongArchOperandType::new(op.type_, op.__bindgen_anon_1);
        LoongArchOperand {
            op_type,
            access: op.access.try_into().ok(),
        }
    }
}

/// LoongArch operand
#[derive(Clone, Debug, PartialEq)]
pub enum LoongArchOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(LoongArchOpMem),

    /// Invalid
    Invalid,
}

impl LoongArchOperandType {
    fn new(
        op_type: loongarch_op_type,
        value: cs_loongarch_op__bindgen_ty_1,
    ) -> LoongArchOperandType {
        match op_type {
            loongarch_op_type::LOONGARCH_OP_REG => {
                LoongArchOperandType::Reg(RegId(unsafe { value.reg } as RegIdInt))
            }
            loongarch_op_type::LOONGARCH_OP_IMM => LoongArchOperandType::Imm(unsafe { value.imm }),
            loongarch_op_type::LOONGARCH_OP_MEM => {
                LoongArchOperandType::Mem(LoongArchOpMem(unsafe { value.mem }))
            }
            loongarch_op_type::LOONGARCH_OP_INVALID => LoongArchOperandType::Invalid,
        }
    }
}

impl cmp::Eq for LoongArchOperandType {}

impl Default for LoongArchOperandType {
    fn default() -> Self {
        LoongArchOperandType::Invalid
    }
}

/// loongarch memory operand
#[derive(Debug, Copy, Clone)]
pub struct LoongArchOpMem(pub(crate) loongarch_op_mem);

impl LoongArchOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(self.0.index as RegIdInt)
    }

    /// Displacement/offset
    pub fn disp(&self) -> i64 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(LoongArchOpMem;
    base, index, disp
);

impl cmp::Eq for LoongArchOpMem {}

def_arch_details_struct!(
    InsnDetail = LoongArchInsnDetail;
    Operand = LoongArchOperand;
    OperandIterator = LoongArchOperandIterator;
    OperandIteratorLife = LoongArchOperandIterator<'a>;
    [ pub struct LoongArchOperandIterator<'a>(slice::Iter<'a, cs_loongarch_op>); ]
    cs_arch_op = cs_loongarch_op;
    cs_arch = cs_loongarch;
);
