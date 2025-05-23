//! Contains tricore-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

pub use capstone_sys::tricore_insn as TriCoreInsn;
pub use capstone_sys::tricore_insn_group as TriCoreInsnGroup;
pub use capstone_sys::tricore_reg as TriCoreReg;
use capstone_sys::{cs_tricore, cs_tricore_op, tricore_op_mem, tricore_op_type};

pub use crate::arch::arch_builder::tricore::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains tricore-specific details for an instruction
pub struct TriCoreInsnDetail<'a>(pub(crate) &'a cs_tricore);

impl_PartialEq_repr_fields!(TriCoreInsnDetail<'a> [ 'a ];
    operands
);

/// tricore operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriCoreOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Memory
    Mem(TriCoreOpMem),

    /// Invalid
    Invalid,
}

impl Default for TriCoreOperand {
    fn default() -> Self {
        TriCoreOperand::Invalid
    }
}

/// tricore memory operand
#[derive(Debug, Copy, Clone)]
pub struct TriCoreOpMem(pub(crate) tricore_op_mem);

impl TriCoreOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(RegIdInt::from(self.0.base))
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(TriCoreOpMem;
    base, disp
);

impl cmp::Eq for TriCoreOpMem {}

impl From<&cs_tricore_op> for TriCoreOperand {
    fn from(insn: &cs_tricore_op) -> TriCoreOperand {
        match insn.type_ {
            tricore_op_type::TRICORE_OP_REG => {
                TriCoreOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            tricore_op_type::TRICORE_OP_IMM => {
                TriCoreOperand::Imm(unsafe { insn.__bindgen_anon_1.imm })
            }
            tricore_op_type::TRICORE_OP_MEM => {
                TriCoreOperand::Mem(TriCoreOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            tricore_op_type::TRICORE_OP_INVALID => TriCoreOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = TriCoreInsnDetail;
    Operand = TriCoreOperand;
    OperandIterator = TriCoreOperandIterator;
    OperandIteratorLife = TriCoreOperandIterator<'a>;
    [ pub struct TriCoreOperandIterator<'a>(slice::Iter<'a, cs_tricore_op>); ]
    cs_arch_op = cs_tricore_op;
    cs_arch = cs_tricore;
);
