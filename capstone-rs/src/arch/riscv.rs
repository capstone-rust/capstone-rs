//! Contains riscv-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::riscv_insn_group as RiscVInsnGroup;
pub use capstone_sys::riscv_insn as RiscVInsn;
pub use capstone_sys::riscv_reg as RiscVReg;
use capstone_sys::{cs_riscv, cs_riscv_op, riscv_op_mem, riscv_op_type};

pub use crate::arch::arch_builder::riscv::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains RISCV-specific details for an instruction
pub struct RiscVInsnDetail<'a>(pub(crate) &'a cs_riscv);

impl_PartialEq_repr_fields!(RiscVInsnDetail<'a> [ 'a ];
    operands
);

/// RISCV operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiscVOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(RiscVOpMem),

    /// Invalid
    Invalid,
}

impl Default for RiscVOperand {
    fn default() -> Self {
        RiscVOperand::Invalid
    }
}

/// RISCV memory operand
#[derive(Debug, Copy, Clone)]
pub struct RiscVOpMem(pub(crate) riscv_op_mem);

impl RiscVOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Disp value
    pub fn disp(&self) -> i64 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(RiscVOpMem;
    base, disp
);

impl cmp::Eq for RiscVOpMem {}

impl From<&cs_riscv_op> for RiscVOperand {
    fn from(insn: &cs_riscv_op) -> RiscVOperand {
        match insn.type_ {
            riscv_op_type::RISCV_OP_REG => {
                RiscVOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            riscv_op_type::RISCV_OP_IMM => RiscVOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            riscv_op_type::RISCV_OP_MEM => {
                RiscVOperand::Mem(RiscVOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            riscv_op_type::RISCV_OP_INVALID => RiscVOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = RiscVInsnDetail;
    Operand = RiscVOperand;
    OperandIterator = RiscVOperandIterator;
    OperandIteratorLife = RiscVOperandIterator<'a>;
    [ pub struct RiscVOperandIterator<'a>(slice::Iter<'a, cs_riscv_op>); ]
    cs_arch_op = cs_riscv_op;
    cs_arch = cs_riscv;
);
