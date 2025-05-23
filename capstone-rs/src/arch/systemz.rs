//! Contains systemz-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

// XXX todo(garnt): create rusty versions
pub use capstone_sys::systemz_insn as SystemZInsn;
pub use capstone_sys::systemz_insn_group as SystemZInsnGroup;
pub use capstone_sys::systemz_reg as SystemZReg;
use capstone_sys::{cs_systemz, cs_systemz_op, systemz_op_mem, systemz_op_type};

pub use crate::arch::arch_builder::systemz::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains systemz-specific details for an instruction
pub struct SystemZInsnDetail<'a>(pub(crate) &'a cs_systemz);

impl_PartialEq_repr_fields!(SystemZInsnDetail<'a> [ 'a ];
    operands
);

/// SystemZ operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemZOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(SystemZOpMem),

    /// Invalid
    Invalid,
}

impl Default for SystemZOperand {
    fn default() -> Self {
        SystemZOperand::Invalid
    }
}

/// SystemZ memory operand
#[derive(Debug, Copy, Clone)]
pub struct SystemZOpMem(pub(crate) systemz_op_mem);

impl SystemZOpMem {
    /// Base register
    pub fn base(&self) -> u8 {
        self.0.base
    }

    /// Index register
    pub fn index(&self) -> u8 {
        self.0.index
    }

    /// BDLAddr operand
    pub fn length(&self) -> u64 {
        self.0.length
    }

    /// Disp value
    pub fn disp(&self) -> i64 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(SystemZOpMem;
    base, index, length, disp
);

impl cmp::Eq for SystemZOpMem {}

impl From<&cs_systemz_op> for SystemZOperand {
    fn from(insn: &cs_systemz_op) -> SystemZOperand {
        match insn.type_ {
            systemz_op_type::SYSTEMZ_OP_REG => {
                SystemZOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            systemz_op_type::SYSTEMZ_OP_IMM => {
                SystemZOperand::Imm(unsafe { insn.__bindgen_anon_1.imm })
            }
            systemz_op_type::SYSTEMZ_OP_MEM => {
                SystemZOperand::Mem(SystemZOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            systemz_op_type::SYSTEMZ_OP_INVALID => SystemZOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = SystemZInsnDetail;
    Operand = SystemZOperand;
    OperandIterator = SystemZOperandIterator;
    OperandIteratorLife = SystemZOperandIterator<'a>;
    [ pub struct SystemZOperandIterator<'a>(slice::Iter<'a, cs_systemz_op>); ]
    cs_arch_op = cs_systemz_op;
    cs_arch = cs_systemz;
);
