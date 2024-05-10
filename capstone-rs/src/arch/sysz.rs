//! Contains sysz-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

// XXX todo(garnt): create rusty versions
pub use capstone_sys::sysz_insn_group as SysZInsnGroup;
pub use capstone_sys::sysz_insn as SysZInsn;
pub use capstone_sys::sysz_reg as SysZReg;
use capstone_sys::{cs_sysz, cs_sysz_op, sysz_op_mem, sysz_op_type};

pub use crate::arch::arch_builder::sysz::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains sysz-specific details for an instruction
pub struct SysZInsnDetail<'a>(pub(crate) &'a cs_sysz);

impl_PartialEq_repr_fields!(SysZInsnDetail<'a> [ 'a ];
    operands
);

/// SysZ operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SysZOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(SysZOpMem),

    /// Access Register
    AcReg(RegId),

    /// Invalid
    Invalid,
}

impl Default for SysZOperand {
    fn default() -> Self {
        SysZOperand::Invalid
    }
}

/// SysZ memory operand
#[derive(Debug, Copy, Clone)]
pub struct SysZOpMem(pub(crate) sysz_op_mem);

impl SysZOpMem {
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

impl_PartialEq_repr_fields!(SysZOpMem;
    base, index, length, disp
);

impl cmp::Eq for SysZOpMem {}

impl <'a> From<&'a cs_sysz_op> for SysZOperand {
    fn from(insn: &cs_sysz_op) -> SysZOperand {
        match insn.type_ {
            sysz_op_type::SYSZ_OP_REG => {
                SysZOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            },
            sysz_op_type::SYSZ_OP_IMM => SysZOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            sysz_op_type::SYSZ_OP_MEM => {
                SysZOperand::Mem(SysZOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            },
            sysz_op_type::SYSZ_OP_ACREG => {
                SysZOperand::AcReg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            },
            sysz_op_type::SYSZ_OP_INVALID => SysZOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = SysZInsnDetail;
    Operand = SysZOperand;
    OperandIterator = SysZOperandIterator;
    OperandIteratorLife = SysZOperandIterator<'a>;
    [ pub struct SysZOperandIterator<'a>(slice::Iter<'a, cs_sysz_op>); ]
    cs_arch_op = cs_sysz_op;
    cs_arch = cs_sysz;
);
