//! Contains mips-specific types

pub use arch::arch_builder::mips::*;
use arch::DetailsArch;
use capstone_sys::{cs_mips, cs_mips_op, mips_op_type, mips_op_mem};
use instruction::RegId;
use std::convert::From;
use std::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::mips_insn_group as MipsInsnGroup;
pub use capstone_sys::mips_insn as MipsInsn;
pub use capstone_sys::mips_reg as MipsReg;

/// Contains MIPS-specific details for an instruction
pub struct MipsInsnDetail<'a>(pub(crate) &'a cs_mips);

/// MIPS operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MipsOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(MipsOpMem),

    /// Invalid
    Invalid,
}

/// MIPS memory operand
#[derive(Debug, Copy, Clone)]
pub struct MipsOpMem(mips_op_mem);

impl MipsOpMem {
    /// Base value
    pub fn base(&self) -> u32 { self.0.base as u32 }

    /// Disp value
    pub fn disp(&self) -> i64 { self.0.disp }
}

impl cmp::PartialEq for MipsOpMem {
    fn eq(&self, other: &Self) -> bool {
        self.base() == other.base() && self.disp() == other.disp()
    }
}

impl cmp::Eq for MipsOpMem {}

impl<'a> From<&'a cs_mips_op> for MipsOperand {
    fn from(insn: &cs_mips_op) -> MipsOperand {
        match insn.type_ {
            mips_op_type::MIPS_OP_REG => MipsOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as u8)),
            mips_op_type::MIPS_OP_IMM => MipsOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            mips_op_type::MIPS_OP_MEM => MipsOperand::Mem(MipsOpMem(unsafe { insn.__bindgen_anon_1.mem })),
            mips_op_type::MIPS_OP_INVALID => MipsOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = MipsInsnDetail;
    Operand = MipsOperand;
    OperandIterator = MipsOperandIterator;
    OperandIteratorLife = MipsOperandIterator<'a>;
    [ pub struct MipsOperandIterator<'a>(slice::Iter<'a, cs_mips_op>); ]
    cs_arch_op = cs_mips_op;
    cs_arch = cs_mips;
);
