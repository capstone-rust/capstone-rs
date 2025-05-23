//! Contains sh-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

pub use capstone_sys::sh_insn as ShInsn;
pub use capstone_sys::sh_reg as ShReg;
use capstone_sys::{cs_sh, cs_sh_op, sh_op_mem, sh_op_mem_type, sh_op_type};

pub use crate::arch::arch_builder::sh::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains sh-specific details for an instruction
pub struct ShInsnDetail<'a>(pub(crate) &'a cs_sh);

impl_PartialEq_repr_fields!(ShInsnDetail<'a> [ 'a ];
    operands
);

/// sh operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(u64),

    /// Memory
    Mem(ShOpMem),

    /// Invalid
    Invalid,
}

impl Default for ShOperand {
    fn default() -> Self {
        ShOperand::Invalid
    }
}

impl From<&cs_sh_op> for ShOperand {
    fn from(insn: &cs_sh_op) -> ShOperand {
        match insn.type_ {
            sh_op_type::SH_OP_REG => {
                ShOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            sh_op_type::SH_OP_IMM => ShOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            sh_op_type::SH_OP_MEM => ShOperand::Mem(ShOpMem(unsafe { insn.__bindgen_anon_1.mem })),
            sh_op_type::SH_OP_INVALID => ShOperand::Invalid,
        }
    }
}

/// SH memory operand
#[derive(Debug, Copy, Clone)]
pub struct ShOpMem(pub(crate) sh_op_mem);

impl ShOpMem {
    /// Register
    pub fn reg(&self) -> RegId {
        RegId(self.0.reg as RegIdInt)
    }

    /// Disp value
    fn disp(&self) -> u32 {
        self.0.disp as u32
    }

    /// Addressing mode
    pub fn address(&self) -> ShOpMemType {
        ShOpMemType::from_u32(self.0.address as u32).unwrap_or(ShOpMemType::Invalid)
    }
}

define_cs_enum_wrapper_reverse!(
    [
        /// SH Memory Operand type
        => ShOpMemType = sh_op_mem_type,
    ]
    /// Invalid
    => Invalid = SH_OP_MEM_INVALID;
    /// Register indirect
    => RegisterIndirect = SH_OP_MEM_REG_IND;
    /// Register post increment
    => RegisterPost = SH_OP_MEM_REG_POST;
    /// Register pre increment
    => RegisterPre = SH_OP_MEM_REG_PRE;
    /// Displacement
    => Displacement = SH_OP_MEM_REG_DISP;
    /// R0 indexed
    => RegisterR0 = SH_OP_MEM_REG_R0;
    /// GBR based displacement
    => GBRDisplacement = SH_OP_MEM_GBR_DISP;
    /// GBR based R0 indexed
    => GBRR0 = SH_OP_MEM_GBR_R0;
    /// PC Relative
    => PCRelative = SH_OP_MEM_PCR;
    /// TBR based displacement
    => TBRDisplacement = SH_OP_MEM_TBR_DISP;
);

impl_PartialEq_repr_fields!(ShOpMem;
    address, reg, disp
);

impl cmp::Eq for ShOpMem {}

def_arch_details_struct!(
    InsnDetail = ShInsnDetail;
    Operand = ShOperand;
    OperandIterator = ShOperandIterator;
    OperandIteratorLife = ShOperandIterator<'a>;
    [ pub struct ShOperandIterator<'a>(slice::Iter<'a, cs_sh_op>); ]
    cs_arch_op = cs_sh_op;
    cs_arch = cs_sh;
);
