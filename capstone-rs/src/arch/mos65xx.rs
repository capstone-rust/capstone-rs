//! Contains mos65xx-specific types

use core::convert::From;
use core::{fmt, slice};

pub use capstone_sys::mos65xx_insn as Mos65xxInsn;
pub use capstone_sys::mos65xx_reg as Mos65xxReg;
use capstone_sys::{cs_mos65xx, cs_mos65xx_op, mos65xx_op_type};

pub use crate::arch::arch_builder::mos65xx::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains mos65xx-specific details for an instruction
pub struct Mos65xxInsnDetail<'a>(pub(crate) &'a cs_mos65xx);

impl_PartialEq_repr_fields!(Mos65xxInsnDetail<'a> [ 'a ];
    operands
);

/// mos65xx operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mos65xxOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(u16),

    /// Memory
    Mem(u32),

    /// Invalid
    Invalid,
}

impl Default for Mos65xxOperand {
    fn default() -> Self {
        Mos65xxOperand::Invalid
    }
}

impl From<&cs_mos65xx_op> for Mos65xxOperand {
    fn from(insn: &cs_mos65xx_op) -> Mos65xxOperand {
        match insn.type_ {
            mos65xx_op_type::MOS65XX_OP_REG => {
                Mos65xxOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            mos65xx_op_type::MOS65XX_OP_IMM => {
                Mos65xxOperand::Imm(unsafe { insn.__bindgen_anon_1.imm })
            }
            mos65xx_op_type::MOS65XX_OP_MEM => {
                Mos65xxOperand::Mem(unsafe { insn.__bindgen_anon_1.mem })
            }
            mos65xx_op_type::MOS65XX_OP_INVALID => Mos65xxOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = Mos65xxInsnDetail;
    Operand = Mos65xxOperand;
    OperandIterator = Mos65xxOperandIterator;
    OperandIteratorLife = Mos65xxOperandIterator<'a>;
    [ pub struct Mos65xxOperandIterator<'a>(slice::Iter<'a, cs_mos65xx_op>); ]
    cs_arch_op = cs_mos65xx_op;
    cs_arch = cs_mos65xx;
);
