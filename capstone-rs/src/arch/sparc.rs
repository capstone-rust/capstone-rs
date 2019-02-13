//! Contains sparc-specific types

pub use arch::arch_builder::sparc::*;
use arch::DetailsArchInsn;
use capstone_sys::{cs_sparc, cs_sparc_op, sparc_op_mem, sparc_op_type};
use instruction::{RegId, RegIdInt};
use std::convert::From;
use std::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::sparc_insn_group as SparcInsnGroup;
pub use capstone_sys::sparc_insn as SparcInsn;
pub use capstone_sys::sparc_reg as SparcReg;
pub use capstone_sys::sparc_cc as SparcCC;
pub use capstone_sys::sparc_hint as SparcHint;

/// Contains SPARC-specific details for an instruction
pub struct SparcInsnDetail<'a>(pub(crate) &'a cs_sparc);

/// SPARC operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SparcOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Memory
    Mem(SparcOpMem),

    /// Invalid
    Invalid,
}

impl<'a> SparcInsnDetail<'a> {
    /// Condition codes
    pub fn cc(&self) -> SparcCC {
        self.0.cc
    }

    /// Branch hint
    pub fn hint(&self) -> SparcHint {
        self.0.hint
    }
}

impl_PartialEq_repr_fields!(SparcInsnDetail<'a> [ 'a ];
    cc, hint, operands
);

impl Default for SparcOperand {
    fn default() -> Self {
        SparcOperand::Invalid
    }
}

/// SPARC memory operand
#[derive(Debug, Copy, Clone)]
pub struct SparcOpMem(pub(crate) sparc_op_mem);

impl SparcOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(RegIdInt::from(self.0.base))
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(RegIdInt::from(self.0.index))
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(SparcOpMem;
    base, index, disp
);

impl cmp::Eq for SparcOpMem {}

impl<'a> From<&'a cs_sparc_op> for SparcOperand {
    fn from(insn: &cs_sparc_op) -> SparcOperand {
        match insn.type_ {
            sparc_op_type::SPARC_OP_REG => {
                SparcOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            sparc_op_type::SPARC_OP_IMM => SparcOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            sparc_op_type::SPARC_OP_MEM => {
                SparcOperand::Mem(SparcOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            sparc_op_type::SPARC_OP_INVALID => SparcOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = SparcInsnDetail;
    Operand = SparcOperand;
    OperandIterator = SparcOperandIterator;
    OperandIteratorLife = SparcOperandIterator<'a>;
    [ pub struct SparcOperandIterator<'a>(slice::Iter<'a, cs_sparc_op>); ]
    cs_arch_op = cs_sparc_op;
    cs_arch = cs_sparc;
);
