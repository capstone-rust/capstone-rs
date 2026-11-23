//! Contains sparc-specific types

use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::sparc_asi as SparcAsi;
pub use capstone_sys::sparc_cc as SparcCC;
pub use capstone_sys::sparc_hint as SparcHint;
pub use capstone_sys::sparc_insn as SparcInsn;
pub use capstone_sys::sparc_insn_group as SparcInsnGroup;
pub use capstone_sys::sparc_membar_tag as SparcMembarTag;
pub use capstone_sys::sparc_reg as SparcReg;
use capstone_sys::{cs_sparc, cs_sparc_op, sparc_op_mem, sparc_op_type};

pub use crate::arch::arch_builder::sparc::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::RegAccessType;

/// Contains SPARC-specific details for an instruction
pub struct SparcInsnDetail<'a>(pub(crate) &'a cs_sparc);

/// SPARC operand
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SparcOperand {
    /// Operand type
    pub op_type: SparcOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<RegAccessType>,
}

impl From<&cs_sparc_op> for SparcOperand {
    fn from(op: &cs_sparc_op) -> SparcOperand {
        let op_type = SparcOperandType::from(op);
        SparcOperand {
            op_type,
            access: op.access.try_into().ok(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SparcOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(SparcOpMem),

    /// Memory barrier tag
    MembarTag(SparcMembarTag),

    /// Address space identifier
    Asi(SparcAsi),

    /// Invalid
    Invalid,
}

impl SparcInsnDetail<'_> {
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

impl Default for SparcOperandType {
    fn default() -> Self {
        SparcOperandType::Invalid
    }
}

/// SPARC memory operand
#[derive(Debug, Copy, Clone)]
pub struct SparcOpMem(pub(crate) sparc_op_mem);

impl SparcOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(self.0.index as RegIdInt)
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

impl From<&cs_sparc_op> for SparcOperandType {
    fn from(insn: &cs_sparc_op) -> SparcOperandType {
        match insn.type_ {
            sparc_op_type::SPARC_OP_REG => {
                SparcOperandType::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            sparc_op_type::SPARC_OP_IMM => {
                SparcOperandType::Imm(unsafe { insn.__bindgen_anon_1.imm })
            }
            sparc_op_type::SPARC_OP_MEM => {
                SparcOperandType::Mem(SparcOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            sparc_op_type::SPARC_OP_MEMBAR_TAG => {
                SparcOperandType::MembarTag(unsafe { insn.__bindgen_anon_1.membar_tag })
            }
            sparc_op_type::SPARC_OP_ASI => {
                SparcOperandType::Asi(unsafe { insn.__bindgen_anon_1.asi })
            }
            sparc_op_type::SPARC_OP_INVALID => SparcOperandType::Invalid,
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
