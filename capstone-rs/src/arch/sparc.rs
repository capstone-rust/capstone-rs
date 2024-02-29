//! Contains sparc-specific types

use core::convert::From;

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::sparc_insn_group as SparcInsnGroup;
pub use capstone_sys::sparc_insn as SparcInsn;
pub use capstone_sys::sparc_reg as SparcReg;
pub use capstone_sys::sparc_cc as SparcCC;
pub use capstone_sys::sparc_hint as SparcHint;
use capstone_sys::{cs_sparc, cs_sparc_op, sparc_op_mem, sparc_op_type};

pub use crate::arch::arch_builder::sparc::*;
use crate::arch::{ArchTag, DetailsArchInsn};
use crate::arch::internal::ArchTagSealed;
use crate::instruction::{RegId, RegIdInt};
use crate::{Arch, InsnDetail};

/// Architecture tag that represents Sparc.
pub struct SparcArchTag;

impl ArchTagSealed for SparcArchTag {}

impl ArchTag for SparcArchTag {
    type Builder = ArchCapstoneBuilder;

    type Mode = ArchMode;
    type ExtraMode = ArchExtraMode;
    type Syntax = ArchSyntax;

    type RegId = SparcReg;
    type InsnId = SparcInsn;
    type InsnGroupId = SparcInsnGroup;

    type InsnDetail<'a> = SparcInsnDetail<'a>;

    fn support_arch(arch: Arch) -> bool {
        arch == Arch::SPARC
    }
}

/// Contains SPARC-specific details for an instruction
pub struct SparcInsnDetail<'a>(pub(crate) &'a cs_sparc);

impl<'a, 'i> From<&'i InsnDetail<'a, SparcArchTag>> for SparcInsnDetail<'a> {
    fn from(value: &'i InsnDetail<'a, SparcArchTag>) -> Self {
        Self(unsafe { &value.0.__bindgen_anon_1.sparc })
    }
}

/// SPARC operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SparcOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

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

impl Eq for SparcOpMem {}

impl<'a> From<&'a cs_sparc_op> for SparcOperand {
    fn from(insn: &cs_sparc_op) -> SparcOperand {
        match insn.type_ {
            sparc_op_type::SPARC_OP_REG => {
                SparcOperand::Reg(unsafe { insn.__bindgen_anon_1.reg.into() })
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
    [ pub struct SparcOperandIterator<'a>(core::slice::Iter<'a, cs_sparc_op>); ]
    cs_arch_op = cs_sparc_op;
    cs_arch = cs_sparc;
);
