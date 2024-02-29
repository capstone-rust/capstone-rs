//! Contains mips-specific types

use core::convert::From;

use capstone_sys::{cs_mips, cs_mips_op, mips_op_mem, mips_op_type};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::mips_insn_group as MipsInsnGroup;
pub use capstone_sys::mips_insn as MipsInsn;
pub use capstone_sys::mips_reg as MipsReg;

pub use crate::arch::arch_builder::mips::*;
use crate::arch::{ArchTag, DetailsArchInsn};
use crate::arch::internal::ArchTagSealed;
use crate::instruction::RegId;
use crate::{Arch, InsnDetail};

/// Architecture tag that represents MIPS.
pub struct MipsArchTag;

impl ArchTagSealed for MipsArchTag {}

impl ArchTag for MipsArchTag {
    type Builder = ArchCapstoneBuilder;

    type Mode = ArchMode;
    type ExtraMode = ArchExtraMode;
    type Syntax = ArchSyntax;

    type RegId = MipsReg;
    type InsnId = MipsInsn;
    type InsnGroupId = MipsInsnGroup;

    type InsnDetail<'a> = MipsInsnDetail<'a>;

    fn support_arch(arch: Arch) -> bool {
        arch == Arch::MIPS
    }
}

/// Contains MIPS-specific details for an instruction
pub struct MipsInsnDetail<'a>(pub(crate) &'a cs_mips);

impl_PartialEq_repr_fields!(MipsInsnDetail<'a> [ 'a ];
    operands
);

impl<'a, 'i> From<&'i InsnDetail<'a, MipsArchTag>> for MipsInsnDetail<'a> {
    fn from(value: &'i InsnDetail<'a, MipsArchTag>) -> Self {
        Self(unsafe { &value.0.__bindgen_anon_1.mips })
    }
}

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

impl Default for MipsOperand {
    fn default() -> Self {
        MipsOperand::Invalid
    }
}

/// MIPS memory operand
#[derive(Debug, Copy, Clone)]
pub struct MipsOpMem(pub(crate) mips_op_mem);

impl MipsOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        self.0.base.into()
    }

    /// Disp value
    pub fn disp(&self) -> i64 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(MipsOpMem;
    base, disp
);

impl Eq for MipsOpMem {}

impl<'a> From<&'a cs_mips_op> for MipsOperand {
    fn from(insn: &cs_mips_op) -> MipsOperand {
        match insn.type_ {
            mips_op_type::MIPS_OP_REG => {
                MipsOperand::Reg(unsafe { insn.__bindgen_anon_1.reg.into() })
            }
            mips_op_type::MIPS_OP_IMM => MipsOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            mips_op_type::MIPS_OP_MEM => {
                MipsOperand::Mem(MipsOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            mips_op_type::MIPS_OP_INVALID => MipsOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = MipsInsnDetail;
    Operand = MipsOperand;
    OperandIterator = MipsOperandIterator;
    OperandIteratorLife = MipsOperandIterator<'a>;
    [ pub struct MipsOperandIterator<'a>(core::slice::Iter<'a, cs_mips_op>); ]
    cs_arch_op = cs_mips_op;
    cs_arch = cs_mips;
);

#[cfg(test)]
mod test {
    use super::*;
    use capstone_sys::*;

    #[test]
    fn test_mips_op_from() {
        let op = cs_mips_op {
            type_: mips_op_type::MIPS_OP_INVALID,
            __bindgen_anon_1: cs_mips_op__bindgen_ty_1 { reg: MipsReg(0) },
        };
        assert_eq!(MipsOperand::from(&op), MipsOperand::Invalid);
    }
}
