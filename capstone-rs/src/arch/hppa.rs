//! Contains hppa-specific types

use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};

pub use capstone_sys::hppa_insn as HppaInsn;
pub use capstone_sys::hppa_reg as HppaReg;
use capstone_sys::{cs_hppa, cs_hppa_op, cs_hppa_op__bindgen_ty_1, hppa_mem, hppa_op_type};

pub use crate::arch::arch_builder::hppa::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::RegAccessType;

/// Contains hppa-specific details for an instruction
pub struct HppaInsnDetail<'a>(pub(crate) &'a cs_hppa);

impl_PartialEq_repr_fields!(HppaInsnDetail<'a> [ 'a ];
    operands
);

/// hppa operand
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct HppaOperand {
    /// Operand type
    pub op_type: HppaOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<RegAccessType>,
}

impl From<&cs_hppa_op> for HppaOperand {
    fn from(op: &cs_hppa_op) -> HppaOperand {
        let op_type = HppaOperandType::new(op.type_, op.__bindgen_anon_1);
        HppaOperand {
            op_type,
            access: op.access.try_into().ok(),
        }
    }
}

/// Hppa operand
#[derive(Clone, Debug, PartialEq)]
pub enum HppaOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Index register
    IdxReg(RegId),

    /// Displacement
    Disp(i64),

    /// Target
    Target(i64),

    /// Memory
    Mem(HppaMem),

    /// Invalid
    Invalid,
}

impl HppaOperandType {
    fn new(op_type: hppa_op_type, value: cs_hppa_op__bindgen_ty_1) -> HppaOperandType {
        match op_type {
            hppa_op_type::HPPA_OP_REG => {
                HppaOperandType::Reg(RegId(unsafe { value.reg } as RegIdInt))
            }
            hppa_op_type::HPPA_OP_IMM => HppaOperandType::Imm(unsafe { value.imm }),
            hppa_op_type::HPPA_OP_IDX_REG => {
                HppaOperandType::IdxReg(RegId(unsafe { value.reg } as RegIdInt))
            }
            hppa_op_type::HPPA_OP_DISP => HppaOperandType::Disp(unsafe { value.imm }),
            hppa_op_type::HPPA_OP_TARGET => HppaOperandType::Target(unsafe { value.imm }),
            hppa_op_type::HPPA_OP_MEM => HppaOperandType::Mem(HppaMem(unsafe { value.mem })),
            hppa_op_type::HPPA_OP_INVALID => HppaOperandType::Invalid,
        }
    }
}

impl cmp::Eq for HppaOperandType {}

impl Default for HppaOperandType {
    fn default() -> Self {
        HppaOperandType::Invalid
    }
}

/// HPPA memory operand
#[derive(Debug, Copy, Clone)]
pub struct HppaMem(pub(crate) hppa_mem);

impl HppaMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Space register
    pub fn space(&self) -> RegId {
        RegId(self.0.space as RegIdInt)
    }

    /// Base access
    pub fn base_access(&self) -> Option<RegAccessType> {
        self.0.base_access.try_into().ok()
    }
}

impl_PartialEq_repr_fields!(HppaMem;
    base, space, base_access
);

impl cmp::Eq for HppaMem {}

def_arch_details_struct!(
    InsnDetail = HppaInsnDetail;
    Operand = HppaOperand;
    OperandIterator = HppaOperandIterator;
    OperandIteratorLife = HppaOperandIterator<'a>;
    [ pub struct HppaOperandIterator<'a>(slice::Iter<'a, cs_hppa_op>); ]
    cs_arch_op = cs_hppa_op;
    cs_arch = cs_hppa;
);
