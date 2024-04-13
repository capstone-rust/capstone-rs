//! Contains bpf specific types

use core::convert::From;
use core::{cmp, fmt, slice};

pub use capstone_sys::bpf_insn_group as BpfInsnGroup;
pub use capstone_sys::bpf_insn as BpfInsn;
pub use capstone_sys::bpf_reg as BpfReg;
use capstone_sys::{cs_bpf, cs_bpf_op, bpf_op_mem, bpf_op_type};

pub use crate::arch::arch_builder::bpf::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains BPF-specific details for an instruction
pub struct BpfInsnDetail<'a>(pub(crate) &'a cs_bpf);

impl_PartialEq_repr_fields!(BpfInsnDetail<'a> [ 'a ];
    operands
);

/// BPF operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BpfOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(u64),

    /// Memory
    Mem(BpfOpMem),

    /// Offset
    Off(u32),

    /// Mmem
    Mmem(u32),

    /// Msh
    Msh(u32),

    /// Ext
    Ext(u32),

    /// Invalid
    Invalid,
}

impl Default for BpfOperand {
    fn default() -> Self {
        BpfOperand::Invalid
    }
}


/// Bpf memory operand
#[derive(Debug, Copy, Clone)]
pub struct BpfOpMem(pub(crate) bpf_op_mem);

impl BpfOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Disp value
    pub fn disp(&self) -> u32 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(BpfOpMem;
    base, disp
);

impl cmp::Eq for BpfOpMem {}

impl<'a> From<&'a cs_bpf_op> for BpfOperand {
    fn from(insn: &cs_bpf_op) -> BpfOperand {
        match insn.type_ {
            bpf_op_type::BPF_OP_EXT => BpfOperand::Ext(unsafe { insn.__bindgen_anon_1.ext }),
            bpf_op_type::BPF_OP_INVALID => BpfOperand::Invalid,
            bpf_op_type::BPF_OP_REG => BpfOperand::Reg(RegId(unsafe {insn.__bindgen_anon_1.reg} as RegIdInt)),
            bpf_op_type::BPF_OP_IMM => BpfOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            bpf_op_type::BPF_OP_MEM => BpfOperand::Mem(BpfOpMem(unsafe { insn.__bindgen_anon_1.mem})),
            bpf_op_type::BPF_OP_OFF => BpfOperand::Off(unsafe { insn.__bindgen_anon_1.off }),
            bpf_op_type::BPF_OP_MMEM => BpfOperand::Mmem(unsafe { insn.__bindgen_anon_1.mmem }),
            bpf_op_type::BPF_OP_MSH => BpfOperand::Msh(unsafe { insn.__bindgen_anon_1.msh }),
        }
    }
}

def_arch_details_struct!(
    InsnDetail = BpfInsnDetail;
    Operand = BpfOperand;
    OperandIterator = BpfOperandIterator;
    OperandIteratorLife = BpfOperandIterator<'a>;
    [ pub struct BpfOperandIterator<'a>(slice::Iter<'a, cs_bpf_op>); ]
    cs_arch_op = cs_bpf_op;
    cs_arch = cs_bpf;
);
