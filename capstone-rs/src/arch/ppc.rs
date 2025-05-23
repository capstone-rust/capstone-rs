//! Contains ppc-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::ppc_bh as PpcBh;
pub use capstone_sys::ppc_insn as PpcInsn;
pub use capstone_sys::ppc_insn_group as PpcInsnGroup;
pub use capstone_sys::ppc_reg as PpcReg;
use capstone_sys::{
    cs_ppc, cs_ppc_op, ppc_bc, ppc_bh, ppc_br_hint, ppc_cr_bit, ppc_op_mem, ppc_op_type, ppc_pred,
    ppc_reg,
};

pub use crate::arch::arch_builder::ppc::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};

/// Contains PPC-specific details for an instruction
pub struct PpcInsnDetail<'a>(pub(crate) &'a cs_ppc);

impl PpcInsnDetail<'_> {
    /// Branch code for branch instructions
    pub fn bc(&self) -> PpcBc {
        PpcBc(self.0.bc)
    }
}

impl_PartialEq_repr_fields!(PpcInsnDetail<'a> [ 'a ];
    bc, operands
);

pub struct PpcBc(pub(crate) ppc_bc);

impl PpcBc {
    /// BO field of branch condition
    pub fn bo(&self) -> u8 {
        self.0.bo
    }

    /// BI field of branch condition
    pub fn bi(&self) -> u8 {
        self.0.bi
    }

    /// CR field bit to test
    pub fn crx_bit(&self) -> ppc_cr_bit {
        self.0.crX_bit
    }

    /// CR field accessed
    pub fn crx(&self) -> ppc_reg::Type {
        self.0.crX
    }

    /// Branch hint
    pub fn hint(&self) -> ppc_br_hint {
        self.0.hint
    }

    /// CR-bit branch predicate
    pub fn pred_cr(&self) -> ppc_pred {
        self.0.pred_cr
    }

    /// CTR branch predicate
    pub fn pred_ctr(&self) -> ppc_pred {
        self.0.pred_ctr
    }

    /// BH field hint
    pub fn bh(&self) -> ppc_bh {
        self.0.bh
    }
}

impl_PartialEq_repr_fields!(PpcBc [ 'a ];
    bo, bi, crx_bit, crx, hint, pred_cr, pred_ctr, bh
);

/// PPC operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PpcOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(PpcOpMem),

    /// Invalid
    Invalid,
}

impl Default for PpcOperand {
    fn default() -> Self {
        PpcOperand::Invalid
    }
}

/// PPC memory operand
#[derive(Debug, Copy, Clone)]
pub struct PpcOpMem(pub(crate) ppc_op_mem);

impl PpcOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(PpcOpMem;
    base, disp
);

impl cmp::Eq for PpcOpMem {}

impl From<&cs_ppc_op> for PpcOperand {
    fn from(insn: &cs_ppc_op) -> PpcOperand {
        match insn.type_ {
            ppc_op_type::PPC_OP_REG => {
                PpcOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            ppc_op_type::PPC_OP_IMM => PpcOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            ppc_op_type::PPC_OP_MEM => {
                PpcOperand::Mem(PpcOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            ppc_op_type::PPC_OP_INVALID => PpcOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = PpcInsnDetail;
    Operand = PpcOperand;
    OperandIterator = PpcOperandIterator;
    OperandIteratorLife = PpcOperandIterator<'a>;
    [ pub struct PpcOperandIterator<'a>(slice::Iter<'a, cs_ppc_op>); ]
    cs_arch_op = cs_ppc_op;
    cs_arch = cs_ppc;
);

#[cfg(test)]
mod test {
    use capstone_sys::ppc_reg::{PPC_REG_R9};

    use super::*;

    #[test]
    fn test_ppc_op_type() {
        use self::PpcOperand::*;
        use super::ppc_op_type::*;
        use capstone_sys::*;

        fn t(op: (ppc_op_type, cs_ppc_op__bindgen_ty_1), expected_op: PpcOperand) {
            let op = PpcOperand::from(&cs_ppc_op {
                type_: op.0,
                __bindgen_anon_1: op.1,
                access: cs_ac_type::CS_AC_READ,
            });
            assert_eq!(expected_op, op);
        }

        t(
            (PPC_OP_INVALID, cs_ppc_op__bindgen_ty_1 { reg: 0 }),
            Invalid,
        );
        t(
            (PPC_OP_REG, cs_ppc_op__bindgen_ty_1 { reg: 0 }),
            Reg(RegId(0)),
        );
        t((PPC_OP_IMM, cs_ppc_op__bindgen_ty_1 { imm: 42 }), Imm(42));

        let op_mem = PpcOperand::from(&cs_ppc_op {
            type_: PPC_OP_MEM,
            __bindgen_anon_1: cs_ppc_op__bindgen_ty_1 {
                mem: ppc_op_mem {
                    base: PPC_REG_R9,
                    disp: -10,
                    offset: 0,
                },
            },
            access: cs_ac_type::CS_AC_READ,
        });
        if let Mem(op_mem) = op_mem {
            assert_eq!(
                (op_mem.base(), op_mem.disp()),
                (RegId(PPC_REG_R9 as RegIdInt), -10)
            );
        } else {
            panic!("Did not get expected Mem");
        }
    }
}
