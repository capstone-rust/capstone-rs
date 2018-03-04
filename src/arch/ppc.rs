//! Contains ppc-specific types

pub use arch::arch_builder::ppc::*;
use arch::DetailsArch;
use capstone_sys::{cs_ppc, cs_ppc_op, ppc_op_mem, ppc_op_type};
use instruction::{RegId, RegIdInt};
use std::convert::From;
use std::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::ppc_insn_group as PpcInsnGroup;
pub use capstone_sys::ppc_insn as PpcInsn;
pub use capstone_sys::ppc_reg as PpcReg;
pub use capstone_sys::ppc_bc as PpcBc;
pub use capstone_sys::ppc_bh as PpcBh;
use capstone_sys::ppc_op_crx;

/// Contains PPC-specific details for an instruction
pub struct PpcInsnDetail<'a>(pub(crate) &'a cs_ppc);

impl<'a> PpcInsnDetail<'a> {
    /// Branch code for branch instructions
    pub fn bc(&self) -> PpcBc {
        self.0.bc
    }

    /// Branch hint for branch instructions
    pub fn bh(&self) -> PpcBh {
        self.0.bh
    }

    /// Whether this 'dot' insn updates CR0
    pub fn update_cr0(&self) -> PpcBh {
        self.0.bh
    }
}

impl_Representative!(PpcInsnDetail<'a> [ 'a ];
    bc: PpcBc, bh: PpcBh, update_cr0: PpcBh, operands: PpcOperandIterator<'a>
);
impl_repr_PartialEq!(PpcInsnDetail<'a> [ 'a ]);

/// PPC operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PpcOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Memory
    Mem(PpcOpMem),

    /// Condition Register field
    Crx(PpcOpCrx),

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

impl_Representative!(PpcOpMem; base: RegId, disp: i32);
impl_repr_PartialEq!(PpcOpMem);

impl cmp::Eq for PpcOpMem {}

/// PPC condition register field
#[derive(Debug, Copy, Clone)]
pub struct PpcOpCrx(pub(crate) ppc_op_crx);

impl PpcOpCrx {
    /// Scale
    pub fn scale(&self) -> u32 {
        self.0.scale as u32
    }

    /// Register value
    pub fn reg(&self) -> RegId {
        RegId(self.0.reg as RegIdInt)
    }

    /// Condition value
    pub fn cond(&self) -> PpcBc {
        self.0.cond
    }
}

impl cmp::PartialEq for PpcOpCrx {
    fn eq(&self, other: &Self) -> bool {
        (self.scale(), self.reg(), self.cond()) == (other.scale(), other.reg(), other.cond())
    }
}

impl cmp::Eq for PpcOpCrx {}

impl<'a> From<&'a cs_ppc_op> for PpcOperand {
    fn from(insn: &cs_ppc_op) -> PpcOperand {
        match insn.type_ {
            ppc_op_type::PPC_OP_REG => {
                PpcOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            ppc_op_type::PPC_OP_IMM => PpcOperand::Imm(unsafe { insn.__bindgen_anon_1.imm }),
            ppc_op_type::PPC_OP_MEM => {
                PpcOperand::Mem(PpcOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            ppc_op_type::PPC_OP_CRX => {
                PpcOperand::Crx(PpcOpCrx(unsafe { insn.__bindgen_anon_1.crx }))
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
    use super::*;

    #[test]
    fn test_ppc_op_type() {
        use capstone_sys::*;
        use super::ppc_op_type::*;
        use super::PpcReg::*;
        use self::PpcOperand::*;

        fn t(
            op: (ppc_op_type, cs_ppc_op__bindgen_ty_1),
            expected_op: PpcOperand,
        ) {
            let op = PpcOperand::from(&cs_ppc_op {
                type_: op.0,
                __bindgen_anon_1: op.1
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
        t(
            (PPC_OP_IMM, cs_ppc_op__bindgen_ty_1 { imm: 42 }),
            Imm(42),
        );

        let op_mem = PpcOperand::from(&cs_ppc_op {
            type_: PPC_OP_MEM,
            __bindgen_anon_1: cs_ppc_op__bindgen_ty_1 { mem: ppc_op_mem {
                base: PPC_REG_VS38,
                disp: -10 }}
        });
        if let Mem(op_mem) = op_mem {
            assert_eq!(
                (op_mem.base(), op_mem.disp()),
                (RegId(PPC_REG_VS38 as RegIdInt), -10)
            );
        } else {
            panic!("Did not get expected Mem");
        }
    }
}
