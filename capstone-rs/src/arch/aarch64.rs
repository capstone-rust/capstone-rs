//! Contains aarch64-specific types

pub use crate::arch::arch_builder::aarch64::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{AccessType, RegId, RegIdInt};
use capstone_sys::{
    aarch64_imm_range, aarch64_op_mem, aarch64_op_pred, aarch64_op_sme, aarch64_op_type,
    aarch64_sme_op_type, aarch64_sysop, cs_aarch64, cs_aarch64_op, cs_ac_type,
};
use core::convert::{From, TryInto};
use core::{cmp, fmt, slice};
use core::ffi::c_uint;

// Re-exports
pub use capstone_sys::aarch64_at as AArch64At;
pub use capstone_sys::aarch64_bti as AArch64Bti;
pub use capstone_sys::aarch64_db as AArch64Db;
pub use capstone_sys::aarch64_dbnxs as AArch64Dbnxs;
pub use capstone_sys::aarch64_dc as AArch64Dc;
pub use capstone_sys::aarch64_exactfpimm as AArch64ExactFpImm;
pub use capstone_sys::aarch64_extender as AArch64Extender;
pub use capstone_sys::aarch64_ic as AArch64Ic;
pub use capstone_sys::aarch64_insn as AArch64Insn;
pub use capstone_sys::aarch64_insn_group as AArch64InsnGroup;
pub use capstone_sys::aarch64_isb as AArch64Isb;
pub use capstone_sys::aarch64_prfm as AArch64Prfm;
pub use capstone_sys::aarch64_psb as AArch64Psb;
pub use capstone_sys::aarch64_pstateimm0_1 as AArch64PStateImm01;
pub use capstone_sys::aarch64_pstateimm0_15 as AArch64PStateImm015;
pub use capstone_sys::aarch64_reg as AArch64Reg;
pub use capstone_sys::aarch64_rprfm as AArch64RPrfm;
pub use capstone_sys::aarch64_svcr as AArch64Svcr;
pub use capstone_sys::aarch64_svepredpat as AArch64SvePredPat;
pub use capstone_sys::aarch64_sveprfm as AArch64SvePrfm;
pub use capstone_sys::aarch64_sveveclenspecifier as AArch64SveVecLenSpecifier;
pub use capstone_sys::aarch64_sysreg as AArch64Sysreg;
pub use capstone_sys::aarch64_tlbi as AArch64Tlbi;
pub use capstone_sys::aarch64_tsb as AArch64Tsb;
pub use capstone_sys::AArch64CondCode as AArch64CC;
pub use capstone_sys::AArch64Layout_VectorLayout as AArch64Vas;

use capstone_sys::aarch64_shifter;
use capstone_sys::cs_aarch64_op__bindgen_ty_2;

/// Contains AARCH64-specific details for an instruction
pub struct AArch64InsnDetail<'a>(pub(crate) &'a cs_aarch64);

/// AARCH64 shift amount
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AArch64Shift {
    Invalid,

    /// Logical shift left
    Lsl(u32),

    /// Masking shift left
    Msl(u32),

    /// Logical shift right
    Lsr(u32),

    /// Arithmetic shift right
    Asr(u32),

    /// Rotate right
    Ror(u32),

    /// Logical shift left
    LslReg(RegId),

    /// Masking shift left
    MslReg(RegId),

    /// Logical shift right
    LsrReg(RegId),

    /// Arithmetic shift right
    AsrReg(RegId),

    /// Rotate right
    RorReg(RegId),
}

impl AArch64OperandType {
    fn new(
        op_type: aarch64_op_type,
        value: cs_aarch64_op__bindgen_ty_2,
        op_sys: aarch64_sysop,
    ) -> AArch64OperandType {
        use self::aarch64_op_type::*;
        use self::AArch64OperandType::*;

        match op_type {
            AARCH64_OP_INVALID => Invalid,
            AARCH64_OP_REG => Reg(RegId(unsafe { value.reg } as RegIdInt)),
            AARCH64_OP_IMM => Imm(unsafe { value.imm }),
            AARCH64_OP_MEM_REG => MemReg(AArch64OpMem(unsafe { value.mem })),
            AARCH64_OP_MEM_IMM => MemImm(AArch64OpMem(unsafe { value.mem })),
            AARCH64_OP_MEM => Mem(AArch64OpMem(unsafe { value.mem })),
            AARCH64_OP_FP => Fp(unsafe { value.fp }),
            AARCH64_OP_CIMM => Cimm(unsafe { value.imm }),
            AARCH64_OP_IMPLICIT_IMM_0 => ImplicitImm0(unsafe { value.imm }),
            AARCH64_OP_SME => Sme(AArch64OpSme(unsafe { value.sme })),
            AARCH64_OP_IMM_RANGE => ImmRange(AArch64ImmRange(unsafe { value.imm_range })),
            AARCH64_OP_SYSREG => match op_sys.sub_type {
                AARCH64_OP_REG_MRS => RegMrs(unsafe { op_sys.reg.sysreg }),
                AARCH64_OP_REG_MSR => RegMsr(unsafe { op_sys.reg.sysreg }),
                AARCH64_OP_SYSREG => Sysreg(unsafe { op_sys.reg.sysreg }),
                AARCH64_OP_TLBI => Tlbi(unsafe { op_sys.reg.tlbi }),
                AARCH64_OP_IC => Ic(unsafe { op_sys.reg.ic }),
                _ => Invalid,
            },
            AARCH64_OP_SYSIMM => match op_sys.sub_type {
                AARCH64_OP_DBNXS => Dbnxs(unsafe { op_sys.imm.dbnxs }),
                AARCH64_OP_EXACTFPIMM => ExactFpImm(unsafe { op_sys.imm.exactfpimm }),
                _ => Invalid,
            },
            AARCH64_OP_SYSALIAS => match op_sys.sub_type {
                AARCH64_OP_SVCR => Svcr(unsafe { op_sys.alias.svcr }),
                AARCH64_OP_AT => At(unsafe { op_sys.alias.at }),
                AARCH64_OP_DB => Db(unsafe { op_sys.alias.db }),
                AARCH64_OP_DC => Dc(unsafe { op_sys.alias.dc }),
                AARCH64_OP_ISB => Isb(unsafe { op_sys.alias.isb }),
                AARCH64_OP_TSB => Tsb(unsafe { op_sys.alias.tsb }),
                AARCH64_OP_PRFM => Prfm(unsafe { op_sys.alias.prfm }),
                AARCH64_OP_SVEPRFM => SvePrfm(unsafe { op_sys.alias.sveprfm }),
                AARCH64_OP_RPRFM => RPrfm(unsafe { op_sys.alias.rprfm }),
                AARCH64_OP_PSTATEIMM0_15 => PStateImm015(unsafe { op_sys.alias.pstateimm0_15 }),
                AARCH64_OP_PSTATEIMM0_1 => PStateImm01(unsafe { op_sys.alias.pstateimm0_1 }),
                AARCH64_OP_PSB => Psb(unsafe { op_sys.alias.psb }),
                AARCH64_OP_BTI => Bti(unsafe { op_sys.alias.bti }),
                AARCH64_OP_SVEPREDPAT => SvePredPat(unsafe { op_sys.alias.svepredpat }),
                AARCH64_OP_SVEVECLENSPECIFIER => {
                    SveVecLenSpecifier(unsafe { op_sys.alias.sveveclenspecifier })
                }
                _ => Invalid,
            },
            AARCH64_OP_PRED => Pred(AArch64OpPred(unsafe { value.pred })),
            _ => Invalid,
        }
    }
}

/// AARCH64 operand
#[derive(Clone, Debug, PartialEq)]
pub struct AArch64Operand {
    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<AccessType>,

    /// Vector Index for some vector operands
    pub vector_index: Option<u32>,

    /// Vector arrangement specifier (for FloatingPoint/Advanced SIMD insn)
    pub vas: AArch64Vas,

    /// Shifter of this operand
    pub shift: AArch64Shift,

    /// Extender type of this operand
    pub ext: AArch64Extender,

    /// Operand type
    pub op_type: AArch64OperandType,
}

/// AARCH64 operand
#[derive(Clone, Debug, PartialEq)]
pub enum AArch64OperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Register which references memory
    MemReg(AArch64OpMem),

    /// Immediate value which references memory
    MemImm(AArch64OpMem),

    /// Memory
    Mem(AArch64OpMem),

    /// Floating point
    Fp(f64),

    /// C-IMM
    Cimm(i64),

    /// System register MRS (move the contents of a PSR to a general-purpose register)
    RegMrs(AArch64Sysreg),

    /// System register MSR (move to system coprocessor register from ARM register)
    RegMsr(AArch64Sysreg),

    /// Implicit immediate operand 0
    ImplicitImm0(i64),

    /// SMSTART/SMSTOP mode (Streaming SVE & ZA storage)
    Svcr(AArch64Svcr),

    /// Address translate operand
    At(AArch64At),

    /// Data barrier operand
    Db(AArch64Db),

    /// Data cache operand
    Dc(AArch64Dc),

    /// Instruction synchronization barrier operand
    Isb(AArch64Isb),

    /// Trace synchronization barrier operand
    Tsb(AArch64Tsb),

    /// Prefetch operand
    Prfm(AArch64Prfm),

    /// SVE prefetch operand
    SvePrfm(AArch64SvePrfm),

    /// Range prefetch operand
    RPrfm(AArch64RPrfm),

    /// PState field operand
    PStateImm015(AArch64PStateImm015),

    /// PState field operand
    PStateImm01(AArch64PStateImm01),

    /// Profiling synchronization barrier operand
    Psb(AArch64Psb),

    /// Branch target identification operand
    Bti(AArch64Bti),

    /// SVE predication pattern operand
    SvePredPat(AArch64SvePredPat),

    /// SVE vector length specifier
    SveVecLenSpecifier(AArch64SveVecLenSpecifier),

    /// SME operand
    Sme(AArch64OpSme),

    /// Immediate range
    ImmRange(AArch64ImmRange),

    /// TLB invalidate operand
    Tlbi(AArch64Tlbi),

    /// Instruction cache operand
    Ic(AArch64Ic),

    /// Synchronization instructions operand
    Dbnxs(AArch64Dbnxs),

    /// Exact floating point immediate operand
    ExactFpImm(AArch64ExactFpImm),

    /// System register
    Sysreg(AArch64Sysreg),

    /// Predicate operand
    Pred(AArch64OpPred),

    /// Invalid
    Invalid,
}

impl AArch64InsnDetail<'_> {
    /// Condition codes
    pub fn cc(&self) -> AArch64CC {
        self.0.cc
    }

    /// Whether this insn updates flags
    pub fn update_flags(&self) -> bool {
        self.0.update_flags
    }
}

impl_PartialEq_repr_fields!(AArch64InsnDetail<'a> [ 'a ];
    cc, update_flags, operands
);

/// AARCH64 memory operand
#[derive(Debug, Copy, Clone)]
pub struct AArch64OpMem(pub(crate) aarch64_op_mem);

impl AArch64OpMem {
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
        self.0.disp as i32
    }
}

impl_PartialEq_repr_fields!(AArch64OpMem;
    base, index, disp
);

impl cmp::Eq for AArch64OpMem {}

/// AARCH64 memory operand
#[derive(Debug, Copy, Clone)]
pub struct AArch64OpPred(pub(crate) aarch64_op_pred);

impl AArch64OpPred {
    /// Vector predicate register
    pub fn reg(&self) -> RegId {
        RegId(self.0.reg as RegIdInt)
    }

    /// Vector select register
    pub fn vec_select(&self) -> RegId {
        RegId(self.0.vec_select as RegIdInt)
    }

    /// Index in range 0 to one less of vector elements in a 128bit reg
    pub fn imm_index(&self) -> i32 {
        self.0.imm_index as i32
    }
}

impl_PartialEq_repr_fields!(AArch64OpPred;
    reg, vec_select, imm_index
);

impl Default for AArch64Operand {
    fn default() -> Self {
        AArch64Operand {
            access: None,
            vector_index: None,
            vas: AArch64Vas::AARCH64LAYOUT_INVALID,
            shift: AArch64Shift::Invalid,
            ext: AArch64Extender::AARCH64_EXT_INVALID,
            op_type: AArch64OperandType::Invalid,
        }
    }
}

impl cmp::Eq for AArch64OpPred {}

/// AARCH64 memory operand
#[derive(Debug, Copy, Clone)]
pub struct AArch64ImmRange(pub(crate) aarch64_imm_range);

impl AArch64ImmRange {
    /// First immediate in range
    pub fn first(&self) -> u8 {
        self.0.first
    }

    /// Immediate offset
    pub fn offset(&self) -> u8 {
        self.0.offset
    }
}

impl_PartialEq_repr_fields!(AArch64ImmRange;
    first, offset
);

impl cmp::Eq for AArch64ImmRange {}

/// AARCH64 slice offset of sme operand
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AArch64OpSmeSliceOffset {
    Imm(u16),
    ImmRange(AArch64ImmRange),
}

/// AARCH64 sme operand
#[derive(Debug, Copy, Clone)]
pub struct AArch64OpSme(pub(crate) aarch64_op_sme);

impl AArch64OpSme {
    /// Operand type
    pub fn type_(&self) -> aarch64_sme_op_type {
        self.0.type_
    }

    /// Tile register
    pub fn tile(&self) -> RegId {
        RegId(self.0.tile as RegIdInt)
    }

    /// Slice index register
    pub fn slice_reg(&self) -> RegId {
        RegId(self.0.slice_reg as RegIdInt)
    }

    /// Slice index offset
    pub fn slice_offset(&self) -> AArch64OpSmeSliceOffset {
        if self.0.has_range_offset {
            // imm range
            AArch64OpSmeSliceOffset::ImmRange(AArch64ImmRange(unsafe {
                self.0.slice_offset.imm_range
            }))
        } else {
            AArch64OpSmeSliceOffset::Imm(unsafe { self.0.slice_offset.imm })
        }
    }

    /// Is vertical or horizontal
    pub fn is_vertical(&self) -> bool {
        self.0.is_vertical
    }
}

impl_PartialEq_repr_fields!(AArch64OpSme;
    type_, tile, slice_reg, slice_offset, is_vertical
);

impl cmp::Eq for AArch64OpSme {}

impl AArch64Shift {
    fn new(type_: aarch64_shifter, value: c_uint) -> AArch64Shift {
        use self::aarch64_shifter::*;
        use self::AArch64Shift::*;

        macro_rules! aarch64_shift_match {
            (
                imm = [ $( $imm_r_enum:ident = $imm_c_enum:ident, )* ]
                reg = [ $( $reg_r_enum:ident = $reg_c_enum:ident, )* ]
            ) => {
                match type_ {
                    AARCH64_SFT_INVALID => Invalid,

                    $(
                        $imm_c_enum => $imm_r_enum(value as u32) ,
                    )*
                    $(
                        $reg_c_enum => $reg_r_enum(RegId(value as RegIdInt)) ,
                    )*
                }
            }
        }

        aarch64_shift_match!(
            imm = [
                Asr = AARCH64_SFT_ASR, Lsl = AARCH64_SFT_LSL, Lsr = AARCH64_SFT_LSR,
                Ror = AARCH64_SFT_ROR, Msl = AARCH64_SFT_MSL,
            ]
            reg = [
                AsrReg = AARCH64_SFT_ASR_REG, LslReg = AARCH64_SFT_LSL_REG, LsrReg = AARCH64_SFT_LSR_REG,
                RorReg = AARCH64_SFT_ROR_REG, MslReg = AARCH64_SFT_MSL_REG,
            ]
        )
    }
}

impl From<&cs_aarch64_op> for AArch64Operand {
    fn from(op: &cs_aarch64_op) -> AArch64Operand {
        let shift = AArch64Shift::new(op.shift.type_, op.shift.value);
        let op_type = AArch64OperandType::new(op.type_, op.__bindgen_anon_1, op.sysop);
        let vector_index = if op.vector_index >= 0 {
            Some(op.vector_index as u32)
        } else {
            None
        };
        AArch64Operand {
            access: cs_ac_type(op.access as _).try_into().ok(),
            vector_index,
            vas: op.vas,
            shift,
            ext: op.ext,
            op_type,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = AArch64InsnDetail;
    Operand = AArch64Operand;
    OperandIterator = AArch64OperandIterator;
    OperandIteratorLife = AArch64OperandIterator<'a>;
    [ pub struct AArch64OperandIterator<'a>(slice::Iter<'a, cs_aarch64_op>); ]
    cs_arch_op = cs_aarch64_op;
    cs_arch = cs_aarch64;
);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_aarch64shift() {
        use super::aarch64_shifter::*;
        use super::AArch64Shift::*;
        use core::ffi::c_uint;

        fn t(shift_type_value: (aarch64_shifter, c_uint), aarch64_shift: AArch64Shift) {
            let (shift_type, value) = shift_type_value;
            assert_eq!(aarch64_shift, AArch64Shift::new(shift_type, value));
        }

        t((AARCH64_SFT_INVALID, 0), Invalid);
        t((AARCH64_SFT_ASR, 0), Asr(0));
    }

    #[test]
    fn test_aarch64_op_type() {
        use super::aarch64_op_type::*;
        use super::AArch64OperandType::*;
        use super::AArch64Sysreg::*;
        use capstone_sys::aarch64_reg::*;
        use capstone_sys::*;

        fn t(
            op_type_value: (aarch64_op_type, cs_aarch64_op__bindgen_ty_2, aarch64_sysop),
            expected_op_type: AArch64OperandType,
        ) {
            let (op_type, op_value, op_sys) = op_type_value;
            let op_type = AArch64OperandType::new(op_type, op_value, op_sys);
            assert_eq!(expected_op_type, op_type);
        }

        let null_sysop = aarch64_sysop {
            reg: aarch64_sysop_reg {
                sysreg: AARCH64_SYSREG_INVALID,
            },
            imm: aarch64_sysop_imm { raw_val: 0 },
            alias: aarch64_sysop_alias { raw_val: 0 },
            sub_type: aarch64_op_type::AARCH64_OP_INVALID,
        };

        t(
            (
                AARCH64_OP_INVALID,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                null_sysop,
            ),
            Invalid,
        );
        t(
            (
                AARCH64_OP_REG,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                null_sysop,
            ),
            Reg(RegId(0)),
        );
        t(
            (
                AARCH64_OP_IMM,
                cs_aarch64_op__bindgen_ty_2 { imm: 42 },
                null_sysop,
            ),
            Imm(42),
        );
        t(
            (
                AARCH64_OP_SYSREG,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                aarch64_sysop {
                    reg: aarch64_sysop_reg {
                        sysreg: AARCH64_SYSREG_MDRAR_EL1,
                    },
                    sub_type: AARCH64_OP_REG_MRS,
                    ..null_sysop
                },
            ),
            RegMrs(AARCH64_SYSREG_MDRAR_EL1),
        );
        t(
            (
                AARCH64_OP_SYSALIAS,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                aarch64_sysop {
                    alias: aarch64_sysop_alias {
                        pstateimm0_15: aarch64_pstateimm0_15::AARCH64_PSTATEIMM0_15_SPSEL,
                    },
                    sub_type: AARCH64_OP_PSTATEIMM0_15,
                    ..null_sysop
                },
            ),
            PStateImm015(aarch64_pstateimm0_15::AARCH64_PSTATEIMM0_15_SPSEL),
        );
        t(
            (
                AARCH64_OP_FP,
                cs_aarch64_op__bindgen_ty_2 { fp: 0.0 },
                null_sysop,
            ),
            Fp(0.0),
        );
        t(
            (
                AARCH64_OP_CIMM,
                cs_aarch64_op__bindgen_ty_2 { imm: 42 },
                null_sysop,
            ),
            Cimm(42),
        );
        t(
            (
                AARCH64_OP_SYSREG,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                aarch64_sysop {
                    reg: aarch64_sysop_reg {
                        sysreg: AARCH64_SYSREG_ICC_EOIR1_EL1,
                    },
                    sub_type: AARCH64_OP_REG_MSR,
                    ..null_sysop
                },
            ),
            RegMsr(AARCH64_SYSREG_ICC_EOIR1_EL1),
        );
        t(
            (
                AARCH64_OP_SYSALIAS,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                aarch64_sysop {
                    alias: aarch64_sysop_alias {
                        at: aarch64_at::AARCH64_AT_S1E0R,
                    },
                    sub_type: AARCH64_OP_AT,
                    ..null_sysop
                },
            ),
            At(aarch64_at::AARCH64_AT_S1E0R),
        );
        t(
            (
                AARCH64_OP_SYSALIAS,
                cs_aarch64_op__bindgen_ty_2 { reg: 0 },
                aarch64_sysop {
                    alias: aarch64_sysop_alias {
                        prfm: aarch64_prfm::AARCH64_PRFM_PLDL2KEEP,
                    },
                    sub_type: AARCH64_OP_PRFM,
                    ..null_sysop
                },
            ),
            Prfm(aarch64_prfm::AARCH64_PRFM_PLDL2KEEP),
        );
        t(
            (
                AARCH64_OP_SME,
                cs_aarch64_op__bindgen_ty_2 {
                    sme: aarch64_op_sme {
                        type_: capstone_sys::aarch64_sme_op_type::AARCH64_SME_OP_TILE_VEC,
                        tile: AARCH64_REG_ZA as aarch64_reg::Type,
                        slice_reg: AARCH64_REG_W12 as aarch64_reg::Type,
                        slice_offset: aarch64_op_sme__bindgen_ty_1 { imm: 4 },
                        has_range_offset: false,
                        is_vertical: false,
                    },
                },
                null_sysop,
            ),
            Sme(AArch64OpSme(aarch64_op_sme {
                type_: capstone_sys::aarch64_sme_op_type::AARCH64_SME_OP_TILE_VEC,
                tile: AARCH64_REG_ZA as aarch64_reg::Type,
                slice_reg: AARCH64_REG_W12 as aarch64_reg::Type,
                slice_offset: aarch64_op_sme__bindgen_ty_1 { imm: 4 },
                has_range_offset: false,
                is_vertical: false,
            })),
        );
    }
}
