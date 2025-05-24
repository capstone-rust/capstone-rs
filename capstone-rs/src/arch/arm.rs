//! Contains arm-specific types

use core::convert::{From, TryInto};
use core::ffi::c_uint;
use core::{cmp, fmt, slice};

use capstone_sys::{
    arm_op_mem, arm_op_type, arm_shifter, cs_ac_type, cs_arm, cs_arm_op, cs_arm_op__bindgen_ty_2,
};

pub use crate::arch::arch_builder::arm::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};
use crate::AccessType;

pub use capstone_sys::arm_bankedreg as ArmBankedReg;
pub use capstone_sys::arm_cpsflag_type as ArmCPSFlag;
pub use capstone_sys::arm_cpsmode_type as ArmCPSMode;
pub use capstone_sys::arm_insn as ArmInsn;
pub use capstone_sys::arm_insn_group as ArmInsnGroup;
pub use capstone_sys::arm_mem_bo_opt as ArmMemBarrier;
pub use capstone_sys::arm_reg as ArmReg;
pub use capstone_sys::arm_setend_type as ArmSetendType;
pub use capstone_sys::arm_spsr_cspr_bits;
pub use capstone_sys::arm_sysreg as ArmSysreg;
pub use capstone_sys::arm_vectordata_type as ArmVectorData;
// Upstream typo: cspr -> cpsr
pub use capstone_sys::arm_spsr_cspr_bits as ArmSpsrCpsrBits;
pub use capstone_sys::ARMCC_CondCodes as ArmCC;

/// Contains ARM-specific details for an instruction
pub struct ArmInsnDetail<'a>(pub(crate) &'a cs_arm);

/// ARM shift amount
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ArmShift {
    Invalid,

    /// Arithmetic shift right (immediate)
    Asr(u32),

    /// Logical shift left (immediate)
    Lsl(u32),

    /// Logical shift right (immediate)
    Lsr(u32),

    /// Rotate right (immediate)
    Ror(u32),

    /// Rotate right with extend (immediate)
    Rrx(u32),

    /// Left shift with unsigned extension (immediate)
    Uxtw(u32),

    /// Shift by register
    Reg(RegId),

    /// Arithmetic shift right (register)
    AsrReg(RegId),

    /// Logical shift left (register)
    LslReg(RegId),

    /// Logical shift right (register)
    LsrReg(RegId),

    /// Rotate right (register)
    RorReg(RegId),
}

impl ArmShift {
    fn new(type_: arm_shifter, value: c_uint) -> ArmShift {
        use self::arm_shifter::*;
        use self::ArmShift::*;

        macro_rules! arm_shift_match {
            (
                imm = [ $( $imm_r_enum:ident = $imm_c_enum:ident, )* ]
                reg = [ $( $reg_r_enum:ident = $reg_c_enum:ident, )* ]
            ) => {
                match type_ {
                    ARM_SFT_INVALID => Invalid,

                    $(
                        $imm_c_enum => $imm_r_enum(value as u32) ,
                    )*
                    $(
                        $reg_c_enum => $reg_r_enum(RegId(value as RegIdInt)) ,
                    )*
                }
            }
        }

        arm_shift_match!(
            imm = [
                Asr = ARM_SFT_ASR, Lsl = ARM_SFT_LSL, Lsr = ARM_SFT_LSR,
                Ror = ARM_SFT_ROR, Rrx = ARM_SFT_RRX, Uxtw = ARM_SFT_UXTW,
            ]
            reg = [
                AsrReg = ARM_SFT_ASR_REG, LslReg = ARM_SFT_LSL_REG, LsrReg = ARM_SFT_LSR_REG,
                RorReg = ARM_SFT_ROR_REG, Reg = ARM_SFT_REG,
            ]
        )
    }
}

impl ArmOperandType {
    fn new(op_type: arm_op_type, value: cs_arm_op__bindgen_ty_2) -> ArmOperandType {
        use self::arm_op_type::*;
        use self::ArmOperandType::*;

        match op_type {
            ARM_OP_INVALID => Invalid,
            ARM_OP_REG => Reg(RegId(unsafe { value.reg } as RegIdInt)),
            ARM_OP_IMM => Imm(unsafe { value.imm }),
            ARM_OP_FP => Fp(unsafe { value.fp }),
            ARM_OP_PRED => Pred(unsafe { value.pred } as i32),
            ARM_OP_CIMM => Cimm(unsafe { value.imm }),
            ARM_OP_PIMM => Pimm(unsafe { value.imm }),
            ARM_OP_SETEND => Setend(unsafe { value.setend }),
            ARM_OP_SYSREG => SysReg(unsafe { value.sysop.reg.mclasssysreg }),
            ARM_OP_BANKEDREG => BankedReg(unsafe { value.sysop.reg.bankedreg }),
            ARM_OP_SPSR => Spsr(unsafe { value.sysop.psr_bits }),
            ARM_OP_CPSR => Cpsr(unsafe { value.sysop.psr_bits }),
            ARM_OP_SYSM => Sysm(unsafe { value.sysop.sysm }),
            ARM_OP_MEM => Mem(ArmOpMem(unsafe { value.mem })),
            _ => Invalid,
        }
    }
}

/// ARM operand
#[derive(Clone, Debug, PartialEq)]
pub struct ArmOperand {
    /// Vector Index for some vector operands
    pub vector_index: Option<u32>,

    /// Whether operand is subtracted
    pub subtracted: bool,

    pub shift: ArmShift,

    /// Operand type
    pub op_type: ArmOperandType,

    /// How is this operand accessed?
    ///
    /// NOTE: this field is always `None` if the "full" feataure is not enabled.
    pub access: Option<AccessType>,
}

/// ARM operand
#[derive(Clone, Debug, PartialEq)]
pub enum ArmOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Floating point
    Fp(f64),

    /// Predicate operand value
    Pred(i32),

    /// C-IMM
    Cimm(i64),

    /// P-IMM
    Pimm(i64),

    /// SETEND instruction endianness
    Setend(ArmSetendType),

    /// Sysreg
    SysReg(ArmSysreg),

    /// Banked register operand
    BankedReg(ArmBankedReg),

    /// Collection of SPSR bits
    Spsr(ArmSpsrCpsrBits),

    /// Collection of CPSR bits
    Cpsr(ArmSpsrCpsrBits),

    /// Raw SYSm field
    Sysm(u16),

    /// Vector predicate that leaves inactive lanes unchanged
    VPredR(RegId),

    /// Vector predicate that does not preserve inactive lanes
    VPredN(RegId),

    /// Memory
    Mem(ArmOpMem),

    /// Invalid
    Invalid,
}

/// ARM memory operand
#[derive(Debug, Copy, Clone)]
pub struct ArmOpMem(pub(crate) arm_op_mem);

impl ArmInsnDetail<'_> {
    /// Whether the instruction is a user mode
    pub fn usermode(&self) -> bool {
        self.0.usermode
    }

    /// Vector size
    pub fn vector_size(&self) -> i32 {
        self.0.vector_size as i32
    }

    /// Type of vector data
    pub fn vector_data(&self) -> ArmVectorData {
        self.0.vector_data
    }

    /// CPS mode for CPS instruction
    pub fn cps_mode(&self) -> ArmCPSMode {
        self.0.cps_mode
    }

    /// CPS flag for CPS instruction
    pub fn cps_flag(&self) -> ArmCPSFlag {
        self.0.cps_flag
    }

    /// Condition codes
    pub fn cc(&self) -> ArmCC {
        self.0.cc
    }

    /// Whether this insn updates flags
    pub fn update_flags(&self) -> bool {
        self.0.update_flags
    }

    /// Memory barrier
    pub fn mem_barrier(&self) -> ArmMemBarrier {
        self.0.mem_barrier
    }
}

impl_PartialEq_repr_fields!(ArmInsnDetail<'a> [ 'a ];
    usermode, vector_size, vector_data, cps_mode, cps_flag, cc, update_flags,
    mem_barrier, operands
);

impl ArmOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Index value
    pub fn index(&self) -> RegId {
        RegId(self.0.index as RegIdInt)
    }

    /// Scale for index register (can be 1, or -1)
    pub fn scale(&self) -> i32 {
        self.0.scale as i32
    }

    /// Disp value
    pub fn disp(&self) -> i32 {
        self.0.disp as i32
    }
}

impl_PartialEq_repr_fields!(ArmOpMem;
    base, index, scale, disp
);

impl cmp::Eq for ArmOpMem {}

impl Default for ArmOperand {
    fn default() -> Self {
        ArmOperand {
            vector_index: None,
            subtracted: false,
            shift: ArmShift::Invalid,
            op_type: ArmOperandType::Invalid,
            access: None,
        }
    }
}

impl From<&cs_arm_op> for ArmOperand {
    fn from(op: &cs_arm_op) -> ArmOperand {
        let shift = ArmShift::new(op.shift.type_, op.shift.value);
        let op_type = ArmOperandType::new(op.type_, op.__bindgen_anon_1);
        let vector_index = if op.vector_index >= 0 {
            Some(op.vector_index as u32)
        } else {
            None
        };
        ArmOperand {
            vector_index,
            shift,
            op_type,
            subtracted: op.subtracted,
            access: cs_ac_type(op.access as _).try_into().ok(),
        }
    }
}

def_arch_details_struct!(
    InsnDetail = ArmInsnDetail;
    Operand = ArmOperand;
    OperandIterator = ArmOperandIterator;
    OperandIteratorLife = ArmOperandIterator<'a>;
    [ pub struct ArmOperandIterator<'a>(slice::Iter<'a, cs_arm_op>); ]
    cs_arch_op = cs_arm_op;
    cs_arch = cs_arm;
);

#[cfg(test)]
mod test {
    use super::*;
    use capstone_sys::*;

    #[test]
    fn test_armshift() {
        use super::arm_shifter::*;
        use super::ArmShift::*;
        use core::ffi::c_uint;

        fn t(shift_type_value: (arm_shifter, c_uint), arm_shift: ArmShift) {
            let (shift_type, value) = shift_type_value;
            assert_eq!(arm_shift, ArmShift::new(shift_type, value));
        }

        t((ARM_SFT_INVALID, 0), Invalid);
        t((ARM_SFT_ASR, 0), Asr(0));
        t((ARM_SFT_ASR_REG, 42), AsrReg(RegId(42)));
    }

    #[test]
    fn test_arm_op_type() {
        use super::arm_op_type::*;
        use super::ArmOperandType::*;

        fn t(
            op_type_value: (arm_op_type, cs_arm_op__bindgen_ty_2),
            expected_op_type: ArmOperandType,
        ) {
            let (op_type, op_value) = op_type_value;
            let op_type = ArmOperandType::new(op_type, op_value);
            assert_eq!(expected_op_type, op_type);
        }

        t(
            (ARM_OP_INVALID, cs_arm_op__bindgen_ty_2 { reg: 0 }),
            Invalid,
        );
        t(
            (ARM_OP_REG, cs_arm_op__bindgen_ty_2 { reg: 0 }),
            Reg(RegId(0)),
        );
    }

    #[test]
    fn test_arm_insn_detail_eq() {
        let a1 = cs_arm {
            usermode: false,
            vector_size: 0,
            vector_data: arm_vectordata_type::ARM_VECTORDATA_INVALID,
            cps_mode: arm_cpsmode_type::ARM_CPSMODE_INVALID,
            cps_flag: arm_cpsflag_type::ARM_CPSFLAG_INVALID,
            cc: CondCodes::ARMCC_Invalid,
            update_flags: false,
            post_index: false,
            mem_barrier: MemBOpt::ARM_MB_RESERVED_0,
            op_count: 0,
            operands: [cs_arm_op {
                vector_index: 0,
                shift: cs_arm_op__bindgen_ty_1 {
                    type_: arm_shifter::ARM_SFT_INVALID,
                    value: 0,
                },
                type_: arm_op_type::ARM_OP_INVALID,
                __bindgen_anon_1: cs_arm_op__bindgen_ty_2 { imm: 0 },
                subtracted: false,
                access: 0,
                neon_lane: 0,
            }; 36],
            vcc: VPTCodes::ARMVCC_None,
            pred_mask: 0,
        };
        let a2 = cs_arm {
            usermode: true,
            ..a1
        };
        let a3 = cs_arm { op_count: 20, ..a1 };
        let a4 = cs_arm { op_count: 19, ..a1 };
        let a4_clone = a4;
        assert_eq!(ArmInsnDetail(&a1), ArmInsnDetail(&a1));
        assert_ne!(ArmInsnDetail(&a1), ArmInsnDetail(&a2));
        assert_ne!(ArmInsnDetail(&a1), ArmInsnDetail(&a3));
        assert_ne!(ArmInsnDetail(&a3), ArmInsnDetail(&a4));
        assert_eq!(ArmInsnDetail(&a4), ArmInsnDetail(&a4_clone));
    }
}
