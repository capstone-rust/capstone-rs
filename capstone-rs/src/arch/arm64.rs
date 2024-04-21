//! Contains arm64-specific types

use libc::c_uint;

pub use crate::arch::arch_builder::arm64::*;
use crate::arch::DetailsArchInsn;
use capstone_sys::{arm64_op_mem, arm64_op_type, cs_arm64, cs_arm64_op};
use crate::instruction::{RegId, RegIdInt};
use core::convert::From;
use core::{cmp, fmt, mem, slice};

// Re-exports
pub use capstone_sys::arm64_insn_group as Arm64InsnGroup;
pub use capstone_sys::arm64_insn as Arm64Insn;
pub use capstone_sys::arm64_reg as Arm64Reg;
pub use capstone_sys::arm64_cc as Arm64CC;
pub use capstone_sys::arm64_extender as Arm64Extender;
pub use capstone_sys::arm64_vas as Arm64Vas;
pub use capstone_sys::arm64_pstate as Arm64Pstate;
pub use capstone_sys::arm64_prefetch_op as ArmPrefetchOp;
pub use capstone_sys::arm64_barrier_op as ArmBarrierOp;
pub use capstone_sys::arm64_sysreg as Arm64Sysreg;
pub use capstone_sys::arm64_sys_op as Arm64SysOp;
pub use capstone_sys::arm64_barrier_op as Arm64BarrierOp;

use capstone_sys::cs_arm64_op__bindgen_ty_2;
use capstone_sys::arm64_shifter;


/// Contains ARM64-specific details for an instruction
pub struct Arm64InsnDetail<'a>(pub(crate) &'a cs_arm64);

/// ARM64 shift amount
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Arm64Shift {
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
}

impl Arm64OperandType {
    fn new(op_type: arm64_op_type, value: cs_arm64_op__bindgen_ty_2) -> Arm64OperandType {
        use self::arm64_op_type::*;
        use self::Arm64OperandType::*;

        match op_type {
            ARM64_OP_INVALID => Invalid,
            ARM64_OP_REG => Reg(RegId(unsafe { value.reg } as RegIdInt)),
            ARM64_OP_IMM => Imm(unsafe { value.imm }),
            ARM64_OP_MEM => Mem(Arm64OpMem(unsafe { value.mem })),
            ARM64_OP_FP => Fp(unsafe { value.fp }),
            ARM64_OP_CIMM => Cimm(unsafe { value.imm }),
            ARM64_OP_REG_MRS => RegMrs(unsafe { mem::transmute(value.reg) }),
            ARM64_OP_REG_MSR => RegMsr(unsafe { mem::transmute(value.reg) }),
            ARM64_OP_PSTATE => Pstate(unsafe { value.pstate }),
            ARM64_OP_SYS => Sys(unsafe { value.sys }),
            ARM64_OP_PREFETCH => Prefetch(unsafe { value.prefetch }),
            ARM64_OP_BARRIER => Barrier(unsafe { value.barrier }),
        }
    }
}

/// ARM64 operand
#[derive(Clone, Debug, PartialEq)]
pub struct Arm64Operand {
    /// Vector Index for some vector operands
    pub vector_index: Option<u32>,

    /// Vector arrangement specifier (for FloatingPoint/Advanced SIMD insn)
    pub vas: Arm64Vas,

    /// Shifter of this operand
    pub shift: Arm64Shift,

    /// Extender type of this operand
    pub ext: Arm64Extender,

    /// Operand type
    pub op_type: Arm64OperandType,
}

/// ARM64 operand
#[derive(Clone, Debug, PartialEq)]
pub enum Arm64OperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(Arm64OpMem),

    /// Floating point
    Fp(f64),

    /// C-IMM
    Cimm(i64),

    /// System register MRS (move the contents of a PSR to a general-purpose register)
    RegMrs(Arm64Sysreg),

    /// System register MSR (move to system coprocessor register from ARM register)
    RegMsr(Arm64Sysreg),

    /// System PState Field (MSR instruction)
    Pstate(Arm64Pstate),

    /// System operation (IC/DC/AT/TLBI)
    Sys(Arm64SysOp),

    /// PRFM operation
    Prefetch(ArmPrefetchOp),

    /// Memory barrier operation (ISB/DMB/DSB instructions)
    Barrier(Arm64BarrierOp),

    /// Invalid
    Invalid,
}

/// ARM64 memory operand
#[derive(Debug, Copy, Clone)]
pub struct Arm64OpMem(pub(crate) arm64_op_mem);

impl<'a> Arm64InsnDetail<'a> {
    /// Condition codes
    pub fn cc(&self) -> Arm64CC {
        self.0.cc
    }

    /// Whether this insn updates flags
    pub fn update_flags(&self) -> bool {
        self.0.update_flags
    }

    /// Whether writeback is required
    pub fn writeback(&self) -> bool {
        self.0.writeback
    }
}

impl_PartialEq_repr_fields!(Arm64InsnDetail<'a> [ 'a ];
    cc, update_flags, writeback, operands
);

impl Arm64OpMem {
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

impl_PartialEq_repr_fields!(Arm64OpMem;
    base, index, disp
);

impl cmp::Eq for Arm64OpMem {}

impl Default for Arm64Operand {
    fn default() -> Self {
        Arm64Operand {
            vector_index: None,
            vas: Arm64Vas::ARM64_VAS_INVALID,
            shift: Arm64Shift::Invalid,
            ext: Arm64Extender::ARM64_EXT_INVALID,
            op_type: Arm64OperandType::Invalid
        }
    }
}

impl Arm64Shift {
    fn new(type_: arm64_shifter, value: c_uint) -> Arm64Shift {
        use self::arm64_shifter::*;
        use self::Arm64Shift::*;

        macro_rules! arm64_shift_match {
            (
                $( $imm_r_enum:ident = $imm_c_enum:ident, )*
            ) => {
                match type_ {
                    ARM64_SFT_INVALID => Invalid,

                    $(
                        $imm_c_enum => $imm_r_enum(value as u32) ,
                    )*
                }
            }
        }

        arm64_shift_match!(
            Lsl = ARM64_SFT_LSL,
            Msl = ARM64_SFT_MSL,
            Lsr = ARM64_SFT_LSR,
            Asr = ARM64_SFT_ASR,
            Ror = ARM64_SFT_ROR,
        )
    }
}

impl<'a> From<&'a cs_arm64_op> for Arm64Operand {
    fn from(op: &cs_arm64_op) -> Arm64Operand {
        let shift = Arm64Shift::new(op.shift.type_, op.shift.value);
        let op_type = Arm64OperandType::new(op.type_, op.__bindgen_anon_1);
        let vector_index = if op.vector_index >= 0 {
            Some(op.vector_index as u32)
        } else {
            None
        };
        Arm64Operand {
            vector_index,
            vas: op.vas,
            shift,
            ext: op.ext,
            op_type,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = Arm64InsnDetail;
    Operand = Arm64Operand;
    OperandIterator = Arm64OperandIterator;
    OperandIteratorLife = Arm64OperandIterator<'a>;
    [ pub struct Arm64OperandIterator<'a>(slice::Iter<'a, cs_arm64_op>); ]
    cs_arch_op = cs_arm64_op;
    cs_arch = cs_arm64;
);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_arm64shift() {
        use super::arm64_shifter::*;
        use super::Arm64Shift::*;
        use libc::c_uint;

        fn t(shift_type_value: (arm64_shifter, c_uint), arm64_shift: Arm64Shift) {
            let (shift_type, value) = shift_type_value;
            assert_eq!(arm64_shift, Arm64Shift::new(shift_type, value));
        }

        t((ARM64_SFT_INVALID, 0), Invalid);
        t((ARM64_SFT_ASR, 0), Asr(0));
    }

    #[test]
    fn test_arm64_op_type() {
        use super::arm64_op_type::*;
        use super::Arm64OperandType::*;
        use super::Arm64Sysreg::*;
        use capstone_sys::*;
        use capstone_sys::arm64_prefetch_op::*;
        use capstone_sys::arm64_pstate::*;

        fn t(
            op_type_value: (arm64_op_type, cs_arm64_op__bindgen_ty_2),
            expected_op_type: Arm64OperandType,
        ) {
            let (op_type, op_value) = op_type_value;
            let op_type = Arm64OperandType::new(op_type, op_value);
            assert_eq!(expected_op_type, op_type);
        }

        t(
            (ARM64_OP_INVALID, cs_arm64_op__bindgen_ty_2 { reg: 0 }),
            Invalid,
        );
        t(
            (ARM64_OP_REG, cs_arm64_op__bindgen_ty_2 { reg: 0 }),
            Reg(RegId(0)),
        );
        t(
            (ARM64_OP_IMM, cs_arm64_op__bindgen_ty_2 { imm: 42 }),
            Imm(42),
        );
        t(
            (ARM64_OP_REG_MRS, cs_arm64_op__bindgen_ty_2 { reg: ARM64_SYSREG_MDRAR_EL1 as arm64_reg::Type }),
            RegMrs(ARM64_SYSREG_MDRAR_EL1),
        );
        t(
            (ARM64_OP_PSTATE, cs_arm64_op__bindgen_ty_2 { pstate: ARM64_PSTATE_SPSEL }),
            Pstate(Arm64Pstate::ARM64_PSTATE_SPSEL),
        );
        t(
            (ARM64_OP_FP, cs_arm64_op__bindgen_ty_2 { fp: 0.0 }),
            Fp(0.0),
        );
        t(
            (ARM64_OP_CIMM, cs_arm64_op__bindgen_ty_2 { imm: 42 }),
            Cimm(42),
        );
        t(
            (ARM64_OP_REG_MSR, cs_arm64_op__bindgen_ty_2 {
                reg: arm64_sysreg::ARM64_SYSREG_ICC_EOIR1_EL1 as arm64_reg::Type }),
            RegMsr(arm64_sysreg::ARM64_SYSREG_ICC_EOIR1_EL1),
        );
        t(
            (ARM64_OP_SYS, cs_arm64_op__bindgen_ty_2 { sys: arm64_sys_op::ARM64_AT_S1E0R }),
            Sys(arm64_sys_op::ARM64_AT_S1E0R),
        );
        t(
            (ARM64_OP_PREFETCH, cs_arm64_op__bindgen_ty_2 {
                prefetch: ARM64_PRFM_PLDL2KEEP }),
            Prefetch(ARM64_PRFM_PLDL2KEEP),
        );
    }
}
