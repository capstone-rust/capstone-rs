//! Contains tms320c64x-specific types

pub use arch::arch_builder::tms320c64x::*;
use capstone_sys::{
    cs_tms320c64x, cs_tms320c64x_op, tms320c64x_funit, tms320c64x_mem_dir, tms320c64x_mem_disp,
    tms320c64x_mem_mod, tms320c64x_op_mem, tms320c64x_op_type,
};
use instruction::{RegId, RegIdInt};
use libc::c_int;
use core::convert::From;
use core::{cmp, fmt, slice};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::tms320c64x_insn as Tms320c64xInsn;
pub use capstone_sys::tms320c64x_insn_group as Tms320c64xInsnGroup;
pub use capstone_sys::tms320c64x_reg as Tms320c64xReg;

/// Contains TMS320C64X-specific details for an instruction
pub struct Tms320c64xInsnDetail<'a>(pub(crate) &'a cs_tms320c64x);

define_cs_enum_wrapper_reverse!(
    [
        /// TMS320C64X Functional Unit
        => Tms320c64xFuntionalUnit = tms320c64x_funit,
    ]
    /// Invalid or unspecified
    => Invalid = TMS320C64X_FUNIT_INVALID;
    /// D
    => D = TMS320C64X_FUNIT_D;
    /// L
    => L = TMS320C64X_FUNIT_L;
    /// M
    => M = TMS320C64X_FUNIT_M;
    /// S
    => S = TMS320C64X_FUNIT_S;
    /// NO
    => No = TMS320C64X_FUNIT_NO;
);

impl<'a> Tms320c64xInsnDetail<'a> {
    /// Whether condition is zero
    pub fn is_condition_zero(&self) -> bool {
        self.0.condition.zero != 0
    }

    /// Condition register
    pub fn condition_reg(&self) -> RegId {
        RegId(self.0.condition.reg as RegIdInt)
    }

    /// Functional unit
    pub fn functional_unit(&self) -> Tms320c64xFuntionalUnit {
        Tms320c64xFuntionalUnit::from_u32(self.0.funit.unit)
            .unwrap_or(Tms320c64xFuntionalUnit::Invalid)
    }

    /// Functional unit side
    pub fn functional_unit_side(&self) -> u8 {
        self.0.funit.side as u8
    }

    /// Functional unit cross path
    pub fn functional_unit_cross_path(&self) -> i8 {
        // todo(tmfink): capstone bug where cs_tms320c64x.funit.crosspath is stored as unsigned
        // instead of signed
        self.0.funit.crosspath as i8
    }

    /// Instruction parallel
    pub fn parallel(&self) -> i8 {
        self.0.parallel as c_int as i8
    }
}

impl_PartialEq_repr_fields!(Tms320c64xInsnDetail<'a> [ 'a ];
    is_condition_zero, condition_reg, functional_unit, functional_unit_side,
    functional_unit_cross_path, parallel
);

/// TMS320C64X operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tms320c64xOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Memory
    Mem(Tms320c64xOpMem),

    /// Pair of registers
    RegPair(RegId, RegId),

    /// Invalid
    Invalid,
}

impl Default for Tms320c64xOperand {
    fn default() -> Self {
        Tms320c64xOperand::Invalid
    }
}

define_cs_enum_wrapper_reverse!(
    [
        /// TMS320C64X Memory Operand modification
        => Tms320c64xMemDisplayType = tms320c64x_mem_disp,
    ]
    /// Invalid or unspecified
    => Invalid = TMS320C64X_MEM_DISP_INVALID;
    /// Constant
    => Constant = TMS320C64X_MEM_DISP_CONSTANT;
    /// Regiter
    => Register = TMS320C64X_MEM_DISP_REGISTER;
);

/// TMS320C64X Operand Memory Display
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Tms320c64xMemDisplay {
    /// Invalid or unspecified
    Invalid,

    /// Constant
    Constant(u32),

    /// Register
    Register(RegId),
}

define_cs_enum_wrapper_reverse!(
    [
        /// TMS320C64X Memory Operand direction
        => Tms320c64xMemDirection = tms320c64x_mem_dir,
    ]
    /// Invalid or unspecified
    => Invalid = TMS320C64X_MEM_DIR_INVALID;
    /// Forward
    => Forward = TMS320C64X_MEM_DIR_FW;
    /// Backward
    => Backward = TMS320C64X_MEM_DIR_BW;
);

define_cs_enum_wrapper_reverse!(
    [
        /// TMS320C64X Memory Operand modification
        => Tms320c64xMemModify = tms320c64x_mem_mod,
    ]
    /// Invalid or unspecified
    => Invalid = TMS320C64X_MEM_MOD_INVALID;
    /// No
    => No = TMS320C64X_MEM_MOD_NO;
    /// Pre
    => Pre = TMS320C64X_MEM_MOD_PRE;
    /// Post
    => Post = TMS320C64X_MEM_MOD_POST;
);

/// TMS320C64X memory operand
#[derive(Debug, Copy, Clone)]
pub struct Tms320c64xOpMem(pub(crate) tms320c64x_op_mem);

/// todo(tmfink): add all getters
impl Tms320c64xOpMem {
    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Disp value (type depends on display_type)
    fn disp(&self) -> u32 {
        self.0.disp as u32
    }

    /// Unit of base and offset register
    pub fn unit(&self) -> u32 {
        self.0.unit as u32
    }

    /// Offset scaled
    pub fn scaled(&self) -> u32 {
        self.0.scaled as u32
    }

    /// Displacement type
    fn display_type(&self) -> Tms320c64xMemDisplayType {
        Tms320c64xMemDisplayType::from_u32(self.0.disptype as u32)
            .unwrap_or(Tms320c64xMemDisplayType::Invalid)
    }

    /// Display
    pub fn display(&self) -> Tms320c64xMemDisplay {
        match self.display_type() {
            Tms320c64xMemDisplayType::Invalid => Tms320c64xMemDisplay::Invalid,
            Tms320c64xMemDisplayType::Constant => Tms320c64xMemDisplay::Constant(self.disp()),
            Tms320c64xMemDisplayType::Register => {
                Tms320c64xMemDisplay::Register(RegId(self.disp() as RegIdInt))
            }
        }
    }

    /// Direction
    pub fn direction(&self) -> Tms320c64xMemDirection {
        Tms320c64xMemDirection::from_u32(self.0.direction as u32)
            .unwrap_or(Tms320c64xMemDirection::Invalid)
    }

    /// Modification
    pub fn modify(&self) -> Tms320c64xMemModify {
        Tms320c64xMemModify::from_u32(self.0.modify as u32).unwrap_or(Tms320c64xMemModify::Invalid)
    }
}

impl_PartialEq_repr_fields!(Tms320c64xOpMem;
    base, disp, unit, scaled, display_type, direction, modify
);

impl cmp::Eq for Tms320c64xOpMem {}

impl<'a> From<&'a cs_tms320c64x_op> for Tms320c64xOperand {
    fn from(insn: &cs_tms320c64x_op) -> Tms320c64xOperand {
        match insn.type_ {
            tms320c64x_op_type::TMS320C64X_OP_REG => {
                Tms320c64xOperand::Reg(RegId(unsafe { insn.__bindgen_anon_1.reg } as RegIdInt))
            }
            tms320c64x_op_type::TMS320C64X_OP_IMM => {
                Tms320c64xOperand::Imm(unsafe { insn.__bindgen_anon_1.imm } as i32)
            }
            tms320c64x_op_type::TMS320C64X_OP_MEM => {
                Tms320c64xOperand::Mem(Tms320c64xOpMem(unsafe { insn.__bindgen_anon_1.mem }))
            }
            tms320c64x_op_type::TMS320C64X_OP_REGPAIR => {
                let reg = unsafe { insn.__bindgen_anon_1.reg };
                // todo(tmfink): bug in capstone?
                Tms320c64xOperand::RegPair(RegId((reg as RegIdInt) + 1), RegId(reg as RegIdInt))
            }
            tms320c64x_op_type::TMS320C64X_OP_INVALID => Tms320c64xOperand::Invalid,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = Tms320c64xInsnDetail;
    Operand = Tms320c64xOperand;
    OperandIterator = Tms320c64xOperandIterator;
    OperandIteratorLife = Tms320c64xOperandIterator<'a>;
    [ pub struct Tms320c64xOperandIterator<'a>(slice::Iter<'a, cs_tms320c64x_op>); ]
    cs_arch_op = cs_tms320c64x_op;
    cs_arch = cs_tms320c64x;
);

#[cfg(test)]
mod test {
    use super::*;
    use capstone_sys::*;
    use libc::{c_int, c_uint};

    const OP_MEM_ZERO: tms320c64x_op_mem = tms320c64x_op_mem {
        base: 0,
        disp: 0,
        unit: 0,
        scaled: 0,
        disptype: 0,
        direction: 0,
        modify: 0,
    };

    #[test]
    fn tms320c64x_insn_detail() {
        let op = cs_tms320c64x_op {
            type_: tms320c64x_op_type::TMS320C64X_OP_IMM,
            __bindgen_anon_1: cs_tms320c64x_op__bindgen_ty_1 { imm: 0 },
        };
        let cs_insn = cs_tms320c64x {
            op_count: 0,
            operands: [op; 8],
            condition: cs_tms320c64x__bindgen_ty_1 {
                reg: tms320c64x_reg::TMS320C64X_REG_GPLYA as c_uint,
                zero: 1,
            },
            funit: cs_tms320c64x__bindgen_ty_2 {
                unit: tms320c64x_funit::TMS320C64X_FUNIT_L as c_uint,
                side: 18,
                crosspath: -1 as c_int as c_uint,
            },
            parallel: 1,
        };
        let d = Tms320c64xInsnDetail(&cs_insn);

        assert!(d.is_condition_zero());
        assert_eq!(
            d.condition_reg(),
            RegId(Tms320c64xReg::TMS320C64X_REG_GPLYA as RegIdInt)
        );
        assert_eq!(d.functional_unit(), Tms320c64xFuntionalUnit::L);
        assert_eq!(d.functional_unit_side(), 18);
        assert_eq!(d.functional_unit_cross_path(), -1);
        assert_eq!(d.parallel(), 1);
    }

    #[test]
    fn tms320c64x_op_from() {
        let op = cs_tms320c64x_op {
            type_: tms320c64x_op_type::TMS320C64X_OP_INVALID,
            __bindgen_anon_1: cs_tms320c64x_op__bindgen_ty_1 { reg: 0 },
        };
        assert_eq!(
            Tms320c64xOperand::from(&op),
            Tms320c64xOperand::Invalid
        );
    }

    #[test]
    fn op_mem() {
        // display type
        assert_eq!(
            Tms320c64xOpMem(OP_MEM_ZERO).display(),
            Tms320c64xMemDisplay::Invalid
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                disptype: 999,
                ..OP_MEM_ZERO
            })
            .display(),
            Tms320c64xMemDisplay::Invalid
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                disptype: tms320c64x_mem_disp::TMS320C64X_MEM_DISP_CONSTANT as c_uint,
                disp: 3133789374,
                ..OP_MEM_ZERO
            })
            .display(),
            Tms320c64xMemDisplay::Constant(3133789374)
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                disptype: tms320c64x_mem_disp::TMS320C64X_MEM_DISP_REGISTER as c_uint,
                disp: tms320c64x_reg::TMS320C64X_REG_A13 as c_uint,
                ..OP_MEM_ZERO
            })
            .display(),
            Tms320c64xMemDisplay::Register(RegId(Tms320c64xReg::TMS320C64X_REG_A13 as RegIdInt))
        );

        // Simple getters
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                base: tms320c64x_reg::TMS320C64X_REG_A13 as c_uint,
                ..OP_MEM_ZERO
            })
            .base(),
            RegId(Tms320c64xReg::TMS320C64X_REG_A13 as RegIdInt)
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                unit: 29393 as c_uint,
                ..OP_MEM_ZERO
            })
            .unit(),
            29393
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                scaled: 29393 as c_uint,
                ..OP_MEM_ZERO
            })
            .scaled(),
            29393
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                direction: tms320c64x_mem_dir::TMS320C64X_MEM_DIR_FW as c_uint,
                ..OP_MEM_ZERO
            })
            .direction(),
            Tms320c64xMemDirection::Forward,
        );
        assert_eq!(
            Tms320c64xOpMem(tms320c64x_op_mem {
                modify: tms320c64x_mem_mod::TMS320C64X_MEM_MOD_PRE as c_uint,
                ..OP_MEM_ZERO
            })
            .modify(),
            Tms320c64xMemModify::Pre,
        );
    }
}
