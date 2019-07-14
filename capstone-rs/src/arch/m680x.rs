//! Contains m680x-specific types

use core::convert::From;
use core::{fmt, slice};

use capstone_sys::{
    cs_m680x, cs_m680x_op, m680x_op_ext, m680x_op_idx, m680x_op_rel, m680x_op_type,
};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::m680x_insn as M680xInsn;
pub use capstone_sys::m680x_reg as M680xReg;

pub use crate::arch::arch_builder::m680x::*;
use crate::arch::DetailsArchInsn;
use crate::instruction::{RegId, RegIdInt};


/// Contains M680X-specific details for an instruction
pub struct M680xInsnDetail<'a>(pub(crate) &'a cs_m680x);

impl_PartialEq_repr_fields!(M680xInsnDetail<'a> [ 'a ];
    operands, flags
);

// M680X instruction flags
const M680X_FIRST_OP_IN_MNEM: u8 = 1;
const M680X_SECOND_OP_IN_MNEM: u8 = 2;

define_impl_bitmask!(
    impl M680xInsnDetail<'a>;
    flags: u8 = { |self_: &M680xInsnDetail| self_.0.flags }
    test_mod = test_M680xInsnDetail;

    /// The first (register) operand is part of the instruction mnemonic
    => is_first_op_in_mnem = M680X_FIRST_OP_IN_MNEM;

    /// The second (register) operand is part of the instruction mnemonic
    => is_second_op_in_mnem = M680X_SECOND_OP_IN_MNEM;
);

/// Instruction's operand referring to indexed addressing
#[derive(Clone, Debug)]
pub struct M680xOpIdx(pub(crate) m680x_op_idx);

impl_PartialEq_repr_fields!(M680xOpIdx [ ];
    base_reg, offset_reg, offset, offset_addr, offset_bits, inc_dec, flags
);

impl Eq for M680xOpIdx {}

macro_rules! define_m680x_register_option_getter {
    (
        $( #[$enum_attr:meta] )*
        => $field:ident
    ) => {
        $( #[$enum_attr] )*
        pub fn $field(&self) -> Option<RegId> {
            if (self.0).$field == M680xReg::M680X_REG_INVALID {
                None
            } else {
                Some(RegId((self.0).$field as RegIdInt))
            }
        }
    }
}

impl M680xOpIdx {
    fn new(op_idx: &m680x_op_idx) -> Self {
        M680xOpIdx(*op_idx)
    }

    define_m680x_register_option_getter!(
        /// Base register
        => base_reg
    );

    define_m680x_register_option_getter!(
        /// Offset register
        => offset_reg
    );

    /// 5-,8- or 16-bit offset
    pub fn offset(&self) -> i16 {
        self.0.offset
    }

    /// Offset address
    ///
    /// if base_reg == M680X_REG_PC, then calculated as offset + PC
    pub fn offset_addr(&self) -> u16 {
        self.0.offset_addr
    }

    /// Offset bits
    pub fn offset_bits(&self) -> u8 {
        self.0.offset_bits
    }

    /// Increment or decrement value
    ///
    /// - `0`: no inc-/decrement
    /// - `1 .. 8`: increment by `1 .. 8`
    /// - `-1 .. -8`: decrement by `1 .. 8`
    ///
    /// if flag `M680X_IDX_POST_INC_DEC` set it is post
    /// inc-/decrement, otherwise pre inc-/decrement.
    pub fn inc_dec(&self) -> i8 {
        self.0.inc_dec
    }
}

// Comes from M680X_IDX_* #defines
const M680X_IDX_INDIRECT: u8 = 1;
const M680X_IDX_NO_COMMA: u8 = 2;
const M680X_IDX_POST_INC_DEC: u8 = 4;

define_impl_bitmask!(
    impl M680xOpIdx<>;
    flags: u8 = { |self_: &M680xOpIdx| self_.0.flags }
    test_mod = test_M680xOpIdx;

    /// Is index indirect?
    => is_indirect = M680X_IDX_INDIRECT;

    /// Is there no comma?
    => is_no_comma = M680X_IDX_NO_COMMA;

    /// Is index indirect?
    => is_post_inc_dec = M680X_IDX_POST_INC_DEC;
);

/// M680X operand
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum M680xOperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i32),

    /// Indexed addressing operand
    Indexed(M680xOpIdx),

    /// Extended addressing operand
    Extended {
        /// Absolute address
        address: u16,

        /// Whether extended indirect addressing
        indirect: bool,
    },

    /// Direct addressing operand
    Direct {
        /// Direct address (lower 8-bit)
        direct_addr: u8,
    },

    /// Relative addressing operand
    Relative {
        /// Absolute address
        address: u16,

        /// Offset/displacement value
        offset: i16,
    },

    /// Constant operand (displayed as number only)
    ///
    /// Used e.g. for a bit index or page number.
    Constant(u8),

    /// Invalid
    Invalid,
}

impl Default for M680xOperandType {
    fn default() -> Self {
        M680xOperandType::Invalid
    }
}

impl<'a> From<&'a cs_m680x_op> for M680xOperand {
    fn from(op: &cs_m680x_op) -> M680xOperand {
        let op_type = match op.type_ {
            m680x_op_type::M680X_OP_REGISTER => {
                M680xOperandType::Reg(RegId(unsafe { op.__bindgen_anon_1.reg } as RegIdInt))
            }
            m680x_op_type::M680X_OP_IMMEDIATE => {
                M680xOperandType::Imm(unsafe { op.__bindgen_anon_1.imm })
            }
            m680x_op_type::M680X_OP_INDEXED => {
                M680xOperandType::Indexed(M680xOpIdx::new(unsafe { &op.__bindgen_anon_1.idx }))
            }
            m680x_op_type::M680X_OP_EXTENDED => {
                let op_ext: m680x_op_ext = unsafe { op.__bindgen_anon_1.ext };
                M680xOperandType::Extended {
                    address: op_ext.address,
                    indirect: op_ext.indirect,
                }
            }
            m680x_op_type::M680X_OP_DIRECT => M680xOperandType::Direct {
                direct_addr: unsafe { op.__bindgen_anon_1.direct_addr },
            },
            m680x_op_type::M680X_OP_RELATIVE => {
                let op_rel: m680x_op_rel = unsafe { op.__bindgen_anon_1.rel };
                M680xOperandType::Relative {
                    address: op_rel.address,
                    offset: op_rel.offset,
                }
            }
            m680x_op_type::M680X_OP_CONSTANT => {
                M680xOperandType::Constant(unsafe { op.__bindgen_anon_1.const_val })
            }
            m680x_op_type::M680X_OP_INVALID => M680xOperandType::Invalid,
        };

        M680xOperand {
            op_type,
            size: op.size,
        }
    }
}

/// M680X operand
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct M680xOperand {
    /// Operand type
    pub op_type: M680xOperandType,

    /// Size of this operand in bytes
    pub size: u8,
}

def_arch_details_struct!(
    InsnDetail = M680xInsnDetail;
    Operand = M680xOperand;
    OperandIterator = M680xOperandIterator;
    OperandIteratorLife = M680xOperandIterator<'a>;
    [ pub struct M680xOperandIterator<'a>(slice::Iter<'a, cs_m680x_op>); ]
    cs_arch_op = cs_m680x_op;
    cs_arch = cs_m680x;
);

#[cfg(test)]
mod test {
    use super::*;
    use capstone_sys::*;

    #[test]
    fn m680x_op_type() {
        let op_base = cs_m680x_op {
            type_: m680x_op_type::M680X_OP_INVALID,
            __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 { reg: 0 },
            size: 1,
            access: 0,
        };

        assert_eq!(
            M680xOperand::from(&op_base).op_type,
            M680xOperandType::Invalid
        );
        assert_eq!(
            M680xOperand::from(&cs_m680x_op {
                type_: m680x_op_type::M680X_OP_REGISTER,
                __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 {
                    reg: M680xReg::M680X_REG_E
                },
                ..op_base
            })
            .op_type,
            M680xOperandType::Reg(RegId(M680xReg::M680X_REG_E as RegIdInt))
        );
        assert_eq!(
            M680xOperand::from(&cs_m680x_op {
                type_: m680x_op_type::M680X_OP_CONSTANT,
                __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 { const_val: 42 },
                ..op_base
            })
            .op_type,
            M680xOperandType::Constant(42)
        );
        assert_eq!(
            M680xOperand::from(&cs_m680x_op {
                type_: m680x_op_type::M680X_OP_IMMEDIATE,
                __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 { imm: 1037 },
                ..op_base
            })
            .op_type,
            M680xOperandType::Imm(1037)
        );
        assert_eq!(
            M680xOperand::from(&cs_m680x_op {
                type_: m680x_op_type::M680X_OP_DIRECT,
                __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 { direct_addr: 67 },
                ..op_base
            })
            .op_type,
            M680xOperandType::Direct { direct_addr: 67 }
        );
        assert_eq!(
            M680xOperand::from(&cs_m680x_op {
                type_: m680x_op_type::M680X_OP_EXTENDED,
                __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 {
                    ext: m680x_op_ext {
                        address: 45876,
                        indirect: true,
                    }
                },
                ..op_base
            })
            .op_type,
            M680xOperandType::Extended {
                address: 45876,
                indirect: true
            }
        );

        let base_reg = m680x_reg::M680X_REG_A;
        let offset_reg = m680x_reg::M680X_REG_B;
        let offset = 5;
        let offset_addr = 0x1337;
        let offset_bits = 4;
        let inc_dec = -3;
        let cs_op_idx = m680x_op_idx {
            base_reg,
            offset_reg,
            offset,
            offset_addr,
            offset_bits,
            inc_dec,
            flags: 7,
        };
        assert_eq!(
            M680xOperand::from(&cs_m680x_op {
                type_: m680x_op_type::M680X_OP_INDEXED,
                __bindgen_anon_1: cs_m680x_op__bindgen_ty_1 { idx: cs_op_idx },
                ..op_base
            })
            .op_type,
            M680xOperandType::Indexed(M680xOpIdx(cs_op_idx))
        );
    }

    #[test]
    fn op_idx() {
        let base_reg = m680x_reg::M680X_REG_A;
        let offset_reg = m680x_reg::M680X_REG_B;
        let offset = 5;
        let offset_addr = 0x1337;
        let offset_bits = 4;
        let inc_dec = -3;

        let mut idx = M680xOpIdx(m680x_op_idx {
            base_reg,
            offset_reg,
            offset,
            offset_addr,
            offset_bits,
            inc_dec,
            flags: 7,
        });

        assert_eq!(idx.base_reg(), Some(RegId(base_reg as RegIdInt)));
        assert_eq!(idx.offset_reg(), Some(RegId(offset_reg as RegIdInt)));
        assert_eq!(idx.offset(), offset);
        assert_eq!(idx.offset_addr(), offset_addr);
        assert_eq!(idx.offset_bits(), offset_bits);
        assert_eq!(idx.inc_dec(), inc_dec);
        assert!(idx.is_indirect());
        assert!(idx.is_no_comma());
        assert!(idx.is_post_inc_dec());

        idx.0.flags = 5;
        assert!(idx.is_indirect());
        assert!(!idx.is_no_comma());
        assert!(idx.is_post_inc_dec());
    }
}
