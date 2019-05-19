//! Contains x86-specific types

pub use arch::arch_builder::x86::*;
use arch::DetailsArchInsn;
use capstone_sys::{x86_op_mem, x86_op_type, cs_x86, cs_x86_op};
use instruction::{RegId, RegIdInt};
use core::convert::From;
use core::{cmp, fmt, slice};

pub use capstone_sys::x86_insn_group as X86InsnGroup;
pub use capstone_sys::x86_insn as X86Insn;
pub use capstone_sys::x86_reg as X86Reg;
pub use capstone_sys::x86_prefix as X86Prefix;

pub use capstone_sys::x86_avx_bcast as X86AvxBcast;
pub use capstone_sys::x86_sse_cc as X86SseCC;
pub use capstone_sys::x86_avx_cc as X86AvxCC;
pub use capstone_sys::x86_xop_cc as X86XopCC;
pub use capstone_sys::x86_avx_rm as X86AvxRm;

use capstone_sys::cs_x86_op__bindgen_ty_1;

/// Contains X86-specific details for an instruction
pub struct X86InsnDetail<'a>(pub(crate) &'a cs_x86);

// todo(tmfink): expose new types cs_x86__bindgen_ty_1, cs_x86_encoding, x86_xop_cc,
// cs_x86_op::access

impl X86OperandType {
    fn new(op_type: x86_op_type, value: cs_x86_op__bindgen_ty_1) -> X86OperandType {
        use self::x86_op_type::*;
        use self::X86OperandType::*;

        match op_type {
            X86_OP_REG => Reg(RegId(unsafe { value.reg } as RegIdInt)),
            X86_OP_IMM => Imm(unsafe { value.imm }),
            X86_OP_MEM => Mem(X86OpMem(unsafe { value.mem })),
            X86_OP_INVALID => Invalid,
        }
    }
}

/// X86 operand
#[derive(Clone, Debug, PartialEq)]
pub struct X86Operand {
    /// Operand size
    pub size: u8,

    /// AVX broadcast
    pub avx_bcast: X86AvxBcast,

    /// AVX zero opmask
    pub avx_zero_opmask: bool,

    /// Operand type
    pub op_type: X86OperandType,
}

/// X86 operand
#[derive(Clone, Debug, PartialEq)]
pub enum X86OperandType {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(i64),

    /// Memory
    Mem(X86OpMem),

    /// Invalid
    Invalid,
}

/// X86 memory operand
#[derive(Debug, Copy, Clone)]
pub struct X86OpMem(pub(crate) x86_op_mem);

impl<'a> X86InsnDetail<'a> {
    /// Instruction prefix, which can be up to 4 bytes.
    /// A prefix byte gets value 0 when irrelevant.
    /// See `X86Prefix` for details.
    ///
    /// prefix[0] indicates REP/REPNE/LOCK prefix (See `X86_PREFIX_REP`/`REPNE`/`LOCK`)
    ///
    /// prefix[1] indicates segment override (irrelevant for x86_64):
    /// See `X86_PREFIX_CS`/`SS`/`DS`/`ES`/`FS`/`GS`.
    ///
    /// prefix[2] indicates operand-size override (`X86_PREFIX_OPSIZE`)
    ///
    /// prefix[3] indicates address-size override (`X86_PREFIX_ADDRSIZE`)
    pub fn prefix(&self) -> &[u8; 4] {
        &self.0.prefix
    }

    /// Instruction opcode, which can be from 1 to 4 bytes in size.
    /// This contains VEX opcode as well.
    /// A trailing opcode byte gets value 0 when irrelevant.
    pub fn opcode(&self) -> &[u8; 4] {
        &self.0.opcode
    }

    /// REX prefix: only a non-zero value is relevant for x86_64
    pub fn rex(&self) -> u8 {
        self.0.rex
    }

    /// Address size
    pub fn addr_size(&self) -> u8 {
        self.0.addr_size
    }

    /// ModR/M byte
    pub fn modrm(&self) -> u8 {
        self.0.modrm
    }

    /// SIB (Scaled Index Byte) value, or 0 when irrelevant
    pub fn sib(&self) -> u8 {
        self.0.sib
    }

    /// Displacement value, valid if encoding.disp_offset != 0
    pub fn disp(&self) -> i64 {
        self.0.disp
    }

    /// Scaled Index Byte (SIB) index, or X86_REG_INVALID when irrelevant
    pub fn sib_index(&self) -> RegId {
        RegId(self.0.sib_index as RegIdInt)
    }

    /// Scaled Index Byte (SIB) scale, or X86_REG_INVALID when irrelevant
    pub fn sib_scale(&self) -> i8 {
        self.0.sib_scale
    }

    /// Scaled Index Byte (SIB) base register, or X86_REG_INVALID when irrelevant
    pub fn sib_base(&self) -> RegId {
        RegId(self.0.sib_base as RegIdInt)
    }

    /// eXtended Operations (XOP) Code Condition
    pub fn xop_cc(&self) -> X86XopCC {
        self.0.xop_cc
    }

    /// Streaming SIMD Extensions (SSE) condition  codes
    pub fn sse_cc(&self) -> X86SseCC {
        self.0.sse_cc
    }

    /// Advanced Vector Extensions (AVX) condition  codes
    pub fn avx_cc(&self) -> X86AvxCC {
        self.0.avx_cc
    }

    /// Advanced Vector Extensions (AVX) sae
    pub fn avx_sae(&self) -> bool {
        self.0.avx_sae
    }

    /// Advanced Vector Extensions (AVX) rm
    pub fn avx_rm(&self) -> X86AvxRm {
        self.0.avx_rm
    }
}

impl_PartialEq_repr_fields!(X86InsnDetail<'a> [ 'a ];
    prefix, opcode, rex, addr_size, modrm, sib, disp, sib_index, sib_scale, sib_base, sse_cc,
    avx_cc, avx_sae, avx_rm, operands
);

impl X86OpMem {
    /// Segment
    pub fn segment(&self) -> u32 {
        self.0.segment as u32
    }

    /// Base register
    pub fn base(&self) -> RegId {
        RegId(self.0.base as RegIdInt)
    }

    /// Index register
    pub fn index(&self) -> RegId {
        RegId(self.0.index as RegIdInt)
    }

    /// Scale
    pub fn scale(&self) -> i32 {
        self.0.scale as i32
    }

    /// Display
    pub fn disp(&self) -> i64 {
        self.0.disp
    }
}

impl_PartialEq_repr_fields!(X86OpMem;
    segment, base, index, scale, disp
);

impl cmp::Eq for X86OpMem {}

impl Default for X86Operand {
    fn default() -> Self {
        X86Operand {
            size: 0,
            avx_bcast: X86AvxBcast::X86_AVX_BCAST_INVALID,
            avx_zero_opmask: false,
            op_type: X86OperandType::Invalid
        }
    }
}

impl<'a> From<&'a cs_x86_op> for X86Operand {
    fn from(op: &cs_x86_op) -> X86Operand {
        let op_type = X86OperandType::new(op.type_, op.__bindgen_anon_1);
        X86Operand {
            size: op.size,
            avx_bcast: op.avx_bcast,
            avx_zero_opmask: op.avx_zero_opmask,
            op_type,
        }
    }
}

def_arch_details_struct!(
    InsnDetail = X86InsnDetail;
    Operand = X86Operand;
    OperandIterator = X86OperandIterator;
    OperandIteratorLife = X86OperandIterator<'a>;
    [ pub struct X86OperandIterator<'a>(slice::Iter<'a, cs_x86_op>); ]
    cs_arch_op = cs_x86_op;
    cs_arch = cs_x86;
);

#[cfg(test)]
mod test {
    use super::*;
    use capstone_sys::*;

    #[test]
    fn test_x86_op_type() {
        use super::x86_op_type::*;
        use super::X86OperandType::*;

        fn t(
            op_type_value: (x86_op_type, cs_x86_op__bindgen_ty_1),
            expected_op_type: X86OperandType,
        ) {
            let (op_type, op_value) = op_type_value;
            let op_type = X86OperandType::new(op_type, op_value);
            assert_eq!(expected_op_type, op_type);
        }

        t(
            (X86_OP_INVALID, cs_x86_op__bindgen_ty_1 { reg: 0 }),
            Invalid,
        );
        t(
            (X86_OP_REG, cs_x86_op__bindgen_ty_1 { reg: 0 }),
            Reg(RegId(0)),
        );
    }

    #[test]
    fn test_x86_op_eq() {
        let a1 = X86Operand {
            op_type: X86OperandType::Imm(0),
            ..Default::default()
        };
        let a2 = X86Operand {
            op_type: X86OperandType::Imm(-100),
            ..Default::default()
        };

        assert_eq!(a1, a1.clone());
        assert_ne!(a1, a2.clone());
    }

    #[test]
    fn test_x86_insn_eq() {
        fn t_eq(a: &cs_x86, b: &cs_x86) {
            assert_eq!(X86InsnDetail(a), X86InsnDetail(b))
        }
        fn t_ne(a: &cs_x86, b: &cs_x86) {
            assert_ne!(X86InsnDetail(a), X86InsnDetail(b))
        }

        let a1 = cs_x86 {
            prefix: [0, 0, 0, 0],
            opcode: [0, 0, 0, 0],
            rex: 0,
            addr_size: 0,
            modrm: 0,
            sib: 0,
            disp: 0,
            sib_index: x86_reg::X86_REG_INVALID,
            sib_scale: 0,
            sib_base: x86_reg::X86_REG_INVALID,
            sse_cc: x86_sse_cc::X86_SSE_CC_INVALID,
            avx_cc: x86_avx_cc::X86_AVX_CC_INVALID,
            avx_sae: false,
            avx_rm: x86_avx_rm::X86_AVX_RM_INVALID,
            op_count: 0,
            __bindgen_anon_1: cs_x86__bindgen_ty_1 {
                eflags: 0,
            },
            encoding: cs_x86_encoding {
                modrm_offset: 0,
                disp_offset: 0,
                disp_size: 0,
                imm_offset: 0,
                imm_size: 0,
            },
            xop_cc: x86_xop_cc::X86_XOP_CC_INVALID,
            operands: [ cs_x86_op {
                type_: x86_op_type::X86_OP_INVALID,
                __bindgen_anon_1: cs_x86_op__bindgen_ty_1 { reg: x86_reg::X86_REG_INVALID },
                size: 0,
                avx_bcast: x86_avx_bcast::X86_AVX_BCAST_INVALID,
                avx_zero_opmask: false,
                access: 0,
            }
            ; 8],

        };
        let mut a2 = a1.clone();
        a2.operands[1].type_ = x86_op_type::X86_OP_REG;
        let a1_clone = cs_x86 {
            ..a1
        };
        let a3 = cs_x86 {
            rex: 1,
            ..a1
        };
        let op_count_differ = cs_x86 {
            op_count: 1,
            ..a1
        };
        let mut op1_differ = op_count_differ.clone();
        op1_differ.operands[0].avx_bcast = x86_avx_bcast::X86_AVX_BCAST_2;

        t_eq(&a1, &a1);
        t_eq(&a1, &a2);
        t_eq(&a1, &a1_clone);
        t_ne(&a1, &a3);
        t_ne(&a1, &op_count_differ);
        t_ne(&op_count_differ, &op1_differ);
    }
}
