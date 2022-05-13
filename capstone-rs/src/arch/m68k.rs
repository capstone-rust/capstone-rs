//! Contains m68k-specific types

use core::convert::From;
use core::{cmp, fmt, slice};

use capstone_sys::{
    cs_m68k, cs_m68k_op, cs_m68k_op__bindgen_ty_1, m68k_address_mode, m68k_cpu_size, m68k_fpu_size,
    m68k_op_br_disp, m68k_op_mem, m68k_op_size, m68k_op_type, m68k_reg, m68k_size_type,
};

// XXX todo(tmfink): create rusty versions
pub use capstone_sys::m68k_address_mode as M68kAddressMode;
pub use capstone_sys::m68k_insn as M68kInsn;
pub use capstone_sys::m68k_reg as M68kReg;

pub use crate::arch::arch_builder::m68k::*;
use crate::arch::DetailsArchInsn;
use crate::Error;
use crate::instruction::{RegId, RegIdInt};
use crate::prelude::*;


/// Contains M68K-specific details for an instruction
pub struct M68kInsnDetail<'a>(pub(crate) &'a cs_m68k);

impl<'a> M68kInsnDetail<'a> {
    /// size of data operand works on in bytes (.b, .w, .l, etc)
    pub fn op_size(&self) -> Option<M68kOpSize> {
        M68kOpSize::new(&self.0.op_size)
    }
}

define_cs_enum_wrapper_reverse!(
    [
        /// Operation size of the CPU instructions
        => M68kCpuSize = m68k_cpu_size,
    ]
    /// Unsized or unspecified
    => None = M68K_CPU_SIZE_NONE;
    /// 1 byte in size
    => Byte = M68K_CPU_SIZE_BYTE;
    /// 2 bytes in size
    => Word = M68K_CPU_SIZE_WORD;
    /// 4 bytes in size
    => Long = M68K_CPU_SIZE_LONG;
);

define_cs_enum_wrapper_reverse!(
    [
        /// Operation size of the FPU instructions (notice that FPU instruction can also use CPU
        /// sizes if needed)
        => M68kFpuSize = m68k_fpu_size,
    ]
    /// Unsized or unspecified
    => None = M68K_FPU_SIZE_NONE;
    /// 1 byte in size
    => Single = M68K_FPU_SIZE_SINGLE;
    /// 2 bytes in size
    => Double = M68K_FPU_SIZE_DOUBLE;
    /// 4 bytes in size
    => Extended = M68K_FPU_SIZE_EXTENDED;
);

/// Operation size of the current instruction (NOT the actually size of instruction)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum M68kOpSize {
    Cpu(M68kCpuSize),
    Fpu(M68kFpuSize),
}

/// Data when operand is a branch displacement
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct M68kOpBranchDisplacement {
    /// Displacement value
    pub disp: i32,

    /// Size from M68kOpBranchDisplacement
    pub disp_size: u8,
}

impl From<m68k_op_br_disp> for M68kOpBranchDisplacement {
    fn from(other: m68k_op_br_disp) -> Self {
        M68kOpBranchDisplacement {
            disp: other.disp,
            disp_size: other.disp_size,
        }
    }
}

impl M68kOpSize {
    fn new(op: &m68k_op_size) -> Option<M68kOpSize> {
        match op.type_ {
            m68k_size_type::M68K_SIZE_TYPE_INVALID => None,
            m68k_size_type::M68K_SIZE_TYPE_CPU => Some(M68kOpSize::Cpu(
                unsafe { op.__bindgen_anon_1.cpu_size }.into(),
            )),
            m68k_size_type::M68K_SIZE_TYPE_FPU => Some(M68kOpSize::Fpu(
                unsafe { op.__bindgen_anon_1.fpu_size }.into(),
            )),
        }
    }
}

impl_PartialEq_repr_fields!(M68kInsnDetail<'a> [ 'a ];
    op_size, operands
);

impl Default for M68kOperand {
    fn default() -> Self {
        M68kOperand::Invalid
    }
}

/// Contains bitfield used with M68kOperand::RegBits
///
/// Contains register bits for movem etc. (always in d0-d7, a0-a7, fp0-fp7 order)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct M68kRegisterBits {
    /// Internal bitfield
    ///
    /// INVARIANT: must only have bits set up to fp7
    bits: u32,
}

/// Allowed bits are 1; disallowed bits are 0
const M68K_REGISTER_BITS_ALLOWED_MASK: u32 =
    (1_u32 << ((m68k_reg::M68K_REG_FP7 as u8 - m68k_reg::M68K_REG_D0 as u8) + 1_u8)) - 1;

impl M68kRegisterBits {
    /// Create from a bitfield where 0th bit is d0, 1th bit is d1, ...
    ///
    /// Returns an error if invalid bits are set.
    pub fn from_bitfield(bitfield: u32) -> CsResult<Self> {
        if bitfield & !M68K_REGISTER_BITS_ALLOWED_MASK != 0 {
            Err(Error::InvalidM68kBitfieldRegister)
        } else {
            Ok(M68kRegisterBits { bits: bitfield })
        }
    }

    /// Create from a bitfield where 0th bit is d0, 1th bit is d1, ...
    ///
    /// Invalid bits are ignored.
    pub fn from_bitfield_infallible(bitfield: u32) -> Self {
        M68kRegisterBits {
            bits: bitfield & M68K_REGISTER_BITS_ALLOWED_MASK,
        }
    }

    /// Create from iterator over registers: d0-d7, a0-a7, fp0-fp7
    /// Invalid registers will cause an error
    pub fn from_register_iter<T: Iterator<Item = R>, R: Into<M68kReg::Type>>(
        reg_iter: T,
    ) -> CsResult<Self> {
        let mut bits: u32 = 0;
        for reg in reg_iter {
            bits |= 1 << M68kRegisterBits::m68k_reg_to_bit_idx(reg.into())?;
        }
        Ok(M68kRegisterBits { bits })
    }

    /// Maps an M68K register to a bitfield index
    ///
    /// Returns an error if the register is invalid
    #[inline]
    pub fn m68k_reg_to_bit_idx(reg: M68kReg::Type) -> CsResult<u8> {
        use capstone_sys::m68k_reg::*;

        if (M68K_REG_D0..=M68K_REG_FP7).contains(&reg) {
            Ok((reg - M68K_REG_D0) as u8)
        } else {
            Err(Error::InvalidM68kBitfieldRegister)
        }
    }

    /// Returns bitfield as integer
    #[inline]
    pub fn as_bits(&self) -> u32 {
        self.bits
    }
}

/// M68K operand type
#[derive(Clone, Debug, PartialEq)]
pub enum M68kOperand {
    /// Register
    Reg(RegId),

    /// Immediate
    Imm(u32),

    /// Memory
    Mem(M68kOpMem),

    /// Single precision floating-point
    FpSingle(f32),

    /// Double precision floating-point
    FpDouble(f64),

    /// Register bits move
    RegBits(M68kRegisterBits),

    /// Register pair in the same op (upper 4 bits for first reg, lower for second)
    RegPair(RegId, RegId),

    /// Branch displacement
    Displacement(M68kOpBranchDisplacement),

    /// Invalid
    Invalid,
}

impl M68kOperand {
    fn new(cs_op: &cs_m68k_op) -> M68kOperand {
        use self::m68k_op_type::*;
        use self::M68kOperand::*;

        let value: cs_m68k_op__bindgen_ty_1 = cs_op.__bindgen_anon_1;

        match cs_op.type_ {
            M68K_OP_REG => Reg(RegId(unsafe { value.reg } as RegIdInt)),
            M68K_OP_IMM => Imm(unsafe { value.imm } as u32),
            M68K_OP_MEM => Mem(M68kOpMem::new(cs_op)),
            M68K_OP_FP_SINGLE => FpSingle(unsafe { value.simm }),
            M68K_OP_FP_DOUBLE => FpDouble(unsafe { value.dimm }),
            M68K_OP_REG_BITS => RegBits(M68kRegisterBits::from_bitfield_infallible(
                cs_op.register_bits,
            )),
            M68K_OP_REG_PAIR => {
                let reg_pair = unsafe { value.reg_pair };
                RegPair(
                    RegId(reg_pair.reg_0 as RegIdInt),
                    RegId(reg_pair.reg_1 as RegIdInt),
                )
            }
            M68K_OP_BR_DISP => Displacement(cs_op.br_disp.into()),
            M68K_OP_INVALID => Invalid,
        }
    }
}

//todo(tmfink: handle all cases
/// Extra info accompanying `M68kOpMem` that is not part of union in `m68k_op_mem`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum M68kOpMemExtraInfo {
    /// No extra info
    None,

    /// Register
    Reg(RegId),

    /// Immediate
    Imm(u32),
}

impl M68kOpMemExtraInfo {
    /// Register (if it exists)
    pub(crate) fn reg(&self) -> Option<RegId> {
        if let M68kOpMemExtraInfo::Reg(reg) = self {
            Some(*reg)
        } else {
            None
        }
    }

    /// Immediate (if it exists)
    pub(crate) fn imm(&self) -> Option<u32> {
        if let M68kOpMemExtraInfo::Imm(imm) = self {
            Some(*imm)
        } else {
            None
        }
    }
}

/// M68K memory operand
#[derive(Debug, Clone)]
pub struct M68kOpMem {
    pub(crate) op_mem: m68k_op_mem,
    pub(crate) address_mode: m68k_address_mode,

    /// Register that is populated depending on address mode
    pub(crate) extra_info: M68kOpMemExtraInfo,
}

macro_rules! define_m68k_register_option_getter {
    (
        $( #[$enum_attr:meta] )*
        => $field:ident
    ) => {
        $( #[$enum_attr] )*
        pub fn $field(&self) -> Option<RegId> {
            if self.op_mem.$field == M68kReg::M68K_REG_INVALID {
                None
            } else {
                Some(RegId(self.op_mem.$field as RegIdInt))
            }
        }
    }
}

macro_rules! define_m68k_getter {
    (
        $( #[$enum_attr:meta] )*
        => $field:ident : $ret_type:ty
    ) => {
        $( #[$enum_attr] )*
        pub fn $field(&self) -> $ret_type {
            self.op_mem.$field
        }
    }
}

/// M68K index size
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum M68kIndexSize {
    W,

    /// Long
    L,
}

impl M68kOpMem {
    /// Create a `M68kOpMem` from `&cs_m68k_op`, which depends on
    pub fn new(op: &cs_m68k_op) -> Self {
        use self::M68kAddressMode::*;

        let address_mode = op.address_mode;
        let value: cs_m68k_op__bindgen_ty_1 = op.__bindgen_anon_1;

        let extra_info = match address_mode {
            M68K_AM_REG_DIRECT_DATA
            | M68K_AM_REG_DIRECT_ADDR
            | M68K_AM_REGI_ADDR
            | M68K_AM_REGI_ADDR_POST_INC
            | M68K_AM_REGI_ADDR_PRE_DEC => {
                M68kOpMemExtraInfo::Reg(RegId(unsafe { value.reg } as RegIdInt))
            }

            // The M68K_AM_IMMEDIATE case cannot be floating point because type will not be op_mem
            M68K_AM_ABSOLUTE_DATA_LONG | M68K_AM_ABSOLUTE_DATA_SHORT | M68K_AM_IMMEDIATE => {
                M68kOpMemExtraInfo::Imm(unsafe { value.imm } as u32)
            }

            M68K_AM_PCI_INDEX_8_BIT_DISP
            | M68K_AM_PCI_INDEX_BASE_DISP
            | M68K_AM_AREGI_INDEX_BASE_DISP
            | M68K_AM_BRANCH_DISPLACEMENT
            | M68K_AM_NONE
            | M68K_AM_REGI_ADDR_DISP
            | M68K_AM_AREGI_INDEX_8_BIT_DISP
            | M68K_AM_PC_MEMI_POST_INDEX
            | M68K_AM_PC_MEMI_PRE_INDEX
            | M68K_AM_MEMI_PRE_INDEX
            | M68K_AM_MEMI_POST_INDEX
            | M68K_AM_PCI_DISP => M68kOpMemExtraInfo::None,
        };

        M68kOpMem {
            op_mem: op.mem,
            address_mode,
            extra_info,
        }
    }

    define_m68k_register_option_getter!(
        /// Base register
        => base_reg
    );

    define_m68k_register_option_getter!(
        /// index register
        => index_reg
    );

    define_m68k_register_option_getter!(
        /// indirect base register
        => in_base_reg
    );

    define_m68k_getter!(
        /// Indirect displacement
        => in_disp: u32
    );

    define_m68k_getter!(
        /// other displacement
        => out_disp: u32
    );

    define_m68k_getter!(
        /// displacement value
        => disp: i16
    );

    define_m68k_getter!(
        /// scale for index register
        => scale: u8
    );

    /// Returns (width, offset)
    pub fn bitfield(&self) -> Option<(u8, u8)> {
        if self.op_mem.bitfield == 0 {
            None
        } else {
            Some((self.op_mem.width, self.op_mem.offset))
        }
    }

    pub fn index_size(&self) -> M68kIndexSize {
        if self.op_mem.index_size == 0 {
            M68kIndexSize::W
        } else {
            M68kIndexSize::L
        }
    }

    /// M68K addressing mode for this op
    pub fn address_mode(&self) -> M68kAddressMode {
        self.address_mode
    }

    /// Extra info not included in mem type
    pub(crate) fn extra_info(&self) -> M68kOpMemExtraInfo {
        self.extra_info
    }

    /// Register value
    pub fn reg(&self) -> Option<RegId> {
        self.extra_info.reg()
    }

    /// Immediate value
    pub fn imm(&self) -> Option<u32> {
        self.extra_info.imm()
    }
}

impl_PartialEq_repr_fields!(M68kOpMem;
    base_reg, index_reg, in_base_reg, in_disp, out_disp, disp, scale, bitfield, index_size,
    address_mode, extra_info
);

impl cmp::Eq for M68kOpMem {}

impl<'a> From<&'a cs_m68k_op> for M68kOperand {
    fn from(insn: &cs_m68k_op) -> M68kOperand {
        M68kOperand::new(insn)
    }
}

def_arch_details_struct!(
    InsnDetail = M68kInsnDetail;
    Operand = M68kOperand;
    OperandIterator = M68kOperandIterator;
    OperandIteratorLife = M68kOperandIterator<'a>;
    [ pub struct M68kOperandIterator<'a>(slice::Iter<'a, cs_m68k_op>); ]
    cs_arch_op = cs_m68k_op;
    cs_arch = cs_m68k;
);

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use capstone_sys::m68k_address_mode::*;
    use capstone_sys::m68k_op_type::*;
    use capstone_sys::m68k_reg::*;
    use crate::instruction::*;

    const MEM_ZERO: m68k_op_mem = m68k_op_mem {
        base_reg: M68K_REG_INVALID,
        index_reg: M68K_REG_INVALID,
        in_base_reg: M68K_REG_INVALID,
        in_disp: 0,
        out_disp: 0,
        disp: 0,
        scale: 0,
        bitfield: 0,
        width: 0,
        offset: 0,
        index_size: 0,
    };

    #[test]
    fn test_m68k_op_from() {
        let op_zero = cs_m68k_op {
            __bindgen_anon_1: cs_m68k_op__bindgen_ty_1 { imm: 0 },
            mem: MEM_ZERO,
            br_disp: m68k_op_br_disp {
                disp: 0,
                disp_size: 0,
            },
            register_bits: 0,
            type_: M68K_OP_IMM,
            address_mode: M68K_AM_NONE,
        };

        // Reg
        let op_reg = cs_m68k_op {
            __bindgen_anon_1: cs_m68k_op__bindgen_ty_1 { reg: M68K_REG_D7 },
            type_: M68K_OP_REG,
            ..op_zero
        };
        assert_eq!(
            M68kOperand::new(&op_reg),
            M68kOperand::Reg(RegId(M68K_REG_D7 as RegIdInt))
        );

        // Imm
        let op_imm = cs_m68k_op {
            __bindgen_anon_1: cs_m68k_op__bindgen_ty_1 { imm: 42 },
            type_: M68K_OP_IMM,
            ..op_zero
        };
        assert_eq!(M68kOperand::new(&op_imm), M68kOperand::Imm(42));

        // Mem
        let op_mem1 = m68k_op_mem {
            base_reg: M68K_REG_A0,
            index_reg: M68K_REG_D0,
            index_size: 0, // w
            ..MEM_ZERO
        };
        let op_mem = cs_m68k_op {
            mem: op_mem1,
            address_mode: M68K_AM_MEMI_POST_INDEX,
            type_: M68K_OP_MEM,
            ..op_zero
        };
        let rust_op_mem = M68kOpMem {
            op_mem: op_mem1,
            address_mode: M68K_AM_MEMI_POST_INDEX,
            extra_info: M68kOpMemExtraInfo::None,
        };
        assert_eq!(
            M68kOperand::new(&op_mem),
            M68kOperand::Mem(rust_op_mem.clone())
        );
        assert_eq!(rust_op_mem.base_reg(), Some(RegId(M68K_REG_A0 as RegIdInt)));
        assert_eq!(
            rust_op_mem.index_reg(),
            Some(RegId(M68K_REG_D0 as RegIdInt))
        );
        assert_eq!(rust_op_mem.in_base_reg(), None);
        assert_eq!(rust_op_mem.disp(), 0);
        assert_eq!(rust_op_mem.scale(), 0);
        assert_eq!(rust_op_mem.bitfield(), None);
        assert_eq!(rust_op_mem.index_size(), M68kIndexSize::W);
        assert_eq!(rust_op_mem.address_mode(), M68K_AM_MEMI_POST_INDEX);
    }

    #[test]
    fn register_bits_mask() {
        assert_eq!(
            M68K_REGISTER_BITS_ALLOWED_MASK,
            0b11111111_11111111_11111111
        );
    }

    #[test]
    fn register_bits_from_bitfield() {
        assert!(M68kRegisterBits::from_bitfield(0xff).is_ok());
        assert!(M68kRegisterBits::from_bitfield(0xff_00).is_ok());
        assert!(M68kRegisterBits::from_bitfield(0xff_00_00).is_ok());
        assert!(M68kRegisterBits::from_bitfield(0xf_ff_00_00).is_err());
    }

    #[test]
    fn register_bits_from_iter() {
        let empty: &[m68k_reg::Type] = &[];
        assert_eq!(
            M68kRegisterBits::from_register_iter(empty.into_iter().map(|x| *x)),
            Ok(M68kRegisterBits { bits: 0 })
        );
        assert_eq!(
            M68kRegisterBits::from_register_iter([M68K_REG_D1].iter().map(|x| *x)),
            Ok(M68kRegisterBits { bits: 0b10 })
        );
        assert_eq!(
            M68kRegisterBits::from_register_iter(
                [M68K_REG_D1, M68K_REG_A2, M68K_REG_FP7].iter().map(|x| *x)
            ),
            Ok(M68kRegisterBits {
                bits: 0b1000_0000_0000_0100_0000_0010
            })
        );
    }

    #[test]
    fn register_bits_as_bits() {
        let mask = 0b00110011;
        assert_eq!(
            mask,
            M68kRegisterBits::from_bitfield(mask).unwrap().as_bits()
        );
    }

    #[test]
    fn op_eq() {
        use crate::arch::m68k::M68kOperand::*;
        use crate::arch::m68k::M68kReg::*;
        use crate::arch::m68k::*;
        use capstone_sys::m68k_address_mode::*;

        assert_ne!(
            M68kOperand::RegBits(
                M68kRegisterBits::from_register_iter(
                    [M68K_REG_D0, M68K_REG_D2, M68K_REG_A2, M68K_REG_A3]
                        .iter()
                        .map(|x| *x)
                )
                .unwrap()
            ),
            M68kOperand::RegBits(
                M68kRegisterBits::from_register_iter(
                    [M68K_REG_D0, M68K_REG_A2, M68K_REG_A3].iter().map(|x| *x)
                )
                .unwrap()
            )
        );
        assert_ne!(
            Mem(M68kOpMem {
                op_mem: MEM_ZERO,
                address_mode: M68K_AM_REGI_ADDR_PRE_DEC,
                extra_info: M68kOpMemExtraInfo::Reg(RegId(M68K_REG_A7 as RegIdInt)),
            }),
            Mem(M68kOpMem {
                op_mem: MEM_ZERO,
                address_mode: M68K_AM_REGI_ADDR_PRE_DEC,
                extra_info: M68kOpMemExtraInfo::Reg(RegId(M68K_REG_A6 as RegIdInt)),
            })
        );
    }

    #[cfg(feature = "not_diet")]
    #[test]
    fn extra_info() {
        use crate::arch::DetailsArchInsn;

        let cs = Capstone::new()
            .m68k()
            .mode(arch::m68k::ArchMode::M68k040)
            .detail(true)
            .build()
            .expect("Failed to create Capstone");

        let code_parts: &[&'static [u8]] = &[
            // jsr     $12.l
            b"\x4e\xb9\x00\x00\x00\x12",
        ];
        let code: Vec<u8> = code_parts
            .iter()
            .map(|x| x.iter())
            .flatten()
            .map(|x| *x)
            .collect();
        let insns = cs.disasm_all(&code, 0x1000).expect("Failed to disasm");
        let mut insns_iter = insns.iter();

        // jsr
        let insn_jsr: &Insn = insns_iter.next().unwrap();
        let detail = cs.insn_detail(&insn_jsr).unwrap();
        let _arch_detail = detail.arch_detail();
        let arch_detail = _arch_detail.m68k().unwrap();
        let mut ops = arch_detail.operands();
        if let M68kOperand::Mem(mem) = ops.next().unwrap() {
            assert_eq!(mem.imm(), Some(0x12));
        } else {
            panic!("Not expected type")
        }
    }
}
