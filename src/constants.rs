use capstone_sys::*;
use capstone_sys::cs_arch::*;
use capstone_sys::cs_mode::*;
use std::convert::From;

/// Define an `enum` that corresponds to a capstone enum
///
/// The different `From` implementations can be disabled by using the cfg attribute
macro_rules! define_cs_enum_wrapper {
    ( [
        $( #[$enum_attr:meta] )*
        => $rust_enum:ident = $cs_enum:ident,
        $( #[$cs_to_rust_attrs:meta] )*
        ,
        $( #[$rust_to_cs_attrs:meta] )*
      ]
      $( $( #[$attr:meta] )*
      => $rust_variant:ident = $cs_variant:tt; )* ) => {

        $( #[$enum_attr] )*
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub enum $rust_enum {
            $(
                $( #[$attr] )*
                $rust_variant,
            )*
        }

        $( #[$cs_to_rust_attrs] )*
        impl From<$cs_enum> for $rust_enum {
            fn from(other: $cs_enum) -> Self {
                match other {
                    $(
                        $cs_enum::$cs_variant => $rust_enum::$rust_variant,
                    )*
                }
            }
        }

        $( #[$rust_to_cs_attrs] )*
        impl From<$rust_enum> for $cs_enum {
            fn from(other: $rust_enum) -> Self {
                match other {
                    $(
                        $rust_enum::$rust_variant => $cs_variant,
                    )*
                }
            }
        }
    }
}

define_cs_enum_wrapper!(
    [
        /// Architectures for the disassembler
        => Arch = cs_arch,
        ,
    ]
    /// ARM (Advanced RISC Machine)
    => ARM = CS_ARCH_ARM;
    /// ARM 64-bit (also known as AArch64)
    => ARM64 = CS_ARCH_ARM64;
    /// MIPS
    => MIPS = CS_ARCH_MIPS;
    /// x86 family (includes 16, 32, and 64 bit modes)
    => X86 = CS_ARCH_X86;
    /// PowerPC
    => PPC = CS_ARCH_PPC;
    /// SPARC
    => SPARC = CS_ARCH_SPARC;
    /// System z
    => SYSZ = CS_ARCH_SYSZ;
    /// XCore
    => XCORE = CS_ARCH_XCORE;
    => MAX = CS_ARCH_MAX;
    /// used for `cs_support()`
    => ALL = CS_ARCH_ALL;
);

define_cs_enum_wrapper!(
    [
        /// Disassembler modes
        => Mode = cs_mode,
        #[cfg(other)]
        ,
    ]
    /// little-endian mode
    => LittleEndian = CS_MODE_LITTLE_ENDIAN;
    /// 32-bit ARM
    => Arm32 = CS_MODE_ARM;
    /// 16-bit mode (X86)
    => Mode16 = CS_MODE_16;
    /// 32-bit mode (X86)
    => Mode32 = CS_MODE_32;
    /// 64-bit mode (X86, PPC)
    => Mode64 = CS_MODE_64;
    /// ARM's Thumb mode, including Thumb-2
    => Thumb = CS_MODE_THUMB;
    /// ARM's Cortex-M series
    => MClass = CS_MODE_MCLASS;
    /// ARMv8 A32 encodings for ARM
    => V8 = CS_MODE_V8;
    /// MicroMips mode (MIPS)
    => Micro = CS_MODE_MICRO;
    /// Mips III ISA
    => Mips3 = CS_MODE_MIPS3;
    /// Mips32r6 ISA
    => Mips32R6 = CS_MODE_MIPS32R6;
    /// General Purpose Registers are 64-bit wide (MIPS)
    => MipsGP64 = CS_MODE_MIPSGP64;
    /// SparcV9 mode (Sparc)
    => V9 = CS_MODE_V9;
    /// big-endian mode
    => BigEndian = CS_MODE_BIG_ENDIAN;
    /// Mips32 ISA (Mips)
    => Mips32 = CS_MODE_MIPS32;
    /// Mips64 ISA (Mips)
    => Mips64 = CS_MODE_MIPS64;
);

pub(crate) struct OptValue(pub cs_opt_value);

impl From<bool> for OptValue {
    fn from(value: bool) -> Self {
        if value {
            OptValue(cs_opt_value::CS_OPT_ON)
        } else {
            OptValue(cs_opt_value::CS_OPT_OFF)
        }
    }
}
