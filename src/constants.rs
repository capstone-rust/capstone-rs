use capstone_sys::cs_arch::*;
use capstone_sys::cs_opt_value::*;
use capstone_sys::*;
use std::convert::From;
use std::fmt::{self, Display};
use std::str::FromStr;


/// Extension trait for C-like enums (no variants have associated data).
/// The string va
pub trait CsEnumVariants: Display + FromStr {
    /// Variants of the Enum
    fn variants() -> &'static [Self];

    /// String variants of enum that MUST translate to the corresponding
    fn str_variants() -> &'static [&'static str];
}

/// Define an `enum` that corresponds to a capstone enum
///
/// The different `From` implementations can be disabled by using the cfg attribute
macro_rules! define_cs_enum_wrapper {
    ( [
        $( #[$enum_attr:meta] )*
        => $rust_enum:ident = $cs_enum:ty
      ]
      $( $( #[$attr:meta] )*
      => $rust_variant:ident ($str_val:ident) = $cs_variant:tt; )* ) => {

        $( #[$enum_attr] )*
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub enum $rust_enum {
            $(
                $( #[$attr] )*
                $rust_variant,
            )*
        }

        impl ::std::convert::From<$rust_enum> for $cs_enum {
            fn from(other: $rust_enum) -> Self {
                match other {
                    $(
                        $rust_enum::$rust_variant => $cs_variant,
                    )*
                }
            }
        }

        impl Display for $rust_enum {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let str_value: &str = match *self {
                    $(
                        $rust_enum::$rust_variant => stringify!($str_val),
                    )*
                };

                write!(f, "{}", str_value)
            }
        }

        impl FromStr for $rust_enum {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(
                        stringify!($str_val) => Ok($rust_enum::$rust_variant),
                    )*
                    _ => Err(concat!("Unable to parse ", stringify!($rust_enum))),
                }
            }
        }

        impl CsEnumVariants for $rust_enum {
            fn variants() -> &'static [Self] {
                &[
                    $( $rust_enum::$rust_variant, )*
                ]
            }

            fn str_variants() -> &'static [&'static str] {
                &[
                    $( stringify!($str_val), )*
                ]
            }
        }
    }
}

define_cs_enum_wrapper!(
    [
        /// Architectures for the disassembler
        => Arch = cs_arch
    ]
    /// ARM (Advanced RISC Machine)
    => ARM (arm) = CS_ARCH_ARM;
    /// ARM 64-bit (also known as AArch64)
    => ARM64 (arm64) = CS_ARCH_ARM64;
    /// MIPS
    => MIPS (mips) = CS_ARCH_MIPS;
    /// x86 family (includes 16, 32, and 64 bit modes)
    => X86 (x86) = CS_ARCH_X86;
    /// PowerPC
    => PPC (powerpc) = CS_ARCH_PPC;
    /// SPARC
    => SPARC (sparc) = CS_ARCH_SPARC;
    /// System z
    => SYSZ (systemz) = CS_ARCH_SYSZ;
    /// XCore
    => XCORE (xcore) = CS_ARCH_XCORE;
);

define_cs_enum_wrapper!(
    [
        /// Disassembler modes
        => Mode = cs_mode
    ]
    /// 32-bit ARM
    => Arm (arm) = CS_MODE_ARM;
    /// 16-bit mode (X86)
    => Mode16 (mode16) = CS_MODE_16;
    /// 32-bit mode (X86)
    => Mode32 (mode32) = CS_MODE_32;
    /// 64-bit mode (X86, PPC)
    => Mode64 (mode64) = CS_MODE_64;
    /// ARM's Thumb mode, including Thumb-2
    => Thumb (thumb) = CS_MODE_THUMB;
    /// Mips III ISA
    => Mips3 (mips3) = CS_MODE_MIPS3;
    /// Mips32r6 ISA
    => Mips32R6 (mips32r6) = CS_MODE_MIPS32R6;
    /// General Purpose Registers are 64-bit wide (MIPS)
    => MipsGP64 (mipsgp64) = CS_MODE_MIPSGP64;
    /// SparcV9 mode (Sparc)
    => V9 (v9) = CS_MODE_V9;
    /// Default mode for little-endian
    => Default (default) = CS_MODE_LITTLE_ENDIAN;
);

define_cs_enum_wrapper!(
    [
        /// Extra modes or features that can be enabled with some modes
        => ExtraMode = cs_mode
    ]
    /// ARM's Cortex-M series. Works with `Arm` mode.
    => MClass (mclass) = CS_MODE_MCLASS;
    /// ARMv8 A32 encodings for ARM. Works with `Arm` and `Thumb` modes.
    => V8 (v8) = CS_MODE_V8;
    /// MicroMips mode. Works in `MIPS` mode.
    => Micro (micro) = CS_MODE_MICRO;
);

define_cs_enum_wrapper!(
    [
        /// Disassembler endianness
        => Endian = cs_mode
    ]
    /// Little-endian mode
    => Little (little) = CS_MODE_LITTLE_ENDIAN;
    /// Big-endian mode
    => Big (big) = CS_MODE_BIG_ENDIAN;
);

define_cs_enum_wrapper!(
    [
        /// Disassembly syntax
        => Syntax = cs_opt_value::Type
    ]
    /// Intel syntax
    => Intel (intel) = CS_OPT_SYNTAX_INTEL;
    /// AT&T syntax (also known as GNU assembler/GAS syntax)
    => Att (att) = CS_OPT_SYNTAX_ATT;
    /// No register name
    => NoRegName (noregname) = CS_OPT_SYNTAX_NOREGNAME;
);

pub(crate) struct OptValue(pub cs_opt_value::Type);

impl From<bool> for OptValue {
    fn from(value: bool) -> Self {
        if value {
            OptValue(cs_opt_value::CS_OPT_ON)
        } else {
            OptValue(cs_opt_value::CS_OPT_OFF)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

}
#[test]
fn constant_string() {
    macro_rules! test_conversion {
            ($mytype:ident) => {
                for variant in $mytype::variants() {
                    let formatted = format!("{}", variant);
                    assert_eq!(formatted.parse::<$mytype>(), Ok(*variant));
                }
            }
        }
    test_conversion!(Arch);
    test_conversion!(Mode);
    test_conversion!(Syntax);
    test_conversion!(ExtraMode);
    assert!("X86089098".parse::<Arch>().is_err());
}
