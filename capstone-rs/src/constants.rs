use capstone_sys::cs_arch::*;
use capstone_sys::cs_opt_value::*;
use capstone_sys::*;
use core::convert::From;
use core::fmt::{self, Display};
use core::str::FromStr;

/// A C-like enum can list its variants
pub trait EnumList
where
    Self: Sized,
{
    /// Slice of available variants
    fn variants() -> &'static [Self];
}

/// Define the rust enum
macro_rules! define_cs_rust_enum {
    ( [
        $( #[$enum_attr:meta] )*
        => $rust_enum:ident = $cs_enum:ty
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
    }
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
      => $rust_variant:ident = $cs_variant:tt; )* ) => {

        define_cs_rust_enum!(
            [
                $( #[$enum_attr] )*
                => $rust_enum = $cs_enum
            ]
            $( $( #[$attr] )*
            => $rust_variant = $cs_variant; )*
        );

        impl ::core::convert::From<$rust_enum> for $cs_enum {
            fn from(other: $rust_enum) -> Self {
                match other {
                    $(
                        $rust_enum::$rust_variant => $cs_variant,
                    )*
                }
            }
        }

        impl EnumList for $rust_enum {
            fn variants() -> &'static [Self] {
                &[
                    $(
                        $rust_enum::$rust_variant,
                    )*
                ]
            }
        }

        impl FromStr for $rust_enum {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let s = s.to_lowercase();

                $(
                    if s == stringify!($rust_variant).to_lowercase() {
                        return Ok($rust_enum::$rust_variant);
                    }
                )*
                Err(concat!("Failed to parse ", stringify!($rust_enum)))
            }
        }

        impl Display for $rust_enum {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    $(
                        $rust_enum::$rust_variant => write!(f, "{}", stringify!($rust_variant)),
                    )*
                }

            }
        }
    }
}

/// Define Rust enum that is created from C enum
#[macro_export]
macro_rules! define_cs_enum_wrapper_reverse {
    ( [
        $( #[$enum_attr:meta] )*
        => $rust_enum:ident = $cs_enum:ident,
        $( from_u32 = $gen_from_u32:ident,)*
      ]
      $( $( #[$attr:meta] )*
      => $rust_variant:ident = $cs_variant:tt; )* ) => {

        define_cs_rust_enum!(
            [
                $( #[$enum_attr] )*
                => $rust_enum = $cs_enum
            ]
            $( $( #[$attr] )*
            => $rust_variant = $cs_variant; )*
        );

        impl ::core::convert::From<$cs_enum> for $rust_enum {
            fn from(other: $cs_enum) -> Self {
                match other {
                    $(
                        $cs_enum::$cs_variant => $rust_enum::$rust_variant,
                    )*
                }
            }
        }

        impl $rust_enum {
            /// Construct from a `u32`
            #[allow(dead_code)]
            pub(crate) fn from_u32(other: u32) -> Option<$rust_enum> {
                match other {
                    $(
                        x if x == ($cs_enum::$cs_variant as u32) => Some($rust_enum::$rust_variant),
                    )*
                    _ => None,
                }
            }
        }
    }
}

/// Defines getters for a bitmask
///
/// mask_constants must be unsigned integers with exactly one bit set to 1
#[macro_export]
macro_rules! define_impl_bitmask {
    (
        impl $struct:ident < $($impl_lifetime:lifetime),* > ;
        $mask_getter:ident : $mask_getter_ty:ty = { $get_mask:expr }
        test_mod = $test_mod:ident;
        $(
            $( #[$attr:meta] )*
            => $getter:ident = $mask_constant:ident;
        )*
    ) => {
        impl < $($impl_lifetime),* > $struct < $($impl_lifetime),* > {
            /// Raw mask from Capstone
            pub(crate) fn $mask_getter(&self) -> $mask_getter_ty {
                $get_mask(self)
            }

            $(
                $( #[$attr] )*
                pub fn $getter(&self) -> bool {
                    ($get_mask(self) & $mask_constant) != 0
                }
            )*
        }

        /// Test that masks have exactly one 1 bit set
        #[allow(non_snake_case)]
        #[cfg(test)]
        mod $test_mod {
            use super::*;

            $(
                #[test]
                fn $getter() {
                    assert_eq!($mask_constant.count_ones(), 1);
                }
            )*
        }
    }
}

define_cs_enum_wrapper!(
    [
        /// Architectures for the disassembler
        => Arch = cs_arch
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
    /// Motorolla 68K
    => M68K = CS_ARCH_M68K;
    /// Texas Instruments TMS320C64x
    => TMS320C64X = CS_ARCH_TMS320C64X;
    /// Motorola 68000
    => M680X = CS_ARCH_M680X;
    /// EVM
    => EVM = CS_ARCH_EVM;
    /// RISC-V
    => RISCV = CS_ARCH_RISCV;
    /// BPF
    => BPF = CS_ARCH_BPF;
);

define_cs_enum_wrapper!(
    [
        /// Disassembler modes
        => Mode = cs_mode
    ]
    /// 32-bit ARM
    => Arm = CS_MODE_ARM;
    /// 16-bit mode (X86)
    => Mode16 = CS_MODE_16;
    /// 32-bit mode (X86)
    => Mode32 = CS_MODE_32;
    /// 64-bit mode (X86, PPC)
    => Mode64 = CS_MODE_64;
    /// ARM's Thumb mode, including Thumb-2
    => Thumb = CS_MODE_THUMB;
    /// Mips II ISA
    => Mips2 = CS_MODE_MIPS2;
    /// Mips III ISA
    => Mips3 = CS_MODE_MIPS3;
    /// Mips32r6 ISA
    => Mips32R6 = CS_MODE_MIPS32R6;
    /// Mips32 ISA (Mips)
    => Mips32 = CS_MODE_MIPS32;
    /// Mips64 ISA (Mips)
    => Mips64 = CS_MODE_MIPS64;
    /// SparcV9 mode (Sparc)
    => V9 = CS_MODE_V9;
    /// Quad Processing eXtensions mode (PPC)
    => Qpx = CS_MODE_QPX;
    /// M68K 68000 mode
    => M68k000 = CS_MODE_M68K_000;
    /// M68K 68010 mode
    => M68k010 = CS_MODE_M68K_010;
    /// M68K 68020 mode
    => M68k020 = CS_MODE_M68K_020;
    /// M68K 68030 mode
    => M68k030 = CS_MODE_M68K_030;
    /// M68K 68040 mode
    => M68k040 = CS_MODE_M68K_040;
    /// M680X Hitachi 6301,6303 mode
    => M680x6301 = CS_MODE_M680X_6301;
    /// M680X Hitachi 6309 mode
    => M680x6309 = CS_MODE_M680X_6309;
    /// M680X Motorola 6800,6802 mode
    => M680x6800 = CS_MODE_M680X_6800;
    /// M680X Motorola 6801,6803 mode
    => M680x6801 = CS_MODE_M680X_6801;
    /// M680X Motorola/Freescale 6805 mode
    => M680x6805 = CS_MODE_M680X_6805;
    /// M680X Motorola/Freescale/NXP 68HC08 mode
    => M680x6808 = CS_MODE_M680X_6808;
    /// M680X Motorola 6809 mode
    => M680x6809 = CS_MODE_M680X_6809;
    /// M680X Motorola/Freescale/NXP 68HC11 mode
    => M680x6811 = CS_MODE_M680X_6811;
    /// M680X Motorola/Freescale/NXP CPU12
    => M680xCpu12 = CS_MODE_M680X_CPU12;
    /// M680X Freescale/NXP HCS08 mode
    => M680xHcs08 = CS_MODE_M680X_HCS08;
    /// RISC-V 32-bit mode
    => RiscV32 = CS_MODE_RISCV32;
    /// RISC-V 64-bit mode
    => RiscV64 = CS_MODE_RISCV64;
    /// Classic BPF mode
    => Cbpf = CS_MODE_BPF_CLASSIC;
    /// Extended BPF mode
    => Ebpf = CS_MODE_BPF_EXTENDED;
    /// Default mode for little-endian
    => Default = CS_MODE_LITTLE_ENDIAN;
);

define_cs_enum_wrapper!(
    [
        /// Extra modes or features that can be enabled with some modes
        => ExtraMode = cs_mode
    ]
    /// ARM's Cortex-M series. Works with `Arm` mode.
    => MClass = CS_MODE_MCLASS;
    /// ARMv8 A32 encodings for ARM. Works with `Arm` and `Thumb` modes.
    => V8 = CS_MODE_V8;
    /// MicroMips mode. Works in `MIPS` mode.
    => Micro = CS_MODE_MICRO;
    /// RISC-V compressed instruction mode
    => RiscVC = CS_MODE_RISCVC;
);

define_cs_enum_wrapper!(
    [
        /// Disassembler endianness
        => Endian = cs_mode
    ]
    /// Little-endian mode
    => Little = CS_MODE_LITTLE_ENDIAN;
    /// Big-endian mode
    => Big = CS_MODE_BIG_ENDIAN;
);

define_cs_enum_wrapper!(
    [
        /// Disassembly syntax
        => Syntax = cs_opt_value::Type
    ]
    /// Intel syntax
    => Intel = CS_OPT_SYNTAX_INTEL;
    /// AT&T syntax (also known as GNU assembler/GAS syntax)
    => Att = CS_OPT_SYNTAX_ATT;
    /// MASM syntax
    => Masm = CS_OPT_SYNTAX_MASM;
    /// No register name
    => NoRegName = CS_OPT_SYNTAX_NOREGNAME;
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

    #[test]
    fn parse_arch() {
        assert_eq!(Arch::from_str("x86"), Ok(Arch::X86));
        assert_eq!(Arch::from_str("X86"), Ok(Arch::X86));
    }
}
