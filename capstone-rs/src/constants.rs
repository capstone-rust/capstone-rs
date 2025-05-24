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
        #[allow(clippy::redundant_closure_call)]
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
    => AARCH64 = CS_ARCH_AARCH64;
    /// Alpha
    => ALPHA = CS_ARCH_ALPHA;
    /// HPPA
    => HPPA = CS_ARCH_HPPA;
    /// LoongArch
    => LOONGARCH = CS_ARCH_LOONGARCH;
    /// MIPS
    => MIPS = CS_ARCH_MIPS;
    /// x86 family (includes 16, 32, and 64 bit modes)
    => X86 = CS_ARCH_X86;
    /// PowerPC
    => PPC = CS_ARCH_PPC;
    /// SH
    => SH = CS_ARCH_SH;
    /// SPARC
    => SPARC = CS_ARCH_SPARC;
    /// System z
    => SYSTEMZ = CS_ARCH_SYSTEMZ;
    /// XCore
    => XCORE = CS_ARCH_XCORE;
    /// Motorolla 68K
    => M68K = CS_ARCH_M68K;
    /// MOS65XX architecture (including MOS6502)
    => MOS65XX = CS_ARCH_MOS65XX;
    /// Texas Instruments TMS320C64x
    => TMS320C64X = CS_ARCH_TMS320C64X;
    /// TriCore
    => TRICORE = CS_ARCH_TRICORE;
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
    => Arm = { cs_mode::CS_MODE_ARM };
    /// 16-bit mode (X86)
    => Mode16 = { cs_mode::CS_MODE_16 };
    /// 32-bit mode (X86)
    => Mode32 = { cs_mode::CS_MODE_32 };
    /// 64-bit mode (X86, PPC)
    => Mode64 = { cs_mode::CS_MODE_64 };
    /// ARM's Thumb mode, including Thumb-2
    => Thumb = { cs_mode::CS_MODE_THUMB };
    /// Mips II ISA
    => Mips2 = { cs_mode::CS_MODE_MIPS2 };
    /// Mips III ISA
    => Mips3 = { cs_mode::CS_MODE_MIPS3 };
    /// Mips32r6 ISA
    => Mips32R6 = { cs_mode::CS_MODE_MIPS32R6 };
    /// Mips32 ISA (Mips)
    => Mips32 = { cs_mode::CS_MODE_MIPS32 };
    /// Mips64 ISA (Mips)
    => Mips64 = { cs_mode::CS_MODE_MIPS64 };
    /// SparcV9 mode (Sparc)
    => V9 = { cs_mode::CS_MODE_V9 };
    /// Quad Processing eXtensions mode (PPC)
    => Qpx = { cs_mode::CS_MODE_QPX };
    /// M68K 68000 mode
    => M68k000 = { cs_mode::CS_MODE_M68K_000 };
    /// M68K 68010 mode
    => M68k010 = { cs_mode::CS_MODE_M68K_010 };
    /// M68K 68020 mode
    => M68k020 = { cs_mode::CS_MODE_M68K_020 };
    /// M68K 68030 mode
    => M68k030 = { cs_mode::CS_MODE_M68K_030 };
    /// M68K 68040 mode
    => M68k040 = { cs_mode::CS_MODE_M68K_040 };
    /// M680X Hitachi 6301,6303 mode
    => M680x6301 = { cs_mode::CS_MODE_M680X_6301 };
    /// M680X Hitachi 6309 mode
    => M680x6309 = { cs_mode::CS_MODE_M680X_6309 };
    /// M680X Motorola 6800,6802 mode
    => M680x6800 = { cs_mode::CS_MODE_M680X_6800 };
    /// M680X Motorola 6801,6803 mode
    => M680x6801 = { cs_mode::CS_MODE_M680X_6801 };
    /// M680X Motorola/Freescale 6805 mode
    => M680x6805 = { cs_mode::CS_MODE_M680X_6805 };
    /// M680X Motorola/Freescale/NXP 68HC08 mode
    => M680x6808 = { cs_mode::CS_MODE_M680X_6808 };
    /// M680X Motorola 6809 mode
    => M680x6809 = { cs_mode::CS_MODE_M680X_6809 };
    /// M680X Motorola/Freescale/NXP 68HC11 mode
    => M680x6811 = { cs_mode::CS_MODE_M680X_6811 };
    /// M680X Motorola/Freescale/NXP CPU12
    => M680xCpu12 = { cs_mode::CS_MODE_M680X_CPU12 };
    /// M680X Freescale/NXP HCS08 mode
    => M680xHcs08 = { cs_mode::CS_MODE_M680X_HCS08 };
    /// MOS65XXX MOS 6502
    => Mos65xx6502 = { cs_mode::CS_MODE_MOS65XX_6502 };
    /// MOS65XXX WDC 65c02
    => Mos65xx65c02 = { cs_mode::CS_MODE_MOS65XX_65C02 };
    /// MOS65XXX WDC W65c02
    => Mos65xxW65c02 = { cs_mode::CS_MODE_MOS65XX_W65C02 };
    /// MOS65XXX WDC 65816, 8-bit m/x
    => Mos65xx65816 = { cs_mode::CS_MODE_MOS65XX_65816 };
    /// MOS65XXX WDC 65816, 16-bit m, 8-bit x
    => Mos65xx65816LongM = { cs_mode::CS_MODE_MOS65XX_65816_LONG_M };
    /// MOS65XXX WDC 65816, 8-bit m, 16-bit x
    => Mos65xx65816LongX = { cs_mode::CS_MODE_MOS65XX_65816_LONG_M };
    /// MOS65XXX WDC 65816, 16-bit m, 16-bit x
    => Mos65xx65816LongMx = { cs_mode::CS_MODE_MOS65XX_65816_LONG_MX };
    /// SH2
    => Sh2 = { cs_mode::CS_MODE_SH2 };
    /// SH2A
    => Sh2a = { cs_mode::CS_MODE_SH2A };
    /// SH3
    => Sh3 = { cs_mode::CS_MODE_SH3 };
    /// SH4
    => Sh4 = { cs_mode::CS_MODE_SH4 };
    /// SH4A
    => Sh4a = { cs_mode::CS_MODE_SH4A };
    /// SH w/ FPU
    => ShFpu = { cs_mode::CS_MODE_SHFPU };
    /// SH w/ DSP
    => ShDsp = { cs_mode::CS_MODE_SHDSP };
    /// RISC-V 32-bit mode
    => RiscV32 = { cs_mode::CS_MODE_RISCV32 };
    /// RISC-V 64-bit mode
    => RiscV64 = { cs_mode::CS_MODE_RISCV64 };
    /// Classic BPF mode
    => Cbpf = { cs_mode::CS_MODE_BPF_CLASSIC };
    /// Extended BPF mode
    => Ebpf = { cs_mode::CS_MODE_BPF_EXTENDED };
    /// TriCore 1.1
    => TriCore110 = { cs_mode::CS_MODE_TRICORE_110 };
    /// TriCore 1.2
    => TriCore120 = { cs_mode::CS_MODE_TRICORE_120 };
    /// TriCore 1.3
    => TriCore130 = { cs_mode::CS_MODE_TRICORE_130 };
    /// TriCore 1.3.1
    => TriCore131 = { cs_mode::CS_MODE_TRICORE_131 };
    /// TriCore 1.6
    => TriCore160 = { cs_mode::CS_MODE_TRICORE_160 };
    /// TriCore 1.6.1
    => TriCore161 = { cs_mode::CS_MODE_TRICORE_161 };
    /// TriCore 1.6.2
    => TriCore162 = { cs_mode::CS_MODE_TRICORE_162 };
    /// SystemZ ARCH8
    => SystemZArch8 = { cs_mode::CS_MODE_SYSTEMZ_ARCH8 };
    /// SystemZ ARCH9
    => SystemZArch9 = { cs_mode::CS_MODE_SYSTEMZ_ARCH9 };
    /// SystemZ ARCH10
    => SystemZArch10 = { cs_mode::CS_MODE_SYSTEMZ_ARCH10 };
    /// SystemZ ARCH11
    => SystemZArch11 = { cs_mode::CS_MODE_SYSTEMZ_ARCH11 };
    /// SystemZ ARCH12
    => SystemZArch12 = { cs_mode::CS_MODE_SYSTEMZ_ARCH12 };
    /// SystemZ ARCH13
    => SystemZArch13 = { cs_mode::CS_MODE_SYSTEMZ_ARCH13 };
    /// SystemZ ARCH14
    => SystemZArch14 = { cs_mode::CS_MODE_SYSTEMZ_ARCH14 };
    /// SystemZ Z10
    => SystemZZ10 = { cs_mode::CS_MODE_SYSTEMZ_Z10 };
    /// SystemZ Z196
    => SystemZZ196 = { cs_mode::CS_MODE_SYSTEMZ_Z196 };
    /// SystemZ ZEC12
    => SystemZZec12 = { cs_mode::CS_MODE_SYSTEMZ_ZEC12 };
    /// SystemZ Z13
    => SystemZZ13 = { cs_mode::CS_MODE_SYSTEMZ_Z13 };
    /// SystemZ Z14
    => SystemZZ14 = { cs_mode::CS_MODE_SYSTEMZ_Z14 };
    /// SystemZ Z15
    => SystemZZ15 = { cs_mode::CS_MODE_SYSTEMZ_Z15 };
    /// SystemZ Z16
    => SystemZZ16 = { cs_mode::CS_MODE_SYSTEMZ_Z16 };
    /// SystemZ Generic
    => SystemZGeneric = { cs_mode::CS_MODE_SYSTEMZ_GENERIC };
    /// HPPA 1.1
    => Hppa11 = { cs_mode::CS_MODE_HPPA_11 };
    /// HPPA 2.0
    => Hppa20 = { cs_mode::CS_MODE_HPPA_20 };
    /// HPPA 2.0 wide
    => Hppa20W = { cs_mode::CS_MODE_HPPA_20W };
    /// LoongArch32
    => LoongArch32 = { cs_mode::CS_MODE_LOONGARCH32 };
    /// LoongArch64
    => LoongArch64 = { cs_mode::CS_MODE_LOONGARCH64 };
    /// Default mode for little-endian
    => Default = { cs_mode::CS_MODE_LITTLE_ENDIAN };
);

define_cs_enum_wrapper!(
    [
        /// Extra modes or features that can be enabled with some modes
        => ExtraMode = cs_mode
    ]
    /// ARM's Cortex-M series. Works with `Arm` mode.
    => MClass = { cs_mode::CS_MODE_MCLASS };
    /// ARMv8 A32 encodings for ARM. Works with `Arm` and `Thumb` modes.
    => V8 = { cs_mode::CS_MODE_V8 };
    /// MicroMips mode. Works in `MIPS` mode.
    => Micro = { cs_mode::CS_MODE_MICRO };
    /// RISC-V compressed instruction mode
    => RiscVC = { cs_mode::CS_MODE_RISCVC };
);

define_cs_enum_wrapper!(
    [
        /// Disassembler endianness
        => Endian = cs_mode
    ]
    /// Little-endian mode
    => Little = { cs_mode::CS_MODE_LITTLE_ENDIAN };
    /// Big-endian mode
    => Big = { cs_mode::CS_MODE_BIG_ENDIAN };
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
