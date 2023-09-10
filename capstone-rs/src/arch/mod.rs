//! Contains architecture-specific types and modules

// We use explicit casts from c_int (and such) so the code compiles on platforms with different
// integer widths
#![allow(clippy::unnecessary_cast)]

use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use crate::capstone::Capstone;
use crate::constants::Endian;
use crate::error::CsResult;

macro_rules! define_subset_enum {
    ( [
        $subset_enum:ident = $base_enum:ident
      ]
      $( $variant:ident, )*
    ) => {
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub enum $subset_enum {
            $(
                $variant,
            )*
        }

        impl From<$subset_enum> for $base_enum {
            fn from(other: $subset_enum) -> $base_enum {
                match other {
                    $(
                        $subset_enum::$variant => $base_enum::$variant,
                    )*
                }
            }
        }
    };
}

/// Define arch builders
macro_rules! define_arch_builder {
    // ExtraMode rules
    ( @extra_modes () ) => {};
    ( @extra_modes ( $( $extra_mode:ident, )+ ) ) => {
        impl super::BuildsCapstoneExtraMode<ArchMode, ArchExtraMode> for ArchCapstoneBuilder {
            fn extra_mode<T: Iterator<Item=ArchExtraMode>>(mut self, extra_mode: T) -> Self {
                self.extra_mode.clear();
                self.extra_mode.extend(extra_mode);
                self
            }
        }
    };

    // Syntax rules
    ( @syntax () ) => {};
    ( @syntax ( $( $syntax:ident, )+ ) ) => {
        impl super::BuildsCapstoneSyntax<ArchMode, ArchSyntax> for ArchCapstoneBuilder {
            fn syntax(mut self, syntax: ArchSyntax) -> Self {
                self.syntax = Some(syntax);
                self
            }
        }
    };

    // Endian rules
    ( @endian ( false) ) => {};
    ( @endian ( true ) ) => {
        impl super::BuildsCapstoneEndian<ArchMode> for ArchCapstoneBuilder {
            fn endian(mut self, endian: Endian) -> Self {
                self.endian = Some(endian);
                self
            }
        }
    };

    // Entrance rule
    (
        $( [
            ( $arch:ident, $arch_variant:ident )
            ( mode: $( $mode:ident, )+ )
            ( extra_modes: $( $extra_mode:ident, )* )
            ( syntax: $( $syntax:ident, )* )
            ( both_endian: $( $endian:ident )* )
        ] )+
    ) => {
        // We put builders in `arch::arch_builder::$ARCH` so we can put manual arch-specific code
        // in `arch::$ARCH`. The contents of each module is imported from `arch::$ARCH`.

        $(
            /// Architecture-specific build code
            pub mod $arch {
                use alloc::vec::Vec;

                use crate::capstone::Capstone;
                use crate::constants::{Arch, Endian, ExtraMode, Mode, Syntax};
                use crate::error::{CsResult, Error};

                define_arch_builder!( @syntax ( $( $syntax, )* ) );
                define_arch_builder!( @endian ( $( $endian )* ) );
                define_arch_builder!( @extra_modes ( $( $extra_mode, )* ) );

                define_subset_enum!(
                    [ ArchMode = Mode ]
                    $( $mode, )*
                );

                define_subset_enum!(
                    [ ArchExtraMode = ExtraMode ]
                    $( $extra_mode, )*
                );

                define_subset_enum!(
                    [ ArchSyntax = Syntax ]
                    $( $syntax, )*
                );

                #[derive(Clone)]
                pub struct ArchCapstoneBuilder {
                    pub(crate) mode: Option<ArchMode>,
                    pub(crate) is_detail: bool,
                    pub(crate) extra_mode: Vec<ArchExtraMode>,
                    pub(crate) syntax: Option<ArchSyntax>,
                    pub(crate) endian: Option<Endian>,
                }

                impl super::BuildsCapstone<ArchMode> for ArchCapstoneBuilder {
                    fn mode(mut self, mode: ArchMode) -> Self {
                        self.mode = Some(mode);
                        self
                    }

                    fn detail(mut self, enable_detail: bool) -> Self {
                        self.is_detail = enable_detail;
                        self
                    }

                    fn build(self) -> CsResult<Capstone> {
                        let mode = match self.mode {
                            Some(mode) => mode,
                            None => {
                                let msg: &'static str = concat!(
                                    "Must specify mode for ",
                                    stringify!($arch),
                                    "::ArchCapstoneBuilder with `mode()` method",
                                );
                                return Err(Error::CustomError(msg));
                            }
                        };
                        let extra_mode = self.extra_mode.iter().map(|x| ExtraMode::from(*x));
                        let mut capstone = Capstone::new_raw(Arch::$arch_variant,
                                                             mode.into(),
                                                             extra_mode,
                                                             self.endian)?;

                        if let Some(syntax) = self.syntax {
                            capstone.set_syntax(Syntax::from(syntax))?;
                        }
                        if self.is_detail {
                            capstone.set_detail(self.is_detail)?;
                        }

                        Ok(capstone)
                    }
                }

                impl Default for ArchCapstoneBuilder {
                    fn default() -> Self {
                        ArchCapstoneBuilder {
                            mode: None,
                            is_detail: false,
                            extra_mode: vec![],
                            endian: None,
                            syntax: None,
                        }
                    }
                }
            }
        )+

        impl CapstoneBuilder {
            $(
                pub fn $arch(self) -> $arch::ArchCapstoneBuilder {
                    Default::default()
                }
            )*
        }
    }
}

/// Base X macro with arch info
///
/// Notes:
/// - Even though [Capstone's documentation](https://www.capstone-engine.org/lang_c.html)
///   classifies V9 as an extra mode, we classify it as a Mode since the only other mode is Default
///   (which is treated as Big endian)
macro_rules! arch_info_base {
    ($x_macro:ident) => {
        $x_macro!(
            [
                ( arm, ARM )
                ( mode:
                    Arm,
                    Thumb,
                    )
                ( extra_modes:
                    MClass,
                    V8,
                    )
                ( syntax:
                    NoRegName,
                    )
                ( both_endian: true )
            ]
            [
                ( arm64, ARM64 )
                ( mode:
                    Arm,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: true )
            ]
            [
                ( evm, EVM )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( m680x, M680X )
                ( mode:
                    M680x6301,
                    M680x6309,
                    M680x6800,
                    M680x6801,
                    M680x6805,
                    M680x6808,
                    M680x6809,
                    M680x6811,
                    M680xCpu12,
                    M680xHcs08,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( m68k, M68K )
                ( mode:
                    M68k000,
                    M68k010,
                    M68k020,
                    M68k030,
                    M68k040,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( mips, MIPS )
                ( mode:
                    Mips32,
                    Mips64,
                    Mips2,
                    Mips3,
                    Mips32R6,
                    )
                ( extra_modes:
                    Micro,
                    )
                ( syntax: )
                ( both_endian: true )
            ]
            [
                ( ppc, PPC )
                ( mode:
                    Mode32,
                    Mode64,
                    Qpx,
                    )
                ( extra_modes: )
                ( syntax:
                    NoRegName,
                    )
                ( both_endian: true )
            ]
            [
                ( riscv, RISCV )
                ( mode:
                    RiscV32,
                    RiscV64,
                    )
                ( extra_modes:
                    RiscVC,
                    )
                ( syntax: )
                ( both_endian: true )
            ]
            [
                ( sparc, SPARC )
                ( mode:
                    Default,
                    V9,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( sysz, SYSZ )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( tms320c64x, TMS320C64X )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( x86, X86 )
                ( mode:
                    Mode16,
                    Mode32,
                    Mode64,
                    )
                ( extra_modes: )
                ( syntax:
                    Intel,
                    Att,
                    Masm,
                    )
                ( both_endian: false )
            ]
            [
                ( xcore, XCORE )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false  )
            ]
            [
                ( bpf, BPF )
                ( mode:
                    Cbpf,
                    Ebpf,
                )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: true  )
            ]
        );
    };
}

/// Builds a `Capstone` struct
pub trait BuildsCapstone<ArchMode> {
    /// Set the disassembly mode
    fn mode(self, mode: ArchMode) -> Self;

    /// Enable detailed output
    fn detail(self, enable_detail: bool) -> Self;

    /// Get final `Capstone`
    fn build(self) -> CsResult<Capstone>;
}

/// Implies that a `CapstoneBuilder` architecture has extra modes
pub trait BuildsCapstoneExtraMode<ArchMode, ArchExtraMode>: BuildsCapstone<ArchMode> {
    /// Set architecture endianness
    fn extra_mode<T: Iterator<Item = ArchExtraMode>>(self, extra_mode: T) -> Self;
}

/// Implies that a `CapstoneBuilder` has different syntax options
pub trait BuildsCapstoneSyntax<ArchMode, ArchSyntax>: BuildsCapstone<ArchMode> {
    /// Set the disassembly syntax
    fn syntax(self, syntax: ArchSyntax) -> Self;
}

/// Implies that a `CapstoneBuilder` architecture has a configurable endianness
pub trait BuildsCapstoneEndian<ArchMode>: BuildsCapstone<ArchMode> {
    /// Set architecture endianness
    fn endian(self, endian: Endian) -> Self;
}

/// Contains builder-pattern implementations
pub(crate) mod arch_builder {
    use super::*;

    arch_info_base!(define_arch_builder);
}

/// Builds `Capstone` object
#[derive(Debug)]
pub struct CapstoneBuilder(
    /// Hidden field to prevent users from instantiating `CapstoneBuilder`
    PhantomData<()>,
);

impl CapstoneBuilder {
    /// Create a `CapstoneBuilder`
    pub(crate) fn new() -> Self {
        CapstoneBuilder(PhantomData)
    }
}

/// Provides architecture-specific details about an instruction
pub trait DetailsArchInsn: PartialEq + Debug {
    type Operand: Into<ArchOperand> + Default + Clone + Debug + PartialEq;
    type OperandIterator: Iterator<Item = Self::Operand>;

    fn operands(&self) -> Self::OperandIterator;
}

/// Define PartialEq for a type given representation getter methods
macro_rules! impl_PartialEq_repr_fields {
    // With generic parameters
    (
        $name:ty [ $( $lifetime:tt ),* ];
        $( $field:ident),*
    ) => {
        impl<$( $lifetime ),*> ::core::cmp::PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                $(
                    if self.$field() != other.$field() {
                        return false;
                    }
                )*
                true
            }
        }
    };

    // No generic parameters
    (
        $name:ty;
        $( $field:ident),*
    ) => {
        impl_PartialEq_repr_fields!(
            $name [];
            $( $field),*
        );
    };
}

/// Base macro for defining arch details
macro_rules! detail_arch_base {
    ($x_macro:ident) => {
        $x_macro!(
            [
                detail = ArmDetail,
                insn_detail = ArmInsnDetail<'a>,
                op = ArmOperand,
                /// Returns the ARM details, if any
                => arch_name = arm,
            ]
            [
                detail = Arm64Detail,
                insn_detail = Arm64InsnDetail<'a>,
                op = Arm64Operand,
                /// Returns the ARM64 details, if any
                => arch_name = arm64,
            ]
            [
                detail = EvmDetail,
                insn_detail = EvmInsnDetail<'a>,
                op = EvmOperand,
                /// Returns the EVM details, if any
                => arch_name = evm,
            ]
            [
                detail = M680xDetail,
                insn_detail = M680xInsnDetail<'a>,
                op = M680xOperand,
                /// Returns the M680X details, if any
                => arch_name = m680x,
            ]
            [
                detail = M68kDetail,
                insn_detail = M68kInsnDetail<'a>,
                op = M68kOperand,
                /// Returns the M68K details, if any
                => arch_name = m68k,
            ]
            [
                detail = MipsDetail,
                insn_detail = MipsInsnDetail<'a>,
                op = MipsOperand,
                /// Returns the MIPS details, if any
                => arch_name = mips,
            ]
            [
                detail = PpcDetail,
                insn_detail = PpcInsnDetail<'a>,
                op = PpcOperand,
                /// Returns the PPC details, if any
                => arch_name = ppc,
            ]
            [
                detail = RiscVDetail,
                insn_detail = RiscVInsnDetail<'a>,
                op = RiscVOperand,
                /// Returns the RISCV details, if any
                => arch_name = riscv,
            ]
            [
                detail = SparcDetail,
                insn_detail = SparcInsnDetail<'a>,
                op = SparcOperand,
                /// Returns the SPARC details, if any
                => arch_name = sparc,
            ]
            [
                detail = Tms320c64xDetail,
                insn_detail = Tms320c64xInsnDetail<'a>,
                op = Tms320c64xOperand,
                /// Returns the Tms320c64x details, if any
                => arch_name = tms320c64x,
            ]
            [
                detail = X86Detail,
                insn_detail = X86InsnDetail<'a>,
                op = X86Operand,
                /// Returns the X86 details, if any
                => arch_name = x86,
            ]
            [
                detail = XcoreDetail,
                insn_detail = XcoreInsnDetail<'a>,
                op = XcoreOperand,
                /// Returns the XCore details, if any
                => arch_name = xcore,
            ]
            [
                detail = BpfDetail,
                insn_detail = BpfInsnDetail<'a>,
                op = BpfOperand,
                /// Returns the XCore details, if any
                => arch_name = bpf,
            ]
        );
    };
}

/// Define ArchDetail enum, ArchOperand enum, and From<$Operand> for ArchOperand
macro_rules! detail_defs {
    (
        $( [
            detail = $Detail:tt,
            insn_detail = $InsnDetail:ty,
            op = $Operand:tt,
            $( #[$func_attr:meta] )+
            => arch_name = $arch_name:ident,
        ] )+
    ) => {
        $(
            use self::$arch_name::*;
        )+

        /// Contains architecture-dependent detail structures.
        ///
        /// For convenience, there are methods for each architecture that return an `Option` of that
        /// architecture's detail structure. This allows you to use an `if let Some(...) = { /* ... */ }`
        /// instead of a match statement.
        #[derive(Debug)]
        pub enum ArchDetail<'a> {
            $( $Detail($InsnDetail), )+
        }

        /// Architecture-independent enum of operands
        #[derive(Clone, Debug, PartialEq)]
        pub enum ArchOperand {
            $( $Operand($Operand), )+
        }

        impl<'a> ArchDetail<'a> {
            /// Returns architecture independent set of operands
            pub fn operands(&'a self) -> Vec<ArchOperand> {
                match *self {
                    $(
                        ArchDetail::$Detail(ref detail) => {
                            let ops = detail.operands();
                            let map = ops.map(ArchOperand::from);
                            let vec: Vec<ArchOperand> = map.collect();
                            vec
                        }
                    )+
                }
            }

            $(
                $( #[$func_attr] )+
                pub fn $arch_name(&'a self) -> Option<& $InsnDetail> {
                    if let ArchDetail::$Detail(ref arch_detail) = *self {
                        Some(arch_detail)
                    } else {
                        None
                    }
                }
            )+
        }

        $(
            impl From<$Operand> for ArchOperand {
                fn from(op: $Operand) -> ArchOperand {
                    ArchOperand::$Operand(op)
                }
            }
        )+
    }
}

/// Define OperandIterator and DetailsArch impl
macro_rules! def_arch_details_struct {
    (
        InsnDetail = $InsnDetail:ident;
        Operand = $Operand:ident;
        OperandIterator = $OperandIterator:ident;
        OperandIteratorLife = $OperandIteratorLife:ty;
        [ $iter_struct:item ]
        cs_arch_op = $cs_arch_op:ty;
        cs_arch = $cs_arch:ty;
    ) => {
        /// Iterates over instruction operands
        #[derive(Clone)]
        $iter_struct

        impl<'a> $OperandIteratorLife {
            fn new(ops: &[$cs_arch_op]) -> $OperandIterator {
                $OperandIterator(ops.iter())
            }
        }

        impl<'a> Iterator for $OperandIteratorLife {
            type Item = $Operand;

            fn next(&mut self) -> Option<Self::Item> {
                self.0.next().map($Operand::from)
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                self.0.size_hint()
            }
        }

        impl<'a> ExactSizeIterator for $OperandIteratorLife {
            fn len(&self) -> usize { self.0.len() }
        }

        impl<'a> PartialEq for $OperandIteratorLife {
            fn eq(&self, other: & $OperandIteratorLife) -> bool {
                self.len() == other.len() && {
                    let self_clone: $OperandIterator = self.clone();
                    let other_clone: $OperandIterator = (*other).clone();
                    self_clone.zip(other_clone).all(|(a, b)| a == b)
                }
            }
        }

        impl<'a> ::core::fmt::Debug for $OperandIteratorLife {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> ::core::fmt::Result {
                fmt.debug_struct(stringify!($OperandIterator)).finish()
            }
        }

        impl<'a> ::core::fmt::Debug for $InsnDetail<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> ::core::fmt::Result {
                fmt.debug_struct(stringify!($InsnDetail))
                    .field(stringify!($cs_arch), &(self.0 as *const $cs_arch))
                    .finish()
            }
        }

        impl<'a> crate::arch::DetailsArchInsn for $InsnDetail<'a> {
            type OperandIterator = $OperandIteratorLife;
            type Operand = $Operand;

            fn operands(&self) -> $OperandIteratorLife {
                $OperandIterator::new(&self.0.operands[..self.0.op_count as usize])
            }
        }
    }
}

detail_arch_base!(detail_defs);

/// Define "pub mod" uses
macro_rules! define_arch_mods {
    (
        $( [
            ( $arch:ident, $arch_variant:ident )
            ( mode: $( $mode:ident, )+ )
            ( extra_modes: $( $extra_mode:ident, )* )
            ( syntax: $( $syntax:ident, )* )
            ( both_endian: $( $endian:expr )* )
        ] )+
    ) => {
        $( pub mod $arch; )+
    }
}

// Define modules at the end so that they can see macro definitions
arch_info_base!(define_arch_mods);
