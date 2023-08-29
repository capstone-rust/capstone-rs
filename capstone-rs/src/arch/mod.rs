//! Contains architecture-specific types and modules

// We use explicit casts from c_int (and such) so the code compiles on platforms with different
// integer widths
#![allow(clippy::unnecessary_cast)]

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::capstone::Capstone;
use crate::constants::Endian;
use crate::error::CsResult;
use crate::{Arch, Error, ExtraMode, InsnDetail, InsnGroupId, InsnId, Mode, RegId, Syntax};

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
    ( @extra_modes ( $arch:ident, $arch_tag:ident, ) ) => {};
    ( @extra_modes ( $arch:ident, $arch_tag:ident, $( $extra_mode:ident, )+ ) ) => {
        impl super::BuildsCapstoneExtraMode<crate::arch::$arch::$arch_tag> for ArchCapstoneBuilder {
            fn extra_mode<T: Iterator<Item=ArchExtraMode>>(mut self, extra_mode: T) -> Self {
                self.extra_mode.clear();
                self.extra_mode.extend(extra_mode);
                self
            }
        }
    };

    // Syntax rules
    ( @syntax ( $arch:ident, $arch_tag:ident, ) ) => {};
    ( @syntax ( $arch:ident, $arch_tag:ident, $( $syntax:ident, )+ ) ) => {
        impl super::BuildsCapstoneSyntax<crate::arch::$arch::$arch_tag> for ArchCapstoneBuilder {
            fn syntax(mut self, syntax: ArchSyntax) -> Self {
                self.syntax = Some(syntax);
                self
            }
        }
    };

    // Endian rules
    ( @endian ( $arch:ident, $arch_tag:ident, false) ) => {};
    ( @endian ( $arch:ident, $arch_tag:ident, true ) ) => {
        impl super::BuildsCapstoneEndian<crate::arch::$arch::$arch_tag> for ArchCapstoneBuilder {
            fn endian(mut self, endian: Endian) -> Self {
                self.endian = Some(endian);
                self
            }
        }
    };

    // Entrance rule
    (
        $( [
            ( $arch:ident, $arch_variant:ident, $arch_tag:ident )
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

                define_arch_builder!( @syntax ( $arch, $arch_tag, $( $syntax, )* ) );
                define_arch_builder!( @endian ( $arch, $arch_tag, $( $endian )* ) );
                define_arch_builder!( @extra_modes ( $arch, $arch_tag, $( $extra_mode, )* ) );

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

                impl super::BuildsCapstone<crate::arch::$arch::$arch_tag> for ArchCapstoneBuilder {
                    fn mode(mut self, mode: ArchMode) -> Self {
                        self.mode = Some(mode);
                        self
                    }

                    fn detail(mut self, enable_detail: bool) -> Self {
                        self.is_detail = enable_detail;
                        self
                    }

                    fn build(self) -> CsResult<Capstone<crate::arch::$arch::$arch_tag>> {
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
                        let mut capstone = Capstone::new_raw(Arch::$arch_variant,
                                                             mode.into(),
                                                             self.extra_mode.iter().copied().map(|x| x.into()),
                                                             self.endian)?;

                        if let Some(syntax) = self.syntax {
                            capstone.set_syntax(syntax)?;
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
                ( arm, ARM, ArmArchTag )
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
                ( arm64, ARM64, Arm64ArchTag )
                ( mode:
                    Arm,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: true )
            ]
            [
                ( evm, EVM, EvmArchTag )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( m680x, M680X, M680xArchTag )
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
                ( m68k, M68K, M68kArchTag )
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
                ( mips, MIPS, MipsArchTag )
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
                ( ppc, PPC, PpcArchTag )
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
                ( riscv, RISCV, RiscVArchTag )
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
                ( sparc, SPARC, SparcArchTag )
                ( mode:
                    Default,
                    V9,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( sysz, SYSZ, SyszArchTag )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( tms320c64x, TMS320C64X, Tms320c64xArchTag )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false )
            ]
            [
                ( x86, X86, X86ArchTag )
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
                ( xcore, XCORE, XcoreArchTag )
                ( mode:
                    Default,
                    )
                ( extra_modes: )
                ( syntax: )
                ( both_endian: false  )
            ]
        );
    };
}

mod internal {
    /// Make sure that only this crate can implement `ArchTag`.
    pub trait ArchTagSealed {}
}

/// Provides types relative to a specific arch.
pub trait ArchTag: internal::ArchTagSealed + 'static + Sized {
    /// Type of capstone builder that builds Capstone instances for this architecture.
    type Builder: Default;

    type Mode: Copy + Into<Mode>;
    type ExtraMode: Copy + Into<ExtraMode>;
    type Syntax: Copy + Into<Syntax>;

    type RegId: Copy + Into<RegId>;
    type InsnId: Copy + Into<InsnId>;
    type InsnGroupId: Copy + Into<InsnGroupId>;

    type InsnDetail<'a>: DetailsArchInsn + for<'i> From<&'i InsnDetail<'a, Self>>;

    /// Determine whether the given [`Arch`] value is supported by this arch tag.
    fn support_arch(arch: Arch) -> bool;
}

/// An architecture tag that indicates the architecture is unknown at compile-time.
pub struct DynamicArchTag;

impl internal::ArchTagSealed for DynamicArchTag {}

impl ArchTag for DynamicArchTag {
    type Builder = CapstoneBuilder;

    type Mode = Mode;
    type ExtraMode = ExtraMode;
    type Syntax = Syntax;

    type RegId = RegId;
    type InsnId = InsnId;
    type InsnGroupId = InsnGroupId;

    type InsnDetail<'a> = ArchInsnDetail<'a>;

    fn support_arch(_: Arch) -> bool {
        true
    }
}

/// Builds a `Capstone` struct
pub trait BuildsCapstone<A: ArchTag> {
    /// Set the disassembly mode
    fn mode(self, mode: A::Mode) -> Self;

    /// Enable detailed output
    fn detail(self, enable_detail: bool) -> Self;

    /// Get final `Capstone`
    fn build(self) -> CsResult<Capstone<A>>;
}

/// Implies that a `CapstoneBuilder` architecture has extra modes
pub trait BuildsCapstoneExtraMode<A: ArchTag>: BuildsCapstone<A> {
    /// Set architecture endianness
    fn extra_mode<T: Iterator<Item = A::ExtraMode>>(self, extra_mode: T) -> Self;
}

/// Implies that a `CapstoneBuilder` has different syntax options
pub trait BuildsCapstoneSyntax<A: ArchTag>: BuildsCapstone<A> {
    /// Set the disassembly syntax
    fn syntax(self, syntax: A::Syntax) -> Self;
}

/// Implies that a `CapstoneBuilder` architecture has a configurable endianness
pub trait BuildsCapstoneEndian<A: ArchTag>: BuildsCapstone<A> {
    /// Set architecture endianness
    fn endian(self, endian: Endian) -> Self;
}

/// Contains builder-pattern implementations
pub(crate) mod arch_builder {
    use super::*;

    arch_info_base!(define_arch_builder);
}

/// Builds `Capstone` object
#[derive(Debug, Default)]
pub struct CapstoneBuilder {
    arch: Option<Arch>,
    mode: Option<Mode>,
    is_detail: bool,
    extra_mode: Vec<ExtraMode>,
    syntax: Option<Syntax>,
    endian: Option<Endian>,
}

impl CapstoneBuilder {
    /// Set the capstone architecture.
    ///
    /// This function must be called before the `build` function is called.
    pub fn arch(mut self, arch: Arch) -> Self {
        self.arch = Some(arch);
        self
    }
}

impl BuildsCapstone<DynamicArchTag> for CapstoneBuilder {
    fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    fn detail(mut self, enable_detail: bool) -> Self {
        self.is_detail = enable_detail;
        self
    }

    fn build(self) -> CsResult<Capstone<DynamicArchTag>> {
        let arch = self
            .arch
            .ok_or_else(|| Error::CustomError("Must specify arch with `arch()` method"))?;
        let mode = self
            .mode
            .ok_or_else(|| Error::CustomError("Must specify mode with `mode()` method"))?;

        let mut capstone = Capstone::new_raw(
            arch,
            mode.into(),
            self.extra_mode.iter().copied().map(|x| x.into()),
            self.endian,
        )?;

        if let Some(syntax) = self.syntax {
            capstone.set_syntax(syntax)?;
        }
        if self.is_detail {
            capstone.set_detail(self.is_detail)?;
        }

        Ok(capstone)
    }
}

impl BuildsCapstoneEndian<DynamicArchTag> for CapstoneBuilder {
    fn endian(mut self, endian: Endian) -> Self {
        self.endian = Some(endian);
        self
    }
}

impl BuildsCapstoneExtraMode<DynamicArchTag> for CapstoneBuilder {
    fn extra_mode<T: Iterator<Item = ExtraMode>>(mut self, extra_mode: T) -> Self {
        self.extra_mode.clear();
        self.extra_mode.extend(extra_mode);
        self
    }
}

impl BuildsCapstoneSyntax<DynamicArchTag> for CapstoneBuilder {
    fn syntax(mut self, syntax: Syntax) -> Self {
        self.syntax = Some(syntax);
        self
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
                op_iter = ArmOperandIterator,
                /// Returns the ARM details, if any
                => arch_name = arm,
            ]
            [
                detail = Arm64Detail,
                insn_detail = Arm64InsnDetail<'a>,
                op = Arm64Operand,
                op_iter = Arm64OperandIterator,
                /// Returns the ARM64 details, if any
                => arch_name = arm64,
            ]
            [
                detail = EvmDetail,
                insn_detail = EvmInsnDetail<'a>,
                op = EvmOperand,
                op_iter = EvmOperandIterator,
                /// Returns the EVM details, if any
                => arch_name = evm,
            ]
            [
                detail = M680xDetail,
                insn_detail = M680xInsnDetail<'a>,
                op = M680xOperand,
                op_iter = M680xOperandIterator,
                /// Returns the M680X details, if any
                => arch_name = m680x,
            ]
            [
                detail = M68kDetail,
                insn_detail = M68kInsnDetail<'a>,
                op = M68kOperand,
                op_iter = M68kOperandIterator,
                /// Returns the M68K details, if any
                => arch_name = m68k,
            ]
            [
                detail = MipsDetail,
                insn_detail = MipsInsnDetail<'a>,
                op = MipsOperand,
                op_iter = MipsOperandIterator,
                /// Returns the MIPS details, if any
                => arch_name = mips,
            ]
            [
                detail = PpcDetail,
                insn_detail = PpcInsnDetail<'a>,
                op = PpcOperand,
                op_iter = PpcOperandIterator,
                /// Returns the PPC details, if any
                => arch_name = ppc,
            ]
            [
                detail = RiscVDetail,
                insn_detail = RiscVInsnDetail<'a>,
                op = RiscVOperand,
                op_iter = RiscVOperandIterator,
                /// Returns the RISCV details, if any
                => arch_name = riscv,
            ]
            [
                detail = SparcDetail,
                insn_detail = SparcInsnDetail<'a>,
                op = SparcOperand,
                op_iter = SparcOperandIterator,
                /// Returns the SPARC details, if any
                => arch_name = sparc,
            ]
            [
                detail = SyszDetail,
                insn_detail = SyszInsnDetail<'a>,
                op = SyszOperand,
                op_iter = SyszOperandIterator,
                /// Returns the Sysz details, if any
                => arch_name = sysz,
            ]
            [
                detail = Tms320c64xDetail,
                insn_detail = Tms320c64xInsnDetail<'a>,
                op = Tms320c64xOperand,
                op_iter = Tms320c64xOperandIterator,
                /// Returns the Tms320c64x details, if any
                => arch_name = tms320c64x,
            ]
            [
                detail = X86Detail,
                insn_detail = X86InsnDetail<'a>,
                op = X86Operand,
                op_iter = X86OperandIterator,
                /// Returns the X86 details, if any
                => arch_name = x86,
            ]
            [
                detail = XcoreDetail,
                insn_detail = XcoreInsnDetail<'a>,
                op = XcoreOperand,
                op_iter = XcoreOperandIterator,
                /// Returns the XCore details, if any
                => arch_name = xcore,
            ]
        );
    };
}

/// Define ArchInsnDetail enum, ArchOperand enum, ArchOperandIterator enum, and From<$Operand> for ArchOperand
macro_rules! detail_defs {
    (
        $( [
            detail = $Detail:tt,
            insn_detail = $InsnDetail:ty,
            op = $Operand:tt,
            op_iter = $OperandIter:tt,
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
        #[derive(Debug, PartialEq)]
        pub enum ArchInsnDetail<'a> {
            $( $Detail($InsnDetail), )+
        }

        /// Architecture-independent enum of operands
        #[derive(Clone, Debug, PartialEq)]
        pub enum ArchOperand {
            Invalid,
            $( $Operand($Operand), )+
        }

        /// Iterate arch-specific operands of an instruction.
        pub enum ArchOperandIterator<'a> {
            $( $OperandIter($OperandIter<'a>), )+
        }

        impl<'a> ArchInsnDetail<'a> {
            $(
                $( #[$func_attr] )+
                pub fn $arch_name(&'a self) -> Option<& $InsnDetail> {
                    if let ArchInsnDetail::$Detail(ref arch_detail) = *self {
                        Some(arch_detail)
                    } else {
                        None
                    }
                }
            )+
        }

        $(
            impl<'a> From<$InsnDetail> for ArchInsnDetail<'a> {
                fn from(insn_detail: $InsnDetail) -> Self {
                    Self::$Detail(insn_detail)
                }
            }
        )+

        impl Default for ArchOperand {
            fn default() -> Self {
                Self::Invalid
            }
        }

        $(
            impl From<$Operand> for ArchOperand {
                fn from(op: $Operand) -> ArchOperand {
                    ArchOperand::$Operand(op)
                }
            }
        )+

        impl<'a> Iterator for ArchOperandIterator<'a> {
            type Item = ArchOperand;

            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    $(
                        Self::$OperandIter( op_iter ) => op_iter.next().map(From::from),
                    )+
                }
            }
        }

        impl<'a> DetailsArchInsn for ArchInsnDetail<'a> {
            type Operand = ArchOperand;
            type OperandIterator = ArchOperandIterator<'a>;

            fn operands(&self) -> Self::OperandIterator {
                todo!()
            }
        }
    }
}

impl<'a, 'i> From<&'i InsnDetail<'a, DynamicArchTag>> for ArchInsnDetail<'a> {
    fn from(insn_detail: &'i InsnDetail<'a, DynamicArchTag>) -> Self {
        macro_rules! def_arch_detail_match {
            (
                $( [ $ARCH:ident, $detail:ident, $insn_detail:ident, $arch:ident ] )*
            ) => {
                use self::ArchInsnDetail::*;
                use crate::Arch::*;
                $( use crate::arch::$arch::$insn_detail; )*

                return match insn_detail.1 {
                    $(
                        $ARCH => {
                            $detail($insn_detail(unsafe { &insn_detail.0.__bindgen_anon_1.$arch }))
                        }
                    )*
                    _ => panic!("Unsupported detail arch"),
                }
            }
        }

        def_arch_detail_match!(
            [ARM, ArmDetail, ArmInsnDetail, arm]
            [ARM64, Arm64Detail, Arm64InsnDetail, arm64]
            [EVM, EvmDetail, EvmInsnDetail, evm]
            [M680X, M680xDetail, M680xInsnDetail, m680x]
            [M68K, M68kDetail, M68kInsnDetail, m68k]
            [MIPS, MipsDetail, MipsInsnDetail, mips]
            [PPC, PpcDetail, PpcInsnDetail, ppc]
            [RISCV, RiscVDetail, RiscVInsnDetail, riscv]
            [SPARC, SparcDetail, SparcInsnDetail, sparc]
            [TMS320C64X, Tms320c64xDetail, Tms320c64xInsnDetail, tms320c64x]
            [X86, X86Detail, X86InsnDetail, x86]
            [XCORE, XcoreDetail, XcoreInsnDetail, xcore]
        );
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
            fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                fmt.debug_struct(stringify!($OperandIterator)).finish()
            }
        }

        impl<'a> ::core::fmt::Debug for $InsnDetail<'a> {
            fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
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
            ( $arch:ident, $arch_variant:ident, $arch_tag:ident )
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
