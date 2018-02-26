//! Contains architecture-specific types and modules

use capstone::Capstone;
use constants::Endian;
use error::CsResult;
use std::marker::PhantomData;

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
            fn extra_mode<T: Iterator<Item=ArchExtraMode>>(&mut self, extra_mode: T) -> & mut Self {
                // self.extra_mode = extra_mode.fold(0usize, |acc, x|
                //     acc | cs_mode::from(x) as usize);
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
            fn syntax(& mut self, syntax: ArchSyntax) -> &mut Self {
                self.syntax = Some(syntax);
                self
            }
        }
    };

    // Endian rules
    ( @endian ( false) ) => {};
    ( @endian ( true ) ) => {
        impl super::BuildsCapstoneEndian<ArchMode> for ArchCapstoneBuilder {
            fn endian(&mut self, endian: Endian) -> &mut Self {
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
                use capstone::Capstone;
                use constants::{Arch, Endian, ExtraMode, Mode, Syntax};
                use error::{CsResult, Error};

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

                pub struct ArchCapstoneBuilder {
                    pub(crate) mode: Option<ArchMode>,
                    pub(crate) is_detail: bool,
                    pub(crate) extra_mode: Vec<ArchExtraMode>,
                    pub(crate) syntax: Option<ArchSyntax>,
                    pub(crate) endian: Option<Endian>,
                }

                impl super::BuildsCapstone<ArchMode> for ArchCapstoneBuilder {
                    fn mode(&mut self, mode: ArchMode) -> &mut Self {
                        self.mode = Some(mode);
                        self
                    }

                    fn detail(&mut self, enable_detail: bool) -> &mut Self {
                        self.is_detail = enable_detail;
                        self
                    }

                    fn build(&mut self) -> CsResult<Capstone> {
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
macro_rules! arch_info_base {
    ( $x_macro:ident ) => { $x_macro!(
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
            ( mips, MIPS )
            ( mode:
                Mode32,
                Mode64,
                Mips32R6,
                MipsGP64,
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
                )
            ( extra_modes: )
            ( syntax:
                NoRegName,
                )
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
    ); }
}

/// Builds a `Capstone` struct
pub trait BuildsCapstone<ArchMode> {
    /// Set the disassembly mode
    fn mode(&mut self, mode: ArchMode) -> &mut Self;

    /// Enable detailed output
    fn detail(&mut self, enable_detail: bool) -> &mut Self;

    /// Get final `Capstone`
    fn build(&mut self) -> CsResult<Capstone>;
}

/// Implies that a `CapstoneBuilder` architecture has extra modes
pub trait BuildsCapstoneExtraMode<ArchMode, ArchExtraMode>
    : BuildsCapstone<ArchMode> {
    /// Set architecture endianness
    fn extra_mode<T: Iterator<Item = ArchExtraMode>>(&mut self, extra_mode: T) -> &mut Self;
}

/// Implies that a `CapstoneBuilder` has different syntax options
pub trait BuildsCapstoneSyntax<ArchMode, ArchSyntax>: BuildsCapstone<ArchMode> {
    /// Set the disassembly syntax
    fn syntax(&mut self, syntax: ArchSyntax) -> &mut Self;
}

/// Implies that a `CapstoneBuilder` architecture has a configurable endianness
pub trait BuildsCapstoneEndian<ArchMode>: BuildsCapstone<ArchMode> {
    /// Set architecture endianness
    fn endian(&mut self, endian: Endian) -> &mut Self;
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
    PhantomData<()>
);

impl CapstoneBuilder {
    /// Create a `CapstoneBuilder`
    pub(crate) fn new() -> Self {
        CapstoneBuilder(PhantomData)
    }
}

/// Provides details about an architecture
pub trait DetailsArch {
    type Operand: Into<ArchOperand>;
    type OperandIterator: Iterator<Item = Self::Operand>;

    fn operands(&self) -> Self::OperandIterator;
}

/// Base macro for defining arch details
macro_rules! detail_arch_base {
    ( $x_macro:ident ) => { $x_macro!(
        [
            detail = MipsDetail,
            insn_detail = MipsInsnDetail<'a>,
            op = MipsOperand,
            /// Returns the MIPS details, if any
            => arch_name = mips,
        ]
        [
            detail = ArmDetail,
            insn_detail = ArmInsnDetail<'a>,
            op = ArmOperand,
            /// Returns the ARM details, if any
            => arch_name = arm,
        ]
    ); }
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

        /// Architecture-independent enum of detail structures
        #[derive(Debug)]
        pub enum ArchDetail<'a> {
            $( $Detail($InsnDetail), )+
            _RemoveMe,
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
                            let map = ops.map(|arch_op| ArchOperand::from(arch_op));
                            let vec: Vec<ArchOperand> = map.collect();
                            vec
                        }
                    )+
                    _ => panic!("Unknown detail type"),
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
        $iter_struct

        impl<'a> $OperandIteratorLife {
            fn new(ops: &[$cs_arch_op]) -> $OperandIterator {
                $OperandIterator(ops.iter())
            }
        }

        impl<'a> Iterator for $OperandIteratorLife {
            type Item = $Operand;

            fn next(&mut self) -> Option<Self::Item> {
                match self.0.next() {
                    None => None,
                    Some(op) => Some($Operand::from(op)),
                }
            }
        }

        impl<'a> ExactSizeIterator for $OperandIteratorLife {
            fn len(&self) -> usize { self.0.len() }
        }

        impl<'a> fmt::Debug for $OperandIteratorLife {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_struct(stringify!($OperandIterator)).finish()
            }
        }

        impl<'a> fmt::Debug for $InsnDetail<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_struct(stringify!($InsnDetail))
                    .field(stringify!($cs_arch), &(self.0 as *const $cs_arch))
                    .finish()
            }
        }

        impl<'a> DetailsArch for $InsnDetail<'a> {
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
            ( both_endian: $( $endian:ident )* )
        ] )+
    ) => {
        $( pub mod $arch; )+
    }
}

// Define modules at the end so that they can see macro definitions
arch_info_base!(define_arch_mods);
