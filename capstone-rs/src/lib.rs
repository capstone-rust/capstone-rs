#![doc = include_str!("../../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

// The `vec` macro cannot be imported directly since it conflicts with the `vec` module
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(any(test, not(feature = "std")))]
#[macro_use]
extern crate std;

#[cfg(any(test, not(feature = "std")))]
#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

// Define first so macros are available
#[macro_use]
mod constants;

pub mod arch;
mod capstone;
mod error;
mod ffi;
mod instruction;

#[cfg(test)]
mod test;

pub use crate::capstone::*;
pub use crate::constants::*;
pub use crate::error::*;
pub use crate::instruction::*;

/// Contains items that you probably want to always import
///
/// For example:
///
/// ```
/// use capstone::prelude::*;
/// ```
pub mod prelude {
    pub use crate::arch::{
        self, ArchDetail, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode,
        BuildsCapstoneSyntax, DetailsArchInsn,
    };
    pub use crate::{
        Capstone, CsResult, InsnDetail, InsnGroupId, InsnGroupIdInt, InsnId, InsnIdInt, RegId,
        RegIdInt,
    };
}
