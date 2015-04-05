#![feature(libc)]
#![feature(core)]
#![feature(debug_builders)]
extern crate libc;

pub mod instruction;
pub mod constants;
pub mod ffi;
pub mod capstone;

pub use instruction::*;
pub use constants::*;

pub use capstone::Capstone;

use std::ptr;

/// An opaque reference to a capstone engine.
///
/// bindgen by default used this type name everywhere, so it is easier to leave it with a confusing
/// name.
///
/// It should not be exported, rust's new visibility rules make tackling this not immediately
/// obvious
#[allow(non_camel_case_types)]
pub type csh = libc::size_t;
