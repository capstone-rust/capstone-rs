#![feature(libc)]
#![feature(core)]
#![feature(debug_builders)]
extern crate libc;

pub mod instruction;
pub mod constants;
pub mod ffi;
pub mod capstone;

use constants::{CsErr};

pub use instruction::*;

use std::ptr;

// bindgen by default used this type name everywhere, it is easier to leave it alone.
#[allow(non_camel_case_types)]
pub type csh = libc::size_t;
