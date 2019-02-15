//! Low-level, unsafe Rust bindings for the [`Capstone`][capstone] disassembly library.
//!
//!
//! We recommend against using this crate directly.
//! Instead, consider using [capstone-rs], which provides a high-level, safe, "Rusty" interface.
//!
//! [capstone]: https://github.com/aquynh/capstone
//! [capstone-rs]: https://github.com/capstone-rust/capstone-rs
//!
//! # Supported disassembly architectures
//!
//! * `arm`: ARM
//! * `arm64`: ARM64 (also known as AArch64)
//! * `mips`: MIPS
//! * `ppc`: PowerPC
//! * `sparc`: SPARC
//! * `sysz`: System z
//! * `x86`: x86 family (includes 16, 32, and 64 bit modes)
//! * `xcore`: XCore
//!
//! For each architecture, *at least* the following types are defined (replace `ARCH` with
//! architecture names shown above):
//!
//! * `enum ARCH_insn`: instruction ids
//! * `enum ARCH_insn_group`: architecture-specific group ids
//! * `enum ARCH_op_type`: instruction operand types ids
//! * `enum ARCH_reg`<sup>1</sup>: register ids
//! * `struct ARCH_op_mem`: operand referring to memory
//! * `struct cs_ARCH_op`: instruction operand
//! * `struct cs_ARCH`: instruction
//!
//! **Note**: documentation for functions/types was taken directly from
//! [Capstone C headers][capstone headers].
//!
//! [capstone headers]: https://github.com/capstone-rust/capstone-sys/blob/master/capstone/include/capstone.h
//! <sup>1</sup>: Defined as a ["constified" enum modules](https://docs.rs/bindgen/0.30.0/bindgen/struct.Builder.html#method.constified_enum_module)
//!               because discriminant values are not unique. Rust requires discriminant values to be unique.

// Suppress errors from Capstone names
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::os::raw::c_int;

// Bindings should be copied here
include!(concat!(env!("OUT_DIR"), "/capstone.rs"));

pub const CS_SUPPORT_DIET: c_int = (cs_arch::CS_ARCH_ALL as c_int) + 1;
pub const CS_SUPPORT_X86_REDUCE: c_int = (cs_arch::CS_ARCH_ALL as c_int) + 2;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/common.rs"));
