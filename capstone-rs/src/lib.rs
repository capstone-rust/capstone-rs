//! Bindings to the [capstone library][upstream] disassembly framework.
//!
//! This crate is a wrapper around the
//! [Capstone disassembly library](http://www.capstone-engine.org/),
//! a "lightweight multi-platform, multi-architecture disassembly framework."
//!
//! The [`Capstone`](struct.Capstone.html) struct is the main interface to the library.
//!
//! ```rust
//! extern crate capstone;
//!
//! use capstone::prelude::*;
//!
//! const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4";
//!
//! /// Print register names
//! fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
//!     let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
//!     names.join(", ")
//! }
//!
//! /// Print instruction group names
//! fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
//!     let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
//!     names.join(", ")
//! }
//!
//! fn main() {
//!     let cs = Capstone::new()
//!         .x86()
//!         .mode(arch::x86::ArchMode::Mode64)
//!         .syntax(arch::x86::ArchSyntax::Att)
//!         .detail(true)
//!         .build()
//!         .expect("Failed to create Capstone object");
//!
//!     let insns = cs.disasm_all(X86_CODE, 0x1000)
//!         .expect("Failed to disassemble");
//!     println!("Found {} instructions", insns.len());
//!     for i in insns.as_ref() {
//!         println!();
//!         println!("{}", i);
//!
//!         let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
//!         let arch_detail: ArchDetail = detail.arch_detail();
//!         let ops = arch_detail.operands();
//!
//!         let output: &[(&str, String)] = &[
//!             ("insn id:", format!("{:?}", i.id().0)),
//!             ("bytes:", format!("{:?}", i.bytes())),
//!             ("read regs:", reg_names(&cs, detail.regs_read())),
//!             ("write regs:", reg_names(&cs, detail.regs_write())),
//!             ("insn groups:", group_names(&cs, detail.groups())),
//!         ];
//!
//!         for &(ref name, ref message) in output.iter() {
//!             println!("{:4}{:12} {}", "", name, message);
//!         }
//!
//!         println!("{:4}operands: {}", "", ops.len());
//!         for op in ops {
//!             println!("{:8}{:?}", "", op);
//!         }
//!     }
//! }
//! ```
//!
//! Produces:
//!
//! ```txt
//! Found 4 instructions
//!
//! 0x1000: pushq %rbp
//!     insn id:     580
//!     bytes:       [85]
//!     read regs:   rsp
//!     write regs:  rsp
//!     insn groups: mode64
//!     operands: 1
//!         X86Operand(X86Operand { size: 8, avx_bcast: X86_AVX_BCAST_INVALID, avx_zero_opmask: false, op_type: Reg(RegId(36)) })
//!
//! 0x1001: movq 0x13b8(%rip), %rax
//!     insn id:     442
//!     bytes:       [72, 139, 5, 184, 19, 0, 0]
//!     read regs:
//!     write regs:
//!     insn groups:
//!     operands: 2
//!         X86Operand(X86Operand { size: 8, avx_bcast: X86_AVX_BCAST_INVALID, avx_zero_opmask: false, op_type: Mem(X86OpMem(x86_op_mem { segment: 0, base: 41, index: 0, scale: 1, disp: 5048 })) })
//!         X86Operand(X86Operand { size: 8, avx_bcast: X86_AVX_BCAST_INVALID, avx_zero_opmask: false, op_type: Reg(RegId(35)) })
//!
//! 0x1008: jmp 0x8ae21
//!     insn id:     266
//!     bytes:       [233, 20, 158, 8, 0]
//!     read regs:
//!     write regs:
//!     insn groups: jump
//!     operands: 1
//!         X86Operand(X86Operand { size: 8, avx_bcast: X86_AVX_BCAST_INVALID, avx_zero_opmask: false, op_type: Imm(568865) })
//!
//! 0x100d: xorl %r12d, %r12d
//!     insn id:     327
//!     bytes:       [69, 49, 228]
//!     read regs:
//!     write regs:  rflags
//!     insn groups:
//!     operands: 2
//!         X86Operand(X86Operand { size: 4, avx_bcast: X86_AVX_BCAST_INVALID, avx_zero_opmask: false, op_type: Reg(RegId(222)) })
//!         X86Operand(X86Operand { size: 4, avx_bcast: X86_AVX_BCAST_INVALID, avx_zero_opmask: false, op_type: Reg(RegId(222)) })
//!
//! ```
//!
//! [upstream]: http://capstone-engine.org/
//!

#![no_std]

// The `vec` macro cannot be imported directly since it conflicts with the `vec` module
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
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
