# capstone-rs

[![Crates.io Badge](https://img.shields.io/crates/v/capstone.svg)](https://crates.io/crates/capstone)
[![Travis CI Badge](https://travis-ci.org/capstone-rust/capstone-rs.svg?branch=master)](https://travis-ci.org/capstone-rust/capstone-rs)
[![codecov](https://codecov.io/gh/capstone-rust/capstone-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/capstone-rust/capstone-rs)


 **[API Documentation](https://docs.rs/capstone/)**


Bindings to the [capstone library][upstream] disassembly framework.


# Requirements

`capstone-rs` uses the [`capstone-sys`](https://github.com/capstone-rust/capstone-sys) crate to provide the low-level bindings to the Capstone C library.

See the [`capstone-sys`](https://github.com/capstone-rust/capstone-sys) GitHub page for the requirements and supported platforms.

* Minimum Rust Version: `1.23.0` or later

# Example

The example from [`demo.rs`](examples/demo.rs):

```rust
extern crate capstone;

use capstone::prelude::*;

const CODE: &'static [u8] =
    b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe8\x4a\xed\xff\xff\xe9\x14\x9e\x08\x00\x45\x31\xe4";

/// Print register names
fn reg_names<T, I>(cs: &Capstone, regs: T) -> String
where
    T: Iterator<Item = I>,
    I: Into<u64>,
{
    let names: Vec<String> = regs.map(|x| cs.reg_name(x.into()).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names<T, I>(cs: &Capstone, regs: T) -> String
where
    T: Iterator<Item = I>,
    I: Into<u64>,
{
    let names: Vec<String> = regs.map(|x| cs.group_name(x.into()).unwrap()).collect();
    names.join(", ")
}

fn example() -> CsResult<()> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()?;

    let insns = cs.disasm_all(CODE, 0x1000)?;
    println!("Found {} instructions", insns.len());
    for i in insns.iter() {
        println!("");
        println!("{}", i);
        let output: &[(&str, String)] =
            &[
                (
                    "read regs:",
                    reg_names(&cs, cs.read_register_ids(&i)?.iter().map(|x| *x)),
                ),
                (
                    "write regs:",
                    reg_names(&cs, cs.write_register_ids(&i)?.iter().map(|x| *x)),
                ),
                (
                    "insn groups:",
                    group_names(&cs, cs.insn_group_ids(&i)?.iter().map(|x| *x)),
                ),
            ];
        for &(ref name, ref message) in output.iter() {
            println!("    {:12} {}", name, message);
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = example() {
        println!("Error: {}", err);
    }
}
```

Produces:

```
Found 5 instructions

0x1000: pushq %rbp
    read regs:   rsp
    write regs:  rsp
    insn groups: mode64

0x1001: movq 0x13b8(%rip), %rax
    read regs:
    write regs:
    insn groups:

0x1008: callq 0xfffffffffffffd57
    read regs:   rsp
    write regs:
    insn groups: call, mode64

0x100d: jmp 0x8ae26
    read regs:
    write regs:
    insn groups: jump

0x1012: xorl %r12d, %r12d
    read regs:
    write regs:  rflags
    insn groups:
```

You can the demo by running:

    cargo run --example=demo

To produce a short demonstration. More complex demos welcome!

# Reporting Issues

Please open a [Github issue](https://github.com/capstone-rust/capstone-rs/issues)

# Author

- Library Author: Nguyen Anh Quynh
- Binding Author(s):
    - m4b <m4b.github.io@gmail.com>
    - Richo Healey <richo@psych0tik.net>
    - Travis Finkenauer <tmfinken@gmail.com>

You may find a [full list of contributors on Github](https://github.com/capstone-rust/capstone-rs/graphs/contributors).

# License

Mit.

[upstream]: http://capstone-engine.org/
