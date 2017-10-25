capstone-rs
===========

Bindings to the [capstone library][upstream] disassembly framework.

There's an example in `demo.rs`, but as a sample:

```rust
extern crate capstone;

use capstone::prelude::*;

const CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn example() -> CsResult<()> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()?;

    let insns = cs.disasm_all(CODE, 0x1000)?;
    println!("Got {} instructions", insns.len());
    for i in insns.iter() {
        println!("{}", i);
        println!("    read regs: {:?}", cs.read_registers(&i).unwrap());
        println!("    write regs: {:?}", cs.write_registers(&i).unwrap());
        println!("    insn groups: {:?}", cs.insn_groups(&i).unwrap());
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
Got 2 instructions
0x1000: pushq %rbp
    read regs: [44]
    write regs: [44]
    insn groups: [145]
0x1001: movq 0x13b8(%rip), %rax
    read regs: []
    write regs: []
    insn groups: []
```

# Reporting Issues

Please open a Github issue

# Demo

You can run:

    cargo run --example=demo

To produce a short demonstration. More complex demos welcome!

# Minimum Rust Version

`capstone-rs` requires Rust `1.20.0` or later.

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
