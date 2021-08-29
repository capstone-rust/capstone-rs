# capstone-rs

[![Crates.io Badge](https://img.shields.io/crates/v/capstone.svg)](https://crates.io/crates/capstone)

Linux [![Github Workflow CI Badge](https://github.com/capstone-rust/capstone-rs/actions/workflows/main.yml/badge.svg)](https://github.com/capstone-rust/capstone-rs/actions)
|
Windows [![Appveyor CI Badge](https://ci.appveyor.com/api/projects/status/github/capstone-rust/capstone-rs?svg=true&branch=master)](https://ci.appveyor.com/project/tmfink/capstone-rs)
|
FreeBSD [![Cirrus CI Badge](https://api.cirrus-ci.com/github/capstone-rust/capstone-rs.svg)](https://cirrus-ci.com/github/capstone-rust/capstone-rs)

[![codecov](https://codecov.io/gh/capstone-rust/capstone-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/capstone-rust/capstone-rs)


 **[API Documentation](https://docs.rs/capstone/)**


Bindings to the [capstone library][upstream] disassembly framework.


# Requirements

`capstone-rs` uses the [`capstone-sys`](capstone-sys) crate to provide the low-level bindings to the Capstone C library.

See the [`capstone-sys`](capstone-sys) page for the requirements and supported platforms.

* Minimum Rust Version: `1.50.0`

# Example

<!-- START: code_sample -->
```rust
extern crate capstone;

use capstone::prelude::*;

const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4";

/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

fn main() {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs.disasm_all(X86_CODE, 0x1000)
        .expect("Failed to disassemble");
    println!("Found {} instructions", insns.len());
    for i in insns.as_ref() {
        println!();
        println!("{}", i);

        let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        let output: &[(&str, String)] = &[
            ("insn id:", format!("{:?}", i.id().0)),
            ("bytes:", format!("{:?}", i.bytes())),
            ("read regs:", reg_names(&cs, detail.regs_read())),
            ("write regs:", reg_names(&cs, detail.regs_write())),
            ("insn groups:", group_names(&cs, detail.groups())),
        ];

        for &(ref name, ref message) in output.iter() {
            println!("{:4}{:12} {}", "", name, message);
        }

        println!("{:4}operands: {}", "", ops.len());
        for op in ops {
            println!("{:8}{:?}", "", op);
        }
    }
}
```
<!-- END: code_sample -->

Produces:

```
Found 4 instructions

0x1000: pushq %rbp
    read regs:   rsp
    write regs:  rsp
    insn groups: mode64

0x1001: movq 0x13b8(%rip), %rax
    read regs:
    write regs:
    insn groups:

0x1008: jmp 0x8ae21
    read regs:
    write regs:
    insn groups: jump

0x100d: xorl %r12d, %r12d
    read regs:
    write regs:  rflags
    insn groups:
```

To see more demos, see the [`examples/`](capstone-rs/examples) directory.
More complex demos welcome!

# Features

- `use_bindgen`: run `bindgen` to generate Rust bindings to Capstone C library
  instead of using pre-generated bindings (not recommended).

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

[MIT](capstone-rs/LICENSE)

[upstream]: https://www.capstone-engine.org/
