capstone3
===========

Bindings to the [capstone library][upstream] disassembly framework.

There's an example in `demo.rs`, but as a sample:

```rust
extern crate capstone;

const CODE: &'static [u8; 8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn main() {
     match capstone::Capstone::new(capstone::Arch::X86) {
         Ok(cs) => {
             cs.detail().unwrap();
             cs.att();
             match cs.disasm(CODE, 0x1000) {
                 Ok(insns) => {
                     println!("Got {} instructions", insns.len());
                     for i in insns.iter() {
                         println!("{}", i);
                         println!("detail: {:?}", i.detail());
                     }
                 },
                 Err(err) => {
                     println!("Error disassembling: {}", err);
                 }
             }
         },
         Err(err) => {
             println!("Error creating disassembler: {}", err);
         }
     }
}
```

Produces:

```
Got 2 instructions
0x1000: push rbp
0x1001: mov rax, qword ptr [rip + 0x13b8]
```

# Reporting Issues

Please open a Github issue

# Demo

You can run:

    cargo run --example=demo

To produce a short demonstration. More complex demos welcome!

# Author

Library Author: Nguyen Anh Quynh
Binding Author(s): m4b <m4b.github.io@gmail.com> Richo Healey <richo@psych0tik.net>

# Contributors

- @ekse

# License

Mit.

[upstream]: http://capstone-engine.org/
