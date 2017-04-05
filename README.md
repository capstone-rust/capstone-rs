capstone-rs
===========

Bindings to [capstone-engine][upstream]

There's an example in demo.rs, but as a sample:

```rust
extern crate capstone;

static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn main() {
    match capstone::Capstone::new(capstone::CsArch::ARCH_X86,
                                  capstone::CsMode::MODE_64) {
        Ok(cs) => {
            match cs.disasm(CODE, 0x1000, 0) {
                Ok(insns) => {
                    println!("Got {} instructions", insns.len());

                    for i in insns.iter() {
                        println!("{}", i);
                    }
                },
                Err(err) => {
                    println!("Error: {}", err);
                    process::exit(1);
                }
            }
        },
        Err(err) => {
            println!("Error: {}", err);
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

Please open a Github issue, or email me directly if you prefer

# Demo

You can run:

    cargo run --example=demo

To produce a short demonstration. More complex demos welcome!

# Author

- Library Author: Nguyen Anh Quynh
- Binding Author: Richo Healey <richo@psych0tik.net>

# Contributors

- @ekse

# License

Mit.

[upstream]: http://capstone-engine.org/
