extern crate capstone;
use std::process;

static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn main() {
    match capstone::Capstone::new(capstone::CsArch::ARCH_X86,
                                  capstone::CsMode::MODE_64) {
        Ok(cs) => {
            match cs.disasm(CODE, 0x1000, 0) {
                Ok(insns) => {
                    println!("Got {} instructions", insns.len());

                    for i in insns.iter() {
                            print!("{:#x}: ", i.address);
                            if let Some(mnemonic) = i.mnemonic() {
                                print!("{} ", mnemonic);
                                if let Some(op_str) = i.op_str() {
                                    print!("{}", op_str);
                                }
                            }
                            println!("");
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
            process::exit(1);
        }
    }
}
