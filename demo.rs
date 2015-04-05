extern crate capstone;

static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn expose(a: &str) {
}

fn main() {
    match capstone::Capstone::new(capstone::CsArch::ARCH_X86,
                                  capstone::CsMode::MODE_64) {
        Some(cs) => {
            if let Some(insns) = cs.disasm(CODE, 0x1000, 0) {
                println!("Got {} instructions", insns.len());

                for i in insns.iter() {
                    println!("{:?}", i);
                }
            }
        },
        None => {
            println!("Ohnoes");
        }
    }
}
