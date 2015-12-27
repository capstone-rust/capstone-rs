extern crate capstone;

static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn main() {
    match capstone::Capstone::new(capstone::CsArch::ARCH_X86,
                                  capstone::CsMode::MODE_64) {
        Some(cs) => {
            if let Some(insns) = cs.disasm(CODE, 0x1000, 0) {
                println!("Got {} instructions", insns.len());

                for i in insns.iter() {
                    println!("{:?}", i);
                }

                let reg_id = 1;
                match cs.reg_name(reg_id) {
                    Some(reg_name) => println!("reg name: {}", reg_name),
                    None => println!("invalid reg_id : {}", reg_id),
                }

                let insn_id = 1;
                match cs.insn_name(insn_id) {
                    Some(insn_name) => println!("insn name: {}", insn_name),
                    None => println!("invalid insn_id : {}", reg_id),
                }

            }
        },
        None => {
            println!("Ohnoes");
        }
    }
}
