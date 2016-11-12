extern crate capstone;

static CODE: &'static [u8; 8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

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
