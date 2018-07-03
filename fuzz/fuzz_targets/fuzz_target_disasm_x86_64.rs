#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate capstone;

use capstone::prelude::*;

fuzz_target!(|data: &[u8]| {
    let mut cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .unwrap();
    for i in cs.disasm_all(data, 0x1000).unwrap().iter() {
        let detail: InsnDetail = cs.insn_detail(&i).unwrap();
        let arch_detail: ArchDetail = detail.arch_detail();
        arch_detail.operands().iter().for_each(drop);
        detail.regs_read().for_each(drop);
        detail.regs_write().for_each(drop);
        detail.groups().for_each(drop);
    }
});
