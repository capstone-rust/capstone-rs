#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate capstone;

use capstone::arch::x86::X86ArchTag;
use capstone::prelude::*;

fuzz_target!(|data: &[u8]| {
    let mut cs = Capstone::<X86ArchTag>::new()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .unwrap();
    for i in cs.disasm_all(data, 0x1000).unwrap().iter() {
        let detail = cs.insn_detail(&i).unwrap();
        let arch_detail = detail.arch_detail();
        arch_detail.operands().iter().for_each(drop);
        detail.regs_read().iter().for_each(drop);
        detail.regs_write().iter().for_each(drop);
        detail.groups().iter().for_each(drop);
    }
});
