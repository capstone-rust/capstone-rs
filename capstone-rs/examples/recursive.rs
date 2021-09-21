use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::process;

use object::{Object, ObjectSection};

use capstone;
use capstone::arch::x86::X86Insn;
use capstone::prelude::*;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        process::exit(-1);
    }

    let buf = if let Ok(bd) = fs::read(&args[1]) {
        bd
    } else {
        eprintln!("cannot read file");
        process::exit(-1);
    };

    let obj = if let Ok(od) = object::File::parse(&*buf) {
        od
    } else {
        eprintln!("cannot parse file");
        process::exit(-1);
    };

    let (sec_addr, sec_text) = if let Some(section) = obj.section_by_name(".text") {
        if let Ok(data) = section.data() {
            (section.address(), data)
        } else {
            eprintln!("cannot get data from .text section");
            process::exit(1);
        }
    } else {
        eprintln!("no section .text found");
        process::exit(2);
    };

    println!(
        ".text section addr: {:#02x?} size: {:#02x?}",
        sec_addr,
        sec_text.len()
    );

    let mut addr_queue: VecDeque<u64> = VecDeque::new();
    let mut addr_seen: HashMap<u64, bool> = HashMap::new();

    addr_queue.push_back(obj.entry());
    let cs = if let Ok(cs) = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
    {
        cs
    } else {
        eprintln!("failed to create capstone handle");
        process::exit(-1);
    };

    let mut disasm = cs.get_disasm_iter();

    while !addr_queue.is_empty() {
        let addr = addr_queue.pop_front().unwrap();
        if let Some(_) = addr_seen.get(&addr) {
            continue;
        }
        addr_seen.insert(addr, true);

        println!("addr: {:#02x?}", addr);

        let offset = (addr - sec_addr) as usize;
        let mut cur_insn = disasm.disasm_iter(&sec_text, offset, addr);
        while let Ok(insn) = cur_insn {
            if insn.id() == InsnId(X86Insn::X86_INS_INVALID as u32) {
                break;
            }
            println!("{}", insn);
            if insn.id() == InsnId(X86Insn::X86_INS_HLT as u32) {
                break;
            }
            // other logic here can add more targets to the addr_queue
            // ...

            cur_insn = disasm.disasm_iter_continue(&sec_text);
        }
    }
}
