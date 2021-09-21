use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::process;

use object::{Object, ObjectSection, SectionKind};

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

    let mut addr_queue: VecDeque<u64> = VecDeque::new();
    let mut addr_seen: HashMap<u64, bool> = HashMap::new();

    for section in obj.sections() {
        if section.kind() == SectionKind::Text {
            println!("{:x?} ", section);
            addr_queue.push_back(section.address());
        }
    }

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

        println!("---> addr: {:#02x?}", addr);

        let offset = addr as usize;
        let mut cur_insn = disasm.disasm_iter(&buf, offset, addr);
        while let Ok(insn) = cur_insn {
            if insn.id() == InsnId(X86Insn::X86_INS_INVALID as u32) {
                break;
            }
            println!("{}", insn);
            match X86Insn::from(insn.id().0) {
                X86Insn::X86_INS_HLT => break,
                X86Insn::X86_INS_CALL => break,
                X86Insn::X86_INS_JMP => break,
                X86Insn::X86_INS_RET => break,
                _ => {}
            }

            // add logic here to add more targets to the addr_queue
            // ...

            cur_insn = disasm.disasm_iter_continue(&buf);
        }
    }
}
