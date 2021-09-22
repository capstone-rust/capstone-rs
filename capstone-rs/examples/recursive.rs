//! This example shows how to do recursive disassemble
//! The example is written specificly for X86 ELF binary format
//!
use std::collections::{HashSet, VecDeque};
use std::env;
use std::fs;
use std::process;

use object::{Object, ObjectSection, SectionKind};

use capstone;
use capstone::prelude::*;
use capstone::InsnGroupType;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        process::exit(-1);
    }

    let buf = fs::read(&args[1]).expect("cannot read file");

    let obj = object::File::parse(&*buf).expect("cannot parse file");

    let mut addr_queue: VecDeque<u64> = VecDeque::new();
    let mut addr_seen: HashSet<u64> = HashSet::new();

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

    while let Some(addr) = addr_queue.pop_front(){
        if addr_seen.contains(&addr) {
            continue;
        }
        addr_seen.insert(addr);

        println!("---> addr: {:#02x?}", addr);

        let offset = addr as usize;
        let mut cur_insn = disasm.disasm_iter(&buf, offset, addr);
        while let Ok(insn) = cur_insn {
            let insn_detail: InsnDetail = cs.insn_detail(&insn).unwrap();
            if is_invalid_insn(&insn_detail) {
                break;
            }
            println!("{}", insn);
            if is_unconditional_cflow_insn(&insn_detail) {
                break;
            }

            // add logic here to add more targets to the addr_queue
            // ...

            cur_insn = disasm.disasm_iter_continue(&buf);
        }
    }
}

fn is_invalid_insn(insn_detail: &InsnDetail) -> bool {
    for insn_grp in insn_detail.groups() {
        if insn_grp.0 as u32 == InsnGroupType::CS_GRP_INVALID {
            return true;
        }
    }
    false
}

fn is_unconditional_cflow_insn(insn_detail: &InsnDetail) -> bool {
    for insn_grp in insn_detail.groups() {
        match insn_grp.0 as u32 {
            InsnGroupType::CS_GRP_JUMP |
            InsnGroupType::CS_GRP_CALL |
            InsnGroupType::CS_GRP_RET => return true,
            _ => {}
        }
    }
    false
}

