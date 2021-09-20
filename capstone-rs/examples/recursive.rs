use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::process;

use capstone;
use capstone::prelude::*;
use capstone::Insn;
use object::{Object, ObjectSection};

fn main() {
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

    let cs_ins = cs.iter_malloc();
    assert!(!cs_ins.is_null());

    addr_queue.push_back(obj.entry());

    while !addr_queue.is_empty() {
        let mut qaddr = addr_queue.pop_front().unwrap();
        if let Some(_) = addr_seen.get(&qaddr) {
            continue;
        }
        addr_seen.insert(qaddr, true);

        println!("addr: {:#02x?}", qaddr);

        let offset = (qaddr - sec_addr) as usize;
        let qpc = &mut sec_text[offset..].as_ptr();
        let mut qcount = sec_text.len() - offset;

        println!("output: count:{} addr:{:#02x?}", qcount, qaddr);
        loop {
            let (ret, count, addr) = cs.disasm_iter(qpc, qcount, qaddr, cs_ins);
            if !ret {
                break;
            }
            qcount = count;
            qaddr = addr;

            let ins = unsafe { Insn::from_raw(cs_ins) };
            println!("{}", ins);
            if ins.id() == InsnId(arch::x86::X86Insn::X86_INS_HLT as u32) {
                break;
            }
        }
    }
}
