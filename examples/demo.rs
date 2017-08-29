extern crate capstone;

const CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

fn example() -> capstone::CsResult<()> {
    let mut cs = capstone::Capstone::new(capstone::Arch::X86, capstone::Mode::Mode64)?;
    cs.set_detail(true).unwrap();
    cs.att();
    let insns = cs.disasm_all(CODE, 0x1000)?;
    println!("Got {} instructions", insns.len());
    for i in insns.iter() {
        println!("{}", i);
        println!("    read regs: {:?}", cs.read_registers(&i).unwrap());
        println!("    write regs: {:?}", cs.write_registers(&i).unwrap());
        println!("    insn groups: {:?}", cs.insn_groups(&i).unwrap());
    }
    Ok(())
}

fn main() {
    if let Err(err) = example() {
        println!("Error: {}", err);
    }
}
