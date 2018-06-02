extern crate capstone;

use capstone::prelude::*;
use capstone::InsnDetail;

const MIPS_CODE: &'static [u8] = b"\x56\x34\x21\x34\xc2\x17\x01\x00";

const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4";

/// Print register names
fn reg_names<T, I>(cs: &Capstone, regs: T) -> String
where
    T: Iterator<Item = I>,
    I: Into<RegId>,
{
    let names: Vec<String> = regs.map(|x| cs.reg_name(x.into()).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names<T, I>(cs: &Capstone, regs: T) -> String
where
    T: Iterator<Item = I>,
    I: Into<InsnGroupId>,
{
    let names: Vec<String> = regs.map(|x| cs.group_name(x.into()).unwrap()).collect();
    names.join(", ")
}

/// Disassemble code and print information
fn arch_example(cs: &mut Capstone, code: &[u8]) -> CsResult<()> {
    let insns = cs.disasm_all(code, 0x1000)?;
    println!("Found {} instructions", insns.len());
    for i in insns.iter() {
        println!();
        println!("{}", i);

        let detail: InsnDetail = cs.insn_detail(&i)?;
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        let output: &[(&str, String)] = &[
            ("insn id:", format!("{:?}", i.id().0)),
            ("bytes:", format!("{:?}", i.bytes())),
            ("read regs:", reg_names(&cs, detail.regs_read())),
            ("write regs:", reg_names(&cs, detail.regs_write())),
            ("insn groups:", group_names(&cs, detail.groups())),
        ];

        for &(ref name, ref message) in output.iter() {
            println!("{:4}{:12} {}", "", name, message);
        }

        println!("{:4}operands: {}", "", ops.len());
        for op in ops {
            println!("{:8}{:?}", "", op);
        }
    }
    Ok(())
}

fn example() -> CsResult<()> {
    let cs_mips: Capstone = Capstone::new()
        .mips()
        .mode(arch::mips::ArchMode::Mips32R6)
        .detail(true)
        .build()?;

    let cs_x86 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()?;

    let mut examples = [("MIPS", cs_mips, MIPS_CODE), ("X86", cs_x86, X86_CODE)];

    for &mut (arch, ref mut cs, code) in examples.iter_mut() {
        println!("\n*************************************");
        println!("Architecture {}:", arch);
        arch_example(cs, &code)?;
    }

    Ok(())
}

fn main() {
    if let Err(err) = example() {
        println!("Error: {}", err);
    }
}
