extern crate capstone;

use capstone::arch::mips::MipsArchTag;
use capstone::arch::x86::X86ArchTag;
use capstone::arch::{ArchTag, DetailsArchInsn};
use capstone::prelude::*;

const MIPS_CODE: &[u8] = b"\x56\x34\x21\x34\xc2\x17\x01\x00";

const X86_CODE: &[u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4";

#[cfg(feature = "full")]
/// Print register names
fn reg_names<A, I>(cs: &Capstone<A>, regs: I) -> String
where
    A: ArchTag,
    I: Iterator<Item = A::RegId>,
{
    let names: Vec<String> = regs.map(|x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

#[cfg(feature = "full")]
/// Print instruction group names
fn group_names<A, I>(cs: &Capstone<A>, regs: I) -> String
where
    A: ArchTag,
    I: Iterator<Item = A::InsnGroupId>,
{
    let names: Vec<String> = regs.map(|x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

/// Disassemble code and print information
fn arch_example<A: ArchTag>(arch: &'static str, cs: &mut Capstone<A>, code: &[u8]) -> CsResult<()> {
    println!("\n*************************************");
    println!("Architecture {}:", arch);

    let insns = cs.disasm_all(code, 0x1000)?;
    println!("Found {} instructions", insns.len());
    for i in insns.iter() {
        println!();
        println!("{}", i);

        let detail = cs.insn_detail(i)?;
        let arch_detail = detail.arch_detail();
        let ops: Vec<_> = arch_detail.operands().collect();

        #[cfg(feature = "full")]
        let output: &[(&str, String)] = &[
            ("insn id:", format!("{:?}", i.id().0)),
            ("bytes:", format!("{:?}", i.bytes())),
            ("read regs:", reg_names(cs, detail.regs_read())),
            ("write regs:", reg_names(cs, detail.regs_write())),
            ("insn groups:", group_names(cs, detail.groups())),
        ];

        #[cfg(not(feature = "full"))]
        let output: &[(&str, String)] = &[
            ("insn id:", format!("{:?}", i.id().0)),
            ("bytes:", format!("{:?}", i.bytes())),
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
    let mut cs_mips = Capstone::<MipsArchTag>::new()
        .mode(arch::mips::ArchMode::Mips32R6)
        .detail(true)
        .build()?;

    let mut cs_x86 = Capstone::<X86ArchTag>::new()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()?;

    arch_example("MIPS", &mut cs_mips, MIPS_CODE)?;
    arch_example("X86", &mut cs_x86, X86_CODE)?;

    Ok(())
}

fn main() {
    if let Err(err) = example() {
        println!("Error: {}", err);
    }
}
