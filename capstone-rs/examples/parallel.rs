//! This example shows how to disassemble in parallel. You need a separate `Capstone` struct for
//! each thread.
//!
//! We shard the input by using parallel iterators from the rayon crate.

use capstone::arch::x86::X86ArchTag;
use capstone::prelude::*;
use rayon::prelude::*;

fn main() -> CsResult<()> {
    // Closure to create `Capstone` instance
    let create_cs = || -> CsResult<Capstone<X86ArchTag>> {
        let cs = Capstone::<X86ArchTag>::new()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()?;
        Ok(cs)
    };

    // Slice of code to disassemble
    let input_code: &[&[u8]] = &[
        b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4",
        b"\x90\x41\xe8\x04\x03\x02\x01",
        b"\xff\xff\xff\xff\xff",
    ];

    let results: Vec<CsResult<Vec<String>>> = input_code
        .par_iter() // iterate in parallel
        .map(|bytes| {
            // map input byte to output mnemonic
            let cs = create_cs()?;
            let insns = cs.disasm_all(bytes, 0x1000)?;
            let result: Option<Vec<String>> = insns
                .iter()
                .map(|insn| -> Option<String> { Some(insn.mnemonic()?.to_string()) })
                .collect();
            let result = result.ok_or(capstone::Error::CustomError("No mnemonic"))?;
            Ok(result)
        })
        .collect();

    println!("{:#?}", results);

    Ok(())
}
