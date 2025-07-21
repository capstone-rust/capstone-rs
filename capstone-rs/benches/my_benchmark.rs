extern crate capstone;
#[macro_use]
extern crate criterion;

use capstone::prelude::*;
use capstone::{Arch, Endian, ExtraMode, Mode, NO_EXTRA_MODE};
use criterion::{black_box, Criterion};

const X86_CODE: &[u8] = include_bytes!("../test-inputs/x86_64.bin_ls.bin");

/// Disassemble code and print information
fn arch_bench<T: Iterator<Item = ExtraMode>>(
    code: &[u8],
    arch: Arch,
    mode: Mode,
    extra_mode: T,
    endian: Option<Endian>,
    detail: bool,
    iter: bool,
) {
    let mut cs =
        Capstone::new_raw(arch, mode, extra_mode, endian).expect("failed to make capstone");
    cs.set_detail(detail).expect("failed to set detail");

    if iter {
        let iter = cs.disasm_iter(code, 0x1000).expect("failed to disassemble");
        for i in iter {
            black_box(i);
        }
    } else {
        let insns = cs.disasm_all(code, 0x1000).expect("failed to disassemble");
        for i in insns.iter() {
            black_box(i);
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    macro_rules! bench {
        ($name:expr; $( $args:expr ),+ ) => {
            c.bench_function($name, |b| {
                b.iter(|| arch_bench($( $args, )+ false, false))
            });

            c.bench_function(concat!($name, "_iter"), |b| {
                b.iter(|| arch_bench($( $args, )+ false, true))
            });

            c.bench_function(concat!($name, "_detail"), move |b| {
                b.iter(|| arch_bench($( $args, )+ true, false))
            });

            c.bench_function(concat!($name, "_detail_iter"), |b| {
                b.iter(|| arch_bench($( $args, )+ true, true))
            });
        }
    }

    bench!("disasm_x86"; X86_CODE, Arch::X86, Mode::Mode64, NO_EXTRA_MODE, None);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
