extern crate capstone;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate stderrlog;

use capstone::{Arch, Endian, ExtraMode, Mode};
use capstone::prelude::*;
use clap::{App, Arg, ArgGroup};
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;
use std::str::FromStr;

const DEFAULT_CAPACITY: usize = 1024;

trait ExpectExit<T> {
    fn expect_exit(self) -> T;
}

impl<T, E> ExpectExit<T> for Result<T, E>
where
    E: ::std::error::Error,
{
    fn expect_exit(self) -> T {
        match self {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {}", e.description());
                exit(1);
            }
        }
    }
}

/// We can't iterate over enums declared in another crate, so we declare a private enum that
/// shadows the values
macro_rules! arch_conversions {
    (
        $arg_struct:ident = $cs_struct:ident
        [ $( $name:ident, )* ]
    ) => {
        arg_enum!{
            #[derive(PartialEq, Debug)]
            pub enum $arg_struct {
                $( $name, )*
            }
        }

        impl From<$arg_struct> for $cs_struct {
            fn from(arch_arg: $arg_struct) -> $cs_struct {
                match arch_arg {
                    $( $arg_struct::$name => $cs_struct::$name, )*
                }
            }
        }

        impl From<$cs_struct> for $arg_struct {
            fn from(arch_arg: $cs_struct) -> $arg_struct {
                match arch_arg {
                    $( $cs_struct::$name => $arg_struct::$name, )*
                }
            }
        }
    }
}

arch_conversions!(
    ArchArg = Arch
    [
        ARM,
        ARM64,
        MIPS,
        X86,
        PPC,
        SPARC,
        SYSZ,
        XCORE,
    ]
);

arch_conversions!(
    ModeArg = Mode
    [
        Arm,
        Mode16,
        Mode32,
        Mode64,
        Thumb,
        Mips3,
        Mips32R6,
        MipsGP64,
        V9,
        Default,
    ]
);

arch_conversions!(
    ExtraModeArg = ExtraMode
    [
        MClass,
        V8,
        Micro,
    ]
);

fn disasm<T: Iterator<Item = ExtraMode>>(
    arch: Arch,
    mode: Mode,
    extra_mode: T,
    endian: Option<Endian>,
    code: &[u8],
    addr: u64,
) {
    let mut cs = Capstone::new_raw(arch, mode, extra_mode, endian).expect_exit();

    for i in cs.disasm_all(code, addr).expect_exit().iter() {
        let bytes: Vec<_> = i.bytes().iter().map(|x| format!("{:02x}", x)).collect();
        let bytes = bytes.join(" ");
        println!(
            "{:-10x}:  {:35} {:7} {}",
            i.address(),
            bytes,
            i.mnemonic().unwrap(),
            i.op_str().unwrap_or("")
        );
    }
}

fn main() {
    // Lowercase arches
    let _arches: Vec<String> = ArchArg::variants()
        .iter()
        .map(|x| x.to_lowercase())
        .collect();
    let arches: Vec<&str> = _arches.iter().map(|x| x.as_str()).collect();

    // Lowercase modes
    let _modes: Vec<String> = ModeArg::variants()
        .iter()
        .map(|x| x.to_lowercase())
        .collect();
    let modes: Vec<&str> = _modes.iter().map(|x| x.as_str()).collect();

    // Lowercase extra modes
    let _extra_modes: Vec<String> = ExtraModeArg::variants()
        .iter()
        .map(|x| x.to_lowercase())
        .collect();
    let extra_modes: Vec<&str> = _extra_modes.iter().map(|x| x.as_str()).collect();

    let matches = App::new("capstone-rs disassembler tool")
        .about("Disassembles binary file")
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .help("input file with binary instructions")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("stdin")
                .short("s")
                .long("stdin")
                .help("read binary instructions from stdin")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("address")
                .short("r")
                .long("addr")
                .help("address of code")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("ARCH")
                .short("a")
                .long("arch")
                .help("Architecture")
                .takes_value(true)
                .required(true)
                .possible_values(arches.as_slice())
                .case_insensitive(true),
        )
        .arg(
            Arg::with_name("MODE")
                .short("m")
                .long("mode")
                .help("Mode")
                .takes_value(true)
                .required(true)
                .possible_values(modes.as_slice())
                .case_insensitive(true),
        )
        .arg(
            Arg::with_name("EXTRA_MODE")
                .short("e")
                .long("extra")
                .help("Extra Mode")
                .takes_value(true)
                .required(false)
                .possible_values(extra_modes.as_slice())
                .case_insensitive(true)
                .multiple(true),
        )
        .group(
            ArgGroup::with_name("INPUT")
                .arg("file")
                .arg("stdin")
                .required(true),
        )
        .get_matches();

    let input_bytes: Vec<u8> = match matches.value_of("INPUT") {
        Some(file_path) => {
            let mut file = File::open(file_path).expect_exit();
            let capacity = match file.metadata() {
                Err(_) => DEFAULT_CAPACITY,
                Ok(metadata) => metadata.len() as usize,
            };
            let mut buf = Vec::with_capacity(capacity as usize);
            file.read_to_end(&mut buf).expect_exit();
            buf
        }
        None => {
            let mut buf = Vec::with_capacity(DEFAULT_CAPACITY);
            let mut stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            stdin.read_to_end(&mut buf).expect_exit();
            buf
        }
    };

    stderrlog::new()
        .verbosity(matches.occurrences_of("v") as usize)
        .init()
        .unwrap();

    let arch: Arch = ArchArg::from_str(matches.value_of("ARCH").unwrap())
        .unwrap()
        .into();
    info!("Arch = {:?}", arch);

    let mode: Mode = ModeArg::from_str(matches.value_of("MODE").unwrap())
        .unwrap()
        .into();
    info!("Mode = {:?}", mode);

    let extra_mode: Vec<_> = match matches.values_of("EXTRA_MODE") {
        None => Vec::with_capacity(0),
        Some(x) => x.map(|x| ExtraMode::from(ExtraModeArg::from_str(x).unwrap()))
            .collect(),
    };
    info!("ExtraMode = {:?}", extra_mode);

    let address =
        u64::from_str_radix(matches.value_of("address").unwrap_or("1000"), 16).expect_exit();
    info!("Address = 0x{:x}", address);

    disasm(
        arch,
        mode,
        extra_mode.iter().map(|x| *x),
        None,
        input_bytes.as_slice(),
        address,
    );
}
