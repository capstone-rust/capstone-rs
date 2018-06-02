extern crate capstone;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate stderrlog;

use capstone::prelude::*;
use capstone::{Arch, Endian, ExtraMode, Mode};
use clap::{App, Arg, ArgGroup};
use std::fmt::Display;
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
    E: Display,
{
    fn expect_exit(self) -> T {
        match self {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {}", e);
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

/// Select only hex bytes from input
fn unhexed_bytes(input: Vec<u8>) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut curr_byte_str = String::with_capacity(2);
    for b_u8 in input {
        let b = char::from(b_u8);
        if ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F') {
            curr_byte_str.push(b);
        }

        if curr_byte_str.len() == 2 {
            debug!("  curr_byte_str={:?}", curr_byte_str);
            let byte = u8::from_str_radix(&curr_byte_str, 16).expect("Unexpect hex parse error");
            output.push(byte);
            curr_byte_str.clear();
        }
    }

    if log::max_level() >= log::LevelFilter::Info {
        let output_hex: Vec<String> = output.iter().map(|x| format!("{:02x}", x)).collect();
        info!("unhexed_output = {:?}", output_hex);
    }

    output
}

fn disasm<T: Iterator<Item = ExtraMode>>(
    arch: Arch,
    mode: Mode,
    extra_mode: T,
    endian: Option<Endian>,
    code: &[u8],
    addr: u64,
    show_detail: bool,
) {
    info!("Got {} bytes", code.len());
    let mut cs = Capstone::new_raw(arch, mode, extra_mode, endian).expect_exit();

    if show_detail {
        cs.set_detail(true).expect("Failed to set detail");
    }

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

        if show_detail {
            let detail = cs.insn_detail(&i).expect("Failed to get insn detail");

            let output: &[(&str, String)] = &[
                ("insn id:", format!("{:?}", i.id().0)),
                ("read regs:", reg_names(&cs, detail.regs_read())),
                ("write regs:", reg_names(&cs, detail.regs_write())),
                ("insn groups:", group_names(&cs, detail.groups())),
            ];

            for &(ref name, ref message) in output.iter() {
                println!("{:13}{:12} {}", "", name, message);
            }
        }
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
            Arg::with_name("hex")
                .short("x")
                .long("hex")
                .help("Treat input has hex; only select characters that are [a-fA-F0-9]")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("DETAIL")
                .short("d")
                .long("detail")
                .help("Print details about instructions")
                .takes_value(false),
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
        .arg(
            Arg::with_name("ENDIAN")
                .short("n")
                .long("endian")
                .help("Endianness")
                .takes_value(true)
                .required(false)
                .possible_values(&["little", "big"])
                .case_insensitive(true),
        )
        .group(
            ArgGroup::with_name("INPUT")
                .arg("file")
                .arg("stdin")
                .required(true),
        )
        .get_matches();

    let direct_input_bytes: Vec<u8> = match matches.value_of("INPUT") {
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

    let is_hex = matches.is_present("hex");
    info!("is_hex = {:?}", is_hex);

    let show_detail = matches.is_present("DETAIL");
    info!("show_detail = {:?}", show_detail);

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

    let endian: Option<Endian> = matches
        .value_of("ENDIAN")
        .map(|x| Endian::from_str(x).expect_exit());
    info!("Endian = {:?}", endian);

    let address =
        u64::from_str_radix(matches.value_of("address").unwrap_or("1000"), 16).expect_exit();
    info!("Address = 0x{:x}", address);

    let input_bytes = if is_hex {
        unhexed_bytes(direct_input_bytes)
    } else {
        direct_input_bytes
    };

    disasm(
        arch,
        mode,
        extra_mode.iter().map(|x| *x),
        endian,
        input_bytes.as_slice(),
        address,
        show_detail,
    );
}
