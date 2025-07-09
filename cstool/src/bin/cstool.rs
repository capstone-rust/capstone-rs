//! Disassembles machine code

use std::fmt::Display;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::exit;
use std::str::FromStr;

use capstone::{self, prelude::*, Arch, Endian, EnumList, ExtraMode, Mode};
use clap::{
    builder::{PossibleValuesParser, Str},
    Arg, ArgAction, ArgGroup, Command,
};
use log::{debug, info};

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
                eprintln!("error: {e}");
                exit(1);
            }
        }
    }
}

/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

/// Select only hex bytes from input
fn unhexed_bytes(input: Vec<u8>) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut curr_byte_str = String::with_capacity(2);
    for b_u8 in input {
        let b = char::from(b_u8);
        if b.is_ascii_hexdigit() {
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
        let output_hex: Vec<String> = output.iter().map(|x| format!("{x:02x}")).collect();
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

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    for i in cs.disasm_all(code, addr).expect_exit().iter() {
        let bytes: Vec<_> = i.bytes().iter().map(|x| format!("{x:02x}")).collect();
        let bytes = bytes.join(" ");
        let _ = writeln!(
            &mut handle,
            "{:-10x}:  {:35} {:7} {}",
            i.address(),
            bytes,
            i.mnemonic().unwrap(),
            i.op_str().unwrap_or("")
        )
        .is_ok();

        if show_detail {
            let detail = cs.insn_detail(i).expect("Failed to get insn detail");

            let output: &[(&str, String)] = &[
                ("insn id:", format!("{:?}", i.id().0)),
                ("read regs:", reg_names(&cs, detail.regs_read())),
                ("write regs:", reg_names(&cs, detail.regs_write())),
                ("insn groups:", group_names(&cs, detail.groups())),
            ];

            for (name, message) in output.iter() {
                let _ = writeln!(&mut handle, "{:13}{:12} {}", "", name, message).is_ok();
            }
        }
    }
}

const FILE_ARG: &str = "file";
const STDIN_ARG: &str = "stdin";
const CODE_ARG: &str = "code";
const ADDRESS_ARG: &str = "address";
const VERBOSE_ARG: &str = "verbose";
const HEX_ARG: &str = "hex";
const DETAIL_ARG: &str = "detail";
const ARCH_ARG: &str = "arch";
const MODE_ARG: &str = "mode";
const EXTRA_MODE_ARG: &str = "extra";
const ENDIAN_ARG: &str = "endian";

const AFTER_HELP: &str = r#"
Example:

    # Disassemble 32-bit X86 (non-hex characters are ignored)
    cstool --arch x86 --mode mode32 --code "90 42 e812345678"
          1000:  90                                  nop
          1001:  42                                  inc     edx
          1002:  e8 12 34 56 78                      call    0x78564419
"#;

fn main() {
    // Lowercase arches
    let arches: Vec<Str> = Arch::variants()
        .iter()
        .map(|x| format!("{x}").to_lowercase().into())
        .collect();

    // Lowercase modes
    let modes: Vec<Str> = Mode::variants()
        .iter()
        .map(|x| format!("{x}").to_lowercase().into())
        .collect();

    // Lowercase extra modes
    let extra_modes: Vec<Str> = ExtraMode::variants()
        .iter()
        .map(|x| format!("{x}").to_lowercase().into())
        .collect();

    let matches = Command::new("capstone-rs disassembler tool")
        .about("Disassembles binary file")
        .after_help(AFTER_HELP)
        .arg(
            Arg::new(FILE_ARG)
                .short('f')
                .long(FILE_ARG)
                .help("input file with binary instructions")
                .value_name("FILE"),
        )
        .arg(
            Arg::new(STDIN_ARG)
                .short('s')
                .long(STDIN_ARG)
                .help("read binary instructions from stdin")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(CODE_ARG)
                .short('c')
                .long(CODE_ARG)
                .help("instruction bytes (implies --hex)"),
        )
        .arg(
            Arg::new(ADDRESS_ARG)
                .short('r')
                .long("addr")
                .help("address of code"),
        )
        .arg(
            Arg::new(VERBOSE_ARG)
                .short('v')
                .help("Sets the level of verbosity")
                .action(ArgAction::Count),
        )
        .arg(
            Arg::new(HEX_ARG)
                .short('x')
                .long(HEX_ARG)
                .help("Treat input has hex; only select characters that are [a-fA-F0-9]")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(DETAIL_ARG)
                .short('d')
                .long(DETAIL_ARG)
                .help("Print details about instructions")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(ARCH_ARG)
                .short('a')
                .long(ARCH_ARG)
                .help("Architecture")
                .required(true)
                .value_parser(PossibleValuesParser::new(arches))
                .ignore_case(true),
        )
        .arg(
            Arg::new(MODE_ARG)
                .short('m')
                .long(MODE_ARG)
                .help(MODE_ARG)
                .required(true)
                .value_parser(PossibleValuesParser::new(modes))
                .ignore_case(true),
        )
        .arg(
            Arg::new(EXTRA_MODE_ARG)
                .short('e')
                .long(EXTRA_MODE_ARG)
                .help("Extra Mode")
                .required(false)
                .value_parser(PossibleValuesParser::new(extra_modes))
                .ignore_case(true),
        )
        .arg(
            Arg::new(ENDIAN_ARG)
                .short('n')
                .long(ENDIAN_ARG)
                .help("Endianness")
                .required(false)
                .value_parser(PossibleValuesParser::new(["little", "big"]))
                .ignore_case(true),
        )
        .group(
            ArgGroup::new("input")
                .arg(FILE_ARG)
                .arg(STDIN_ARG)
                .arg(CODE_ARG)
                .required(true),
        )
        .get_matches();

    let direct_input_bytes: Vec<u8> = if let Some(file_path) = matches.get_one::<String>(FILE_ARG) {
        let mut file = File::open(file_path).expect_exit();
        let capacity = match file.metadata() {
            Err(_) => DEFAULT_CAPACITY,
            Ok(metadata) => metadata.len() as usize,
        };
        let mut buf = Vec::with_capacity(capacity);
        file.read_to_end(&mut buf).expect_exit();
        buf
    } else if let Some(code) = matches.get_one::<String>(CODE_ARG) {
        code.as_bytes().to_vec()
    } else {
        let mut buf = Vec::with_capacity(DEFAULT_CAPACITY);
        let stdin = std::io::stdin();
        stdin.lock().read_to_end(&mut buf).expect_exit();
        buf
    };

    stderrlog::new()
        .verbosity(matches.get_count(VERBOSE_ARG) as usize)
        .init()
        .unwrap();

    let is_hex = matches.get_flag(HEX_ARG) || matches.get_one::<String>(CODE_ARG).is_some();
    info!("is_hex = {:?}", is_hex);

    let show_detail = matches.get_flag(DETAIL_ARG);
    info!("show_detail = {:?}", show_detail);

    let arch: Arch = Arch::from_str(matches.get_one::<String>(ARCH_ARG).unwrap()).unwrap();
    info!("Arch = {:?}", arch);

    let mode: Mode = Mode::from_str(matches.get_one::<String>(MODE_ARG).unwrap()).unwrap();
    info!("Mode = {:?}", mode);

    let extra_mode: Vec<_> = match matches.get_many::<String>(EXTRA_MODE_ARG) {
        None => Vec::with_capacity(0),
        Some(x) => x.map(|x| ExtraMode::from_str(x).unwrap()).collect(),
    };
    info!("ExtraMode = {:?}", extra_mode);

    let endian: Option<Endian> = matches
        .get_one::<String>(ENDIAN_ARG)
        .map(|x| Endian::from_str(x).expect_exit());
    info!("Endian = {:?}", endian);

    let address = u64::from_str_radix(
        matches
            .get_one::<String>(ADDRESS_ARG)
            .unwrap_or(&"1000".into()),
        16,
    )
    .expect_exit();
    info!("Address = 0x{:x}", address);

    let input_bytes = if is_hex {
        unhexed_bytes(direct_input_bytes)
    } else {
        direct_input_bytes
    };

    disasm(
        arch,
        mode,
        extra_mode.iter().copied(),
        endian,
        input_bytes.as_slice(),
        address,
        show_detail,
    );
}
