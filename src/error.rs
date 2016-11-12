use capstone_sys::{self, cs_strerror};

use std::ffi::CStr;
use std::fmt;
use std::error::Error;

#[derive(Debug, Copy, Clone, PartialEq)]
/// An error emanating from the capstone system library
pub enum CsErr {
    Mem = 0, // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    Arch, // Unsupported Architecture: cs_open()
    Handle, // Invalid Handle: cs_op_count(), cs_op_index()
    Csh, // Invalid Csh argument: cs_close(), cs_errno(), cs_Option()
    Mode, // Invalid/unsupported Mode: cs_open()
    Option, // Invalid/unsupported Option: cs_Option()
    Detail, // Information is unavailable because Detail Option is OFF
    MemSetup, // Dynamic Memory management uninitialized (see CS_OPT_MEM)
    Version, // Unsupported Version (bindings)
    Diet, // Access irrelevant data in "Diet" engine
    SkipData, // Access irrelevant data for "data" instruction in SkipData Mode
    X86Att, // X86 AT&T syntax is unsupported (opt-out at compile time)
    X86Intel, // X86 Intel syntax is unsupported (opt-out at compile time)
}

#[derive(Debug, Copy, Clone, PartialEq)]
/// An error enum for this library
pub enum Err {
    Cs(CsErr),
    /// An unknown error not equal to a `CsErr`
    UnknownCapstoneError,
}

impl Err {
    pub fn from(err: capstone_sys::cs_err) -> Err {
        use self::Err::*;
        use self::CsErr::*;
        use capstone_sys::*;
        match err {
            CS_ERR_MEM => Cs(Mem),
            CS_ERR_ARCH => Cs(Arch),
            CS_ERR_HANDLE => Cs(Handle),
            CS_ERR_CSH => Cs(Csh),
            CS_ERR_MODE => Cs(Mode),
            CS_ERR_OPTION => Cs(Option),
            CS_ERR_DETAIL => Cs(Detail),
            CS_ERR_MEMSETUP => Cs(MemSetup),
            CS_ERR_VERSION => Cs(Version),
            CS_ERR_DIET => Cs(Diet),
            CS_ERR_SKIPDATA => Cs(SkipData),
            CS_ERR_X86_ATT => Cs(X86Att),
            CS_ERR_X86_INTEL => Cs(X86Intel),
            _ => UnknownCapstoneError,
        }
    }
}

impl fmt::Display for Err {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::Err::*;
        match *self {
            Cs(err) => {
                let s = unsafe {
                    let err = cs_strerror(err as u8);
                    CStr::from_ptr(err).to_string_lossy().into_owned()
                };
                write!(fmt, "{}", s)
            }
            UnknownCapstoneError => write!(fmt, "Encountered Unknown Capstone Return Error"),
        }
    }
}

impl Error for Err {
    fn description(&self) -> &str {
        use self::Err::*;
        use self::CsErr::*;
        match *self {
            Cs(Mem) => "Out-Of-Memory error",
            Cs(Arch) => "Unsupported architecture",
            Cs(Handle) => "Invalid handle",
            Cs(Csh) => "Invalid csh argument",
            Cs(Mode) => "Invalid/unsupported mode",
            Cs(Option) => "Invalid/unsupported option",
            Cs(Detail) => "Information is unavailable because detail option is OFF",
            Cs(MemSetup) => "Dynamic memory management uninitialized (see CS_OPT_MEM)",
            Cs(Version) => "Unsupported version (bindings)",
            Cs(Diet) => "Access irrelevant data in \"diet\" engine",
            Cs(SkipData) => "Access irrelevant data for \"data\" instruction in SKIPDATA Mode",
            Cs(X86Att) => "X86 AT&T syntax is unsupported (opt-out at compile time)",
            Cs(X86Intel) => "X86 Intel syntax is unsupported (opt-out at compile time)",
            UnknownCapstoneError => "Encountered Unknown Capstone Return Error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

pub type CsResult<T> = Result<T, Err>;
