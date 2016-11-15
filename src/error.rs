use capstone_sys::{self, cs_strerror};

use std::ffi::CStr;
use std::fmt;
use std::error;
use std::result;

#[derive(Debug, Copy, Clone, PartialEq)]
/// An error emanating from the capstone system library
pub enum CapstoneError {
    /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    OutOfMemory = 0,
    /// Unsupported Architecture: cs_open()
    UnsupportedArch,
    /// Invalid Handle: cs_op_count(), cs_op_index()
    InvalidHandle,
    /// Invalid InvalidCsh argument: cs_close(), cs_errno(), cs_option()
    InvalidCsh,
    /// Invalid/unsupported mode: cs_open()
    InvalidMode,
    /// Invalid/unsupported option: cs_option()
    InvalidOption,
    /// Information is unavailable because detail option is OFF
    DetailOff,
    /// Dynamic Memory management uninitialized (see CS_OPT_MEM)
    UninitializedMemSetup,
    /// Unsupported Version (bindings)
    UnsupportedVersion,
    /// Access irrelevant data in "diet" engine
    IrrelevantDataInDiet,
    /// Access irrelevant data for "data" instruction in SKIPDATA Mode
    IrrelevantDataInSkipData,
    /// X86 AT&T syntax is unsupported (opt-out at compile time)
    UnsupportedX86Att,
    /// X86 Intel syntax is unsupported (opt-out at compile time)
    UnsupportedX86Intel,
}

#[derive(Debug, Copy, Clone, PartialEq)]
/// An error enum for this library
pub enum Error {
    /// An error emanating from the capstone framework library calls
    Capstone(CapstoneError),
    /// An unknown error not equal to a `CapstoneError`
    UnknownCapstoneError,
}

impl Error {
    pub fn from(err: capstone_sys::cs_err) -> Self {
        use self::Error::*;
        use self::CapstoneError::*;
        use capstone_sys::*;
        match err {
            CS_ERR_MEM => Capstone(OutOfMemory),
            CS_ERR_ARCH => Capstone(UnsupportedArch),
            CS_ERR_HANDLE => Capstone(InvalidHandle),
            CS_ERR_CSH => Capstone(InvalidCsh),
            CS_ERR_MODE => Capstone(InvalidMode),
            CS_ERR_OPTION => Capstone(InvalidOption),
            CS_ERR_DETAIL => Capstone(DetailOff),
            CS_ERR_MEMSETUP => Capstone(UninitializedMemSetup),
            CS_ERR_VERSION => Capstone(UnsupportedVersion),
            CS_ERR_DIET => Capstone(IrrelevantDataInDiet),
            CS_ERR_SKIPDATA => Capstone(IrrelevantDataInSkipData),
            CS_ERR_X86_ATT => Capstone(UnsupportedX86Att),
            CS_ERR_X86_INTEL => Capstone(UnsupportedX86Intel),
            _ => UnknownCapstoneError,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match *self {
            Capstone(err) => {
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

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;
        use self::CapstoneError::*;
        match *self {
            Capstone(OutOfMemory) => "Out-Of-Memory error",
            Capstone(UnsupportedArch) => "Unsupported architecture",
            Capstone(InvalidHandle) => "Invalid handle",
            Capstone(InvalidCsh) => "Invalid csh argument",
            Capstone(InvalidMode) => "Invalid/unsupported mode",
            Capstone(InvalidOption) => "Invalid/unsupported option",
            Capstone(DetailOff) => "Information is unavailable because detail option is OFF",
            Capstone(UninitializedMemSetup) => "Dynamic memory management uninitialized (see CS_OPT_MEM)",
            Capstone(UnsupportedVersion) => "Unsupported version (bindings)",
            Capstone(IrrelevantDataInDiet) => "Access irrelevant data in \"diet\" engine",
            Capstone(IrrelevantDataInSkipData) => "Access irrelevant data for \"data\" instruction in SKIPDATA mode",
            Capstone(UnsupportedX86Att) => "X86 AT&T syntax is unsupported (opt-out at compile time)",
            Capstone(UnsupportedX86Intel) => "X86 Intel syntax is unsupported (opt-out at compile time)",
            UnknownCapstoneError => "Encountered Unknown Capstone Return Error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub type Result<T> = result::Result<T, Error>;
