//! Capstone errors

use capstone_sys::{self, cs_strerror};
use capstone_sys::cs_err::*;

use std::ffi::CStr;
use std::fmt;
use std::error;
use std::result;

/// Create `RustFeatures` struct definition, `new()`, and a getter for each field
macro_rules! capstone_error_def {
    ( $( $( #[$attr:meta] )* => $rust_variant:ident = $cs_variant:ident; )* ) => {
        /// Error for Capstone
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        pub enum CapstoneError {
            $(
                $(
                    #[$attr]
                )*
                $rust_variant,
            )*
        }

        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        /// An error enum for this library
        pub enum Error {
            /// An error emanating from the capstone framework library calls
            Capstone(CapstoneError),
            /// An unknown error not equal to a `CapstoneError`
            UnknownCapstoneError,
            /// Error with a custom message
            CustomError(&'static str),
        }

        impl From<capstone_sys::cs_err::Type> for Error {
            fn from(err: capstone_sys::cs_err::Type) -> Self {
                use self::Error::*;
                use self::CapstoneError::*;
                match err {
                    $(
                        $cs_variant => Capstone($rust_variant),
                    )*
                    _ => UnknownCapstoneError,
                }
            }
        }

        impl From<CapstoneError> for capstone_sys::cs_err::Type {
            fn from(err: CapstoneError) -> Self {
                match err {
                    $(
                        CapstoneError::$rust_variant => $cs_variant,
                    )*
                }
            }
        }
    }
}

capstone_error_def!(
    /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    => OutOfMemory = CS_ERR_MEM;
    /// Unsupported Architecture: cs_open()
    => UnsupportedArch = CS_ERR_ARCH;
    /// Invalid Handle: cs_op_count(), cs_op_index()
    => InvalidHandle = CS_ERR_HANDLE;
    /// Invalid InvalidCsh argument: cs_close(), cs_errno(), cs_option()
    => InvalidCsh = CS_ERR_CSH;
    /// Invalid/unsupported mode: cs_open()
    => InvalidMode = CS_ERR_MODE;
    /// Invalid/unsupported option: cs_option()
    => InvalidOption = CS_ERR_OPTION;
    /// Information is unavailable because detail option is OFF
    => DetailOff = CS_ERR_DETAIL;
    /// Dynamic Memory management uninitialized (see CS_OPT_MEM)
    => UninitializedMemSetup = CS_ERR_MEMSETUP;
    /// Unsupported Version (bindings)
    => UnsupportedVersion = CS_ERR_VERSION;
    /// Access irrelevant data in "diet" engine
    => IrrelevantDataInDiet = CS_ERR_DIET;
    /// Access irrelevant data for "data" instruction in SKIPDATA Mode
    => IrrelevantDataInSkipData = CS_ERR_SKIPDATA;
    /// X86 AT&T syntax is unsupported (opt-out at compile time)
    => UnsupportedX86Att = CS_ERR_X86_ATT;
    /// X86 Intel syntax is unsupported (opt-out at compile time)
    => UnsupportedX86Intel = CS_ERR_X86_INTEL;
);

#[must_use]
pub type CsResult<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match *self {
            Capstone(err) => {
                let s = unsafe {
                    let err = cs_strerror(err.into());
                    CStr::from_ptr(err).to_string_lossy().into_owned()
                };
                write!(fmt, "{}", s)
            }
            UnknownCapstoneError => write!(fmt, "Encountered Unknown Capstone Return Error"),
            CustomError(msg) => write!(fmt, "{}", msg),
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
            Capstone(UninitializedMemSetup) => {
                "Dynamic memory management uninitialized (see CS_OPT_MEM)"
            }
            Capstone(UnsupportedVersion) => "Unsupported version (bindings)",
            Capstone(IrrelevantDataInDiet) => "Access irrelevant data in \"diet\" engine",
            Capstone(IrrelevantDataInSkipData) => {
                "Access irrelevant data for \"data\" instruction in SKIPDATA mode"
            }
            Capstone(UnsupportedX86Att) => {
                "X86 AT&T syntax is unsupported (opt-out at compile time)"
            }
            Capstone(UnsupportedX86Intel) => {
                "X86 Intel syntax is unsupported (opt-out at compile time)"
            }
            UnknownCapstoneError => "Encountered Unknown Capstone Return Error",
            CustomError(msg) => msg,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}
