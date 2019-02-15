//! Capstone errors

use capstone_sys;
use capstone_sys::cs_err::*;

use std::error;
use std::fmt;
use std::result;

/// Create `RustFeatures` struct definition, `new()`, and a getter for each field
macro_rules! capstone_error_def {
    ( $( $( #[$attr:meta] )* => $rust_variant:ident = $cs_variant:ident; )* ) => {
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        /// An error enum for this library
        pub enum Error {
            $(
                $(
                    #[$attr]
                )*
                $rust_variant,
            )*

            /// An unknown error not equal to a `CapstoneError`
            UnknownCapstoneError,

            /// Error with a custom message
            CustomError(&'static str),
        }

        impl From<capstone_sys::cs_err::Type> for Error {
            fn from(err: capstone_sys::cs_err::Type) -> Self {
                match err {
                    $(
                        $cs_variant => Error::$rust_variant,
                    )*
                    _ => Error::UnknownCapstoneError,
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
        use std::error::Error;
        write!(fmt, "{}", self.description())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;
        match *self {
            OutOfMemory => "Out-Of-Memory error",
            UnsupportedArch => "Unsupported architecture",
            InvalidHandle => "Invalid handle",
            InvalidCsh => "Invalid csh argument",
            InvalidMode => "Invalid/unsupported mode",
            InvalidOption => "Invalid/unsupported option",
            DetailOff => "Information is unavailable because detail option is OFF",
            UninitializedMemSetup => "Dynamic memory management uninitialized (see CS_OPT_MEM)",
            UnsupportedVersion => "Unsupported version (bindings)",
            IrrelevantDataInDiet => "Access irrelevant data in \"diet\" engine",
            IrrelevantDataInSkipData => {
                "Access irrelevant data for \"data\" instruction in SKIPDATA mode"
            }
            UnsupportedX86Att => "X86 AT&T syntax is unsupported (opt-out at compile time)",
            UnsupportedX86Intel => "X86 Intel syntax is unsupported (opt-out at compile time)",
            UnknownCapstoneError => "Encountered Unknown Capstone Return Error",
            CustomError(msg) => msg,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::Error;
    use capstone_sys::cs_err;

    #[test]
    fn test_error() {
        let errors = [
            Error::OutOfMemory,
            Error::UnknownCapstoneError,
            Error::CustomError("custom error"),
            Error::from(cs_err::CS_ERR_ARCH),
            Error::from(500 as cs_err::Type),
        ];

        for error in errors.iter() {
            println!("{}", error);
        }
    }
}
