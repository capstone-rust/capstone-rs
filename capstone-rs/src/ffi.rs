//! Functions useful for FFI

use core::ffi::c_char;
use core::ffi::CStr;

// This function will go unused in Diet mode
#[allow(unused)]
/// Given a valid C-style, NUL terminated string, returns a Rust `&str`
///
/// Returns `None` if the pointer is null or the bytes are not valid UTF-8.
///
/// Warnings:
/// - The pointer must point to a NUL terminated string
/// - This function "creates" a reference with an arbitrary lifetime, so be careful to limit the
///   lifetime appropriately
#[inline]
#[allow(clippy::unnecessary_cast)]
pub(crate) unsafe fn str_from_cstr_ptr<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    /* ASSUMPTION: capstone returns NUL terminated string */
    let cstr = CStr::from_ptr(ptr);
    /* capstone does not guarantee UTF-8: custom mnemonics may contain arbitrary bytes */
    core::str::from_utf8(cstr.to_bytes()).ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cstr_convert() {
        unsafe {
            assert_eq!(str_from_cstr_ptr(core::ptr::null() as *const c_char), None);
            assert_eq!(
                str_from_cstr_ptr(b"\x00".as_ptr() as *const c_char),
                Some("")
            );
            assert_ne!(
                str_from_cstr_ptr(b"\x00".as_ptr() as *const c_char),
                Some("b")
            );
            assert_eq!(
                str_from_cstr_ptr(b"this is my TEST string\x00".as_ptr() as *const c_char),
                Some("this is my TEST string")
            );
        }
    }
}
