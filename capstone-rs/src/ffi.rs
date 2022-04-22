//! Functions useful for FFI

use core::{slice, str};
use libc::{self, c_char};

/// Given a valid C-style, NUL terminated, UTF8-encoded string, returns a Rust `&str`
///
/// Warnings:
/// - No checks are made for: valid UTF-8
/// - This function "creates" a reference with an arbitrary lifetime, so be careful to limit the
///   lifetime appropriately
pub(crate) unsafe fn str_from_cstr_ptr<'a>(ptr: *const c_char) -> Option<&'a str> {
    (!ptr.is_null()).then(||  {
        let len = libc::strlen(ptr);

        /* ASSUMPTION: capstone returns NUL terminated string */
        let view: &[u8] = slice::from_raw_parts(ptr as *const u8, len as usize);
        str::from_utf8_unchecked(view)
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use core;

    #[test]
    fn cstr_convert() {
        unsafe {
            assert_eq!(str_from_cstr_ptr(core::ptr::null() as *const c_char), None);
            assert_eq!(
                str_from_cstr_ptr(b"\xff\x00".as_ptr() as *const c_char),
                None
            );
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
