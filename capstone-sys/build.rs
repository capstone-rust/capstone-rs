//! The following environment variables affect the build:
//!
//! * `UPDATE_CAPSTONE_BINDINGS`: setting indicates that the pre-generated `capstone.rs` should be
//!   updated with the output bindgen
//!
//! # Bindgen enum mapping
//!
//! Bindgen can convert C enums in several ways:
//!
//! 1. **"Rustified" enum**: Bindgen creates a Rust enum, which provides the most "type safety" and
//!    reduces the chance of confusing variants for a different type. For variants whose
//!    discriminant values are not distinct, bindgen defines constants.
//! 2. **"Constified" enum**: Bindgen defines constants for each enum variant.
//! 3. **"Constified" enum module**: Bindgen defines constants for each enum variant in a separate
//!    module.
//!
//! # Rationale for enum types
//!
//! Rustified enum: these have distinct variant discriminants
//!
//! * `cs_arch`
//! * `cs_op_type`
//! * `cs_opt_type`
//!
//! Constified enum module:
//!
//! * `cs_err`: avoid undefined behavior in case an error is instantiated with an invalid value; the
//!   compiler could make false assumptions that the value is only within a certain range.
//! * `cs_group_type`/`ARCH_insn_group`: each architecture adds group types to the `cs_group_type`,
//!   so we constify to avoid needing to transmute.
//! * `cs_mode`: used as a bitmask; when values are OR'd together, they are not a valid discriminant
//!   value
//! * `cs_opt_value`/`ARCH_reg`: variant discriminants are not unique
//!
//! Bitfield enum: fields are OR'd together to form new values
//! * `cs_mode`

#[cfg(feature = "use_bindgen")]
extern crate bindgen;

extern crate cc;

#[cfg(feature = "use_bindgen")]
extern crate regex;

#[cfg(feature = "use_bindgen")]
use {
    regex::Regex,
    std::{fs::File, io::Write},
};

use std::env;
use std::fs::copy;
use std::path::PathBuf;

include!("common.rs");

const CAPSTONE_DIR: &str = "capstone";

/// Indicates how capstone library should be linked
#[allow(dead_code)]
enum LinkType {
    Dynamic,
    Static,
}

/// Build capstone using the cc crate
fn build_capstone_cc() {
    use std::fs::DirEntry;

    fn read_dir_and_filter<F: Fn(&DirEntry) -> bool>(dir: &str, filter: F) -> Vec<String> {
        use std::fs::read_dir;

        read_dir(dir)
            .expect("Failed to read capstone source directory")
            .map(|e| e.expect("Failed to read capstone source directory"))
            .filter(|e| filter(e))
            .map(|e| {
                format!(
                    "{}/{}",
                    dir,
                    e.file_name().to_str().expect("Invalid filename")
                )
            })
            .collect()
    }

    fn find_c_source_files(dir: &str) -> Vec<String> {
        read_dir_and_filter(dir, |e| {
            let file_type = e
                .file_type()
                .expect("Failed to read capstone source directory");
            let file_name = e.file_name().into_string().expect("Invalid filename");
            file_type.is_file() && (file_name.ends_with(".c") || file_name.ends_with(".C"))
        })
    }

    fn find_arch_dirs() -> Vec<String> {
        read_dir_and_filter(&format!("{}/{}", CAPSTONE_DIR, "arch"), |e| {
            let file_type = e
                .file_type()
                .expect("Failed to read capstone source directory");
            file_type.is_dir()
        })
    }

    let mut files = find_c_source_files(CAPSTONE_DIR);
    for arch_dir in find_arch_dirs().into_iter() {
        files.append(&mut find_c_source_files(&arch_dir));
    }

    let use_static_crt = {
        let target_features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
        target_features.split(',').any(|f| f == "crt-static")
    };
    let mut builder = cc::Build::new();
    builder
        .files(files)
        .include(format!("{}/{}", CAPSTONE_DIR, "include"))
        .define("CAPSTONE_USE_SYS_DYN_MEM", None)
        .define("CAPSTONE_HAS_ARM", None)
        .define("CAPSTONE_HAS_ARM64", None)
        .define("CAPSTONE_HAS_EVM", None)
        .define("CAPSTONE_HAS_M680X", None)
        .define("CAPSTONE_HAS_M68K", None)
        .define("CAPSTONE_HAS_MIPS", None)
        .define("CAPSTONE_HAS_POWERPC", None)
        .define("CAPSTONE_HAS_RISCV", None)
        .define("CAPSTONE_HAS_SPARC", None)
        .define("CAPSTONE_HAS_SYSZ", None)
        .define("CAPSTONE_HAS_TMS320C64X", None)
        .define("CAPSTONE_HAS_WASM", None)
        .define("CAPSTONE_HAS_X86", None)
        .define("CAPSTONE_HAS_XCORE", None)
        .define("CAPSTONE_HAS_BPF", None)
        // No need to display any warnings from the C library
        .flag_if_supported("-w")
        .static_crt(use_static_crt);

    if !cfg!(feature = "full") {
        builder.define("CAPSTONE_DIET", "yes");
    }

    builder.compile("capstone");
}

/// Search for header in search paths
#[cfg(feature = "use_bindgen")]
fn find_capstone_header(header_search_paths: &[PathBuf], name: &str) -> Option<PathBuf> {
    for search_path in header_search_paths.iter() {
        let potential_file = search_path.join(name);
        if potential_file.is_file() {
            return Some(potential_file);
        }
    }
    None
}

/// Gets environment variable value. Panics if variable is not set.
fn env_var(var: &str) -> String {
    env::var(var).unwrap_or_else(|_| panic!("Environment variable {} is not set", var))
}

/// Parse generated bindings and impl from_insn_id() for all architectures
/// instructions enum declaration.
#[cfg(feature = "use_bindgen")]
fn impl_insid_to_insenum(bindings: &str) -> String {
    use std::fmt::Write as _;

    let mut impl_arch_enum = String::new();
    impl_arch_enum.push_str("use core::convert::From;\n");

    for cs_arch in ARCH_INCLUDES {
        let arch = cs_arch.cs_name();

        // find architecture instructions enum declaration
        let re_enum_def = Regex::new(&format!("pub enum {}_insn (?s)\\{{.*?\\}}", arch))
            .expect("Unable to compile regex");
        let cap_enum_def = &re_enum_def
            .captures(bindings)
            .expect("Unable to capture group")[0];

        // find instructions and their id
        let re_ins_ids = Regex::new(&format!(
            "{}_INS_(?P<ins>[A-Z0-9_]+) = (?P<id>\\d+)",
            &arch.to_uppercase()
        ))
        .expect("Unable to compile regex");

        write!(
            impl_arch_enum,
            "impl From<u32> for {}_insn {{\n
            fn from(id: u32) -> Self {{\n
            match id {{\n",
            &arch
        )
        .unwrap();

        // fill match expression
        for cap_ins_id in re_ins_ids.captures_iter(cap_enum_def) {
            writeln!(
                impl_arch_enum,
                "{} => {}_insn::{}_INS_{},",
                &cap_ins_id["id"],
                &arch,
                &arch.to_uppercase(),
                &cap_ins_id["ins"]
            )
            .unwrap();
        }

        // if id didn't match, return [arch]_INS_INVALID.
        // special case for m680x which has 'INVLD' variant instead of 'INVALID'
        let invalid_str = match arch {
            "m680x" => "INVLD",
            _ => "INVALID",
        };
        write!(
            impl_arch_enum,
            "_ => {}_insn::{}_INS_{},",
            &arch,
            &arch.to_uppercase(),
            invalid_str,
        )
        .unwrap();

        impl_arch_enum.push_str("}\n}\n}\n");
    }

    impl_arch_enum
}

/// Create bindings using bindgen
#[cfg(feature = "use_bindgen")]
fn write_bindgen_bindings(
    header_search_paths: &[PathBuf],
    update_pregenerated_bindings: bool,
    pregenerated_bindgen_header: PathBuf,
    pregenerated_bindgen_impl: PathBuf,
    out_bindings_path: PathBuf,
    out_impl_path: PathBuf,
) {
    let mut builder = bindgen::Builder::default()
        .rust_target(bindgen::RustTarget::Stable_1_19)
        .size_t_is_usize(true)
        .use_core()
        .ctypes_prefix("libc")
        .header(
            find_capstone_header(header_search_paths, "capstone.h")
                .expect("Could not find header")
                .to_str()
                .unwrap(),
        )
        .disable_name_namespacing()
        .prepend_enum_name(false)
        .generate_comments(true)
        .layout_tests(false) // eliminate test failures on platforms with different pointer sizes
        .impl_debug(true)
        .constified_enum_module("cs_err|cs_group_type|cs_opt_value")
        .bitfield_enum("cs_mode|cs_ac_type")
        .rustified_enum(".*")
        .no_copy("cs_insn");

    // Whitelist cs_.* functions and types
    let pattern = String::from("cs_.*");
    builder = builder
        .allowlist_function(&pattern)
        .allowlist_type(&pattern);

    // Whitelist types with architectures
    for arch in ARCH_INCLUDES {
        // .*(^|_)ARCH(_|$).*
        let arch_type_pattern = format!(".*(^|_){}(_|$).*", arch.cs_name);
        let const_mod_pattern = format!("^{}_(reg|insn_group)$", arch.cs_name);
        builder = builder
            .allowlist_type(&arch_type_pattern)
            .constified_enum_module(&const_mod_pattern);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    // Write bindings to $OUT_DIR/bindings.rs
    bindings
        .write_to_file(&out_bindings_path)
        .expect("Unable to write bindings");

    // Parse bindings and impl fn to cast u32 to <arch>_insn, write output to file
    let bindings_impl_str = impl_insid_to_insenum(&bindings.to_string());
    let mut bindings_impl = File::create(&out_impl_path).expect("Unable to open file");
    bindings_impl
        .write_all(bindings_impl_str.as_bytes())
        .expect("Unable to write file");

    if update_pregenerated_bindings {
        copy(out_bindings_path, pregenerated_bindgen_header)
            .expect("Unable to update capstone bindings");
        copy(out_impl_path, pregenerated_bindgen_impl).expect("Unable to update capstone bindings");
    }
}

fn main() {
    #[allow(unused_assignments)]
    let mut link_type: Option<LinkType> = None;

    // C header search paths
    let mut header_search_paths: Vec<PathBuf> = Vec::new();

    build_capstone_cc();

    header_search_paths.push([CAPSTONE_DIR, "include", "capstone"].iter().collect());
    link_type = Some(LinkType::Static);

    match link_type.expect("Must specify link type") {
        LinkType::Dynamic => {
            println!("cargo:rustc-link-lib=dylib=capstone");
        }
        LinkType::Static => {
            println!("cargo:rustc-link-lib=static=capstone");
        }
    }

    // If UPDATE_CAPSTONE_BINDINGS is set, then updated the pre-generated capstone bindings
    let update_pregenerated_bindings = env::var("UPDATE_CAPSTONE_BINDINGS").is_ok();
    if update_pregenerated_bindings && !cfg!(feature = "use_bindgen") {
        panic!( "Setting UPDATE_CAPSTONE_BINDINGS only makes sense when enabling feature \"use_bindgen\"");
    }

    let pregenerated_bindgen_header: PathBuf = [
        env_var("CARGO_MANIFEST_DIR"),
        "pre_generated".into(),
        BINDINGS_FILE.into(),
    ]
    .iter()
    .collect();
    let pregenerated_bindgen_impl: PathBuf = [
        env_var("CARGO_MANIFEST_DIR"),
        "pre_generated".into(),
        BINDINGS_IMPL_FILE.into(),
    ]
    .iter()
    .collect();

    let out_bindings_path = PathBuf::from(env_var("OUT_DIR")).join(BINDINGS_FILE);
    let out_impl_path = PathBuf::from(env_var("OUT_DIR")).join(BINDINGS_IMPL_FILE);

    // Only run bindgen if we are *not* using the bundled capstone bindings
    #[cfg(feature = "use_bindgen")]
    write_bindgen_bindings(
        &header_search_paths,
        update_pregenerated_bindings,
        pregenerated_bindgen_header,
        pregenerated_bindgen_impl,
        out_bindings_path,
        out_impl_path,
    );

    // Otherwise, copy the pregenerated bindings
    #[cfg(not(feature = "use_bindgen"))]
    {
        copy(pregenerated_bindgen_header, out_bindings_path)
            .expect("Unable to update capstone bindings");
        copy(pregenerated_bindgen_impl, out_impl_path).expect("Unable to update capstone bindings");
    }
}
