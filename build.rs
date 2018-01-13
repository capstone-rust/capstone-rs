//! The following environment variables affect the build:
//!
//! * `UPDATE_CAPSTONE_BINDINGS`: setting indicates that the pre-generated `capstone.rs` should be
//!   updated with the output bindgen

#[cfg(feature = "use_bindgen")]
extern crate bindgen;

#[cfg(feature = "use_system_capstone")]
extern crate pkg_config;

#[cfg(feature = "build_capstone_cmake")]
extern crate cmake;

#[cfg(any(windows, feature = "build_capstone_cc"))]
extern crate cc;

use std::fs::copy;
use std::path::PathBuf;
use std::env;

include!("common.rs");

const CAPSTONE_DIR: &'static str = "capstone";

/// Indicates how capstone library should be linked
#[allow(dead_code)]
enum LinkType {
    Dynamic,
    Static,
}

/// Build capstone with cmake
#[cfg(all(not(windows), feature = "build_capstone_cmake"))]
fn build_capstone_cmake() {
    let mut cfg = cmake::Config::new("capstone");
    let dst = cfg.build();
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
}

/// Build capstone with gmake
#[cfg(not(windows))]
fn build_capstone_gmake() {
    use std::process::Command;

    // In BSDs, `make` does not refer to GNU make
    let target_os = env_var("CARGO_CFG_TARGET_OS");
    let make_cmd = if target_os.contains("bsd") || target_os == "dragonfly" {
        "gmake"
    } else {
        "make"
    };

    let out_dir = env_var("OUT_DIR");
    Command::new(make_cmd)
        .current_dir(CAPSTONE_DIR)
        .status()
        .expect("Failed to build Capstone library");
    let capstone = "libcapstone.a";
    Command::new("cp")
        .current_dir(CAPSTONE_DIR)
        .arg(&capstone)
        .arg(&out_dir)
        .status()
        .expect("Failed to copy capstone library to OUT_DIR");

    println!("cargo:rustc-link-search=native={}", out_dir);
}

/// Build capstone using the cc crate
#[cfg(any(windows, feature = "build_capstone_cc"))]
fn build_capstone_cc() {
    use std::fs::DirEntry;

    fn read_dir_and_filter<F: Fn(&DirEntry) -> bool>(dir: &str, filter: F) -> Vec<String> {
        use std::fs::read_dir;

        read_dir(dir)
            .expect("Failed to read capstone source directory")
            .into_iter()
            .map(|e| e.expect("Failed to read capstone source directory"))
            .filter(|e| filter(e))
            .map(|e| format!("{}/{}", dir, e.file_name().to_str().expect("Invalid filename")))
            .collect()
    }

    fn find_c_source_files(dir: &str) -> Vec<String> {
        read_dir_and_filter(dir, |e| {
            let file_type = e.file_type().expect("Failed to read capstone source directory");
            let file_name = e.file_name().into_string().expect("Invalid filename");
            file_type.is_file() && (file_name.ends_with(".c") || file_name.ends_with(".C"))
        })
    }

    fn find_arch_dirs() -> Vec<String> {
        read_dir_and_filter(&format!("{}/{}", CAPSTONE_DIR, "arch"), |e| {
            let file_type = e.file_type().expect("Failed to read capstone source directory");
            file_type.is_dir()
        })
    }

    let mut files = find_c_source_files(CAPSTONE_DIR);
    for arch_dir in find_arch_dirs().into_iter() {
        files.append(&mut find_c_source_files(&arch_dir));
    }

    let use_static_crt = {
        let target_features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or(String::new());
        target_features.split(",").any(|f| f == "crt-static")
    };

    cc::Build::new()
        .files(files)
        .include(format!("{}/{}", CAPSTONE_DIR, "include"))
        .define("CAPSTONE_X86_ATT_DISABLE_NO", None)
        .define("CAPSTONE_DIET_NO", None)
        .define("CAPSTONE_X86_REDUCE_NO", None)
        .define("CAPSTONE_USE_SYS_DYN_MEM", None)
        .define("CAPSTONE_HAS_ARM", None)
        .define("CAPSTONE_HAS_ARM64", None)
        .define("CAPSTONE_HAS_MIPS", None)
        .define("CAPSTONE_HAS_POWERPC", None)
        .define("CAPSTONE_HAS_SPARC", None)
        .define("CAPSTONE_HAS_SYSZ", None)
        .define("CAPSTONE_HAS_X86", None)
        .define("CAPSTONE_HAS_XCORE", None)
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unknown-pragmas")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-return-type")
        .static_crt(use_static_crt)
        .compile("capstone");
}

/// Search for header in search paths
#[cfg(feature = "use_bindgen")]
fn find_capstone_header(header_search_paths: &Vec<PathBuf>, name: &str) -> Option<PathBuf> {
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
    env::var(var).expect(&format!("Environment variable {} is not set", var))
}

/// Create bindings using bindgen
#[cfg(feature = "use_bindgen")]
fn write_bindgen_bindings(
    header_search_paths: &Vec<PathBuf>,
    update_pregenerated_bindings: bool,
    pregenerated_bindgen_header: PathBuf,
    out_path: PathBuf,
) {
    let mut builder = bindgen::Builder::default()
        .rust_target(bindgen::RustTarget::Stable_1_19)
        .header(
            find_capstone_header(header_search_paths, "capstone.h")
                .expect("Could not find header")
                .to_str()
                .unwrap(),
        )
        .disable_name_namespacing()
        .prepend_enum_name(false)
        .generate_comments(true)
        .constified_enum_module("[^_]+_reg$"); // Some registers have aliases


    // Whitelist cs_.* functions and types
    let pattern = String::from("cs_.*");
    builder = builder
        .whitelisted_function(pattern.clone())
        .whitelisted_type(pattern.clone());

    // Whitelist types with architectures
    for arch in ARCH_INCLUDES {
        let pattern = format!(".*(^|_){}(_|$).*", arch.cs_name);
        builder = builder.whitelisted_type(pattern);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    // Write bindings to $OUT_DIR/bindings.rs
    bindings.write_to_file(out_path.clone()).expect(
        "Unable to write bindings",
    );

    if update_pregenerated_bindings {
        copy(out_path, pregenerated_bindgen_header).expect("Unable to update capstone bindings");
    }
}

/// Find system capstone library and return link type
#[cfg(all(not(windows), feature = "use_system_capstone"))]
fn find_system_capstone(header_search_paths: &mut Vec<PathBuf>) -> Option<LinkType> {
    assert!(
        !cfg!(feature = "build_capstone_cmake"),
        "build_capstone_cmake feature is only valid when using bundled cmake"
    );

    let capstone_lib =
        pkg_config::find_library("capstone").expect("Could not find system capstone");
    header_search_paths.append(&mut capstone_lib.include_paths.clone());
    Some(LinkType::Dynamic)
}

fn main() {
    #[allow(unused_assignments)]
    let mut link_type: Option<LinkType> = None;

    // C header search paths
    let mut header_search_paths: Vec<PathBuf> = Vec::new();

    if cfg!(feature = "use_system_capstone") {
        #[cfg(windows)] panic!("Feature 'use_system_capstone' is not supported on Windows");
        #[cfg(all(not(windows), feature = "use_system_capstone"))]
        {
            link_type = find_system_capstone(&mut header_search_paths);
        }
    } else {
        if cfg!(feature = "build_capstone_cmake") {
            #[cfg(windows)] panic!("Feature 'build_capstone_cmake' is not supported on Windows");
            #[cfg(all(not(windows), feature = "build_capstone_cmake"))] build_capstone_cmake();
        } else if cfg!(any(windows, feature = "build_capstone_cc")) {
            #[cfg(any(windows, feature = "build_capstone_cc"))] build_capstone_cc();
        } else {
            #[cfg(not(windows))] build_capstone_gmake();
        }

        header_search_paths.push([CAPSTONE_DIR, "include"].iter().collect());
        link_type = Some(LinkType::Static);
    }

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
    if update_pregenerated_bindings {
        assert!(
            cfg!(feature = "use_bindgen"),
            concat!(
                "Setting UPDATE_CAPSTONE_BINDINGS only makes ",
                "sense when enabling feature \"use_bindgen\""
            )
        );
    }

    let pregenerated_bindgen_header: PathBuf = [
        env_var("CARGO_MANIFEST_DIR"),
        "pre_generated".into(),
        BINDINGS_FILE.into(),
    ].iter()
        .collect();
    let out_path = PathBuf::from(env_var("OUT_DIR")).join(BINDINGS_FILE);

    // Only run bindgen if we are *not* using the bundled capstone bindings
    #[cfg(feature = "use_bindgen")]
    write_bindgen_bindings(
        &header_search_paths,
        update_pregenerated_bindings,
        pregenerated_bindgen_header,
        out_path,
    );

    // Otherwise, copy the pregenerated bindings
    #[cfg(not(feature = "use_bindgen"))]
    copy(&pregenerated_bindgen_header, &out_path).expect("Unable to update capstone bindings");
}
