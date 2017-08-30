//! The following environment variables affect the build:
//!
//! * `UPDATE_CAPSTONE_BINDINGS`: setting indicates that the pre-generated `capstone.rs` should be
//!   updated with the output bindgen

#[cfg(feature = "use_bindgen")]
extern crate bindgen;
extern crate pkg_config;

#[cfg(feature = "build_capstone_cmake")]
extern crate cmake;

#[cfg(feature = "use_bindgen")]
use std::fs::copy;
use std::path::PathBuf;
use std::process::Command;
use std::env;

#[cfg(feature = "use_bindgen")]
include!("common.rs");

/// Indicates how capstone library should be linked
enum LinkType {
    Dynamic,
    Static,
}

#[cfg(feature = "build_capstone_cmake")]
fn cmake() {
    let mut cfg = cmake::Config::new("capstone");
    let dst = cfg.build();
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
}

#[cfg(feature = "use_bindgen")]
/// Search for header in search paths
fn find_capstone_header(header_search_paths: &Vec<PathBuf>, name: &str) -> Option<PathBuf> {
    for search_path in header_search_paths.iter() {
        let potential_file = search_path.join(name);
        if potential_file.is_file() {
            return Some(potential_file);
        }
    }
    None
}

/// Create bindings using bindgen
#[cfg(feature = "use_bindgen")]
fn write_bindgen_bindings(header_search_paths: &Vec<PathBuf>, update_pregenerated_bindings: bool) {
    let mut builder = bindgen::Builder::default()
        .unstable_rust(false)
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
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join(BINDINGS_FILE);
    bindings.write_to_file(out_path.clone()).expect(
        "Unable to write bindings",
    );

    if update_pregenerated_bindings {
        let stored_bindgen_header: PathBuf =
            [
                env::var("CARGO_MANIFEST_DIR").expect("Could not find cargo environment variable"),
                "pre_generated".into(),
                BINDINGS_FILE.into(),
            ].iter()
                .collect();
        copy(out_path, stored_bindgen_header).expect("Unable to update capstone bindings");
    }
}

fn main() {
    let link_type: Option<LinkType>;

    // C header search paths
    let mut header_search_paths: Vec<PathBuf> = Vec::new();

    if cfg!(feature = "use_system_capstone") {
        assert!(
            !cfg!(feature = "build_capstone_cmake"),
            "build_capstone_cmake feature is only valid when using bundled cmake"
        );

        let capstone_lib =
            pkg_config::find_library("capstone").expect("Could not find system capstone");
        header_search_paths.append(&mut capstone_lib.include_paths.clone());
        link_type = Some(LinkType::Dynamic);
    } else {
        if cfg!(feature = "build_capstone_cmake") {
            #[cfg(feature = "build_capstone_cmake")]
            cmake();
        } else {
            //let target = env::var("TARGET").unwrap();
            //let windows = target.contains("windows");
            // TODO: need to add this argument for windows 64-bit, msvc, dunno, read
            // COMPILE_MSVC.txt file cygwin-mingw64
            let out_dir = env::var("OUT_DIR").unwrap();
            let _ = Command::new("./make.sh")
                .current_dir("capstone")
                .status();
            let capstone = "libcapstone.a";
            let _ = Command::new("cp")
                .current_dir("capstone")
                .arg(&capstone)
                .arg(&out_dir)
                .status();
            println!("cargo:rustc-link-search=native={}", out_dir);
        }
        header_search_paths.push(PathBuf::from("capstone/include"));
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

    // Only run bindgen if we are *not* using the bundled capstone bindings
    #[cfg(feature = "use_bindgen")]
    write_bindgen_bindings(&header_search_paths, update_pregenerated_bindings);
}
