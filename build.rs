extern crate gcc;
extern crate pkg_config;
#[cfg(feature="build_src_cmake")]
extern crate cmake;

use std::path::{Path};
use std::process::Command;
use std::env;

#[cfg(feature = "build_src_cmake")]
fn cmake() {
    let mut cfg = cmake::Config::new("capstone");
    let dst = cfg.build();
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
}

fn main() {
    if !cfg!(feature = "build_src") && pkg_config::find_library("capstone").is_ok() {
    } else {
        if !Path::new("capstone/.git").exists() {
            let _ = Command::new("git").args(&["submodule", "update", "--init", "--depth", "5"])
                .status();
        }
        if cfg!(feature = "build_src_cmake") {
            #[cfg(feature = "build_src_cmake")]
            cmake();
        } else {
            //let target = env::var("TARGET").unwrap();
            //let windows = target.contains("windows");
            // TODO: need to add this argument for windows 64-bit, msvc, dunno, read the COMPILE_MSVC.txt
            // file cygwin-mingw64
            let out_dir = env::var("OUT_DIR").unwrap();
            let _ = Command::new("./make.sh").current_dir("capstone").status();
            let capstone = "libcapstone.a";
            let _ = Command::new("cp").current_dir("capstone").arg(&capstone).arg(&out_dir).status();
            println!("cargo:rustc-link-search=native={}", out_dir);
        }
    }
    println!("cargo:rustc-link-lib=static=capstone");
}
