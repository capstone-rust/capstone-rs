extern crate gcc;
extern crate pkg_config;
#[cfg(feature="use_cmake")]
extern crate cmake;

use std::path::{Path};
use std::process::Command;

#[cfg(feature = "use_cmake")]
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
        if cfg!(feature = "use_cmake") {
            #[cfg(feature = "use_cmake")]
            cmake();
        } else {
            //let target = env::var("TARGET").unwrap();
            //let windows = target.contains("windows");
            // TODO: need to add this argument for windows 64-bit, msvc, dunno, read the COMPILE_MSVC.txt
            // file cygwin-mingw64
            let _ = Command::new("./make.sh").current_dir("capstone").status();
            //args(&["submodule", "update", "--init"]).status();
            println!("cargo:rustc-link-search=native=capstone");
        }
    }
    println!("cargo:rustc-link-lib=static=capstone");
}
