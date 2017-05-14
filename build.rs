extern crate cmake;

use std::path::Path;
use std::env;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();
    let windows = target.contains("windows");

    if !windows {
        return
    }

    if !Path::new("capstone/.git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init"])
                                   .status();
    }

    if windows {
        let dst = cmake::build("capstone");

        println!("cargo:rustc-link-search=native={}/lib", dst.display());
        println!("cargo:rustc-link-lib=static=capstone");
    }
}