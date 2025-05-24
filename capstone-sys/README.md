# capstone-sys

Low-level, unsafe Rust bindings for the [`Capstone`][capstone] disassembly library.

[capstone]: https://github.com/aquynh/capstone

[![Crates.io Badge](https://img.shields.io/crates/v/capstone-sys.svg)](https://crates.io/crates/capstone-sys)

**[API Documentation](https://docs.rs/capstone-sys/)**


**NOTE**:
We recommend against using this crate directly.
Instead, consider using [capstone-rs](https://github.com/capstone-rust/capstone-rs), which provides a high-level, "Rusty" interface.


## Requirements

* Minimum Rust Version: `1.70.0`
* A toolchain capable of compiling Capstone
    - We build the bundled Capstone with the [`cc` crate](https://github.com/alexcrichton/cc-rs)

## Features

You can specify the following [features](https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section) in `Cargo.toml`:
* `use_bindgen`: instead of using the pre-generated Capstone bindings, dynamically generate bindings with [`bindgen`][bindgen].
* `full` (enabled by default): enable full capstone build instead of diet.
* `arch_$ARCH` (enabled by default): enable arch `$ARCH` support in capstone, e.g. `arch_aarch64` enables arch arm64 support.
* `support_all_archs` (enabled by default): enable all archs available in capstone, imply all `arch_$ARCH` features.

[bindgen]: https://github.com/rust-lang-nursery/rust-bindgen
