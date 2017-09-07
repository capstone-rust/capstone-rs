# capstone-sys

Low-level, unsafe Rust bindings for the [`capstone`][capstone] disassembly library.

[capstone]: https://github.com/aquynh/capstone

**[API Documentation](https://docs.rs/capstone-sys/)**


## Requirements

* Rust version >= 1.19
    - We export Rust unions, which were first stabilized with release 1.19
* One of the following:
    1. A toolchain capable of compiling `capstone` (see the [`make.sh`](capstone/make.sh) script)
    2. A pre-built version 3.0 `capstone` dynamic library (specify the `use_system_capstone` feature)


## Features

`capstone-sys` will build differently based on [features](http://doc.crates.io/manifest.html#the-features-section) that are specified in `Cargo.toml`.

`capstone-sys` supports the following features:

* `use_system_capstone`: use the system capstone instead of the bundled copy of the `capstone` library.
    - Requires that `capstone` is already installed on the system
    - Eliminates the default step of compiling `capstone`
* `build_capstone_cmake`: if using the bundled `capstone` library, then build `capstone` using `cmake`.
* `use_bindgen`: instead of using the pre-generated capstone bindings, dynamically generate bindings with [`bindgen`][bindgen].

[bindgen]: https://github.com/rust-lang-nursery/rust-bindgen
