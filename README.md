# capstone-sys

Low-level, unsafe Rust bindings for the [`Capstone`][capstone] disassembly library.

[capstone]: https://github.com/aquynh/capstone

[![Crates.io Badge](https://img.shields.io/crates/v/capstone-sys.svg)](https://crates.io/crates/capstone-sys)
[![Travis CI Badge](https://travis-ci.org/capstone-rust/capstone-sys.svg?branch=master)](https://travis-ci.org/capstone-rust/capstone-sys)

**[API Documentation](https://docs.rs/capstone-sys/)**


## Requirements

* Rust version >= 1.19
    - We export [Rust unions], which were first stabilized with release 1.19
* One of the following:
    1. A toolchain capable of compiling Capstone (see the [`make.sh`](capstone/make.sh) script)
    2. A pre-built version 3.0 Capstone dynamic library (specify the `use_system_capstone` feature)

[Rust unions]: https://doc.rust-lang.org/stable/reference/items/unions.html

### Supported Platforms

| Platform                   | sys capstone  | gmake | cmake | cc    |
| -------------------------- | ------------- | ----- | ----- | ----- |
| `x86_64-apple-darwin`      | X             | X     | X     | X  |
| `i686-apple-darwin`        | X*            |       | X*    | X* |
| `x86_64-pc-windows-msvc`   |               |       |       | X  |
| `x86_64-pc-windows-gnu`    |               |       |       | X  |
| `i686-pc-windows-msvc`     |               |       |       | X* |
| `i686-pc-windows-gnu`      |               |       |       | X* |
| `x86_64-unknown-linux-gnu` | X             | X     | X     | X  |
| `i686-unknown-linux-gnu`   | X*            |       | X*    | X* |

| Symbol | Meaning |
| ------ | ------- |
| X      | build succeeds, all tests pass |
| X*     | build succeeds, some `bindgen` tests fail ([issue #18][issue18]) |
|        | build method is not supported |

[issue18]: https://github.com/capstone-rust/capstone-sys/issues/18

## Features

`capstone-sys` has different [features](https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section) that can be specified in `Cargo.toml`.

### Build Features

These features affect how `capstone-sys` will use/build the [bundled Capstone](capstone) C library:

* no feature or *gmake* (*default on non-Windows platforms*): build bundled Capstone with [GNU make](https://www.gnu.org/software/make/).
* `use_system_capstone`: use the system Capstone instead of the bundled copy of the Capstone library.
    - Requires that Capstone is already manually installed on the system. We highly recommend that you supply the exact version bundled with `capstone-sys`.
        - See the `CAPSTONE_REVISION` variable in [`scripts/update_capstone.sh`](scripts/update_capstone.sh) to determine the exact Git commit of Capstone.
    - Does not compile Capstone
* `build_capstone_cmake`: build the bundled Capstone with `cmake` (requires [CMake](https://cmake.org/) to be installed).
* `build_capstone_cc` (*default on Windows platforms*): build the bundled Capstone with the `cc` Rust crate.

### Other Features

* `use_bindgen`: instead of using the pre-generated Capstone bindings, dynamically generate bindings with [`bindgen`][bindgen].

[bindgen]: https://github.com/rust-lang-nursery/rust-bindgen


## Tested Platforms

The following platforms have automated testing:

* `x86_64-unknown-linux-gnu`: Travis CI
