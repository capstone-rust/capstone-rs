# capstone-sys

Low-level, unsafe Rust bindings for the [`Capstone`][capstone] disassembly library.

[capstone]: https://github.com/aquynh/capstone

[![Crates.io Badge](https://img.shields.io/crates/v/capstone-sys.svg)](https://crates.io/crates/capstone-sys)
[![Travis CI Badge](https://travis-ci.org/capstone-rust/capstone-sys.svg?branch=master)](https://travis-ci.org/capstone-rust/capstone-sys)
[![Appveyor CI Badge](https://ci.appveyor.com/api/projects/status/github/capstone-rust/capstone-sys?svg=true&branch=master)](https://ci.appveyor.com/project/tmfink/capstone-sys)

**[API Documentation](https://docs.rs/capstone-sys/)**


**NOTE**:
We recommend against using this crate directly.
Instead, consider using [capstone-rs](https://github.com/capstone-rust/capstone-rs), which provides a high-level, "Rusty" interface.


## Requirements

* Rust version >= 1.40.0
* A toolchain capable of compiling Capstone
    - We build the bundled Capstone with the [`cc` crate](https://github.com/alexcrichton/cc-rs)

[Rust unions]: https://doc.rust-lang.org/stable/reference/items/unions.html

### Supported Platforms

| Platform                   | Supported |
| -------------------------- | -- |
| `x86_64-apple-darwin`      | X  |
| `i686-apple-darwin`        | X  |
| `x86_64-pc-windows-msvc`   | X  |
| `x86_64-pc-windows-gnu`    | X  |
| `i686-pc-windows-msvc`     | X  |
| `i686-pc-windows-gnu`      | X  |
| `x86_64-unknown-linux-gnu` | X  |
| `i686-unknown-linux-gnu`   | X  |
| `x86_64-unknown-freebsd`   | X  |

## Features

You can specify the following [features](https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section) in `Cargo.toml`:
* `use_bindgen`: instead of using the pre-generated Capstone bindings, dynamically generate bindings with [`bindgen`][bindgen].

[bindgen]: https://github.com/rust-lang-nursery/rust-bindgen
