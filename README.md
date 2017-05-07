# capstone-sys

Low-level, unsafe Rust bindings for the `capstone` disassembly library.


## Features

`capstone-sys` will build differently based on [features](http://doc.crates.io/manifest.html#the-features-section) that are specified in `Cargo.toml`.

`capstone-sys` supports the following features:

* `use_system_capstone`: use the system capstone instead of the bundled copy of the `capstone` library.
* `build_capstone_cmake`: if using the bundled `capstone` library, then build `capstone` using `cmake`.
* `use_bundled_capstone_bindings`: instead of using [`bindgen`](https://github.com/rust-lang-nursery/rust-bindgen), use the pre-generated capstone bindings (if available for the current platform).
