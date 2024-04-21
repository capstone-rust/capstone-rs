# Changelog

Notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED] - YYYY-MM-DD
### Changed
- Bump minimum Rust version to 1.70.0

### Removed
- `From<u32> for RegId` impl

## [0.12.0] - 2024-02-25
### Added
- `full` feature (enabled by default) which disables [diet mode] for the Capstone C library

### Changed
- Bump minimum Rust version to 1.60.0
- `Arm64OperandType::Sys` contains `Arm64SysOp` instead of `u32`

## [0.11.0] - 2022-05-01

### Added
- Owned insn type `OwnedInsn` ([#123](https://github.com/capstone-rust/capstone-rs/pull/123))

### Removed
- `Insn` `Clone` impl to fix soundness issue ([#122](https://github.com/capstone-rust/capstone-rs/pull/122))

### Fixed
- Soundness issue by remove `Insn` `Clone` impl (see "Removed" note above)

## [0.10.0] - 2021-08-09

### Added
- Links to related types/functions in API documentation

### Changed
- Access `Insn` elements of `Instructions` via `Deref`/`AsRef` traits instead of an iterator
- Access `Insn` groups and read/write registers via a slice
- Update README.md code example

## [0.9.0] - 2021-07-13

### Added
- Support for RISC-V architecture

### Changed
- Updated minimum supported Rust version to 1.40.0

## [0.8.0] - 2021-04-09

### Added
- `Insn::from_raw()` to convert from a `cs_insn` pointer
- `Deref` impl for `Instructions`

### Changed
- X86: return `X86OpMem::segment()` as `RegId` instead of `u32`

### Fixed
- Fixed data race in multi-threaded environment ([#87](https://github.com/capstone-rust/capstone-rs/issues/87))

## [0.7.0] - 2020-03-16

### Added
- `no_std` compatibility
- Parallel disassemble example
- X86: add `X86Operand.access` field
- Implement `From<u32>` for *_ins enums

### Changed
- Bump minimum Rust version to 1.36.0

## [0.6.0] - 2019-04-17

### Added
- Architectures: EVM, M68K, M680X, TMS320C64X
- Mips modes: `Mips2`, `Mips3`, `Mips32`, `Mips64`
- Trait `EnumList` to allow you to enumerate enum variants
- X86: `X86InsnDetail::xop_cc()` getter

### Changed
- Bump minimum Rust version to 1.29.2
- Upgraded internal capstone C library to version 4.0
- Moved `capstone-sys` repository into `capstone-rs` repository
- Converted operand `Imm` variant from `i32` to `i64` for PPC, SPARC
- `X86InsnDetail::disp()` returns `i64` instead of `i32`

### Removed
- Mips modes: `Mode32`, `Mode64`, `MipsGP64`
- `X86OperandType` variant `Fp`


## [0.5.0] - 2018-09-21
### Added
- `InsnDetail` to preamble

### Changed
- Flattened `Error` enum

### Removed
- `X86InsnDetail::avx_rm()`


## [0.4.0] - 2018-06-02
### Added
- [Criterion](https://github.com/japaric/criterion.rs) [benchmark](benches)
- [cstool example](examples/cstool.rs)
- [Codecov](https://codecov.io/gh/capstone-rust/capstone-rs) code coverage integration
- `PartialOrd`/`Ord` implementation for `InsnId`, `InsnGroupId`, `RegId`
- Lifetime to `Capstone`/`Insn` struct
- `alloc_system` feature to use the system allocator instead of the default allocator (currently requires nightly)

### Changed
- Minimum Rust version to 1.23.0
- `Capstone::disasm()` methods take `&mut self` instead of `&self` and returns a new lifetime
- `Capstone` is no longer `Send`/`Sync` (it was mistakenly auto-implemented)
- `Capstone::new()` builder pattern methods take `self` instead of `&mut self`
- `Capstone::set_endian()` is now public (allowed since internal Capstone version was upgraded)

### Removed
- Duplicate/unneeded `Capstone` methods that have equivalents in `InsnDetail`
    - `insn_belongs_to_group()`, `insn_group_ids()`, `register_id_is_read()`, `read_register_ids()`,
      `register_id_is_written()`, `write_register_ids()`

### Fixed
- Race condition and memory unsafety in issue most easily observed on Mac OS (issue [#26](https://github.com/capstone-rust/capstone-rs/issues/26))

## [0.3.1] - 2018-03-26
### Fixed
- Documentation URL

## [0.3.0] - 2018-03-26
### Added
- Architecture-specific detail API with `InsnDetail::arch_detail()` method
- README badges!

### Changed
- `Capstone::disasm()` (and related methods) return empty `Instructions` instead of an error
- Make `Instructions::from_raw_parts()` private

## [0.2.0] - 2017-11-01
### Added
- `Capstone::new_raw()` has the same interface as the old `Capstone::new_raw()`
- Add setters to modify mode, syntax, etc.

### Changed
- `Capstone::new()` uses the builder pattern
- Partition `Mode` enum into: `Mode`, `ExtraMode`, and `Endian`
- Rename `Capstone` methods that return IDs to include `_ids` in name
    - Example: `read_registers()` renamed to `read_register_ids()`
- Minimum Rust version is 1.20.0

### Removed
- `libc` dependency

## [0.1.0] - 2017-09-29
### Added
- `Capstone` methods to set syntax and mode
- Travis continuous integration

### Changed
- Use [`capstone-sys`](https://github.com/capstone-rust/capstone-sys) crate for low-level Capstone bindings
- `Capstone::new()` takes a `arch` and `mode` arguments
- `Capstone::disasm()` replaced with `Capstone::disasm_all()`/`Capstone::disasm_count()`

### Removed
- Dependency

[UNRELEASED]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.12.0...master
[0.12.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.11.0...capstone-v0.12.0
[0.11.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.10.0...capstone-v0.11.0
[0.10.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.9.0...capstone-v0.10.0
[0.9.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.8.0...capstone-v0.9.0
[0.8.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.7.0...capstone-v0.8.0
[0.7.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-v0.6.0...capstone-v0.7.0
[0.6.0]: https://github.com/capstone-rust/capstone-rs/compare/v0.5.0...capstone-v0.6.0
[0.5.0]: https://github.com/capstone-rust/capstone-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/capstone-rust/capstone-rs/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/capstone-rust/capstone-rs/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/capstone-rust/capstone-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/capstone-rust/capstone-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/capstone-rust/capstone-rs/releases/tag/v0.1.0
