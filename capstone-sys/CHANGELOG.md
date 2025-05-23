# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED] - YYYY-MM-DD
### Added
- Support for TriCore arch
- Support for MOS65XX arch
- Support for SH arch

### Changed
- Bump bundled capstone to 5.0.6
- Change `cs_regs_access()` `regs_read`/`regs_write` args to take `*mut cs_regs` (instead of `*mut u16`)
    - makes it more clear that args should be fixed size arrays

## [0.17.0] - 2025-02-04
### Fixed
- Segfault when running on s390x (AKA SystemZ)

### Added
- Support for BPF arch

### Changed
- Bump MSRV to 1.70

## [0.16.0] - 2024-02-25
### Fixed
- Make builds more reproducible

### Added
- `full` feature (enabled by default) which disables [diet mode] for the Capstone C library

[diet mode]: https://www.capstone-engine.org/diet.html

### Changed
- Upgraded bundled capstone to from [f278de39 to 3b298421](https://github.com/aquynh/capstone/compare/f278de39...3b298421)
- Merged enums `arm64_tlbi_op`, `arm64_at_op`, `arm64_dc_op`, `arm64_ic_op` into single enum `arm64_sys_op` (based on upstream [`3e23b60af0`](https://github.com/capstone-engine/capstone/commit/3e23b60af04aa75eb17c14ba33d6ed139a2c405c))

## [0.15.0] - 2022-05-01
### Fixed
- Document that minimum supported Rust version is actually 1.50.0
    - Improperly documented as 1.40.0 in 0.14.0 release
- Suppress C compiler warning

## [0.14.0] - 2021-08-09

### Added
- Compile WASM support

### Changed
- Bump bindgen version to 0.59.1

## [0.13.0] - 2021-07-13

### Added
- Support for RISC-V architecture

### Changed
- Upgraded bundled capstone to from [a42f9fa9 to f278de39](https://github.com/aquynh/capstone/compare/a42f9fa9...f278de39)
- Updated minimum supported Rust version to 1.40.0

## [0.12.0] - 2021-04-09
### Changed
- Upgraded bundled capstone to from [154f91a5 to a42f9fa9](https://github.com/aquynh/capstone/compare/154f91a5...a42f9fa9)

## [0.11.0] - 2020-03-16
### Changed
- Upgraded bundled capstone to from [0cc60fb9 to 154f91a5](https://github.com/aquynh/capstone/compare/0cc60fb9...154f91a5)

## [0.10.0] - 2019-04-17
### Changed
- Upgraded bundled capstone to release 4.0

### Removed
- Capstone doc and IDE folders

## [0.9.1] - 2018-09-20
### Changed
- Upgraded bundled capstone to release [3.0.5](https://github.com/aquynh/capstone/releases/tag/3.0.5)
  (Git commit [a31b5328 to db19431d](https://github.com/aquynh/capstone/compare/a31b5328...db19431d)).

## [0.9.0] - 2018-07-08

### Changed
- Upgraded bundled capstone from
  [7e004bd4 to a31b5328](https://github.com/aquynh/capstone/compare/7e004bd4...a31b5328),
  which incorporates upstream Capstone PR
  [#1171](https://github.com/aquynh/capstone/pull/1171)
- Always use `cc` crate to build Capstone

### Removed
- Features affecting build: `use_system_capstone`, `build_capstone_cmake`, `build_capstone_cc`
    - The old build features were never used and complicated the code/documentation

## [0.8.0] - 2018-06-02
### Added
- Documented FreeBSD support

### Changed
- Upgraded bundled capstone from
  [8308ace3 to 7e004bd4](https://github.com/aquynh/capstone/compare/8308ace3...7e004bd4),
  which incorporates upstream Capstone PRs
  [#1022](https://github.com/aquynh/capstone/pull/1022) and
  [#1029](https://github.com/aquynh/capstone/pull/1029)

### Removed
- Unicode characters from README

## [0.7.0] - 2018-03-25
### Added
- Added support for Windows with `cc` crate
- Explicitly document supported platforms

### Changed
- Changed method bindgen uses to create enum types (depends on type; see API documentation)
- Updated bindgen version

## [0.6.0] - 2017-10-22
### Added
- Added support for Mac OS
- Added more CI tests

## [0.5.0] - 2017-08-31
### Added
- Add documentation for some types and function

### Changed
- Use Rust unions instead of `bindgen` unions
- Depend on necessary packages only
- Use pre-generated bindings by default (instead of running `bindgen`)

### Removed
- Dependency

[UNRELEASED]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.17.0...master
[0.17.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.16.0...capstone-sys-v0.17.0
[0.16.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.15.0...capstone-sys-v0.16.0
[0.15.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.14.0...capstone-sys-v0.15.0
[0.14.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.13.0...capstone-sys-v0.14.0
[0.13.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.12.0...capstone-sys-v0.13.0
[0.12.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.11.0...capstone-sys-v0.12.0
[0.11.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.10.0...capstone-sys-v0.11.0
[0.10.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.9.1...capstone-sys-v0.10.0
[0.9.1]: https://github.com/capstone-rust/capstone-sys/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/capstone-rust/capstone-sys/releases/tag/v0.5.0
