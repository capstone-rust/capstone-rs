# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.11.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.10.0...capstone-sys-v0.11.0
[0.10.0]: https://github.com/capstone-rust/capstone-rs/compare/capstone-sys-v0.9.1...capstone-sys-v0.10.0
[0.9.1]: https://github.com/capstone-rust/capstone-sys/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/capstone-rust/capstone-sys/releases/tag/v0.5.0
