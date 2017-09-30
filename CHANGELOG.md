# Changelog
Notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/capstone-rust/capstone-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/capstone-rust/capstone-rs/releases/tag/v0.1.0