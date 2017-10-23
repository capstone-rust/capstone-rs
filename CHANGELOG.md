# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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

[0.6.0]: https://github.com/capstone-rust/capstone-sys/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/capstone-rust/capstone-sys/releases/tag/v0.5.0