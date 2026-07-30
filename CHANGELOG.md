# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-30

### Added
- Fluent CSP builder rewrite with validated `from()` / `from_json()` / `from_file()`
- Cryptographic `generate_nonce()` with OpenResty and `/dev/urandom` backends
- `hash()` helper via `resty.sha256` / `sha384` / `sha512`
- Report helpers: `parse_report()`, `report_handler()`
- Unit tests (`t/csp_test.lua`), OpenResty `resty` tests, and `Test::Nginx` suite
- GitHub Actions CI and release workflows
- Examples, issue templates, and pull request template

### Changed
- Stricter presets (`strict`, `basic`, `api`) including `object-src 'none'`
- `:apply()` returns `nil, err` outside OpenResty instead of raising

### Fixed
- Nonce generation no longer requires `ngx` when `/dev/urandom` is available
- Unknown keys in `from()` are rejected instead of silently dropped
- `report_only` is honored in `from()` config tables

## [0.1.0] - 2026-01-10

### Added
- Initial OPM package with basic CSP builder and presets

[0.3.0]: https://github.com/Vivirinter/lua-resty-csp/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/Vivirinter/lua-resty-csp/releases/tag/v0.1.0
