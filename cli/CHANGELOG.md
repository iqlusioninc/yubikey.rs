# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (2022-11-14)
### Changed
- Bump `clap` to v4.0 ([#438])
- Bump `x509-parser` to v0.14 ([#441])
- Switch from `lazy_static` to `once_cell` ([#442])
- Switch from `subtle-encoding` to `base16ct` ([#443])
- Bump `yubikey` dependency to v0.7 ([#444])

[#438]: https://github.com/iqlusioninc/yubikey.rs/pull/438
[#441]: https://github.com/iqlusioninc/yubikey.rs/pull/441
[#442]: https://github.com/iqlusioninc/yubikey.rs/pull/442
[#443]: https://github.com/iqlusioninc/yubikey.rs/pull/443
[#444]: https://github.com/iqlusioninc/yubikey.rs/pull/444

## 0.6.0 (2022-08-10)
### Changed
- 2021 edition upgrade; MSRV 1.57 ([#343])
- Migrate from `gumdrop` to `clap` v3 ([#379])
- Bump `yubikey` dependency to v0.6 ([#403])

[#343]: https://github.com/iqlusioninc/yubikey.rs/pull/343
[#379]: https://github.com/iqlusioninc/yubikey.rs/pull/379
[#403]: https://github.com/iqlusioninc/yubikey.rs/pull/403

## 0.5.0 (2021-11-21)
### Changed
- Bump `yubikey` dependency to v0.5 ([#327])

[#327]: https://github.com/iqlusioninc/yubikey.rs/pull/327
 
## 0.4.0 (2021-07-12)
### Changed
- Switch to renamed `yubikey` crate ([#283])
- Bump MSRV to 1.51+ ([#283])

[#283]: https://github.com/iqlusioninc/yubikey.rs/pull/283

## 0.3.0 (2021-03-22)
### Changed
- Bump `yubikey-piv` dependency to v0.3 ([#240])

[#240]: https://github.com/iqlusioninc/yubikey.rs/pull/240

## 0.2.0 (2021-01-30)
### Changed
- Bump MSRV to 1.46+ ([#208])
- Bump `yubikey-piv` dependency to v0.2 ([#220])

[#208]: https://github.com/iqlusioninc/yubikey.rs/pull/208
[#220]: https://github.com/iqlusioninc/yubikey.rs/pull/220

## 0.1.0 (2020-10-19)
### Added
- `status` command ([#72], [#74])

### Changed
- Bump `yubikey-piv` to v0.1 ([#180])
- Bump `x509-parser` to v0.8 ([#181])
- Bump `sha2` to v0.9 ([#182])
- Rename `list` command to `readers`; improve usage ([#71])

[#182]: https://github.com/iqlusioninc/yubikey.rs/pull/182
[#181]: https://github.com/iqlusioninc/yubikey.rs/pull/181
[#180]: https://github.com/iqlusioninc/yubikey.rs/pull/180
[#74]: https://github.com/iqlusioninc/yubikey.rs/pull/74
[#72]: https://github.com/iqlusioninc/yubikey.rs/pull/72
[#71]: https://github.com/iqlusioninc/yubikey.rs/pull/71

## 0.0.1 (2019-12-02)
- Initial release
