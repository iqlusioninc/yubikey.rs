# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2021-03-22)
### Added
- Typed structs for PIN-protected and admin metadata ([#223])
- `MgmKey::set_default`/`MgmKey::set_manual` methods ([#224])

### Changed
- Have `Transaction::set_mgm_key` take touch requirement as bool ([#224])

### Removed
- `MgmKey::set` method ([#224])

[#223]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/223
[#224]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/224

## 0.2.0 (2021-01-30)
### Changed
- Bump `der-parser` to v5.0 ([#194])
- Improve self-signed certificates ([#207])
- Bump `x509-parser` to v0.9 ([#208])
- Bump elliptic-curve to 0.8. Also requires bumping p256 and p384 ([#208])
- Bump MSRV to 1.46+ ([#208])
- Bump `pbkdf2` dependency to v0.7 ([#219])

[#194]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/194
[#207]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/207
[#208]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/208
[#219]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/219

## 0.1.0 (2020-10-19)
### Added
- `Certificate::generate_self_signed` ([#80])
- `YubiKey::open_by_serial` ([#69])
- CCCID/CHUID tests and cleanups ([#65])
- Test `Config::get` ([#64])
- Test `Key::list` ([#61])
- Test `YubiKey::verify_pin` ([#60])

### Changed
- Bump `crypto-mac`, `des`, `hmac`, `pbkdf2` ([#177])
- Bump `p256` to v0.5; `p384` to v0.4; MSRV 1.44+ ([#175])
- Refactor key import function ([#128])
- Extract `ChangeRefAction` enum ([#82])
- TLV extraction ([#73])
- Rename `container` to `mscmap` ([#68])
- Finish eliminating `consts` module ([#67])
- Move `sign`/`decrypt`/`import`/`attest` to the `key` module ([#62])

### Fixed
- `pcsc::Error::NoReadersAvailable` -> `Error::NotFound` in `YubiKey::open*` ([#88])

### Removed
- YubiKey NEO support ([#63])

[#177]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/177
[#175]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/175
[#128]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/128
[#82]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/82
[#73]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/73
[#88]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/88
[#80]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/80
[#69]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/69
[#68]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/68
[#67]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/67
[#65]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/65
[#64]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/64
[#63]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/63
[#62]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/62
[#61]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/61
[#60]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/60

## 0.0.3 (2019-12-02)
### Added
- Initial `Readers` enumerator for detecting YubiKeys ([#51])
- Certificate parsing ([#45])

### Changed
- Use `Reader` to connect to `YubiKey` ([#51])
- Convert `SlotId` and `AlgorithmId` into enums ([#44])
- Use `secrecy` crate for storing `CachedPin` ([#43])
- Change `CHUID` struct to hold complete CHUID value ([#42])
- Eliminate all usages of `unsafe` ([#37], [#39])
- Make anonymous CHUID struct public ([#36])
- Have `sign_data` and `decrypt_data` return a `Buffer` ([#34])
- `Ins` (APDU instruction codes) enum ([#33])
- Factor `Response` into `apdu` module; improved debugging ([#32])

[#51]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/51
[#45]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/45
[#44]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/44
[#43]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/43
[#42]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/42
[#39]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/39
[#37]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/37
[#36]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/36
[#34]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/34
[#33]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/33
[#32]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/32

## 0.0.2 (2019-11-25)
### Added
- `untested` Cargo feature to mark untested functionality ([#30])
- Initial connect test and docs ([#19])
- Clean up APDU construction with builder API ([#15])

### Changed
- Rewrite translated code to use the `pcsc` crate ([#17])
- Rename ErrorKind to Error ([#13])
- Use `des` crate for 3DES operations ([#10])
- Replace `PKCS5_PBKDF2_HMAC_SHA1` with `pbkdf2` et al crates ([#9])
- Replace `RAND_bytes` with `getrandom` crate ([#8])
- Use `log` crate for logging ([#7])
- Replace `ErrorKind::Ok` with `Result` ([#6])

[#30]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/30
[#19]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/19
[#17]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/17
[#15]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/15
[#13]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/13
[#10]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/10
[#9]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/9
[#8]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/8
[#7]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/7
[#6]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/6

## 0.0.1 (2019-11-18)
- Initial release
