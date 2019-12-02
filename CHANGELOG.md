# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] (2019-12-02)
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

[0.0.3]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/53
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

## [0.0.2] (2019-11-25)
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

[0.0.2]: https://github.com/iqlusioninc/yubikey-piv.rs/pull/31
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
- It typechecks, ship it!
