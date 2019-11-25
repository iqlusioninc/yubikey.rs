# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.0.2]: https://github.com/tarcieri/yubikey-piv.rs/pull/31
[#30]: https://github.com/tarcieri/yubikey-piv.rs/pull/30
[#19]: https://github.com/tarcieri/yubikey-piv.rs/pull/19
[#17]: https://github.com/tarcieri/yubikey-piv.rs/pull/17
[#15]: https://github.com/tarcieri/yubikey-piv.rs/pull/15
[#13]: https://github.com/tarcieri/yubikey-piv.rs/pull/13
[#10]: https://github.com/tarcieri/yubikey-piv.rs/pull/10
[#9]: https://github.com/tarcieri/yubikey-piv.rs/pull/9
[#8]: https://github.com/tarcieri/yubikey-piv.rs/pull/8
[#7]: https://github.com/tarcieri/yubikey-piv.rs/pull/7
[#6]: https://github.com/tarcieri/yubikey-piv.rs/pull/6

## 0.0.1 (2019-11-18)
- It typechecks, ship it!
