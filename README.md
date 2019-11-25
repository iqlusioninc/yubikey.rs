<img src="https://raw.githubusercontent.com/tendermint/yubihsm-rs/develop/img/logo.png" width="150" height="110">

# yubikey-piv.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
![Maintenance Status: Experimental][maintenance-image]
[![Build Status][build-image]][build-link]
[![Gitter Chat][gitter-image]][gitter-link]

Pure Rust host-side YubiKey [Personal Identity Verification (PIV)][PIV] driver
with general-purpose public-key encryption and signing support.

[Documentation][docs-link]

## About

YubiKeys are versatile devices and through their PIV support, you can use them
to store a number of RSA (2048/1024) and ECC (NIST P-256/P-384) private keys
with configurable access control policies. Both the signing (RSASSA/ECDSA) and
encryption (PKCS#1v1.5/ECIES) use cases are supported for either key type.

See [Yubico's guide to PIV-enabled YubiKeys][yk-guide] for more information
on which devices support PIV and the available functionality.

If you've been wanting to use Rust to sign and/or encrypt stuff using a
private key generated and stored on a Yubikey (with option PIN-based access),
this is the crate you've been after!

Note that while this project started as a fork of a [Yubico] project,
this fork is **NOT** an official Yubico project and is in no way supported or
endorsed by Yubico.

## Minimum Supported Rust Version

- Rust **1.39+**

## Supported YubiKeys

- [YubiKey NEO] series (may be dropped in the future, see [#18])
- [YubiKey 4] series
- [YubiKey 5] series

NOTE: Nano and USB-C variants of the above are also supported

## Security Warning

No security audits of this crate have ever been performed. Presently it is in
an experimental stage and may still contain high-severity issues.

USE AT YOUR OWN RISK!

## Status

This project is a largely incomplete work-in-progress. So far the only
functionality which has actually been tested is connecting to Yubikeys.

If you're interested helping test functionality, the table below documents
the current status of the project and relevant GitHub issues for various
functions of the YubiKey:

|    | Module        | Issue | Description |
|----|---------------|-------|-------------|
| 🚧 | `yubikey`     | [#20] | Core functionality: auth, keys, PIN/PUK, encrypt, sign, attest |
| ⚠️ | `cccid`       | [#21] | Cardholder Capability Container (CCC) IDs |
| ⚠️ | `certificate` | [#22] | Certificates for stored keys |
| ⚠️ | `chuid`       | [#23] | Cardholder Unique Identifier (CHUID) |
| ⚠️ | `config`      | [#24] | Support for reading on-key configuration |
| ⚠️ | `container`   | [#25] | MS Container Map Records |
| ⚠️ | `key`         | [#26] | Crypto key management: list, generate, import |
| ⚠️ | `mgm`         | [#26] | Management Key (MGM) support: set, get, derive
| ⚠️ | `msroots`     | [#28] | `msroots` file: PKCS#7 formatted certificate store for enterprise trusted roots |

Legend:

|    | Description                        |
|----|------------------------------------|
| 🚧 | Testing and validation in progress |
| ⚠️ | Untested support                   |

NOTE: Commands marked ⚠️ are disabled by default as they have have not been properly tested and may contain bugs or
not work at all. USE AT YOUR OWN RISK!

Enable the `untested` feature in your `Cargo.toml` to enable features marked ⚠️
above.

## Testing

To run the full test suite, you'll need a connected YubiKey NEO/4/5 device in
the default state (i.e. default PIN/PUK).

Tests which run live against a YubiKey device are marked as `#[ignore]` by
default in order to pass when running in a CI environment. To run these
tests locally, invoke the following command:

```
cargo test -- --ignored
```

This crate makes extensive use of the `log` facade to provide detailed
information about what is happening. If you'd like to print this logging
information while running the tests, set the `RUST_LOG` environment variable
to a relevant loglevel (e.g. `error`, `warn`, `info`, `debug`, `trace`):

```
RUST_LOG=info cargo test -- --ignored
```

To trace every message sent to/from the card i.e. the raw
Application Protocol Data Unit (APDU) messages, use the `trace` log level:

```
running 1 test
[INFO  yubikey_piv::yubikey] trying to connect to reader 'Yubico YubiKey OTP+FIDO+CCID'
[INFO  yubikey_piv::yubikey] connected to 'Yubico YubiKey OTP+FIDO+CCID' successfully
[TRACE yubikey_piv::transaction] >>> [0, 164, 4, 0, 5, 160, 0, 0, 3, 8]
[TRACE yubikey_piv::transaction] <<< [97, 17, 79, 6, 0, 0, 16, 0, 1, 0, 121, 7, 79, 5, 160, 0, 0, 3, 8, 144, 0]
[TRACE yubikey_piv::transaction] >>> [0, 253, 0, 0, 0]
[TRACE yubikey_piv::transaction] <<< [5, 1, 2, 144, 0]
[TRACE yubikey_piv::transaction] >>> [0, 248, 0, 0, 0]
[TRACE yubikey_piv::transaction] <<< [0, 115, 0, 178, 144, 0]
test connect ... ok
```

APDU messages labeled `>>>` are being sent to the YubiKey's internal SmartCard,
and ones labeled `<<<` are the responses.

## History

This library is a Rust translation of the [yubico-piv-tool] utility by
Yubico, which was originally written in C. It was mechanically translated
from C into Rust using [Corrode], and then subsequently heavily
refactored into safer, more idiomatic Rust.

## Code of Conduct

We abide by the [Contributor Covenant][cc-md] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md][cc-md].

## License

**yubikey-piv.rs** is a fork of and originally a mechanical translation from
Yubico's [yubico-piv-tool], a C library/CLI program. The original library
was licensed under a [2-Clause BSD License][BSDL], which this library inherits
as a derived work.

Copyright (c) 2014-2019 Yubico AB, Tony Arcieri
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided
  with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be licensed under the
[2-Clause BSD License][BSDL] as shown above, without any additional terms
or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/yubikey-piv.svg
[crate-link]: https://crates.io/crates/yubikey-piv
[docs-image]: https://docs.rs/yubikey-piv/badge.svg
[docs-link]: https://docs.rs/yubikey-piv/
[license-image]: https://img.shields.io/badge/license-BSD-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.39+-blue.svg
[maintenance-image]: https://img.shields.io/badge/maintenance-experimental-blue.svg
[build-image]: https://github.com/tarcieri/yubikey-piv.rs/workflows/Rust/badge.svg
[build-link]: https://github.com/tarcieri/yubikey-piv.rs/actions
[gitter-image]: https://badges.gitter.im/yubihsm-piv-rs.svg
[gitter-link]: https://gitter.im/yubikey-piv-rs/community

[//]: # (general links)

[PIV]: https://piv.idmanagement.gov/
[yk-guide]: https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html
[Yubico]: https://www.yubico.com/
[YubiKey NEO]: https://support.yubico.com/support/solutions/articles/15000006494-yubikey-neo
[YubiKey 4]: https://support.yubico.com/support/solutions/articles/15000006486-yubikey-4
[YubiKey 5]: https://www.yubico.com/products/yubikey-5-overview/
[yubico-piv-tool]: https://github.com/Yubico/yubico-piv-tool/
[Corrode]: https://github.com/jameysharp/corrode
[cc-web]: https://contributor-covenant.org/
[cc-md]: https://github.com/tarcieri/yubikey-piv.rs/blob/develop/CODE_OF_CONDUCT.md
[BSDL]: https://opensource.org/licenses/BSD-2-Clause

[//]: # (github issues)

[#18]: https://github.com/tarcieri/yubikey-piv.rs/issues/18
[#20]: https://github.com/tarcieri/yubikey-piv.rs/issues/20
[#21]: https://github.com/tarcieri/yubikey-piv.rs/issues/21
[#22]: https://github.com/tarcieri/yubikey-piv.rs/issues/22
[#23]: https://github.com/tarcieri/yubikey-piv.rs/issues/23
[#24]: https://github.com/tarcieri/yubikey-piv.rs/issues/24
[#25]: https://github.com/tarcieri/yubikey-piv.rs/issues/25
[#26]: https://github.com/tarcieri/yubikey-piv.rs/issues/26
[#27]: https://github.com/tarcieri/yubikey-piv.rs/issues/27
[#28]: https://github.com/tarcieri/yubikey-piv.rs/issues/28
