<img src="https://raw.githubusercontent.com/tendermint/yubihsm-rs/develop/img/logo.png" width="150" height="110">

# yubikey-piv.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
![Maintenance Status: Experimental][maintenance-image]
[![Build Status][build-image]][build-link]
[![Gitter Chat][gitter-image]][gitter-link]

Pure Rust host-side YubiKey [Personal Identity Verification (PIV)][1] driver
with general-purpose public-key encryption and signing support.

[Documentation][docs-link]

## About

YubiKeys are versatile devices and through their PIV support, you can use them
to store a number of RSA (2048/1024) and ECC (NIST P-256/P-384) private keys
with configurable access control policies. Both the signing (RSASSA/ECDSA) and
encryption (PKCS#1v1.5/ECIES) use cases are supported for either key type.

See [Yubico's guide to PIV-enabled YubiKeys][2] for more information
on which devices support PIV and the available functionality.

If you've been wanting to use Rust to sign and/or encrypt stuff using a
private key generated and stored on a Yubikey (with option PIN-based access),
this is the crate you've been after!

One small problem, it's not done yet... 😫

But it might be close?

## Minimum Supported Rust Version

- Rust **1.39+**

## Security Warning

No security audits of this crate have ever been performed. Presently it is in
an experimental stage and may still contain high-severity issues.

USE AT YOUR OWN RISK!

## History

This library is a Rust translation of the [yubico-piv-tool][3] utility by
Yubico, which was originally written in C. It was mechanically translated
from C into Rust using [Corrode][4], and then subsequently heavily
refactored into safer, more idiomatic Rust.

Note that while this project started as a fork of a [Yubico][5] project,
this fork is **NOT** an official Yubico project and is in no way supported or
endorsed by Yubico.

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

## Code of Conduct

We abide by the [Contributor Covenant][6] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md][7].

## License

**yubikey-piv.rs** is a fork of and originally a mechanical translation from
Yubico's [`yubico-piv-tool`][3], a C library/CLI program. The original library
was licensed under a [2-Clause BSD License][8], which this library inherits
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
[2-Clause BSD License][8] as shown above, without any additional terms
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

[1]: https://piv.idmanagement.gov/
[2]: https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html
[3]: https://github.com/Yubico/yubico-piv-tool/
[4]: https://github.com/jameysharp/corrode
[5]: https://www.yubico.com/
[6]: https://contributor-covenant.org/
[7]: https://github.com/tarcieri/yubikey-piv.rs/blob/develop/CODE_OF_CONDUCT.md
[8]: https://opensource.org/licenses/BSD-2-Clause
