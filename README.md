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

If you've been wanting to use Rust to sign and/or encrypt stuff using a
private key generated and stored on a Yubikey (with option PIN-based access),
this is the crate you've been after!

One small problem, it's not done yet... 😫

But it might be close?

## History

This library is a Rust translation of the [yubico-piv-tool][2] utility by
Yubico, which was originally written in C. It was mechanically translated
from C into Rust using [Corrode][3], and then subsequently heavily
refactored into safer, more idiomatic Rust§.

Note that while this project started as a fork of a [Yubico][4] project,
this fork is **NOT** an official Yubico project and is in no way supported or
endorsed by Yubico.

§ *NOTE*: This section is actually full of lies and notes aspirations/goals,
  not history. That said, there's been a decent amount of work cleaning up the
  mechanically translated code, and at ~5klocs it's not that much.

## Security Warning

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

USE AT YOUR OWN RISK!

## Requirements

- Rust 1.39+

## Code of Conduct

We abide by the [Contributor Covenant][5] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md][6].

## License

**yubikey-piv.rs** is a fork of and originally a mechanical translation from
Yubico's [`yubico-piv-tool`][2], a C library/CLI program. The original library
was licensed under a [2-Clause BSD License][5], which this library inherits
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
[2-Clause BSD License][5] as shown above, without any additional terms
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
[2]: https://github.com/Yubico/yubico-piv-tool/
[3]: https://github.com/jameysharp/corrode
[4]: https://www.yubico.com/
[5]: https://contributor-covenant.org/
[6]: https://github.com/tarcieri/yubikey-piv.rs/blob/develop/CODE_OF_CONDUCT.md
[7]: https://opensource.org/licenses/BSD-2-Clause
