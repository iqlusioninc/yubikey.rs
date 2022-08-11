<img src="https://raw.githubusercontent.com/iqlusioninc/yubikey.rs/main/img/logo.png" width="150" height="110">

# yubikey-cli.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
![Maintenance Status: Experimental][maintenance-image]
[![Safety Dance][safety-image]][safety-link]
[![Build Status][build-image]][build-link]
[![Gitter Chat][gitter-image]][gitter-link]

Pure Rust host-side YubiKey [Personal Identity Verification (PIV)][PIV] CLI
utility with general-purpose public-key encryption and signing support.

[Documentation][docs-link]

## Minimum Supported Rust Version

Rust **1.57** or newer.

## Supported YubiKeys

- [YubiKey 4] series
- [YubiKey 5] series

NOTE: Nano and USB-C variants of the above are also supported.
      Pre-YK4 [YubiKey NEO] series is **NOT** supported (see [#18]).

## Security Warning

No security audits of this crate have ever been performed. Presently it is in
an experimental stage and may still contain high-severity issues.

USE AT YOUR OWN RISK!

## Code of Conduct

We abide by the [Contributor Covenant][cc-md] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md][cc-md].

## License

Copyright (c) 2014-2022 Yubico AB, Tony Arcieri
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

[crate-image]: https://img.shields.io/crates/v/yubikey-cli.svg
[crate-link]: https://crates.io/crates/yubikey-cli
[docs-image]: https://docs.rs/yubikey-cli/badge.svg
[docs-link]: https://docs.rs/yubikey-cli/
[license-image]: https://img.shields.io/badge/license-BSD-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.57+-blue.svg
[maintenance-image]: https://img.shields.io/badge/maintenance-experimental-blue.svg
[safety-image]: https://img.shields.io/badge/unsafe-forbidden-success.svg
[safety-link]: https://github.com/rust-secure-code/safety-dance/
[build-image]: https://github.com/iqlusioninc/yubikey.rs/workflows/CI/badge.svg?branch=main&event=push
[build-link]: https://github.com/iqlusioninc/yubikey.rs/actions
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/iqlusioninc/community

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
[cc-md]: https://github.com/iqlusioninc/yubikey-cli.rs/blob/main/CODE_OF_CONDUCT.md
[BSDL]: https://opensource.org/licenses/BSD-2-Clause
