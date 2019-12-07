//! [YubiKey] PIV: [Personal Identity Verification][PIV] support for
//! [Yubico] devices using the Personal Computer/Smart Card ([PC/SC])
//! interface as provided by the [`pcsc` crate].
//!
//! **PIV** is a [NIST] standard for both *signing* and *encryption*
//! using SmartCards and SmartCard-based hardware tokens like YubiKeys.
//!
//! This library natively implements the protocol used to manage and
//! utilize PIV encryption and signing keys which can be generated, imported,
//! and stored on YubiKey devices.
//!
//! See [Yubico's guide to PIV-enabled YubiKeys][yk-guide] for more information
//! on which devices support PIV and the available functionality.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust 1.39+
//!
//! ## Supported YubiKeys
//!
//! - [YubiKey 4] series
//! - [YubiKey 5] series
//!
//! NOTE: Nano and USB-C variants of the above are also supported.
//!       Pre-YK4 [YubiKey NEO] series is **NOT** supported.
//!
//! ## Supported Algorithms
//!
//! - **Authentication**: `3DES`
//! - **Encryption**: `RSA1024`, `RSA2048`, `ECCP256`, `ECCP384`
//! - **Signatures**:
//!   - RSASSA-PKCS#1v1.5: `RSA1024`, `RSA2048`
//!   - ECDSA: `ECCP256`, `ECCP384`
//!
//! NOTE: RSASSA-PSS signatures and RSA-OAEP encryption may be supportable (TBD)
//!
//! ## Status
//!
//! This is a work-in-progress effort, and while much of the library-level
//! code from upstream [yubico-piv-tool] has been translated into Rust
//! presenting a safe interface, much of it is still untested.
//!
//! Please see the [project's README.md for a complete status][status].
//!
//! ## History
//!
//! This library is a Rust translation of the [yubico-piv-tool] utility by
//! Yubico, which was originally written in C. It was mechanically translated
//! from C into Rust using [Corrode], and then subsequently heavily
//! refactored into safer, more idiomatic Rust.
//!
//! For more information on [yubico-piv-tool] and background information on how
//! the YubiKey implementation of PIV works in general, see the
//! [Yubico PIV Tool Command Line Guide][piv-tool-guide].
//!
//! ## Security Warning
//!
//! No security audits of this crate have ever been performed. Presently it is in
//! an experimental stage and may still contain high-severity issues.
//!
//! USE AT YOUR OWN RISK!
//!
//! ## Code of Conduct
//!
//! We abide by the [Contributor Covenant][cc-md] and ask that you do as well.
//!
//! For more information, please see [CODE_OF_CONDUCT.md][cc-md].
//!
//! ## License
//!
//! **yubikey-piv.rs** is a fork of and originally a mechanical translation from
//! Yubico's [yubico-piv-tool], a C library/CLI program. The original library
//! was licensed under a [2-Clause BSD License][BSDL], which this library inherits
//! as a derived work.
//!
//! [YubiKey]: https://www.yubico.com/products/yubikey-hardware/
//! [PIV]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
//! [Yubico]: https://www.yubico.com/
//! [PC/SC]: https://en.wikipedia.org/wiki/PC/SC
//! [`pcsc` crate]: https://github.com/bluetech/pcsc-rust
//! [NIST]: https://www.nist.gov/
//! [yk-guide]: https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html
//! [YubiKey NEO]: https://support.yubico.com/support/solutions/articles/15000006494-yubikey-neo
//! [YubiKey 4]: https://support.yubico.com/support/solutions/articles/15000006486-yubikey-4
//! [YubiKey 5]: https://www.yubico.com/products/yubikey-5-overview/
//! [status]: https://github.com/tarcieri/yubikey-piv.rs#status
//! [yubico-piv-tool]: https://github.com/Yubico/yubico-piv-tool/
//! [Corrode]: https://github.com/jameysharp/corrode
//! [piv-tool-guide]: https://www.yubico.com/wp-content/uploads/2016/05/Yubico_PIV_Tool_Command_Line_Guide_en.pdf
//! [cc-web]: https://contributor-covenant.org/
//! [cc-md]: https://github.com/tarcieri/yubikey-piv.rs/blob/develop/CODE_OF_CONDUCT.md
//! [BSDL]: https://opensource.org/licenses/BSD-2-Clause

// Adapted from yubico-piv-tool:
// <https://github.com/Yubico/yubico-piv-tool/>
//
// Copyright (c) 2014-2016 Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tarcieri/yubikey-piv.rs/develop/img/logo.png",
    html_root_url = "https://docs.rs/yubikey-piv/0.0.3"
)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_lifetimes,
    unused_qualifications
)]

mod apdu;
#[cfg(feature = "untested")]
pub mod cccid;
pub mod certificate;
#[cfg(feature = "untested")]
pub mod chuid;
pub mod config;
pub mod consts;
#[cfg(feature = "untested")]
pub mod container;
pub mod error;
pub mod key;
mod metadata;
pub mod mgm;
#[cfg(feature = "untested")]
pub mod msroots;
pub mod policy;
pub mod readers;
mod serialization;
#[cfg(feature = "untested")]
pub mod settings;
mod transaction;
pub mod yubikey;

pub use self::{readers::Readers, yubikey::YubiKey};

#[cfg(feature = "untested")]
pub use self::{key::Key, mgm::MgmKey};

/// Object identifiers
pub type ObjectId = u32;

/// Buffer type (self-zeroizing byte vector)
pub(crate) type Buffer = zeroize::Zeroizing<Vec<u8>>;
