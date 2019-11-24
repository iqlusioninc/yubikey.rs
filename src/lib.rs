//! [YubiKey][1] PIV: [Personal Identity Verification][2] support for
//! [Yubico][3] devices using the Chip Card Interface Device ([CCID][4])
//! protocol.
//!
//! **PIV** is a [NIST][5] standard for both *signing* and *encryption*
//! using SmartCards and SmartCard-based hardware tokens like YubiKeys.
//!
//! This library natively implements the CCID protocol used to manage and
//! utilize PIV encryption and signing keys which can be generated, imported,
//! and stored on YubiKey devices.
//!
//! See [Yubico's guide to PIV-enabled YubiKeys][6] for more information
//! on which devices support PIV and the available functionality.
//!
//! Supported algorithms:
//!
//! - **Authentication**: `3DES`
//! - **Encryption**: `RSA1024`, `RSA2048`, `ECCP256`, `ECCP384`
//! - **Signatures**:
//!   - RSASSA-PKCS#1v1.5: `RSA1024`, `RSA2048`
//!   - ECDSA: `ECCP256`, `ECCP384`
//!
//! ## Status
//!
//! This library is a work-in-progress translation and is not yet usable.
//! Check back later for updates.
//!
//! ## History
//!
//! This library is a Rust translation of the [yubico-piv-tool][7] utility by
//! Yubico, which was originally written in C. It was mechanically translated
//! from C into Rust using [Corrode][8], and then subsequently heavily
//! refactored into safer, more idiomatic Rust.
//!
//! For more information on `yubico-piv-tool` and background information on how
//! the YubiKey implementation of PIV works in general, see the
//! [Yubico PIV Tool Command Line Guide][9].
//!
//! [1]: https://www.yubico.com/products/yubikey-hardware/
//! [2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
//! [3]: https://www.yubico.com/
//! [4]: https://en.wikipedia.org/wiki/CCID_(protocol)
//! [5]: https://www.nist.gov/
//! [6]: https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html
//! [7]: https://github.com/Yubico/yubico-piv-tool/
//! [8]: https://github.com/jameysharp/corrode
//! [9]: https://www.yubico.com/wp-content/uploads/2016/05/Yubico_PIV_Tool_Command_Line_Guide_en.pdf

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
    html_root_url = "https://docs.rs/yubikey-piv/0.0.1"
)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_lifetimes,
    unused_qualifications
)]

mod apdu;
pub mod cccid;
pub mod certificate;
pub mod chuid;
pub mod config;
pub mod consts;
pub mod container;
pub mod error;
pub mod key;
mod metadata;
pub mod mgm;
pub mod msroots;
mod response;
mod serialization;
pub mod settings;
mod transaction;
pub mod yubikey;

pub use self::{key::Key, mgm::MgmKey, yubikey::YubiKey};

/// Algorithm identifiers
// TODO(tarcieri): make this an enum
pub type AlgorithmId = u8;

/// Object identifiers
pub type ObjectId = u32;

/// Buffer type (self-zeroizing byte vector)
pub(crate) type Buffer = zeroize::Zeroizing<Vec<u8>>;
