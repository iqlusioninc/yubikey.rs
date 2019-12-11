//! YubiKey Certificates

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

use crate::{
    error::Error,
    key::{AlgorithmId, SlotId},
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use elliptic_curve::weierstrass::{
    curve::{NistP256, NistP384},
    PublicKey as EcPublicKey,
};
use log::error;
use rsa::{PublicKey, RSAPublicKey};
use std::convert::TryFrom;
use std::fmt;
use x509_parser::{parse_x509_der, x509::SubjectPublicKeyInfo};
use zeroize::Zeroizing;

#[cfg(feature = "untested")]
use crate::CB_OBJ_MAX;

// TODO: Make these der_parser::oid::Oid constants when it has const fn support.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NIST_P256: &str = "1.2.840.10045.3.1.7";
const OID_NIST_P384: &str = "1.3.132.0.34";

const TAG_CERT: u8 = 0x70;
#[cfg(feature = "untested")]
const TAG_CERT_COMPRESS: u8 = 0x71;
#[cfg(feature = "untested")]
const TAG_CERT_LRC: u8 = 0xFE;

/// Information about how a [`Certificate`] is stored within a YubiKey.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CertInfo {
    /// The certificate is uncompressed.
    Uncompressed,

    /// The certificate is gzip-compressed.
    Gzip,
}

impl TryFrom<u8> for CertInfo {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(CertInfo::Uncompressed),
            0x01 => Ok(CertInfo::Gzip),
            _ => Err(Error::InvalidObject),
        }
    }
}

impl From<CertInfo> for u8 {
    fn from(certinfo: CertInfo) -> u8 {
        match certinfo {
            CertInfo::Uncompressed => 0x00,
            CertInfo::Gzip => 0x01,
        }
    }
}

/// Information about a public key within a [`Certificate`].
#[derive(Clone, Eq, PartialEq)]
pub enum PublicKeyInfo {
    /// RSA keys
    Rsa {
        /// RSA algorithm
        algorithm: AlgorithmId,

        /// Public key
        pubkey: RSAPublicKey,
    },

    /// EC P-256 keys
    EcP256(EcPublicKey<NistP256>),

    /// EC P-384 keys
    EcP384(EcPublicKey<NistP384>),
}

impl fmt::Debug for PublicKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyInfo({:?})", self.algorithm())
    }
}

impl PublicKeyInfo {
    fn parse(subject_pki: &SubjectPublicKeyInfo<'_>) -> Result<Self, Error> {
        match subject_pki.algorithm.algorithm.to_string().as_str() {
            OID_RSA_ENCRYPTION => {
                let pubkey = read_pki::rsa_pubkey(subject_pki.subject_public_key.data)?;

                Ok(PublicKeyInfo::Rsa {
                    algorithm: match pubkey.n().bits() {
                        1024 => AlgorithmId::Rsa1024,
                        2048 => AlgorithmId::Rsa2048,
                        _ => return Err(Error::AlgorithmError),
                    },
                    pubkey,
                })
            }
            OID_EC_PUBLIC_KEY => {
                let key_bytes = &subject_pki.subject_public_key.data;
                match read_pki::ec_parameters(&subject_pki.algorithm.parameters)? {
                    AlgorithmId::EccP256 => EcPublicKey::from_bytes(key_bytes)
                        .map(PublicKeyInfo::EcP256)
                        .ok_or(Error::InvalidObject),
                    AlgorithmId::EccP384 => EcPublicKey::from_bytes(key_bytes)
                        .map(PublicKeyInfo::EcP384)
                        .ok_or(Error::InvalidObject),
                    _ => Err(Error::AlgorithmError),
                }
            }
            _ => Err(Error::InvalidObject),
        }
    }

    /// Returns the algorithm that this public key can be used with.
    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            PublicKeyInfo::Rsa { algorithm, .. } => *algorithm,
            PublicKeyInfo::EcP256(_) => AlgorithmId::EccP256,
            PublicKeyInfo::EcP384(_) => AlgorithmId::EccP384,
        }
    }
}

/// Certificates
#[derive(Clone, Debug)]
pub struct Certificate {
    subject: String,
    subject_pki: PublicKeyInfo,
    data: Buffer,
}

impl<'a> TryFrom<&'a [u8]> for Certificate {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes.to_vec())
    }
}

impl Certificate {
    /// Read a certificate from the given slot in the YubiKey
    pub fn read(yubikey: &mut YubiKey, slot: SlotId) -> Result<Self, Error> {
        let txn = yubikey.begin_transaction()?;
        let buf = read_certificate(&txn, slot)?;

        if buf.is_empty() {
            return Err(Error::InvalidObject);
        }

        Certificate::from_bytes(buf)
    }

    /// Write this certificate into the YubiKey in the given slot
    #[cfg(feature = "untested")]
    pub fn write(
        &self,
        yubikey: &mut YubiKey,
        slot: SlotId,
        certinfo: CertInfo,
    ) -> Result<(), Error> {
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, Some(&self.data), certinfo)
    }

    /// Delete a certificate located at the given slot of the given YubiKey
    #[cfg(feature = "untested")]
    pub fn delete(yubikey: &mut YubiKey, slot: SlotId) -> Result<(), Error> {
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, None, CertInfo::Uncompressed)
    }

    /// Initialize a local certificate struct from the given bytebuffer
    pub fn from_bytes(cert: impl Into<Buffer>) -> Result<Self, Error> {
        let cert = cert.into();

        if cert.is_empty() {
            error!("certificate cannot be empty");
            return Err(Error::SizeError);
        }

        let parsed_cert = match parse_x509_der(&cert) {
            Ok((_, cert)) => cert,
            _ => return Err(Error::InvalidObject),
        };

        let subject = format!("{}", parsed_cert.tbs_certificate.subject);
        let subject_pki = PublicKeyInfo::parse(&parsed_cert.tbs_certificate.subject_pki)?;

        Ok(Certificate {
            subject,
            subject_pki,
            data: cert,
        })
    }

    /// Returns the SubjectName field of the certificate.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the SubjectPublicKeyInfo field of the certificate.
    pub fn subject_pki(&self) -> &PublicKeyInfo {
        &self.subject_pki
    }

    /// Extract the inner buffer
    pub fn into_buffer(self) -> Buffer {
        self.data
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// Read certificate
pub(crate) fn read_certificate(txn: &Transaction<'_>, slot: SlotId) -> Result<Buffer, Error> {
    let object_id = slot.object_id();

    let buf = match txn.fetch_object(object_id) {
        Ok(b) => b,
        Err(_) => {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }
    };

    // TODO(str4d): Check the rest of the buffer (TAG_CERT_COMPRESS and TAG_CERT_LRC)
    if buf[0] == TAG_CERT {
        Tlv::parse_single(buf, TAG_CERT).or_else(|_| {
            // TODO(tarcieri): is this really ok?
            Ok(Zeroizing::new(vec![]))
        })
    } else {
        Ok(buf)
    }
}

/// Write certificate
#[cfg(feature = "untested")]
pub(crate) fn write_certificate(
    txn: &Transaction<'_>,
    slot: SlotId,
    data: Option<&[u8]>,
    certinfo: CertInfo,
) -> Result<(), Error> {
    let object_id = slot.object_id();

    if data.is_none() {
        return txn.save_object(object_id, &[]);
    }

    let data = data.unwrap();

    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset = Tlv::write(&mut buf, TAG_CERT, data)?;

    // write compression info and LRC trailer
    offset += Tlv::write(&mut buf, TAG_CERT_COMPRESS, &[certinfo.into()])?;
    offset += Tlv::write(&mut buf, TAG_CERT_LRC, &[])?;

    txn.save_object(object_id, &buf[..offset])
}

mod read_pki {
    use der_parser::{
        ber::BerObjectContent,
        der::{parse_der_integer, DerObject},
        error::BerError,
        *,
    };
    use nom::{combinator, IResult};
    use rsa::{BigUint, RSAPublicKey};

    use super::{OID_NIST_P256, OID_NIST_P384};
    use crate::{error::Error, key::AlgorithmId};

    /// From [RFC 8017](https://tools.ietf.org/html/rfc8017#appendix-A.1.1):
    /// ```text
    /// RSAPublicKey ::= SEQUENCE {
    ///     modulus           INTEGER,  -- n
    ///     publicExponent    INTEGER   -- e
    /// }
    /// ```
    pub(super) fn rsa_pubkey(encoded: &[u8]) -> Result<RSAPublicKey, Error> {
        fn parse_rsa_pubkey(i: &[u8]) -> IResult<&[u8], DerObject<'_>, BerError> {
            parse_der_sequence_defined!(i, parse_der_integer >> parse_der_integer)
        }

        fn rsa_pubkey_parts(i: &[u8]) -> IResult<&[u8], (BigUint, BigUint), BerError> {
            combinator::map(parse_rsa_pubkey, |object| {
                let seq = object.as_sequence().expect("is DER sequence");
                assert_eq!(seq.len(), 2);

                let n = match seq[0].content {
                    BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
                    _ => panic!("expected DER integer"),
                };
                let e = match seq[1].content {
                    BerObjectContent::Integer(s) => BigUint::from_bytes_be(s),
                    _ => panic!("expected DER integer"),
                };

                (n, e)
            })(i)
        }

        let (n, e) = match rsa_pubkey_parts(encoded) {
            Ok((_, res)) => res,
            _ => return Err(Error::InvalidObject),
        };

        RSAPublicKey::new(n, e).map_err(|_| Error::InvalidObject)
    }

    /// From [RFC 5480](https://tools.ietf.org/html/rfc5480#section-2.1.1):
    /// ```text
    /// ECParameters ::= CHOICE {
    ///   namedCurve         OBJECT IDENTIFIER
    ///   -- implicitCurve   NULL
    ///   -- specifiedCurve  SpecifiedECDomain
    /// }
    /// ```
    pub(super) fn ec_parameters(parameters: &DerObject<'_>) -> Result<AlgorithmId, Error> {
        let curve_oid = match parameters.as_context_specific() {
            Ok((_, Some(named_curve))) => {
                named_curve.as_oid_val().map_err(|_| Error::InvalidObject)
            }
            _ => Err(Error::InvalidObject),
        }?;

        match curve_oid.to_string().as_str() {
            OID_NIST_P256 => Ok(AlgorithmId::EccP256),
            OID_NIST_P384 => Ok(AlgorithmId::EccP384),
            _ => Err(Error::AlgorithmError),
        }
    }
}
