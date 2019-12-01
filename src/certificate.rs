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
    consts::*,
    error::Error,
    key::{AlgorithmId, SlotId},
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use ecdsa::{
    curve::{CompressedCurvePoint, NistP256, NistP384, UncompressedCurvePoint},
    generic_array::GenericArray,
};
use log::error;
use rsa::{PublicKey, RSAPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use x509_parser::{parse_x509_der, x509::SubjectPublicKeyInfo};
use zeroize::Zeroizing;

// TODO: Make these der_parser::oid::Oid constants when it has const fn support.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NIST_P256: &str = "1.2.840.10045.3.1.7";
const OID_NIST_P384: &str = "1.3.132.0.34";

/// An encoded point on the Nist P-256 curve.
#[derive(Clone, Eq, PartialEq)]
pub enum EcP256Point {
    /// Compressed encoding of a point on the curve.
    Compressed(CompressedCurvePoint<NistP256>),

    /// Uncompressed encoding of a point on the curve.
    Uncompressed(UncompressedCurvePoint<NistP256>),
}

/// An encoded point on the Nist P-384 curve.
#[derive(Clone, Eq, PartialEq)]
pub enum EcP384Point {
    /// Compressed encoding of a point on the curve.
    Compressed(CompressedCurvePoint<NistP384>),

    /// Uncompressed encoding of a point on the curve.
    Uncompressed(UncompressedCurvePoint<NistP384>),
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
    EcP256(EcP256Point),

    /// EC P-384 keys
    EcP384(EcP384Point),
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
                    AlgorithmId::EccP256 => match key_bytes.len() {
                        33 => CompressedCurvePoint::<NistP256>::from_bytes(
                            GenericArray::clone_from_slice(key_bytes),
                        )
                        .map(EcP256Point::Compressed),
                        65 => UncompressedCurvePoint::<NistP256>::from_bytes(
                            GenericArray::clone_from_slice(key_bytes),
                        )
                        .map(EcP256Point::Uncompressed),
                        _ => None,
                    }
                    .map(PublicKeyInfo::EcP256)
                    .ok_or(Error::InvalidObject),
                    AlgorithmId::EccP384 => match key_bytes.len() {
                        49 => CompressedCurvePoint::<NistP384>::from_bytes(
                            GenericArray::clone_from_slice(key_bytes),
                        )
                        .map(EcP384Point::Compressed),
                        97 => UncompressedCurvePoint::<NistP384>::from_bytes(
                            GenericArray::clone_from_slice(key_bytes),
                        )
                        .map(EcP384Point::Uncompressed),
                        _ => None,
                    }
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

impl Certificate {
    /// Read a certificate from the given slot in the YubiKey
    pub fn read(yubikey: &mut YubiKey, slot: SlotId) -> Result<Self, Error> {
        let txn = yubikey.begin_transaction()?;
        let buf = read_certificate(&txn, slot)?;

        if buf.is_empty() {
            return Err(Error::InvalidObject);
        }

        Certificate::new(buf)
    }

    /// Write this certificate into the YubiKey in the given slot
    pub fn write(&self, yubikey: &mut YubiKey, slot: SlotId, certinfo: u8) -> Result<(), Error> {
        let max_size = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, Some(&self.data), certinfo, max_size)
    }

    /// Delete a certificate located at the given slot of the given YubiKey
    pub fn delete(yubikey: &mut YubiKey, slot: SlotId) -> Result<(), Error> {
        let max_size = yubikey.obj_size_max();
        let txn = yubikey.begin_transaction()?;
        write_certificate(&txn, slot, None, 0, max_size)
    }

    /// Initialize a local certificate struct from the given bytebuffer
    pub fn new(cert: impl Into<Buffer>) -> Result<Self, Error> {
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
    let mut len: usize = 0;
    let object_id = slot.object_id();

    let mut buf = match txn.fetch_object(object_id) {
        Ok(b) => b,
        Err(_) => {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }
    };

    if buf.len() < CB_OBJ_TAG_MIN {
        // TODO(tarcieri): is this really ok?
        return Ok(Zeroizing::new(vec![]));
    }

    if buf[0] == TAG_CERT {
        let offset = 1 + get_length(&buf[1..], &mut len);

        if len > buf.len() - offset {
            // TODO(tarcieri): is this really ok?
            return Ok(Zeroizing::new(vec![]));
        }

        buf.copy_within(offset..offset + len, 0);
        buf.truncate(len);
    }

    Ok(buf)
}

/// Write certificate
pub(crate) fn write_certificate(
    txn: &Transaction<'_>,
    slot: SlotId,
    data: Option<&[u8]>,
    certinfo: u8,
    max_size: usize,
) -> Result<(), Error> {
    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset = 0;

    let object_id = slot.object_id();

    if data.is_none() {
        return txn.save_object(object_id, &[]);
    }

    let data = data.unwrap();

    let mut req_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
    req_len += set_length(&mut buf, data.len());
    req_len += data.len();

    if req_len < data.len() || req_len > max_size {
        return Err(Error::SizeError);
    }

    buf[offset] = TAG_CERT;
    offset += 1;
    offset += set_length(&mut buf[offset..], data.len());

    buf[offset..(offset + data.len())].copy_from_slice(&data);

    offset += data.len();

    // write compression info and LRC trailer
    buf[offset] = TAG_CERT_COMPRESS;
    buf[offset + 1] = 0x01;
    buf[offset + 2] = if certinfo == YKPIV_CERTINFO_GZIP {
        0x01
    } else {
        0x00
    };
    buf[offset + 3] = TAG_CERT_LRC;
    buf[offset + 4] = 00;

    offset += 5;

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

///Write information about certificate found in slot a la yubico-piv-tool output.
pub fn print_cert_info(yubikey: &mut YubiKey, slot: SlotId) -> Result<(), Error> {
    let txn = yubikey.begin_transaction()?;
    let buf = match read_certificate(&txn, slot) {
        Ok(b) => b,
        Err(e) => {
            println!("error reading certificate in slot {:?}: {}", slot, e);
            return Err(e);
        }
    };

    if !buf.is_empty() {
        let mut hasher = Sha256::new();
        hasher.input(buf.clone().to_vec());
        let fingerprint = hasher.result();

        let slot_id: u8 = slot.into();
        println!("Slot {:x}: ", slot_id);
        match parse_x509_der(&buf) {
            Ok((_rem, cert)) => {
                println!(
                    "\tAlgorithm: {}",
                    cert.tbs_certificate.subject_pki.algorithm.algorithm
                );
                println!("\tSubject: {}", cert.tbs_certificate.subject);
                println!("\tIssuer: {}", cert.tbs_certificate.issuer);
                println!("\tFingerprint: {:X}", fingerprint);
                println!(
                    "\tNot Before: {}",
                    cert.tbs_certificate.validity.not_before.asctime()
                );
                println!(
                    "\tNot After: {}",
                    cert.tbs_certificate.validity.not_after.asctime()
                );
            }
            _ => {
                println!("Failed to parse certificate");
                return Err(Error::GenericError);
            }
        };
    }

    Ok(())
}
