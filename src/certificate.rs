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
use log::error;
use rsa::{PublicKey, RSAPublicKey};
use x509_parser::{parse_x509_der, x509::SubjectPublicKeyInfo};
use zeroize::Zeroizing;

/// An encoded point for some elliptic curve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EcPoint {
    /// A point in compressed form.
    Compressed {
        /// EC algorithm
        algorithm: AlgorithmId,

        /// Encoded point
        bytes: Buffer,
    },

    /// A point in uncompressed form.
    Uncompressed {
        /// EC algorithm
        algorithm: AlgorithmId,

        /// Encoded point
        bytes: Buffer,
    },
}

/// Information about a public key within a [`Certificate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyInfo {
    /// RSA keys
    Rsa {
        /// RSA algorithm
        algorithm: AlgorithmId,

        /// Public key
        pubkey: RSAPublicKey,
    },

    /// EC keys
    Ec(EcPoint),
}

impl PublicKeyInfo {
    fn parse(subject_pki: &SubjectPublicKeyInfo<'_>) -> Result<Self, Error> {
        match subject_pki.algorithm.algorithm.to_string().as_str() {
            // RSA encryption
            "1.2.840.113549.1.1.1" => {
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
            // EC Public Key
            "1.2.840.10045.2.1" => {
                let algorithm = read_pki::ec_parameters(&subject_pki.algorithm.parameters)?;
                read_pki::ec_point(algorithm, subject_pki.subject_public_key.data)
                    .map(PublicKeyInfo::Ec)
            }
            _ => Err(Error::InvalidObject),
        }
    }

    /// Returns the algorithm that this public key can be used with.
    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            PublicKeyInfo::Rsa { algorithm, .. } => *algorithm,
            PublicKeyInfo::Ec(point) => match point {
                EcPoint::Compressed { algorithm, .. } => *algorithm,
                EcPoint::Uncompressed { algorithm, .. } => *algorithm,
            },
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
    use zeroize::Zeroizing;

    use super::EcPoint;
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
            "1.2.840.10045.3.1.7" => Ok(AlgorithmId::EccP256),
            "1.3.132.0.34" => Ok(AlgorithmId::EccP384),
            _ => Err(Error::InvalidObject),
        }
    }

    /// From [RFC 5480](https://tools.ietf.org/html/rfc5480#section-2.2):
    /// ```text
    /// ECPoint ::= OCTET STRING
    ///
    /// o The first octet of the OCTET STRING indicates whether the key is
    ///   compressed or uncompressed.  The uncompressed form is indicated
    ///   by 0x04 and the compressed form is indicated by either 0x02 or
    ///   0x03 (see 2.3.3 in [SEC1]).  The public key MUST be rejected if
    ///   any other value is included in the first octet.
    /// ```
    pub(super) fn ec_point(algorithm: AlgorithmId, encoded: &[u8]) -> Result<EcPoint, Error> {
        if encoded.is_empty() {
            return Err(Error::InvalidObject);
        }

        match encoded[0] {
            0x02 | 0x03 => {
                if encoded.len()
                    == match algorithm {
                        AlgorithmId::EccP256 => 33,
                        AlgorithmId::EccP384 => 49,
                        _ => return Err(Error::AlgorithmError),
                    }
                {
                    Ok(EcPoint::Compressed {
                        algorithm,
                        bytes: Zeroizing::new(encoded[1..].to_vec()),
                    })
                } else {
                    Err(Error::InvalidObject)
                }
            }
            0x04 => {
                if encoded.len()
                    == match algorithm {
                        AlgorithmId::EccP256 => 65,
                        AlgorithmId::EccP384 => 97,
                        _ => return Err(Error::AlgorithmError),
                    }
                {
                    Ok(EcPoint::Uncompressed {
                        algorithm,
                        bytes: Zeroizing::new(encoded[1..].to_vec()),
                    })
                } else {
                    Err(Error::InvalidObject)
                }
            }
            _ => Err(Error::InvalidObject),
        }
    }
}
