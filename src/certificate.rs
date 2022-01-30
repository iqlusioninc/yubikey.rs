//! X.509 certificate support.

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
    consts::CB_OBJ_MAX,
    error::{Error, Result},
    piv::{sign_data, AlgorithmId, SlotId},
    serialization::*,
    transaction::Transaction,
    yubikey::YubiKey,
    Buffer,
};
use elliptic_curve::sec1::EncodedPoint as EcPublicKey;
use num_bigint_dig::BigUint;
use p256::NistP256;
use p384::NistP384;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use der::asn1::{Any, BitString, ObjectIdentifier, UIntBytes, UtcTime};
use der::{Decodable, Encodable, Sequence};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509::{AlgorithmIdentifier, Name, SubjectPublicKeyInfo, TBSCertificate, Validity};
use x509::{Certificate, Extensions, Time};

// These exist in certval now and might ought move to x509. duplicating for now.
/// OID for SubjectPublicKeyInfo structs with RSA keys
pub const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");
/// OID for SubjectPublicKeyInfo structs with EC keys
pub const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
/// OID for parameters SubjectPublicKeyInfo structs with p256 keys
pub const OID_NIST_P256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");
/// OID for parameters SubjectPublicKeyInfo structs with p284 keys
pub const OID_NIST_P384: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");
/// Signature OID for EC keys
pub const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.2");
/// Signature OID for RSA keys
pub const OID_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.11");
/// Hash OID
pub const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.1");

const TAG_CERT: u8 = 0x70;
const TAG_CERT_COMPRESS: u8 = 0x71;
const TAG_CERT_LRC: u8 = 0xFE;

/// A serial number for a [`Certificate`].
#[derive(Clone, Debug)]
pub struct Serial(BigUint);

impl From<BigUint> for Serial {
    fn from(num: BigUint) -> Serial {
        Serial(num)
    }
}

impl From<[u8; 20]> for Serial {
    fn from(bytes: [u8; 20]) -> Serial {
        Serial(BigUint::from_bytes_be(&bytes))
    }
}

impl TryFrom<&[u8]> for Serial {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Serial> {
        if bytes.len() <= 20 {
            Ok(Serial(BigUint::from_bytes_be(bytes)))
        } else {
            Err(Error::ParseError)
        }
    }
}

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

    fn try_from(value: u8) -> Result<Self> {
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
        pubkey: RsaPublicKey,
    },

    /// EC P-256 keys
    EcP256(EcPublicKey<NistP256>),

    /// EC P-384 keys
    EcP384(EcPublicKey<NistP384>),
}

/// from RFC8017
///    DigestInfo ::= SEQUENCE {
///      digestAlgorithm DigestAlgorithmIdentifier,
///      digest Digest }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct DigestInfo<'a> {
    digest_algorithm: AlgorithmIdentifier<'a>,
    #[asn1(type = "OCTET STRING")]
    digest: &'a [u8],
}

/// Creates a new self-signed certificate for the given key. Writes the resulting
/// certificate to the slot before returning it.
///
/// `extensions` is optional; if empty, no extensions will be included.
#[allow(clippy::too_many_arguments)]
pub fn generate_self_signed<'a>(
    yubikey: &mut YubiKey,
    key: SlotId,
    serial: &[u8],
    opt_not_after: Option<Time>,
    subject: &Name<'a>,
    spkibuf: &[u8],
    extensions: Option<Extensions<'a>>,
    alg_id: AlgorithmId,
) -> Result<Vec<u8>> {
    let serial_number = UIntBytes::new(serial).unwrap();
    let spki = match SubjectPublicKeyInfo::from_der(spkibuf) {
        Ok(spki) => spki,
        Err(_e) => return Err(Error::ParseError),
    };

    let mut oid = OID_SHA256_WITH_RSA_ENCRYPTION;
    if OID_EC_PUBLIC_KEY == spki.algorithm.oid {
        oid = OID_ECDSA_WITH_SHA256;
    } else if OID_RSA_ENCRYPTION != spki.algorithm.oid {
        return Err(Error::AlgorithmError);
    }

    let signature = AlgorithmIdentifier {
        oid,
        parameters: None,
    };

    let ten_years_duration = Duration::from_secs(365 * 24 * 60 * 60 * 10);
    let ten_years_time = SystemTime::now().checked_add(ten_years_duration).unwrap();
    let not_after = match opt_not_after {
        Some(na) => na,
        None => Time::UtcTime(
            UtcTime::from_unix_duration(ten_years_time.duration_since(UNIX_EPOCH).unwrap())
                .unwrap(),
        ),
    };

    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(SystemTime::now().duration_since(UNIX_EPOCH).unwrap())
                .unwrap(),
        ),
        not_after,
    };

    let tbs_certificate = TBSCertificate {
        version: 2,
        serial_number,
        signature,
        issuer: subject.clone(),
        validity,
        subject: subject.clone(),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    };

    let tbs_cert = match tbs_certificate.to_vec() {
        Ok(tbs_cert) => tbs_cert,
        Err(_e) => return Err(Error::GenericError),
    };
    if CB_OBJ_MAX < tbs_cert.len() {
        return Err(Error::GenericError);
    }

    if OID_SHA256_WITH_RSA_ENCRYPTION == oid {
        let h = Sha256::digest(&tbs_cert);
        let ysd = DigestInfo {
            digest_algorithm: AlgorithmIdentifier {
                oid: OID_SHA256,
                parameters: Some(Any::NULL),
            },
            digest: h.as_slice(),
        };

        let em_len = if let AlgorithmId::Rsa1024 = alg_id {
            128
        } else {
            256
        };
        let mut t = ysd.to_vec().unwrap();
        let tlen = t.len();
        let mut em = vec![];
        em.append(&mut vec![0x00_u8, 0x01]);
        em.append(&mut vec![0xff_u8; em_len - tlen - 3]);
        em.append(&mut vec![0x00_u8]);
        em.append(&mut t);

        let signature_buf = sign_data(yubikey, em.as_slice(), alg_id, key)?;

        let signature_algorithm = AlgorithmIdentifier {
            oid: OID_SHA256_WITH_RSA_ENCRYPTION,
            parameters: None,
        };
        let signature = BitString::new(0, signature_buf.as_slice()).unwrap();
        let c = Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
        };

        let enc_cert = c.to_vec().unwrap();
        write(yubikey, key, CertInfo::Uncompressed, enc_cert.as_slice())?;
        Ok(enc_cert)
    } else {
        let signature_buf = sign_data(yubikey, &Sha256::digest(tbs_cert.as_slice()), alg_id, key)?;

        let signature_algorithm = AlgorithmIdentifier {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signature = BitString::new(0, signature_buf.as_slice()).unwrap();
        let c = Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
        };

        let enc_cert = c.to_vec().unwrap();
        write(yubikey, key, CertInfo::Uncompressed, enc_cert.as_slice())?;
        Ok(enc_cert)
    }
}

/// Read a certificate from the given slot in the YubiKey
pub fn read(yubikey: &mut YubiKey, slot: SlotId) -> Result<Buffer> {
    let txn = yubikey.begin_transaction()?;
    let buf = read_certificate(&txn, slot)?;

    if buf.is_empty() {
        return Err(Error::InvalidObject);
    }

    Ok(buf)
}

/// Write this certificate into the YubiKey in the given slot
pub fn write(yubikey: &mut YubiKey, slot: SlotId, certinfo: CertInfo, cert: &[u8]) -> Result<()> {
    let txn = yubikey.begin_transaction()?;
    write_certificate(&txn, slot, Some(cert), certinfo)
}

/// Delete a certificate located at the given slot of the given YubiKey
#[cfg(feature = "untested")]
#[cfg_attr(docsrs, doc(cfg(feature = "untested")))]
pub fn delete(yubikey: &mut YubiKey, slot: SlotId) -> Result<()> {
    let txn = yubikey.begin_transaction()?;
    write_certificate(&txn, slot, None, CertInfo::Uncompressed)
}

/// Read certificate
pub(crate) fn read_certificate(txn: &Transaction<'_>, slot: SlotId) -> Result<Buffer> {
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
pub(crate) fn write_certificate(
    txn: &Transaction<'_>,
    slot: SlotId,
    data: Option<&[u8]>,
    certinfo: CertInfo,
) -> Result<()> {
    let object_id = slot.object_id();

    if data.is_none() {
        return txn.save_object(object_id, &[]);
    }

    let data = data.unwrap();

    let mut buf = [0u8; CB_OBJ_MAX];
    let mut offset = Tlv::write(&mut buf, TAG_CERT, data)?;

    // write compression info and LRC trailer
    offset += Tlv::write(&mut buf[offset..], TAG_CERT_COMPRESS, &[certinfo.into()])?;
    offset += Tlv::write(&mut buf[offset..], TAG_CERT_LRC, &[])?;

    txn.save_object(object_id, &buf[..offset])
}
