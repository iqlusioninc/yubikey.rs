//! Provides a wrapper to allow ed25519 implementations using ed25519_dalek

use crate::piv::ED25519_ALGORITHM_OID;
use der::asn1::BitString;
use x509_cert::spki::{
    self, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureBitStringEncoding, SubjectPublicKeyInfoRef,
};

/// ed25519_dalek::Signature wrapper to implement required traits
#[derive(Debug)]
pub struct SignatureWrapper(ed25519_dalek::Signature);

impl SignatureBitStringEncoding for SignatureWrapper {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(self.0.to_bytes().as_ref())
    }
}

impl TryFrom<&[u8]> for SignatureWrapper {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ed25519_dalek::Signature::from_slice(bytes)
            .map(SignatureWrapper)
            .map_err(|e| signature::Error::from_source(e))
    }
}

/// Wrapper type for  verifying key that implements required X.509 traits
#[derive(Debug, Clone)]
pub struct VerifyingKeyWrapper(ed25519_dalek::VerifyingKey);

impl ed25519_dalek::Verifier<ed25519_dalek::Signature> for VerifyingKeyWrapper {
    fn verify(
        &self,
        msg: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<(), ed25519_dalek::ed25519::Error> {
        self.0.verify(msg, signature)
    }
}

impl EncodePublicKey for VerifyingKeyWrapper {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        let document = ed25519_dalek::pkcs8::spki::EncodePublicKey::to_public_key_der(&self.0)
            .map_err(|_| spki::Error::KeyMalformed)?;
        let vec = document.to_vec();
        der::Document::try_from(vec).map_err(|_| spki::Error::KeyMalformed)
    }
}

impl DynSignatureAlgorithmIdentifier for VerifyingKeyWrapper {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ED25519_ALGORITHM_OID,
            parameters: None,
        })
    }
}

impl From<ed25519_dalek::VerifyingKey> for VerifyingKeyWrapper {
    fn from(key: ed25519_dalek::VerifyingKey) -> Self {
        Self(key)
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for VerifyingKeyWrapper {
    type Error = spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        // Extract the raw public key bytes from SPKI
        let key_data: &[u8; 32] = spki.subject_public_key.raw_bytes().try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(key_data)
            .map(VerifyingKeyWrapper)
            .map_err(|_| spki::Error::KeyMalformed)
    }
}
