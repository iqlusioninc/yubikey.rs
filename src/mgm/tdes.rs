use cipher::{Key, KeyInit};

use crate::{Error, Result};

use super::{MgmAlgorithmId, MgmKeyAlgorithm, SpecificMgmKey};

/// Size of a DES key
const DES_LEN_DES: usize = 8;

/// Size of a 3DES key
pub(super) const DES_LEN_3DES: usize = DES_LEN_DES * 3;

impl MgmKeyAlgorithm for des::TdesEde3 {
    const ALGORITHM_ID: MgmAlgorithmId = MgmAlgorithmId::ThreeDes;

    fn check_weak_key(key: &Key<Self>) -> Result<()> {
        des::TdesEde3::weak_key_test(key).map_err(|_| Error::KeyError)
    }
}

/// A Management Key (MGM) using Triple-DES
pub type MgmKey3Des = SpecificMgmKey<des::TdesEde3>;
