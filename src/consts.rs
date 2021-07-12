//! Miscellaneous constant values

/// YubiKey max buffer size
pub(crate) const CB_BUF_MAX: usize = 3072;

/// YubiKey max object size
pub(crate) const CB_OBJ_MAX: usize = CB_BUF_MAX - 9;

pub(crate) const CB_OBJ_TAG_MIN: usize = 2; // 1 byte tag + 1 byte len
#[cfg(feature = "untested")]
pub(crate) const CB_OBJ_TAG_MAX: usize = CB_OBJ_TAG_MIN + 2; // 1 byte tag + 3 bytes len

// Admin tags
pub(crate) const TAG_ADMIN_FLAGS_1: u8 = 0x81;
pub(crate) const TAG_ADMIN_SALT: u8 = 0x82;
pub(crate) const TAG_ADMIN_TIMESTAMP: u8 = 0x83;

// Protected tags
pub(crate) const TAG_PROTECTED_FLAGS_1: u8 = 0x81;
pub(crate) const TAG_PROTECTED_MGM: u8 = 0x89;
