/// YubiKey OTP Applet Name
pub(crate) const APPLET_NAME: &str = "YubiKey OTP";

/// YubiKey OTP Applet ID. Needed to query serial on YK4.
pub(crate) const APPLET_ID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01];
