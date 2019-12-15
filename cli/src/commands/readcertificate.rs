//! Print a certificate

use crate::terminal::STDOUT;
use gumdrop::Options;
use std::convert::TryFrom;
use termcolor::WriteColor;
use yubikey_piv::{key::*, YubiKey};

use crate::print_cert_info;

/// The `readcertificate` subcommand
#[derive(Debug, Options)]
pub struct ReadCertificateCmd {}

impl ReadCertificateCmd {
    /// Run the `readcertificate` subcommand
    pub fn run(&self, mut yk: YubiKey, slot: String) {
        let slot_enum: SlotId = SlotId::try_from(slot).unwrap();

        let mut s = STDOUT.lock();
        s.reset().unwrap();

        print_cert_info(&mut yk, slot_enum, &mut s).unwrap();
    }
}
