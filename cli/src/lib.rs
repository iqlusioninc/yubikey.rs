//! `yubikey` command-line utility

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[macro_use]
pub mod terminal;

pub mod commands;

use log::debug;
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::str;
use subtle_encoding::hex;
use termcolor::{ColorSpec, StandardStreamLock, WriteColor};
use x509_parser::parse_x509_der;
use yubikey_piv::{certificate::Certificate, key::*, YubiKey};

///Write information about certificate found in slot a la yubico-piv-tool output.
pub fn print_cert_info(
    yubikey: &mut YubiKey,
    slot: SlotId,
    stream: &mut StandardStreamLock<'_>,
) -> Result<(), io::Error> {
    let cert = match Certificate::read(yubikey, slot) {
        Ok(c) => c,
        Err(e) => {
            debug!("error reading certificate in slot {:?}: {}", slot, e);
            return Ok(());
        }
    };
    let buf = cert.into_buffer();

    if !buf.is_empty() {
        let fingerprint = Sha256::digest(&buf);
        let slot_id: u8 = slot.into();
        print_cert_attr(stream, "Slot", format!("{:x}", slot_id))?;
        match parse_x509_der(&buf) {
            Ok((_rem, cert)) => {
                print_cert_attr(
                    stream,
                    "Algorithm",
                    cert.tbs_certificate.subject_pki.algorithm.algorithm,
                )?;

                print_cert_attr(stream, "Subject", cert.tbs_certificate.subject)?;
                print_cert_attr(stream, "Issuer", cert.tbs_certificate.issuer)?;
                print_cert_attr(
                    stream,
                    "Fingerprint",
                    str::from_utf8(hex::encode(fingerprint).as_slice()).unwrap(),
                )?;
                print_cert_attr(
                    stream,
                    "Not Before",
                    cert.tbs_certificate.validity.not_before.asctime(),
                )?;
                print_cert_attr(
                    stream,
                    "Not After",
                    cert.tbs_certificate.validity.not_after.asctime(),
                )?;
            }
            _ => {
                println!("Failed to parse certificate");
                return Ok(());
            }
        };
    }

    Ok(())
}

/// Print a status attribute
fn print_cert_attr(
    stream: &mut StandardStreamLock<'_>,
    name: &str,
    value: impl ToString,
) -> Result<(), io::Error> {
    stream.set_color(ColorSpec::new().set_bold(true))?;
    write!(stream, "{:>12}:", name)?;
    stream.reset()?;
    writeln!(stream, " {}", value.to_string())?;
    stream.flush()?;
    Ok(())
}
