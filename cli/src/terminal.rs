//! Status messages

use der::asn1::ObjectIdentifier;
use der::{Decodable, Encodable};
use lazy_static::lazy_static;
use log::debug;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    str,
    sync::Mutex,
};
use subtle_encoding::hex;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, StandardStreamLock, WriteColor};
use x501::attr::AttributeTypeAndValue;
use x501::name::Name;
use x509::Certificate;
use yubikey::{certificate::read, piv::*, YubiKey};

// the next three functions currently live in certval and may move to x509
fn oid_lookup(oid: &ObjectIdentifier) -> String {
    let oidstr = oid.to_string();
    if oidstr == "2.5.4.41" {
        return "name".to_string();
    } else if oidstr == "2.5.4.4" {
        return "sn".to_string();
    } else if oidstr == "2.5.4.42" {
        return "givenName".to_string();
    } else if oidstr == "2.5.4.43" {
        return "initials".to_string();
    } else if oidstr == "2.5.4.44" {
        return "generationQualifier".to_string();
    } else if oidstr == "2.5.4.3" {
        return "cn".to_string();
    } else if oidstr == "2.5.4.7" {
        return "l".to_string();
    } else if oidstr == "2.5.4.8" {
        return "st".to_string();
    } else if oidstr == "2.5.4.9" {
        return "street".to_string();
    } else if oidstr == "2.5.4.11" {
        return "ou".to_string();
    } else if oidstr == "2.5.4.10" {
        return "o".to_string();
    } else if oidstr == "2.5.4.12" {
        return "title".to_string();
    } else if oidstr == "2.5.4.46" {
        return "dnQualifier".to_string();
    } else if oidstr == "2.5.4.6" {
        return "c".to_string();
    } else if oidstr == "2.5.4.5" {
        return "serialNumber".to_string();
    } else if oidstr == "2.5.4.65" {
        return "pseudonym".to_string();
    } else if oidstr == "0.9.2342.19200300.100.1.25" {
        return "dc".to_string();
    } else if oidstr == "1.2.840.113549.1.9.1" {
        return "emailAddress".to_string();
    }

    oid.to_string()
}

fn atav_to_str(atav: &AttributeTypeAndValue<'_>) -> String {
    // Since character sets are so loosely used, just try the usual suspects
    let s = atav.value.printable_string();
    if let Ok(s) = s {
        return s.to_string();
    }

    let s = atav.value.utf8_string();
    if let Ok(s) = s {
        return s.to_string();
    }

    let s = atav.value.ia5_string();
    if let Ok(s) = s {
        return s.to_string();
    }

    let hex = hex::encode_upper(atav.value.to_vec().unwrap().as_slice());
    let r = str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

fn dn_to_string(name: &Name<'_>) -> String {
    let mut s = vec![];
    for rdn_set in name.iter().rev() {
        let index = s.len();
        for i in 0..rdn_set.len() {
            let atav = rdn_set.get(i).unwrap();
            let attr = oid_lookup(&atav.oid);
            let val = atav_to_str(atav);
            if 0 == i {
                s.push(format!("{}={}", attr, val));
            } else {
                s[index] = format!("{}+{}={}", s[index], attr, val);
            }
        }
    }
    s.join(",")
}

/// Print a success status message (in green if colors are enabled)
#[macro_export]
macro_rules! status_ok {
    ($status:expr, $msg:expr) => {
        $crate::terminal::Status::new()
            .justified()
            .bold()
            .color(termcolor::Color::Green)
            .status($status)
            .print_stdout($msg);
    };
    ($status:expr, $fmt:expr, $($arg:tt)+) => {
        $crate::status_ok!($status, format!($fmt, $($arg)+));
    };
}

/// Print a warning status message (in yellow if colors are enabled)
#[macro_export]
macro_rules! status_warn {
    ($msg:expr) => {
        $crate::terminal::Status::new()
            .bold()
            .color(termcolor::Color::Yellow)
            .status("warning:")
            .print_stdout($msg);
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::status_warn!(format!($fmt, $($arg)+));
    };
}

/// Print an error message (in red if colors are enabled)
#[macro_export]
macro_rules! status_err {
    ($msg:expr) => {
        $crate::terminal::Status::new()
            .bold()
            .color(termcolor::Color::Red)
            .status("error:")
            .print_stderr($msg);
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::status_err!(format!($fmt, $($arg)+));
    };
}

lazy_static! {
    /// Color configuration
    static ref COLOR_CHOICE: Mutex<Option<ColorChoice>> = Mutex::new(None);

    /// Standard output
    pub static ref STDOUT: StandardStream = StandardStream::stdout(get_color_choice());

    /// Standard error
    pub static ref STDERR: StandardStream = StandardStream::stderr(get_color_choice());
}

/// Obtain the color configuration.
///
/// Panics if no configuration has been provided.
fn get_color_choice() -> ColorChoice {
    let choice = COLOR_CHOICE.lock().unwrap();
    *choice
        .as_ref()
        .expect("terminal stream accessed before initialized!")
}

/// Set the color configuration.
///
/// Panics if the terminal has already been configured.
pub(super) fn set_color_choice(color_choice: ColorChoice) {
    let mut choice = COLOR_CHOICE.lock().unwrap();
    assert!(choice.is_none(), "terminal colors already configured!");
    *choice = Some(color_choice);
}

/// Status message builder
#[derive(Clone, Debug, Default)]
pub struct Status {
    /// Should the status be justified?
    justified: bool,

    /// Should colors be bold?
    bold: bool,

    /// Color in which status should be displayed
    color: Option<Color>,

    /// Prefix of the status message (e.g. `Success`)
    status: Option<String>,
}

impl Status {
    /// Create a new status message with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Justify status on display
    pub fn justified(mut self) -> Self {
        self.justified = true;
        self
    }

    /// Make colors bold
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Set the colors used to display this message
    pub fn color(mut self, c: Color) -> Self {
        self.color = Some(c);
        self
    }

    /// Set a status message to display
    pub fn status<S>(mut self, msg: S) -> Self
    where
        S: ToString,
    {
        self.status = Some(msg.to_string());
        self
    }

    /// Print the given message to stdout
    pub fn print_stdout(self, msg: impl AsRef<str>) {
        self.print(&*STDOUT, msg)
            .expect("error printing to stdout!")
    }

    /// Print the given message to stderr
    pub fn print_stderr(self, msg: impl AsRef<str>) {
        self.print(&*STDERR, msg)
            .expect("error printing to stderr!")
    }

    /// Print the given message
    fn print(self, stream: &StandardStream, msg: impl AsRef<str>) -> io::Result<()> {
        let mut s = stream.lock();
        s.reset()?;
        s.set_color(ColorSpec::new().set_fg(self.color).set_bold(self.bold))?;

        if let Some(status) = self.status {
            if self.justified {
                write!(s, "{:>12}", status)?;
            } else {
                write!(s, "{}", status)?;
            }
        }

        s.reset()?;
        writeln!(s, " {}", msg.as_ref())?;
        s.flush()?;

        Ok(())
    }
}

/// Write information about certificate found in slot a la yubico-piv-tool output.
pub fn print_cert_info(
    yubikey: &mut YubiKey,
    slot: SlotId,
    stream: &mut StandardStreamLock<'_>,
) -> io::Result<()> {
    let buf = match read(yubikey, slot) {
        Ok(c) => c,
        Err(e) => {
            debug!("error reading certificate in slot {:?}: {}", slot, e);
            return Ok(());
        }
    };

    if !buf.is_empty() {
        let fingerprint = Sha256::digest(&buf);
        let slot_id: u8 = slot.into();
        print_cert_attr(stream, "Slot", format!("{:x}", slot_id))?;
        let cert = Certificate::from_der(buf.as_slice());
        match cert {
            Ok(cert) => {
                print_cert_attr(
                    stream,
                    "Algorithm",
                    cert.tbs_certificate.subject_public_key_info.algorithm.oid,
                )?;

                print_cert_attr(
                    stream,
                    "Subject",
                    dn_to_string(&cert.tbs_certificate.subject),
                )?;
                print_cert_attr(stream, "Issuer", dn_to_string(&cert.tbs_certificate.issuer))?;
                print_cert_attr(
                    stream,
                    "Fingerprint",
                    str::from_utf8(hex::encode(fingerprint).as_slice()).unwrap(),
                )?;
                print_cert_attr(
                    stream,
                    "Not Before",
                    cert.tbs_certificate.validity.not_before.to_string(),
                )?;
                print_cert_attr(
                    stream,
                    "Not After",
                    cert.tbs_certificate.validity.not_after.to_string(),
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
) -> io::Result<()> {
    stream.set_color(ColorSpec::new().set_bold(true))?;
    write!(stream, "{:>12}:", name)?;
    stream.reset()?;
    writeln!(stream, " {}", value.to_string())?;
    stream.flush()?;
    Ok(())
}
