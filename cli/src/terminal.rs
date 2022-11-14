//! Status messages

use log::debug;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    str,
    sync::Mutex,
};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, StandardStreamLock, WriteColor};
use x509_parser::parse_x509_certificate;
use yubikey::{certificate::Certificate, piv::*, YubiKey};

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

/// Color configuration
static COLOR_CHOICE: Lazy<Mutex<Option<ColorChoice>>> = Lazy::new(|| Mutex::new(None));

/// Standard output
pub static STDOUT: Lazy<StandardStream> = Lazy::new(|| StandardStream::stdout(get_color_choice()));

/// Standard error
pub static STDERR: Lazy<StandardStream> = Lazy::new(|| StandardStream::stderr(get_color_choice()));

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
        self.print(&STDOUT, msg).expect("error printing to stdout!")
    }

    /// Print the given message to stderr
    pub fn print_stderr(self, msg: impl AsRef<str>) {
        self.print(&STDERR, msg).expect("error printing to stderr!")
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
        match parse_x509_certificate(&buf) {
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
                    &hex::upper::encode_string(&fingerprint),
                )?;
                print_cert_attr(
                    stream,
                    "Not Before",
                    cert.tbs_certificate
                        .validity
                        .not_before
                        .to_rfc2822()
                        .unwrap(),
                )?;
                print_cert_attr(
                    stream,
                    "Not After",
                    cert.tbs_certificate
                        .validity
                        .not_after
                        .to_rfc2822()
                        .unwrap(),
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
