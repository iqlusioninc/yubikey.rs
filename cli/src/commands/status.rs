//! Print device status

use crate::terminal::STDOUT;
use gumdrop::Options;
use std::io::{self, Write};
use termcolor::{ColorSpec, StandardStreamLock, WriteColor};
use yubikey::{key::*, YubiKey};

use crate::print_cert_info;

// String to use for `None`
const NONE_STR: &str = "<none>";

/// The `status` subcommand
#[derive(Debug, Options)]
pub struct StatusCmd {}

impl StatusCmd {
    /// Run the `status` subcommand
    pub fn run(&self, mut yk: YubiKey) {
        let mut s = STDOUT.lock();
        s.reset().unwrap();

        self.attr(&mut s, "name", yk.name()).unwrap();
        self.attr(&mut s, "version", yk.version()).unwrap();
        self.attr(&mut s, "serial", yk.serial()).unwrap();

        if let Ok(chuid) = yk.chuid() {
            self.attr(&mut s, "CHUID", chuid).unwrap();
        } else {
            self.attr(&mut s, "CHUID", NONE_STR).unwrap();
        }

        if let Ok(chuid) = yk.cccid() {
            self.attr(&mut s, "CCC", chuid).unwrap();
        } else {
            self.attr(&mut s, "CCC", NONE_STR).unwrap();
        }

        self.attr(&mut s, "PIN retries", yk.get_pin_retries().unwrap())
            .unwrap();

        for slot in SLOTS.iter().cloned() {
            print_cert_info(&mut yk, slot, &mut s).unwrap();
        }
    }

    /// Print a status attribute
    fn attr(
        &self,
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
}
