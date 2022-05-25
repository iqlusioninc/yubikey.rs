//! List detected readers

use crate::terminal::STDOUT;
use clap::Parser;
use std::{
    io::{self, Write},
    process::exit,
};
use termcolor::{ColorSpec, StandardStreamLock, WriteColor};
use yubikey::{Context, Serial};

/// The `readers` subcommand
#[derive(Debug, Parser)]
pub struct ReadersCmd {}

impl ReadersCmd {
    /// Run the `readers` subcommand
    pub fn run(&self) {
        let mut readers = Context::open().unwrap_or_else(|e| {
            status_err!("couldn't open PC/SC context: {}", e);
            exit(1);
        });

        let readers_iter = readers.iter().unwrap_or_else(|e| {
            status_err!("couldn't enumerate PC/SC readers: {}", e);
            exit(1);
        });

        if readers_iter.len() == 0 {
            status_err!("no YubiKeys detected!");
            exit(1);
        }

        let mut s = STDOUT.lock();
        s.reset().unwrap();

        for (i, reader) in readers_iter.enumerate() {
            let name = reader.name();
            let yubikey = match reader.open() {
                Ok(yk) => yk,
                Err(_) => continue,
            };

            let serial = yubikey.serial();
            self.print_reader(&mut s, i + 1, &name, serial).unwrap();
        }
    }

    /// Print a reader
    fn print_reader(
        &self,
        stream: &mut StandardStreamLock<'_>,
        index: usize,
        name: &str,
        serial: Serial,
    ) -> io::Result<()> {
        stream.set_color(ColorSpec::new().set_bold(true))?;
        write!(stream, "{:>3}:", index)?;
        stream.reset()?;
        writeln!(stream, " {} (serial: {})", name, serial)?;
        stream.flush()?;
        Ok(())
    }
}
