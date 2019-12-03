//! List detected readers

use gumdrop::Options;
use std::process::exit;
use yubikey_piv::readers::Readers;

/// The `list` subcommand
#[derive(Debug, Options)]
pub struct ListCmd {}

impl ListCmd {
    /// Run the `list` subcommand
    pub fn run(&self) {
        let mut readers = Readers::open().unwrap_or_else(|e| {
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

        for (i, reader) in readers_iter.enumerate() {
            let name = reader.name();
            let mut yubikey = match reader.open() {
                Ok(yk) => yk,
                Err(_) => continue,
            };

            let serial = yubikey.serial();
            println!("{}: {} (serial: {})", i + 1, name, serial);
        }
    }
}
