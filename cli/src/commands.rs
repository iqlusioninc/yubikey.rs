//! Commands of the CLI application

pub mod readers;
pub mod status;

use self::{readers::ReadersCmd, status::StatusCmd};
use crate::terminal;
use clap::Parser;
use std::{env, process::exit};
use termcolor::ColorChoice;
use yubikey::{Serial, YubiKey};

/// The `yubikey` CLI utility
#[derive(Debug, Parser)]
pub struct YubiKeyCli {
    /// Serial number of the YubiKey to connect to
    #[clap(short = 's', long = "serial")]
    pub serial: Option<Serial>,

    /// Subcommand to execute.
    #[clap(subcommand)]
    pub command: Commands,
}

impl YubiKeyCli {
    /// Run the underlying command type or print usage info and exit
    pub fn run(&self) {
        // TODO(tarcieri): make this more configurable
        terminal::set_color_choice(ColorChoice::Auto);

        // Only show logs if `RUST_LOG` is set
        if env::var("RUST_LOG").is_ok() {
            env_logger::builder().format_timestamp(None).init();
        }

        self.command.run(self.yubikey_init())
    }

    /// Initialize the YubiKey client driver
    fn yubikey_init(&self) -> YubiKey {
        match self.serial {
            Some(serial) => YubiKey::open_by_serial(serial).unwrap_or_else(|e| {
                status_err!("couldn't open YubiKey (serial #{}): {}", serial, e);
                exit(1);
            }),
            None => YubiKey::open().unwrap_or_else(|e| {
                status_err!("couldn't open default YubiKey: {}", e);
                exit(1);
            }),
        }
    }
}

/// Subcommands of this application
#[derive(Debug, Parser)]
pub enum Commands {
    /// `version` subcommand
    #[clap(about = "display version information")]
    Version(VersionOpts),

    /// `readers` subcommand
    #[clap(about = "list detected readers")]
    Readers(ReadersCmd),

    /// `status` subcommand
    #[clap(about = "show yubikey status")]
    Status(StatusCmd),
}

impl Commands {
    /// Run the given command
    pub fn run(&self, yubikey: YubiKey) {
        match self {
            Commands::Version(version) => version.run(),
            Commands::Readers(list) => list.run(),
            Commands::Status(status) => status.run(yubikey),
        }
    }
}

/// Version options
#[derive(Debug, Parser)]
pub struct VersionOpts {}

impl VersionOpts {
    /// Display version information
    pub fn run(&self) {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    }
}
