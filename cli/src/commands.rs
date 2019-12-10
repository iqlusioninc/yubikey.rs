//! Commands of the CLI application

pub mod readers;
pub mod status;

use self::{readers::ReadersCmd, status::StatusCmd};
use crate::terminal::{self, STDOUT};
use gumdrop::Options;
use std::{
    env,
    io::{self, Write},
    process::exit,
};
use termcolor::{ColorChoice, ColorSpec, WriteColor};
use yubikey_piv::{Serial, YubiKey};

/// The `yubikey` CLI utility
#[derive(Debug, Options)]
pub struct YubiKeyCli {
    /// Obtain help about the current command
    #[options(short = "h", help = "print help message")]
    pub help: bool,

    /// Specify the serial number of the YubiKey to connect to
    #[options(
        short = "s",
        long = "serial",
        help = "serial number of the YubiKey to connect to"
    )]
    pub serial: Option<Serial>,

    /// Subcommand to execute.
    #[options(command)]
    pub command: Option<Commands>,
}

impl YubiKeyCli {
    /// Print usage information
    pub fn print_usage() -> Result<(), io::Error> {
        let mut stdout = STDOUT.lock();
        stdout.reset()?;

        let mut bold = ColorSpec::new();
        bold.set_bold(true);

        stdout.set_color(&bold)?;
        writeln!(
            stdout,
            "{} {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )?;
        stdout.reset()?;

        writeln!(stdout, "{}", env!("CARGO_PKG_AUTHORS"))?;
        writeln!(stdout, "{}", env!("CARGO_PKG_DESCRIPTION").trim())?;
        writeln!(stdout)?;
        writeln!(stdout, "{}", Commands::usage())?;

        Ok(())
    }

    /// Run the underlying command type or print usage info and exit
    pub fn run(&self) {
        // TODO(tarcieri): make this more configurable
        terminal::set_color_choice(ColorChoice::Auto);

        // Only show logs if `RUST_LOG` is set
        if env::var("RUST_LOG").is_ok() {
            env_logger::builder().format_timestamp(None).init();
        }

        match &self.command {
            Some(cmd) => cmd.run(self.yubikey_init()),
            None => Self::print_usage().unwrap(),
        }
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
#[derive(Debug, Options)]
pub enum Commands {
    /// `help` subcommand
    #[options(help = "show help for a command")]
    Help(HelpOpts),

    /// `version` subcommand
    #[options(help = "display version information")]
    Version(VersionOpts),

    /// `readers` subcommand
    #[options(help = "list detected readers")]
    Readers(ReadersCmd),

    /// `status` subcommand
    #[options(help = "show yubikey status")]
    Status(StatusCmd),
}

impl Commands {
    /// Run the given command
    pub fn run(&self, yubikey: YubiKey) {
        match self {
            Commands::Help(help) => help.run(),
            Commands::Version(version) => version.run(),
            Commands::Readers(list) => list.run(),
            Commands::Status(status) => status.run(yubikey),
        }
    }
}

/// Help options
#[derive(Debug, Options)]
pub struct HelpOpts {
    #[options(free, help = "subcommand to get help for")]
    free: Vec<String>,
}

impl HelpOpts {
    fn run(&self) {
        if let Some(command) = self.free.first() {
            if let Some(usage) = Commands::command_usage(command) {
                println!("{}", usage);
                exit(1);
            }
        }

        println!("{}", Commands::usage());
    }
}

/// Version options
#[derive(Debug, Options)]
pub struct VersionOpts {}

impl VersionOpts {
    /// Display version information
    pub fn run(&self) {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    }
}
