//! Commands of the CLI application

pub mod readers;

use self::readers::ReadersCmd;
use crate::status::{self, STDOUT};
use gumdrop::Options;
use std::{
    env,
    io::{self, Write},
    process::exit,
};
use termcolor::{ColorChoice, ColorSpec, WriteColor};

/// The `yubikey` CLI utility
#[derive(Debug, Options)]
pub struct YubikeyCli {
    /// Obtain help about the current command
    #[options(short = "h", help = "print help message")]
    pub help: bool,

    /// Subcommand to execute.
    #[options(command)]
    pub command: Option<Commands>,
}

impl YubikeyCli {
    /// Run the underlying command type or print usage info and exit
    pub fn run(&self) {
        // TODO(tarcieri): make this more configurable
        status::set_color_choice(ColorChoice::Auto);

        // Only show logs if `RUST_LOG` is set
        if env::var("RUST_LOG").is_ok() {
            env_logger::builder().format_timestamp(None).init();
        }

        match &self.command {
            Some(cmd) => cmd.run(),
            None => Self::print_usage().unwrap(),
        }
    }

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
}

impl Commands {
    /// Run the given command
    pub fn run(&self) {
        match self {
            Commands::Help(help) => help.run(),
            Commands::Version(version) => version.run(),
            Commands::Readers(list) => list.run(),
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
