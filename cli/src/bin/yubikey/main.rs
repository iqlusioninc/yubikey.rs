//! `yubikey` command-line utility

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

use clap::Parser;
use yubikey_cli::commands::YubiKeyCli;

fn main() {
    YubiKeyCli::parse().run()
}
