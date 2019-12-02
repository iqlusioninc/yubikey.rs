//! `yubikey` command-line utility

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

use gumdrop::Options;
use yubikey_cli::commands::YubikeyCli;

fn main() {
    YubikeyCli::parse_args_default_or_exit().run();
}
