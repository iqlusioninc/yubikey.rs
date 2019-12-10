//! `yubikey` command-line utility

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[macro_use]
pub mod terminal;

pub mod commands;
