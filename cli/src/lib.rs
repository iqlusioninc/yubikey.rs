//! `yubikey` command-line utility.
//!
//! The goal of this tool is to provide functionality similar to `yubico-piv-tool`
//! but implemented in pure Rust.
//!
//! It also serves as a demonstration/example of how to use the `yubikey` crate.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[macro_use]
pub mod terminal;
pub mod commands;
