//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

use std::env;
use yubikey_piv::YubiKey;

#[test]
#[ignore]
fn connect() {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let mut yubikey = YubiKey::open(None).unwrap();
    dbg!(&yubikey.version());
    dbg!(&yubikey.serial());
}
