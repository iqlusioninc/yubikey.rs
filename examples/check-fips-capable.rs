//! Check both FIPS-capable and FIPS-approved status
//!
//! Demonstrates the difference between:
//! - FIPS-capable: Hardware is FIPS 140-2 validated
//! - FIPS-approved: Application is currently in FIPS-approved mode
//!
//! # Usage
//!
//! ```bash
//! cargo run --example check-fips-capable --features untested
//! ```

use yubikey::YubiKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("YubiKey FIPS Status Check");
    println!("==========================\n");

    let mut yubikey = YubiKey::open()?;

    println!("Connected to YubiKey:");
    println!("  Serial:  {}", yubikey.serial());
    println!("  Version: {}", yubikey.version());
    println!();

    // Check if hardware is FIPS-capable
    let is_capable = yubikey.is_fips_capable()?;
    println!(
        "FIPS-capable (hardware): {}",
        if is_capable { "✅ Yes" } else { "❌ No" }
    );

    // Check if PIV is in FIPS-approved mode
    let is_approved = yubikey.is_fips()?;
    println!(
        "FIPS-approved (PIV mode): {}",
        if is_approved { "✅ Yes" } else { "❌ No" }
    );

    println!();

    if is_capable && !is_approved {
        println!("ℹ️  This is FIPS-capable hardware, but PIV is not in FIPS-approved mode.");
        println!("   To activate FIPS-approved mode:");
        println!("   1. Change PIN from default (123456)");
        println!("   2. Change PUK from default (12345678)");
        println!("   3. Change MGM key from default");
    } else if !is_capable {
        println!("ℹ️  This is not FIPS-capable hardware.");
        println!("   FIPS validation requires specific YubiKey FIPS models.");
    } else if is_capable && is_approved {
        println!("✅ This YubiKey is FIPS-capable and PIV is in FIPS-approved mode!");
    }

    Ok(())
}
