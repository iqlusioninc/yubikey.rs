//! Check if connected YubiKey devices are FIPS 140-2 validated
//!
//! This example demonstrates how to use the FIPS detection API to identify
//! FIPS-validated YubiKeys. This is useful for government and enterprise
//! environments that require FIPS 140-2 Level 2 validated cryptographic modules.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example check-fips --features untested
//! ```
//!
//! # Requirements
//!
//! - One or more YubiKeys connected via USB
//! - Firmware 5.4.2+ for FIPS detection (earlier versions will show as non-FIPS)
//!
//! # Output
//!
//! For each connected YubiKey, displays:
//! - Reader name
//! - Serial number
//! - Firmware version
//! - FIPS validation status (Yes/No)

use yubikey::reader::Context;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging if RUST_LOG is set
    env_logger::init();

    println!("YubiKey FIPS 140-2 Detection Tool");
    println!("==================================\n");

    // Open the PC/SC context and enumerate readers
    let mut readers = Context::open()?;
    let mut found_yubikeys = 0;

    for reader in readers.iter()? {
        let reader_name = reader.name();

        // Try to open this reader
        match reader.open() {
            Ok(mut yubikey) => {
                found_yubikeys += 1;

                println!("YubiKey #{}", found_yubikeys);
                println!("  Reader:  {}", reader_name);
                println!("  Serial:  {}", yubikey.serial());
                println!("  Version: {}", yubikey.version());

                // Check FIPS status
                match yubikey.is_fips() {
                    Ok(true) => {
                        println!("  FIPS:    ✅ Yes (FIPS 140-2 Level 2 Validated)");
                    }
                    Ok(false) => {
                        let version = yubikey.version();

                        // Firmware < 5.7 cannot report FIPS-approved status
                        if version.major == 5 && version.minor < 7 {
                            println!(
                                "  FIPS:    ⚠️  Cannot determine (Firmware {} limitation)",
                                version
                            );
                            println!(
                                "           ℹ️  Firmware < 5.7 cannot report FIPS-approved status"
                            );
                            println!("           ℹ️  Use is_fips_capable() to detect FIPS-capable hardware");
                            println!(
                                "           ℹ️  Verify activation manually by checking credentials"
                            );
                        } else {
                            println!("  FIPS:    ❌ No (Not FIPS-validated)");
                        }
                    }
                    Err(e) => {
                        println!("  FIPS:    ⚠️  Unable to determine: {}", e);
                        println!("           This may indicate a communication error or unsupported device");
                    }
                }

                println!();

                // Disconnect cleanly
                let _ = yubikey.disconnect(pcsc::Disposition::LeaveCard);
            }
            Err(e) => {
                // Reader exists but couldn't open (might be in use, or not a YubiKey)
                eprintln!("⚠️  Could not open reader '{}': {}", reader_name, e);
                println!();
            }
        }
    }

    if found_yubikeys == 0 {
        println!("❌ No YubiKeys detected.");
        println!();
        println!("Troubleshooting:");
        println!("  • Ensure a YubiKey is connected via USB");
        println!("  • Check that pcscd service is running (Linux/macOS)");
        println!("  • Try unplugging and reconnecting the YubiKey");
        println!("  • On Linux, you may need to install libpcsclite");
        return Ok(());
    }

    println!("Summary");
    println!("=======");
    println!("Found {} YubiKey(s)", found_yubikeys);
    println!();
    println!("About FIPS 140-2 Validation:");
    println!("  FIPS-validated YubiKeys are required for U.S. government");
    println!("  and certain enterprise environments. FIPS validation ensures");
    println!("  the device meets Federal Information Processing Standards");
    println!("  (FIPS) 140-2 Level 2 cryptographic module requirements.");
    println!();
    println!("FIPS Mode Activation:");
    println!("  • FIPS YubiKeys are manufactured with validated hardware");
    println!("  • To operate in FIPS-approved mode, ALL THREE credentials must be changed:");
    println!("    1. Change the PIN from default (123456) - 6-8 chars (8 recommended)");
    println!("    2. Change the PUK from default (12345678) - 6-8 chars (8 recommended)");
    println!("    3. Change the Management Key from default");
    println!("  • Until activated, FIPS hardware reports as non-FIPS");
    println!("  • This ensures the device operates in a FIPS-compliant state");
    println!();
    println!("To activate FIPS mode programmatically:");
    println!("  let mut yubikey = YubiKey::open()?;");
    println!("  yubikey.change_pin(b\"123456\", b\"Ab123!@#\")?;");
    println!("  yubikey.change_puk(b\"12345678\", b\"Cd456$%^\")?;");
    println!("  // Also change management key (see activate-fips example)");
    println!("  // Firmware 5.7+: is_fips()? will return true");
    println!("  // Firmware < 5.7: Cannot detect, verify manually");
    println!();
    println!("How to identify FIPS-capable hardware:");
    println!("  • Product labeling: Look for \"FIPS\" in the model name");
    println!("  • Part number: Ends with -FIPS (e.g., YubiKey 5 NFC FIPS)");
    println!("  • API: Use is_fips_capable() on firmware 5.4.2+");
    println!("  • Standard (non-FIPS) YubiKeys cannot enter FIPS mode");
    println!();
    println!("  Learn more: https://www.yubico.com/products/yubikey-fips/");

    Ok(())
}
