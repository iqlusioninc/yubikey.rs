//! Activate FIPS mode on a FIPS-capable YubiKey
//!
//! This example demonstrates how to activate FIPS-approved mode on a FIPS YubiKey
//! by changing the PIN, PUK, and Management Key from their default values.
//!
//! # ⚠️⚠️⚠️ SECURITY WARNING ⚠️⚠️⚠️
//!
//! This example contains HARDCODED TEST CREDENTIALS that are publicly visible in this
//! repository. These values are for demonstration purposes ONLY.
//!
//! **NEVER use these credentials in production!**
//!
//! This will change your YubiKey's PIN, PUK, and Management Key! Make sure you remember
//! the new values. Generate secure, random credentials for production use.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example activate-fips --features untested
//! ```
//!
//! # Default Values
//!
//! - Default PIN: 123456
//! - Default PUK: 12345678
//! - Default Management Key: 010203040506070801020304050607080102030405060708
//!
//! # FIPS Requirements
//!
//! - PIN must be 6-8 characters (8 recommended for FIPS compliance)
//! - PUK must be 6-8 characters (8 recommended for FIPS compliance)
//! - Management Key must be changed from default (24 bytes for 3DES/AES192)

use yubikey::YubiKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("YubiKey FIPS Mode Activation Tool");
    println!("===================================\n");

    // Open the YubiKey
    let mut yubikey = YubiKey::open()?;

    println!("Connected to YubiKey:");
    println!("  Serial:  {}", yubikey.serial());
    println!("  Version: {}", yubikey.version());
    println!();

    // Check current FIPS status
    println!("Checking current FIPS status...");
    let was_fips = yubikey.is_fips()?;
    println!(
        "  Current FIPS mode: {}",
        if was_fips { "Active" } else { "Inactive" }
    );
    println!();

    if was_fips {
        println!("✅ FIPS mode is already active!");
        println!("   PIN and PUK have been changed from defaults.");
        return Ok(());
    }

    println!("⚠️  FIPS mode is NOT active.");
    println!("   This YubiKey has default PIN/PUK values.");
    println!();

    println!("To activate FIPS mode, we need to:");
    println!("  1. Change PIN from default (123456)");
    println!("  2. Change PUK from default (12345678)");
    println!();

    // For safety, let's ask for confirmation
    println!("PRESS ENTER to activate FIPS mode, or Ctrl+C to cancel...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Define new credentials (you should use secure values!)
    // FIPS mode requires changing PIN, PUK, AND management key from defaults
    // FIPS REQUIREMENTS:
    //   - PIN must be 6-8 characters (8 recommended for FIPS compliance)
    //   - PUK must be 6-8 characters (8 recommended for FIPS compliance)
    let default_pin = b"123456";
    let new_pin = b"Ab123!@#"; // ⚠️ Use a secure PIN in production!

    let default_puk = b"12345678";
    let new_puk = b"Cd456$%^"; // ⚠️ Use a secure PUK in production!

    // First verify the current PIN to ensure it's correct
    println!("Step 1: Verifying current PIN...");
    match yubikey.verify_pin(default_pin) {
        Ok(()) => println!("✅ PIN verified - defaults are in use"),
        Err(e) => {
            eprintln!("❌ Failed to verify default PIN: {}", e);
            eprintln!("   This suggests the PIN has already been changed.");
            eprintln!("   If FIPS mode should be active but isn't showing,");
            eprintln!("   please ensure both PIN and PUK have been changed.");
            return Err(e.into());
        }
    }

    println!("Step 2: Changing PIN...");
    match yubikey.change_pin(default_pin, new_pin) {
        Ok(()) => println!("✅ PIN changed successfully"),
        Err(e) => {
            eprintln!("❌ Failed to change PIN: {}", e);
            eprintln!("   (PIN may have already been changed)");
            return Err(e.into());
        }
    }

    println!("Step 3: Changing PUK...");
    match yubikey.change_puk(default_puk, new_puk) {
        Ok(()) => println!("✅ PUK changed successfully"),
        Err(e) => {
            eprintln!("❌ Failed to change PUK: {}", e);
            eprintln!("   (PUK may have already been changed)");
            return Err(e.into());
        }
    }

    println!("Step 4: Changing Management Key...");
    // CRITICAL: Management key must also be changed for FIPS-approved mode
    use yubikey::{MgmAlgorithmId, MgmKey};

    // Default management key (same for both 3DES and AES192)
    let default_mgm_bytes: [u8; 24] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];

    // Firmware 5.7+ uses AES192, earlier versions use 3DES
    let alg = if yubikey.version().major >= 5 && yubikey.version().minor >= 7 {
        MgmAlgorithmId::Aes192
    } else {
        MgmAlgorithmId::ThreeDes
    };

    let default_mgm = MgmKey::from_bytes(default_mgm_bytes, Some(alg))?;

    // Hardcoded test management key (24 bytes)
    // ⚠️ Use a secure, randomly generated key in production!
    let new_mgm_bytes: [u8; 24] = [
        9, 8, 7, 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2,
    ];
    let new_mgm = MgmKey::from_bytes(new_mgm_bytes, Some(alg))?;

    match yubikey.authenticate(&default_mgm) {
        Ok(()) => {
            println!("✅ Authenticated with default management key");
            match new_mgm.set_manual(&mut yubikey, false) {
                Ok(()) => println!("✅ Management key changed successfully"),
                Err(e) => {
                    eprintln!("❌ Failed to set new management key: {}", e);
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            eprintln!(
                "❌ Failed to authenticate with default management key: {}",
                e
            );
            eprintln!("   (Management key may have already been changed)");
            return Err(e.into());
        }
    }

    println!();
    println!("Verifying FIPS mode activation...");

    // Note: Firmware 5.4.3 FIPS (the FIPS-certified version) does not have
    // TAG_FIPS_APPROVED, so is_fips() will return false even after successful activation
    let is_fips_now = yubikey.is_fips()?;
    let version = yubikey.version();

    if version.major == 5 && version.minor < 7 {
        // Firmware < 5.7 cannot report FIPS-approved status
        println!("✅ Credentials changed successfully!");
        println!();
        println!(
            "⚠️  Note: Firmware {} cannot report FIPS-approved status.",
            version
        );
        println!("   Your YubiKey should now be in FIPS-approved mode since all");
        println!("   credentials (PIN, PUK, MGM key) have been changed from defaults.");
        println!();
        println!("   To verify FIPS mode on firmware < 5.7:");
        println!("   • Use ykman: ykman info");
        println!("   • Verify credentials are not defaults");
        println!("   • Confirm hardware is FIPS-capable with: is_fips_capable()");
    } else {
        println!(
            "  FIPS mode: {}",
            if is_fips_now {
                "✅ Active"
            } else {
                "❌ Inactive"
            }
        );
        println!();

        if is_fips_now {
            println!("🎉 SUCCESS! FIPS mode is now active!");
        } else {
            println!("❌ FIPS mode activation failed!");
            println!("   This may indicate:");
            println!("   • The YubiKey is not FIPS-capable hardware");
            println!("   • Not all credentials (PIN, PUK, MGM) were changed");
            println!("   • An error occurred during activation");
        }
    }

    println!();
    println!("IMPORTANT: Remember your new credentials:");
    println!("  New PIN: Ab123!@#");
    println!("  New PUK: Cd456$%^");
    println!("  New MGM: [09 08 07 06 05 04 03 02 ...] (24 bytes)");

    println!();
    println!("⚠️  These are TEST VALUES. For production:");
    println!("   • Use secure, complex PIN and PUK values");
    println!("   • Avoid sequential patterns (123456, 654321)");
    println!("   • Store management key in secure key storage");
    println!("   • Never share them or commit them to version control");

    Ok(())
}
