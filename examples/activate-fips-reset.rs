//! Activate FIPS mode by resetting PIV and initializing with new credentials
//!
//! This example demonstrates the proper FIPS initialization sequence:
//! 1. Block PIN and PUK (required for reset)
//! 2. Reset the PIV application
//! 3. Set new PIN, PUK, and Management Key
//! 4. Verify FIPS mode is active
//!
//! # ⚠️⚠️⚠️ SECURITY WARNING ⚠️⚠️⚠️
//!
//! This example contains HARDCODED TEST CREDENTIALS that are publicly visible in this
//! repository. These values are for demonstration purposes ONLY.
//!
//! **NEVER use these credentials in production!**
//!
//! # ⚠️ DESTRUCTIVE OPERATION ⚠️
//!
//! This will RESET your YubiKey's PIV application, deleting all keys and certificates!
//! This is a destructive operation. Make sure you have backups.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example activate-fips-reset --features untested
//! ```
//!
//! # FIPS Requirements
//!
//! - PIN must be 6-8 characters (8 recommended for FIPS compliance)
//! - PUK must be 6-8 characters (8 recommended for FIPS compliance)
//! - Management Key must be changed from default (24 bytes for 3DES/AES192)

use yubikey::{Error, YubiKey};

fn block_pin(yubikey: &mut YubiKey) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Blocking PIN (required for reset)...");

    let wrong_pin = b"000000";
    let mut attempts = 0;

    loop {
        match yubikey.verify_pin(wrong_pin) {
            Err(Error::WrongPin { tries }) => {
                attempts += 1;
                println!("    Attempt {}: {} tries remaining", attempts, tries);
                if tries == 0 {
                    println!("  ✅ PIN is now blocked");
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!("  ❌ Unexpected error: {}", e);
                return Err(e.into());
            }
            Ok(()) => {
                eprintln!("  ⚠️  Wrong PIN succeeded unexpectedly!");
                return Err("PIN verification should have failed".into());
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("YubiKey FIPS Mode Activation (via PIV Reset)");
    println!("=============================================\n");

    println!("⚠️  WARNING: This will RESET your YubiKey's PIV application!");
    println!("   All PIV keys and certificates will be DELETED.");
    println!();

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
        println!("   No reset needed.");
        return Ok(());
    }

    println!("To activate FIPS mode, we will:");
    println!("  1. Block the PIN");
    println!("  2. Block the PUK");
    println!("  3. Reset the PIV application");
    println!("  4. Set new PIN (654321)");
    println!("  5. Set new PUK (87654321)");
    println!();

    // For safety, let's ask for confirmation
    println!("Type 'RESET' to continue, or Ctrl+C to cancel:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if input.trim() != "RESET" {
        println!("Cancelled.");
        return Ok(());
    }

    println!();
    println!("Step 1: Blocking PIN...");
    block_pin(&mut yubikey)?;

    println!("Step 2: Blocking PUK...");
    yubikey.block_puk()?;
    println!("  ✅ PUK is now blocked");

    println!("Step 3: Resetting PIV application...");
    yubikey.reset_device()?;
    println!("  ✅ PIV application reset");

    // After reset, PIV is back to defaults
    // FIPS mode requires changing PIN, PUK, AND management key from defaults
    // FIPS REQUIREMENTS:
    //   - PIN must be 6-8 characters (8 recommended for FIPS compliance)
    //   - PUK must be 6-8 characters (8 recommended for FIPS compliance)
    let default_pin = b"123456";
    let new_pin = b"Ab123!@#";
    let new_puk = b"Cd456$%^";

    println!("Step 4: Setting new PIN...");
    yubikey.change_pin(default_pin, new_pin)?;
    println!("  ✅ New PIN set: Ab123!@#");

    println!("Step 5: Setting new PUK...");
    let default_puk = b"12345678";
    yubikey.change_puk(default_puk, new_puk)?;
    println!("  ✅ New PUK set: Cd456$%^");

    println!("Step 6: Setting new Management Key...");
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

    yubikey.authenticate(&default_mgm)?;
    new_mgm.set_manual(&mut yubikey, false)?;
    println!("  ✅ New Management Key set");

    println!();
    println!("Verifying FIPS mode activation...");
    let is_fips_now = yubikey.is_fips()?;
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
        println!();
        println!("IMPORTANT: Remember your new credentials:");
        println!("  New PIN: 5h2!9k");
        println!("  New PUK: 9P!x4Q@2");
        println!("  New MGM: [09 08 07 06 05 04 03 02 ...] (24 bytes)");
        println!();
        println!("⚠️  These are TEST VALUES. For production:");
        println!("   • Use secure, complex PIN and PUK values");
        println!("   • Avoid sequential patterns (123456, 654321)");
        println!("   • Store management key in secure key storage");
        println!("   • Never share them or commit them to version control");
    } else {
        println!("❌ FIPS mode activation failed!");
        println!("   This may indicate:");
        println!("   • The YubiKey is not FIPS-capable hardware");
        println!("   • Firmware version < 5.7");
        println!("   • Not all credentials (PIN, PUK, MGM) were changed");
        println!("   • An error occurred during activation");
    }

    Ok(())
}
