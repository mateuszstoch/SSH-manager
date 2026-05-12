use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rpassword::read_password;

use crate::store::{load_config, save_config};

// ── Public API ────────────────────────────────────────────────────────────────

/// Prompts for the master password and verifies it against the stored Argon2id hash.
/// Returns the entered password on success so callers can use it as the AES key source.
pub fn verify_master_password() -> Result<String> {
    print!("Master password: ");
    // Flush stdout so the prompt appears before the hidden input starts.
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let password = read_password().context("Failed to read password")?;

    let cfg = load_config()?;
    let hash_str = cfg
        .password_hash
        .as_deref()
        .context("No master password is set but auth is enabled – run `sm config set-master-password`")?;

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| anyhow::anyhow!("Stored hash is malformed: {e}"))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| anyhow::anyhow!("Incorrect master password"))?;

    Ok(password)
}

/// Interactively sets a new master password (prompts twice for confirmation).
/// Returns the new raw password so the caller can re-encrypt stored SSH passwords.
pub fn set_master_password() -> Result<String> {
    let password = prompt_new_password("New master password: ")?;

    let hash = hash_password(&password)?;

    let mut cfg = load_config()?;
    cfg.auth_enabled = true;
    cfg.password_hash = Some(hash);
    save_config(&cfg)?;

    println!("Master password set. Authentication is now enabled.");
    Ok(password)
}

/// Disables authentication – clears the stored hash and the `auth_enabled` flag.
pub fn disable_auth() -> Result<()> {
    let mut cfg = load_config()?;
    cfg.auth_enabled = false;
    cfg.password_hash = None;
    save_config(&cfg)?;
    println!("Warning: master password protection disabled. SSH passwords will be stored as plaintext.");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Hashes `password` with Argon2id using a random salt.
fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Prompts for a new password and asks the user to confirm it.
fn prompt_new_password(prompt: &str) -> Result<String> {
    loop {
        print!("{prompt}");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let pw = read_password().context("Failed to read password")?;

        print!("Confirm password: ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let confirm = read_password().context("Failed to read confirmation")?;

        if pw == confirm {
            return Ok(pw);
        }
        eprintln!("Passwords do not match - try again.");
    }
}
