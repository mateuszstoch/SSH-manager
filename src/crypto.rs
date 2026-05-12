use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::connection::Password;

// PBKDF2 iteration count – high enough to slow brute-force attempts.
const PBKDF2_ITERATIONS: u32 = 200_000;
const KEY_LEN: usize = 32; // AES-256 → 32-byte key
const NONCE_LEN: usize = 12; // AES-GCM standard nonce size
const SALT_LEN: usize = 16; // 128-bit salt

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derives a 256-bit AES key from `password` using PBKDF2-HMAC-SHA256.
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Encrypts `plaintext` with AES-256-GCM using a key derived from `master_password`.
/// Returns a `Password::Encrypted` variant ready to be serialised.
pub fn encrypt(plaintext: &str, master_password: &str) -> Result<Password> {
    // Generate a fresh random salt and nonce for every encryption.
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(master_password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    // aes_gcm::Error does not implement std::error::Error, so we convert manually.
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    Ok(Password::Encrypted {
        ciphertext: hex_encode(&ciphertext),
        nonce: hex_encode(&nonce_bytes),
        salt: hex_encode(&salt),
    })
}

/// Decrypts a `Password::Encrypted` using the provided `master_password`.
pub fn decrypt(password: &Password, master_password: &str) -> Result<String> {
    let (ciphertext_hex, nonce_hex, salt_hex) = match password {
        Password::Encrypted { ciphertext, nonce, salt } => (ciphertext, nonce, salt),
        Password::Plain { value } => return Ok(value.clone()),
    };

    // hex::decode returns Result<_, String>; map_err converts to anyhow.
    let ciphertext = hex_decode(ciphertext_hex).map_err(|e| anyhow::anyhow!("Invalid ciphertext hex: {e}"))?;
    let nonce_bytes = hex_decode(nonce_hex).map_err(|e| anyhow::anyhow!("Invalid nonce hex: {e}"))?;
    let salt = hex_decode(salt_hex).map_err(|e| anyhow::anyhow!("Invalid salt hex: {e}"))?;

    let key_bytes = derive_key(master_password, &salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("Decryption failed - wrong master password?"))?;

    String::from_utf8(plaintext_bytes).context("Decrypted bytes are not valid UTF-8")
}

/// Re-encrypts every `Encrypted` password in `connections` with `new_password`.
/// Used when the master password is changed.
pub fn reencrypt_all(
    connections: &mut [crate::connection::Connection],
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    for conn in connections.iter_mut() {
        if let Some(pw) = &conn.password {
            if matches!(pw, Password::Encrypted { .. }) {
                let plain = decrypt(pw, old_password)?;
                conn.password = Some(encrypt(&plain, new_password)?);
            }
        }
    }
    Ok(())
}

/// Strips encryption (converts `Encrypted` → `Plain`). Used when auth is disabled.
pub fn strip_encryption(
    connections: &mut [crate::connection::Connection],
    master_password: &str,
) -> Result<()> {
    for conn in connections.iter_mut() {
        if let Some(pw) = &conn.password {
            if matches!(pw, Password::Encrypted { .. }) {
                let plain = decrypt(pw, master_password)?;
                conn.password = Some(Password::Plain { value: plain });
            }
        }
    }
    Ok(())
}

// ── Minimal hex helpers ───────────────────────────────────────────────────────
// A tiny implementation to avoid pulling in an extra crate.

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Password;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = "hunter2";
        let master = "correct-horse-battery-staple";
        let encrypted = encrypt(plaintext, master).unwrap();
        let decrypted = decrypt(&encrypted, master).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_master_password_fails() {
        let encrypted = encrypt("secret", "correct").unwrap();
        // A different master password must not decrypt successfully.
        assert!(decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn plain_password_passes_through_decrypt() {
        let pw = Password::Plain { value: "plain-text".into() };
        // decrypt() on a Plain variant must return the value unchanged.
        assert_eq!(decrypt(&pw, "any").unwrap(), "plain-text");
    }

    #[test]
    fn each_encryption_produces_unique_ciphertext() {
        // Independent encryptions of the same plaintext must differ due to random salt/nonce.
        let enc1 = encrypt("same", "master").unwrap();
        let enc2 = encrypt("same", "master").unwrap();
        if let (
            Password::Encrypted { ciphertext: c1, .. },
            Password::Encrypted { ciphertext: c2, .. },
        ) = (enc1, enc2)
        {
            assert_ne!(c1, c2);
        } else {
            panic!("Expected Encrypted variant");
        }
    }
}

