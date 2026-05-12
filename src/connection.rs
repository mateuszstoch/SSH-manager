use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored SSH connection profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Unique identifier – used for stable references across renames.
    pub id: Uuid,

    /// Human-readable label chosen by the user.
    pub name: String,

    /// Remote hostname or IP address.
    pub host: String,

    /// SSH port (usually 22).
    pub port: u16,

    /// SSH login username.
    pub user: String,

    /// Optional stored password (encrypted or plaintext depending on config).
    pub password: Option<Password>,

    /// When this connection was first saved.
    pub created_at: DateTime<Utc>,
}

impl Connection {
    /// Build a new connection with a freshly generated UUID and current timestamp.
    pub fn new(name: String, host: String, port: u16, user: String, password: Option<Password>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            host,
            port,
            user,
            password,
            created_at: Utc::now(),
        }
    }

    /// Returns `user@host` – the standard SSH target notation.
    pub fn ssh_target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }
}

/// Password storage variant – either encrypted (ciphertext + metadata) or plain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Password {
    /// AES-256-GCM ciphertext with the nonce and PBKDF2 salt encoded as hex.
    Encrypted {
        ciphertext: String, // hex-encoded
        nonce: String,      // hex-encoded, 96-bit
        salt: String,       // hex-encoded, 128-bit
    },
    /// Stored as-is when no master password is set (a warning is shown to the user).
    Plain { value: String },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make(name: &str, host: &str, port: u16, user: &str) -> Connection {
        Connection::new(name.into(), host.into(), port, user.into(), None)
    }

    #[test]
    fn ssh_target_format() {
        let c = make("prod", "10.0.0.1", 22, "admin");
        assert_eq!(c.ssh_target(), "admin@10.0.0.1");
    }

    #[test]
    fn custom_port_stored_correctly() {
        let c = make("staging", "host", 2222, "deploy");
        assert_eq!(c.port, 2222);
    }

    #[test]
    fn no_password_by_default() {
        let c = make("test", "host", 22, "user");
        assert!(c.password.is_none());
    }

    #[test]
    fn unique_uuids() {
        // Two independently created connections must never share a UUID.
        let a = make("a", "host", 22, "user");
        let b = make("b", "host", 22, "user");
        assert_ne!(a.id, b.id);
    }
}
