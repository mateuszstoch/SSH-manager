use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::connection::Connection;

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Returns `~/.config/ssh-manager/connections.json`.
pub fn connections_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("Cannot locate user config directory")?;
    Ok(base.join("ssh-manager").join("connections.json"))
}

/// Returns `~/.config/ssh-manager/config.toml`.
pub fn config_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("Cannot locate user config directory")?;
    Ok(base.join("ssh-manager").join("config.toml"))
}

/// Ensures the `~/.config/ssh-manager/` directory exists.
fn ensure_dir(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Cannot create directory {:?}", parent))?;
    }
    Ok(())
}

// ── Connection store ──────────────────────────────────────────────────────────

/// Reads all connections from disk. Returns an empty list when the file is absent.
pub fn load_connections() -> Result<Vec<Connection>> {
    let path = connections_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Cannot read {:?}", path))?;
    let conns: Vec<Connection> = serde_json::from_str(&raw)
        .context("Connections file is malformed")?;
    Ok(conns)
}

/// Persists the full list of connections to disk (atomic-ish write via temp rename isn't
/// needed for a simple CLI tool, but we at least ensure the directory exists).
pub fn save_connections(connections: &[Connection]) -> Result<()> {
    let path = connections_path()?;
    ensure_dir(&path)?;
    let json = serde_json::to_string_pretty(connections)
        .context("Failed to serialise connections")?;
    fs::write(&path, json)
        .with_context(|| format!("Cannot write {:?}", path))?;
    Ok(())
}

/// Appends a new connection and saves.
pub fn add_connection(conn: Connection) -> Result<()> {
    let mut conns = load_connections()?;
    conns.push(conn);
    save_connections(&conns)
}

/// Removes a connection by name or UUID prefix. Returns `true` when something was deleted.
pub fn remove_connection(name_or_id: &str) -> Result<bool> {
    let mut conns = load_connections()?;
    let before = conns.len();
    conns.retain(|c| {
        c.name != name_or_id && !c.id.to_string().starts_with(name_or_id)
    });
    let removed = conns.len() < before;
    if removed {
        save_connections(&conns)?;
    }
    Ok(removed)
}

/// Finds the first connection matching name or UUID prefix.
pub fn find_connection<'a>(conns: &'a [Connection], name_or_id: &str) -> Option<&'a Connection> {
    conns.iter().find(|c| {
        c.name == name_or_id || c.id.to_string().starts_with(name_or_id)
    })
}

// ── Application config ────────────────────────────────────────────────────────

/// Application settings stored in `config.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// When `true`, the app requires a master password at startup.
    pub auth_enabled: bool,

    /// Argon2id hash of the master password (absent when auth is disabled).
    pub password_hash: Option<String>,
}

/// Reads the config file; returns a default config when the file is absent.
pub fn load_config() -> Result<AppConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Cannot read {:?}", path))?;
    let cfg: AppConfig = toml::from_str(&raw)
        .context("Config file is malformed")?;
    Ok(cfg)
}

/// Writes the application config to disk.
pub fn save_config(cfg: &AppConfig) -> Result<()> {
    let path = config_path()?;
    ensure_dir(&path)?;
    let toml_str = toml::to_string_pretty(cfg)
        .context("Failed to serialise config")?;
    fs::write(&path, toml_str)
        .with_context(|| format!("Cannot write {:?}", path))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Connection;

    fn conn(name: &str) -> Connection {
        Connection::new(name.into(), "host".into(), 22, "user".into(), None)
    }

    // ── find_connection ───────────────────────────────────────────────────────

    #[test]
    fn find_by_name_returns_correct_entry() {
        let conns = vec![conn("prod"), conn("staging")];
        let found = find_connection(&conns, "prod").unwrap();
        assert_eq!(found.name, "prod");
    }

    #[test]
    fn find_missing_name_returns_none() {
        let conns = vec![conn("prod")];
        assert!(find_connection(&conns, "dev").is_none());
    }

    #[test]
    fn find_by_uuid_prefix() {
        let c = conn("test");
        let prefix = c.id.to_string()[..8].to_string();
        let conns = vec![c];
        assert!(find_connection(&conns, &prefix).is_some());
    }

    // ── AppConfig ─────────────────────────────────────────────────────────────

    #[test]
    fn default_config_is_auth_disabled() {
        let cfg = AppConfig::default();
        assert!(!cfg.auth_enabled);
        assert!(cfg.password_hash.is_none());
    }

    // ── JSON serialization ────────────────────────────────────────────────────

    #[test]
    fn connection_serializes_and_deserializes() {
        let original = conn("roundtrip");
        let json = serde_json::to_string(&original).unwrap();
        let restored: Connection = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, original.name);
        assert_eq!(restored.id, original.id);
        assert_eq!(restored.host, original.host);
    }
}

