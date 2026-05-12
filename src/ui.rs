use anyhow::Result;
use inquire::Select;
use tabled::{Table, Tabled};

use crate::connection::Connection;
use crate::host_check::HostStatus;
use crate::store::AppConfig;

// ── Table row definition ──────────────────────────────────────────────────────

/// One row in the connections table rendered by `tabled`.
#[derive(Tabled)]
struct Row {
    #[tabled(rename = "#")]
    index: usize,

    #[tabled(rename = "Name")]
    name: String,

    #[tabled(rename = "User@Host")]
    target: String,

    #[tabled(rename = "Port")]
    port: u16,

    #[tabled(rename = "Password")]
    password: &'static str,

    #[tabled(rename = "Status")]
    status: String,
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/// Prints a formatted table of connections with their live reachability statuses.
pub fn print_connections(connections: &[Connection], statuses: &[HostStatus]) {
    if connections.is_empty() {
        println!("No connections saved yet. Use `sm add` to add one.");
        return;
    }

    let rows: Vec<Row> = connections
        .iter()
        .zip(statuses.iter())
        .enumerate()
        .map(|(i, (c, s))| Row {
            index: i + 1,
            name: c.name.clone(),
            target: c.ssh_target(),
            port: c.port,
            password: if c.password.is_some() { "yes" } else { "-" },
            status: s.label().to_string(),
        })
        .collect();

    println!("{}", Table::new(rows));
}

/// Prints current application settings in a human-readable form.
pub fn print_config(cfg: &AppConfig) {
    println!("Auth enabled : {}", if cfg.auth_enabled { "yes" } else { "no" });
    println!(
        "Encryption   : {}",
        if cfg.auth_enabled {
            "AES-256-GCM (key derived from master password)"
        } else {
            "disabled - passwords stored as plaintext"
        }
    );
    println!("Connections  : ~/.config/ssh-manager/connections.json");
    println!("Config       : ~/.config/ssh-manager/config.toml");
}

// ── Interactive selection ─────────────────────────────────────────────────────

/// Shows an interactive `inquire::Select` picker for the given connections.
/// Returns the chosen connection or `None` if the user pressed Escape.
pub fn select_connection<'a>(connections: &'a [Connection]) -> Result<Option<&'a Connection>> {
    if connections.is_empty() {
        println!("No connections to select from.");
        return Ok(None);
    }

    // Build display labels: "name  (user@host:port)"
    let labels: Vec<String> = connections
        .iter()
        .map(|c| format!("{:20} {}:{}", c.name, c.host, c.port))
        .collect();

    let choice = Select::new("Select a connection:", labels.clone())
        .prompt_skippable()?; // returns None on Esc

    let selected = choice.and_then(|label| {
        labels
            .iter()
            .position(|l| l == &label)
            .map(|i| &connections[i])
    });

    Ok(selected)
}
