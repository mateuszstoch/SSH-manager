use clap::{Parser, Subcommand};

/// SSH Manager – manage saved SSH connections from the terminal.
#[derive(Parser)]
#[command(
    name = "sm",
    version,
    about = "CLI SSH connection manager with optional encryption",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List all saved connections with live reachability status.
    #[command(alias = "l")]
    List,

    /// Connect to a saved host (interactive picker if name is omitted).
    #[command(alias = "c")]
    Connect {
        /// Connection name or UUID prefix to connect to directly.
        name: Option<String>,
    },

    /// Add a new SSH connection.
    #[command(alias = "a")]
    Add {
        /// Friendly label for this connection.
        #[arg(long, short)]
        name: String,

        /// Remote hostname or IP address.
        #[arg(long, short)]
        host: String,

        /// SSH username.
        #[arg(long, short)]
        user: String,

        /// Remote port (defaults to 22).
        #[arg(long, default_value_t = 22)]
        port: u16,

        /// Prompt for an SSH password and store it (encrypted if auth is enabled).
        #[arg(long,short)]
        password: bool,
    },

    /// Remove a connection by name or UUID prefix.
    #[command(alias = "r")]
    Remove {
        /// Name or UUID prefix of the connection to delete.
        name: String,
    },

    /// Manage application settings.
    #[command(alias = "cg")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Set or change the master password (enables encryption).
    SetMasterPassword,

    /// Disable master-password protection (and encryption).
    DisableAuth,

    /// Show current application settings.
    Show,
}
