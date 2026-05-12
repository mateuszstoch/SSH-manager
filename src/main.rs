mod app;
mod auth;
mod cli;
mod connection;
mod crypto;
mod host_check;
mod store;
mod ui;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config once to decide whether authentication is required.
    let cfg = store::load_config()?;

    // Verify master password at startup when auth is enabled.
    // The raw password is kept in memory so it can be used as the AES key source.
    let master_password: Option<String> = if cfg.auth_enabled {
        match auth::verify_master_password() {
            Ok(pw) => Some(pw),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let mp = master_password.as_deref();

    match cli.command {
        Command::List => app::cmd_list(mp).await?,

        Command::Connect { name } => app::cmd_connect(name, mp).await?,

        Command::Add { name, host, user, port, password } => {
            app::cmd_add(name, host, user, port, password, mp)?;
        }

        Command::Remove { name } => app::cmd_remove(&name)?,

        Command::Config { action } => app::cmd_config(action, mp)?,
    }

    Ok(())
}
