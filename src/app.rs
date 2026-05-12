use anyhow::{bail, Result};
use rpassword::read_password;
use std::io::Write;
use std::process::Command;

use crate::cli::ConfigAction;
use crate::connection::{Connection, Password};
use crate::crypto;
use crate::host_check;
use crate::store;
use crate::ui;

// ── list ──────────────────────────────────────────────────────────────────────

/// Loads all connections, checks their reachability concurrently, and prints the table.
pub async fn cmd_list(master_password: Option<&str>) -> Result<()> {
    let _ = master_password; // not needed for listing, but kept for API symmetry
    let conns = store::load_connections()?;
    if conns.is_empty() {
        println!("No connections saved yet. Use `sm add` to add one.");
        return Ok(());
    }

    println!("Checking host reachability...");
    let pairs: Vec<(String, u16)> = conns.iter().map(|c| (c.host.clone(), c.port)).collect();
    let statuses = host_check::check_all(&pairs).await;

    ui::print_connections(&conns, &statuses);
    Ok(())
}

// ── connect ───────────────────────────────────────────────────────────────────

/// Resolves the target connection (either by name/ID or via interactive picker),
/// then launches `ssh` as a child process.
pub async fn cmd_connect(name: Option<String>, master_password: Option<&str>) -> Result<()> {
    let conns = store::load_connections()?;

    let conn = if let Some(ref n) = name {
        store::find_connection(&conns, n)
            .ok_or_else(|| anyhow::anyhow!("No connection named '{n}'"))?
    } else {
        match ui::select_connection(&conns)? {
            Some(c) => c,
            None => return Ok(()), // user pressed Esc
        }
    };

    // Build the ssh command.
    let args: Vec<String> = vec![
        "-p".into(),
        conn.port.to_string(),
        conn.ssh_target(),
    ];

    // If a password is stored and a master password is available, we could pass it via
    // sshpass – but that requires sshpass to be installed.  Instead, we print a hint.
    if let Some(pw) = &conn.password {
        match master_password {
            Some(mp) => {
                let plain = crypto::decrypt(pw, mp)?;
                // Try to use sshpass; fall back gracefully if it's not found.
                let sshpass = Command::new("which")
                    .arg("sshpass")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);

                if sshpass {
                    println!("Using sshpass for password authentication.");
                    let status = Command::new("sshpass")
                        .arg("-p")
                        .arg(&plain)
                        .arg("ssh")
                        .args(&args)
                        .status()?;
                    std::process::exit(status.code().unwrap_or(1));
                } else {
                    println!("sshpass not found - you'll need to enter the password manually.");
                }
            }
            None => println!("No master password - enter the SSH password manually when prompted."),
        }
    }

    println!("Connecting: ssh {}", args.join(" "));
    let status = Command::new("ssh").args(&args).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

// ── add ───────────────────────────────────────────────────────────────────────

/// Adds a new connection profile, optionally prompting for and encrypting a password.
pub fn cmd_add(
    name: String,
    host: String,
    user: String,
    port: u16,
    want_password: bool,
    master_password: Option<&str>,
) -> Result<()> {
    let password = if want_password {
        print!("SSH password for {user}@{host}: ");
        std::io::stdout().flush().ok();
        let plain = read_password()?;

        let pw = match master_password {
            Some(mp) => {
                println!("Encrypting password with AES-256-GCM...");
                crypto::encrypt(&plain, mp)?
            }
            None => {
                eprintln!("No master password set - storing SSH password as plaintext.");
                Password::Plain { value: plain }
            }
        };
        Some(pw)
    } else {
        None
    };

    let conn = Connection::new(name.clone(), host, port, user, password);
    store::add_connection(conn)?;
    println!("Connection '{name}' saved.");
    Ok(())
}

// ── remove ────────────────────────────────────────────────────────────────────

/// Removes a connection by name or UUID prefix.
pub fn cmd_remove(name: &str) -> Result<()> {
    if store::remove_connection(name)? {
        println!("Connection '{name}' removed.");
    } else {
        bail!("No connection named or prefixed '{name}'");
    }
    Ok(())
}

// ── config ────────────────────────────────────────────────────────────────────

/// Handles the `config` subcommand family.
pub fn cmd_config(action: ConfigAction, current_master: Option<&str>) -> Result<()> {
    match action {
        ConfigAction::SetMasterPassword => {
            let mut conns = store::load_connections()?;

            // If there was an old password, re-encrypt everything first.
            if let Some(old_pw) = current_master {
                let new_pw = crate::auth::set_master_password()?;
                crypto::reencrypt_all(&mut conns, old_pw, &new_pw)?;
            } else {
                crate::auth::set_master_password()?;
                // Connections with Plain passwords could be encrypted here, but
                // we leave them as-is – only newly added passwords will be encrypted.
                eprintln!("Existing plaintext passwords will not be encrypted automatically. Remove and re-add them to encrypt.");
            }

            store::save_connections(&conns)?;
        }

        ConfigAction::DisableAuth => {
            // Decrypt all SSH passwords before removing the master key.
            if let Some(mp) = current_master {
                let mut conns = store::load_connections()?;
                crypto::strip_encryption(&mut conns, mp)?;
                store::save_connections(&conns)?;
            }
            crate::auth::disable_auth()?;
        }

        ConfigAction::Show => {
            let cfg = store::load_config()?;
            ui::print_config(&cfg);
        }
    }
    Ok(())
}
