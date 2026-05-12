# sm — SSH Connection Manager

A fast CLI tool for managing SSH connections, written in Rust.
Supports optional master-password protection with AES-256-GCM encrypted password storage.

## Features

- Save and organize SSH connections by name
- Live reachability check (TCP on port 22) when listing connections
- Interactive connection picker
- Optional master password — derives an AES-256-GCM key via PBKDF2 to encrypt stored SSH passwords
- Master password hash stored with Argon2id

## Installation

### Option 1 — Download pre-built binary (recommended)

Download the latest release for your platform from the
[GitHub Releases page](https://github.com/mateuszstoch/SSH-manager/releases/latest).

**Linux / macOS (x86_64)**

```sh
curl -Lo sm https://github.com/mateuszstoch/SSH-manager/releases/latest/download/sm-x86_64-unknown-linux-musl
chmod +x sm
mv sm ~/.local/bin/
```

**macOS (Apple Silicon)**

```sh
curl -Lo sm https://github.com/mateuszstoch/SSH-manager/releases/latest/download/sm-aarch64-apple-darwin
chmod +x sm
mv sm ~/.local/bin/
```

**Windows (PowerShell)**

```powershell
Invoke-WebRequest -Uri https://github.com/mateuszstoch/SSH-manager/releases/latest/download/sm-x86_64-pc-windows-msvc.exe `
                  -OutFile sm.exe
# Move to a directory that is on your PATH, e.g.:
Move-Item sm.exe "$env:USERPROFILE\.local\bin\sm.exe"
```

Verify the binary is on your `PATH`:

```sh
sm --version
```

---

### Option 2 — Build from source

Requires Rust 1.75+ and Cargo.

```sh
git clone https://github.com/mateuszstoch/SSH-manager.git
cd SSH-manager
cargo build --release
cp target/release/sm ~/.local/bin/   # or anywhere on your PATH
```


## Usage

```
sm <COMMAND>

Commands:
  list     (alias: l)   List all saved connections with reachability status
  connect  (alias: c)   Connect to a host (interactive picker if no name given)
  add      (alias: a)   Add a new SSH connection
  remove   (alias: r)   Remove a connection by name or UUID prefix
  config   (alias: cg)  Manage application settings
  help                  Print help
```

### list

```sh
sm list
sm l
```

Checks all saved hosts concurrently (2-second timeout) and prints a table:

```
+---+---------+--------------------+------+----------+--------+
| # | Name    | User@Host          | Port | Password | Status |
+---+---------+--------------------+------+----------+--------+
| 1 | prod    | admin@10.0.0.1     | 22   | yes      | [up]   |
| 2 | staging | deploy@10.0.0.50   | 2222 | -        | [down] |
+---+---------+--------------------+------+----------+--------+
```

### connect

```sh
sm connect           # interactive picker
sm connect prod      # connect by name directly
sm c prod
```

Launches the system `ssh` binary. If `sshpass` is installed and a password is stored,
it is passed automatically.

### add

```sh
sm add --name prod --host 10.0.0.1 --user admin
sm add -n staging -h 10.0.0.50 -u deploy --port 2222
sm add -n prod -h 10.0.0.1 -u admin --password   # prompts for SSH password
```

| Flag              | Short | Description                              |
|-------------------|-------|------------------------------------------|
| `--name <NAME>`   | `-n`  | Friendly label for this connection       |
| `--host <HOST>`   | `-h`  | Remote hostname or IP address            |
| `--user <USER>`   | `-u`  | SSH username                             |
| `--port <PORT>`   |       | Remote port (default: `22`)              |
| `--password`      | `-p`  | Prompt for an SSH password and store it  |

If a master password is active, the SSH password is encrypted with AES-256-GCM.
Otherwise it is stored as plaintext and a warning is printed.

### remove

```sh
sm remove prod
sm r prod
sm remove 3f2a      # UUID prefix works too
```

### config

```sh
sm config show               # print current settings
sm config set-master-password  # set or change the master password
sm config disable-auth         # disable protection (decrypts stored passwords first)
```

## Security model

```
Startup
  |
  +-- auth_enabled?
        |
       YES --> prompt master password --> Argon2id verify
        |                                     |
        |                                   FAIL --> exit 1
        |
       NO  --> proceed without encryption

AES key = PBKDF2-HMAC-SHA256(master_password, random_salt, 200 000 iterations)
Used to encrypt/decrypt stored SSH passwords per connection.
When auth is disabled, passwords are stored as plaintext.
```

Each encrypted password stores its own randomly-generated 128-bit salt and 96-bit nonce,
so every write produces a unique ciphertext even for the same plaintext.

## Data files

| File | Path |
|---|---|
| Connections | `~/.config/ssh-manager/connections.json` |
| Config | `~/.config/ssh-manager/config.toml` |

## Dependencies

| Crate | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `tokio` | Async runtime for concurrent host checks |
| `serde` / `serde_json` / `toml` | Serialization |
| `aes-gcm` | AES-256-GCM encryption |
| `pbkdf2` + `sha2` | Key derivation |
| `argon2` | Master password hashing |
| `uuid` | Unique connection identifiers |
| `chrono` | Timestamps |
| `inquire` | Interactive selection menu |
| `tabled` | Terminal table rendering |
| `rpassword` | Hidden password prompt |
| `dirs` | Home directory resolution |
| `anyhow` / `thiserror` | Error handling |

## Note

`sm` calls the system `ssh` binary — it does not re-implement the SSH protocol.
Password auto-fill via `sshpass` is used only when `sshpass` is found on `PATH`.
