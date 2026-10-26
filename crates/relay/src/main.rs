#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, generate_identity, hex_encode, is_valid_name, load_identity,
    save_identity,
};
use rtunnel_relay::{AuditLogger, RelayServer, SqliteStore};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

/// Hardened systemd unit embedded at build time so `install` needs no checkout.
const RELAY_UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/rtunneld.service");

#[derive(Parser, Debug)]
#[command(name = "rtunneld", version, about = "Relay daemon for rtunnel")]
struct Cli {
    #[arg(long, default_value = "text")]
    log_format: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize the relay key material and state directory.
    Init {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Install this binary and a hardened systemd unit.
    Install {
        #[arg(long, default_value = "/usr/local/bin")]
        bin_dir: PathBuf,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
        /// Install the unit without enabling or starting the service.
        #[arg(long)]
        no_start: bool,
    },
    /// Start the relay daemon service.
    Serve {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
    },
    /// Manage single-use enrollment tokens.
    Token {
        #[command(subcommand)]
        action: TokenCommand,
    },
    /// Manage client-to-agent access grants.
    Grant {
        #[command(subcommand)]
        action: GrantCommand,
    },
    /// List all enrolled peers.
    PeersList {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Revoke a peer by name or certificate fingerprint.
    Revoke {
        name: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum TokenCommand {
    /// Create a single-use enrollment token.
    Create {
        #[arg(long)]
        role: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "15m")]
        ttl: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        relay_host: String,
        #[arg(long, default_value_t = 4433)]
        relay_port: u16,
    },
    /// List active unexpired enrollment tokens.
    List {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Revoke an enrollment token by its hash.
    Revoke {
        token: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum GrantCommand {
    /// Authorize a client to connect to an agent.
    Add {
        client: String,
        agent: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Remove authorization for a client to connect to an agent.
    Remove {
        client: String,
        agent: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// List client access grants.
    List {
        client: Option<String>,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
}

fn parse_ttl(ttl: &str) -> Result<u64> {
    if let Some(m) = ttl.strip_suffix('m') {
        let mins = m.parse::<u64>().context("invalid minutes format")?;
        return Ok(mins * 60);
    }
    if let Some(h) = ttl.strip_suffix('h') {
        let hours = h.parse::<u64>().context("invalid hours format")?;
        return Ok(hours * 3600);
    }
    if let Some(s) = ttl.strip_suffix('s') {
        return s.parse::<u64>().context("invalid seconds format");
    }
    ttl.parse::<u64>()
        .context("invalid TTL numeric seconds format")
}

/// Creates the relay identity and SQLite store if they do not exist yet.
fn initialize_state(state_dir: &Path) -> Result<KeyMaterial> {
    rtunnel_install::create_private_dir(state_dir)
        .with_context(|| format!("failed to prepare {}", state_dir.display()))?;
    let id = generate_identity("relay")?;
    save_identity(state_dir, &id)?;
    let _db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
    Ok(id)
}

/// Installs the running relay binary, writes its systemd unit, and starts it.
fn install_relay(
    bin_dir: &Path,
    state_dir: &Path,
    listen: SocketAddr,
    no_start: bool,
) -> Result<()> {
    rtunnel_install::ensure_root()
        .context("installing the relay service requires root; rerun with sudo")?;
    rtunnel_install::validate_unit_path(state_dir)?;

    let bin_dir = std::path::absolute(bin_dir).context("invalid binary directory")?;
    let bin_path = bin_dir.join("rtunneld");
    rtunnel_install::validate_unit_path(&bin_path)?;
    let installed = rtunnel_install::install_self(&bin_path)
        .with_context(|| format!("failed to install {}", bin_path.display()))?;

    rtunnel_install::create_private_dir(state_dir)
        .with_context(|| format!("failed to prepare {}", state_dir.display()))?;

    let identity = if state_dir.join("identity.key").exists() {
        load_identity(state_dir).context("failed to load existing relay identity")?
    } else {
        initialize_state(state_dir)?
    };

    let exec_start = format!(
        "{} serve --state-dir {} --listen {listen}",
        installed.display(),
        state_dir.display()
    );
    let unit = rtunnel_install::render_unit(RELAY_UNIT_TEMPLATE, &exec_start, state_dir);
    let unit_path = rtunnel_install::install_unit("rtunneld.service", &unit)
        .context("failed to install rtunneld.service")?;

    println!("Installed rtunneld at {}", installed.display());
    println!("Systemd unit: {}", unit_path.display());
    println!("Relay fingerprint: {}", identity.fingerprint);

    if no_start {
        println!("Service not started (--no-start).");
        println!(
            "Load and start it later with: systemctl daemon-reload && systemctl enable --now rtunneld.service"
        );
    } else {
        rtunnel_install::enable_service("rtunneld.service", true)
            .context("failed to enable or start rtunneld.service")?;
        println!("rtunneld.service is enabled and running.");
    }

    println!();
    println!("Next steps:");
    println!("  rtunneld token create --role agent --name <agent-name> --relay-host <public-host>");
    println!(
        "  rtunneld token create --role client --name <client-name> --relay-host <public-host>"
    );
    println!("  rtunneld grant add <client-name> <agent-name>");

    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "linear startup wiring; splitting would only scatter the sequence"
)]
#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    if cli.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    match cli.command {
        Command::Init { state_dir } => {
            let id = initialize_state(&state_dir)?;
            println!("Relay initialized.");
            println!("State directory: {}", state_dir.display());
            println!("Relay fingerprint: {}", id.fingerprint);
        }
        Command::Install {
            bin_dir,
            state_dir,
            listen,
            no_start,
        } => {
            install_relay(&bin_dir, &state_dir, listen, no_start)?;
        }
        Command::Serve { state_dir, listen } => {
            let id = load_identity(&state_dir)
                .context("could not load relay identity; run rtunneld init first")?;

            let db = Arc::new(SqliteStore::open(state_dir.join("rtunnel.db"))?);
            let audit = Arc::new(AuditLogger::open(&state_dir)?);

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let server = Arc::new(RelayServer::new(listen, &id, db, audit, shutdown_rx)?);

            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                println!("\nShutdown signal received; draining sessions...");
                let _ = shutdown_tx.send(true);
            });

            server.run().await;
        }
        Command::Token { action } => match action {
            TokenCommand::Create {
                role,
                name,
                ttl,
                state_dir,
                relay_host,
                relay_port,
            } => {
                if role != "agent" && role != "client" {
                    bail!("role must be 'agent' or 'client'");
                }
                if !is_valid_name(&name) {
                    bail!("name must match [a-z0-9-]{{1,63}}");
                }

                let ttl_secs = parse_ttl(&ttl)?;
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let expires_at = (now + ttl_secs).cast_signed();

                let mut token_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut token_bytes);
                let token = hex_encode(&token_bytes);
                let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));

                let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
                db.store_token(&token_hash, &name, &role, expires_at)?;

                let id = load_identity(&state_dir)?;
                let uri = EnrollmentUri {
                    host: relay_host,
                    port: relay_port,
                    relay_fingerprint: id.fingerprint,
                    token: token.clone(),
                };

                println!("Single-use token: {token}");
                println!("Enrollment URI:   {uri}");
            }
            TokenCommand::List { state_dir } => {
                let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
                let tokens = db.list_tokens()?;
                println!("{:<64} {:<10} {:<15} EXPIRES", "TOKEN HASH", "ROLE", "NAME");
                for t in tokens {
                    println!(
                        "{:<64} {:<10} {:<15} {}",
                        t.token_hash, t.role, t.name, t.expires_at
                    );
                }
            }
            TokenCommand::Revoke { token, state_dir } => {
                let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
                let hash = if token.len() == 64 {
                    token
                } else {
                    hex_encode(&Sha256::digest(token.as_bytes()))
                };
                if db.revoke_token(&hash)? {
                    println!("Token revoked.");
                } else {
                    println!("Token not found.");
                }
            }
        },
        Command::Grant { action } => match action {
            GrantCommand::Add {
                client,
                agent,
                state_dir,
            } => {
                let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
                db.add_grant(&client, &agent)?;
                let audit = AuditLogger::open(&state_dir)?;
                audit.log_grant_change("add", &client, &agent);
                println!("Granted '{client}' access to '{agent}'.");
            }
            GrantCommand::Remove {
                client,
                agent,
                state_dir,
            } => {
                let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
                if db.remove_grant(&client, &agent)? {
                    let audit = AuditLogger::open(&state_dir)?;
                    audit.log_grant_change("remove", &client, &agent);
                    println!("Removed access for '{client}' to '{agent}'.");
                } else {
                    println!("Grant not found.");
                }
            }
            GrantCommand::List { client, state_dir } => {
                let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
                let grants = db.list_grants(client.as_deref())?;
                println!("{:<20} -> AGENT", "CLIENT");
                for (c, a) in grants {
                    println!("{c:<20} -> {a}");
                }
            }
        },
        Command::PeersList { state_dir } => {
            let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
            let peers = db.list_peers()?;
            println!("{:<15} {:<8} {:<8} FINGERPRINT", "NAME", "ROLE", "REVOKED");
            for p in peers {
                println!(
                    "{:<15} {:<8} {:<8} {}",
                    p.name, p.role, p.revoked, p.fingerprint
                );
            }
        }
        Command::Revoke { name, state_dir } => {
            let db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
            if db.revoke_peer(&name)? {
                let audit = AuditLogger::open(&state_dir)?;
                audit.log_revoke(&name);
                println!(
                    "Revoked peer '{name}'. Live connections will terminate within 5 seconds."
                );
            } else {
                println!("Peer '{name}' not found.");
            }
        }
    }
    Ok(())
}
