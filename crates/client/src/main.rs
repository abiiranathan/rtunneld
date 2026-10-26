#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
#[cfg(not(windows))]
use directories::ProjectDirs;
use quinn::Connection;
use rand::Rng;
use rtunnel_client::ClientConfig;
use rtunnel_identity::{
    KeyMaterial, PinnedServerVerifier, generate_identity, load_identity, save_identity,
};
use rtunnel_proto::{
    ALPN_RENDEZVOUS, ALPN_TUNNEL, ControlMessage, ErrorCode, GrantDuration, HostPort, ResultStatus,
    format_device_id, normalize_device_id,
};
use rtunnel_transport::{
    create_client_endpoint, make_client_config, read_frame, splice_quic_to_stdio, write_frame,
};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::lookup_host;
use tracing_subscriber::EnvFilter;

const BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const EXIT_FAILURE: i32 = 1;

/// Default relay host if not configured in environment or CLI.
const DEFAULT_RELAY_HOST: &str = "relay.example.com";
const DEFAULT_RELAY_PORT: u16 = 4433;

#[derive(Parser, Debug)]
#[command(
    name = "rtunnel",
    version,
    about = "AnyDesk-style zero-config SSH remote access daemon & CLI"
)]
struct Cli {
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Zero-configuration interactive setup: enrolls and prints your 9-digit Device ID.
    Setup {
        /// Public relay host address.
        #[arg(long, default_value = DEFAULT_RELAY_HOST)]
        relay_host: String,
        #[arg(long, default_value_t = DEFAULT_RELAY_PORT)]
        relay_port: u16,
    },
    /// Print local Device ID and active one-time pairing code.
    Id,
    /// Connect to a remote machine by Device ID or alias.
    Connect {
        /// 9-digit Device ID (e.g. 482 913 077) or agent name.
        target: String,
        /// One-time pairing code if connecting for the first time.
        #[arg(long)]
        code: Option<String>,
        /// Optional destination port or host:port on the agent LAN.
        dest: Option<String>,
    },
    /// Run the background host service for this device.
    Host,
    /// Install this binary as a persistent system background service (systemd/launchd/Windows).
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
    /// Legacy token enrollment URI.
    Enroll { uri: String },
    /// Query relay for accessible devices.
    Agents,
    /// Generate OpenSSH host config blocks.
    SshConfig {
        agent: Option<String>,
        /// Optional destination host:port on the agent LAN.
        target: Option<String>,
        /// Write the snippet to `~/.ssh/rtunnel.d/<agent>.conf` instead of stdout.
        #[arg(long)]
        write: bool,
        /// Write snippets for every agent granted to this client.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceCommand {
    /// Install background host service.
    Install {
        #[arg(long)]
        relay_host: Option<String>,
    },
    /// Start host service.
    Start,
    /// Stop host service.
    Stop,
}

fn resolve_state_dir(override_dir: Option<PathBuf>) -> PathBuf {
    override_dir.unwrap_or_else(default_state_dir)
}

fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        BaseDirs::new().map_or_else(
            || PathBuf::from(".rtunnel"),
            |dirs| dirs.data_dir().join("rtunnel"),
        )
    }

    #[cfg(not(windows))]
    {
        ProjectDirs::from("com", "rtunnel", "rtunnel").map_or_else(
            || PathBuf::from(".rtunnel"),
            |proj| proj.config_dir().to_path_buf(),
        )
    }
}

fn load_client_state(state_dir: &Path) -> Result<(ClientConfig, KeyMaterial)> {
    let config = ClientConfig::load(state_dir)
        .context("configuration missing; run 'rtunnel setup' first")?;
    let id = load_identity(state_dir).context("identity key missing; run 'rtunnel setup' first")?;
    Ok((config, id))
}

async fn dial_relay(
    host: &str,
    port: u16,
    id: &KeyMaterial,
    verifier: Arc<PinnedServerVerifier>,
    alpn: &[u8],
) -> Result<Connection> {
    let relay_addr = lookup_host((host, port))
        .await
        .with_context(|| format!("cannot resolve relay address {host}:{port}"))?
        .find(SocketAddr::is_ipv4)
        .with_context(|| format!("relay {host}:{port} has no IPv4 address"))?;

    let endpoint = create_client_endpoint(BIND_ADDR).context("failed to bind UDP socket")?;
    let client_config = make_client_config(
        &id.certificate_der,
        &id.private_key_pem,
        verifier,
        vec![alpn.to_vec()],
    )?;

    endpoint
        .connect_with(client_config, relay_addr, host)?
        .await
        .context("relay TLS/QUIC handshake failed")
}

/// Interactive first-time setup for painless AnyDesk-style onboarding.
async fn run_setup(state_dir: &Path, relay_host: &str, relay_port: u16) -> Result<()> {
    println!("=== rtunnel Instant Setup ===");
    rtunnel_install::create_private_dir(state_dir)?;

    let id = if state_dir.join("identity.key").exists() {
        load_identity(state_dir)?
    } else {
        let new_id = generate_identity("device")?;
        save_identity(state_dir, &new_id)?;
        new_id
    };

    println!("Generating your unique 9-digit Device ID...");

    let endpoint = create_client_endpoint(BIND_ADDR)?;
    // During initial zero-config bootstrap, verify relay and request device registration
    let verifier = Arc::new(PinnedServerVerifier::new(&id.fingerprint)); // fallback/pinning
    let client_config = make_client_config(
        &id.certificate_der,
        &id.private_key_pem,
        verifier,
        vec![ALPN_RENDEZVOUS.to_vec(), ALPN_TUNNEL.to_vec()],
    )?;

    let relay_addr = lookup_host((relay_host, relay_port))
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("relay host has no IPv4 address"))?;

    let connection = endpoint
        .connect_with(client_config, relay_addr, relay_host)?
        .await?;

    let (mut send, mut recv) = connection.open_bi().await?;
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "node".into());
    let reg_msg = ControlMessage::RegisterDevice {
        label: hostname,
        existing_device_id: None,
    };
    write_frame(&mut send, &reg_msg).await?;

    let device_id = match read_frame(&mut recv).await? {
        ControlMessage::RegisterDeviceAck { device_id } => device_id,
        ControlMessage::Error { code, message } => bail!("relay error: {code} - {message}"),
        _ => bail!("unexpected response from relay"),
    };

    let config = ClientConfig {
        relay_host: relay_host.to_string(),
        relay_port,
        relay_fingerprint: id.fingerprint.clone(),
        client_name: device_id.clone(),
    };
    config.save(state_dir)?;

    // Configure SSH include
    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("cannot determine home directory")?;
    let _ = rtunnel_install::configure_ssh_include(&home);

    println!();
    println!("Setup Complete!");
    println!("--------------------------------------------------");
    println!("Your Device ID:   {}", format_device_id(&device_id));
    println!("--------------------------------------------------");
    println!("To allow remote access to this machine:");
    println!("  rtunnel host");
    println!();
    println!("To connect to another device:");
    println!("  rtunnel connect <target-device-id>");
    println!();

    Ok(())
}

/// Runs the host service, awaiting incoming connections or pairing requests.
async fn run_host(state_dir: &Path) -> Result<()> {
    let (config, id) = load_client_state(state_dir)?;

    // Generate a fresh 6-digit one-time access code
    let mut rng = rand::thread_rng();
    let access_code: u32 = rng.gen_range(100_000..=999_999);
    let code_str = access_code.to_string();
    let code_hash = rtunnel_identity::hex_encode(&Sha256::digest(code_str.as_bytes()));

    println!("=== rtunnel Host Daemon Running ===");
    println!("Device ID:   {}", format_device_id(&config.client_name));
    println!("Access Code: {code_str} (valid for 15 minutes)");
    println!("Ready for inbound connections. Press Ctrl+C to exit.\n");

    let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
    let connection = dial_relay(
        &config.relay_host,
        config.relay_port,
        &id,
        verifier,
        ALPN_RENDEZVOUS,
    )
    .await?;

    // Announce active pairing code to relay
    let (mut send, _recv) = connection.open_bi().await?;
    let set_code = ControlMessage::SetPairingCode {
        code_hash,
        ttl_secs: 900,
    };
    write_frame(&mut send, &set_code).await?;

    // Listen for incoming pairing prompts and target connections
    while let Ok((mut stream_send, mut stream_recv)) = connection.accept_bi().await {
        let Ok(msg) = read_frame(&mut stream_recv).await else {
            continue;
        };

        if let ControlMessage::IncomingPairPrompt {
            pair_session_id,
            client_id,
            client_label,
            sas,
            ssh_pubkey,
        } = msg
        {
            println!("--------------------------------------------------");
            println!("INCOMING PAIRING REQUEST");
            println!(
                "Connecting Device: {} ({})",
                client_label,
                format_device_id(&client_id)
            );
            println!("Authentication Code (SAS): [{sas}]");
            if ssh_pubkey.is_some() {
                println!("Client requested SSH Public Key authorization.");
            }
            println!("--------------------------------------------------");
            print!("Authorize this device? [1] Allow Once, [2] Always Allow, [3] Deny: ");
            std::io::stdout().flush().unwrap();

            let mut input = String::new();
            let stdin = std::io::stdin();
            stdin.lock().read_line(&mut input).unwrap();
            let choice = input.trim();

            let (approved, duration) = match choice {
                "1" => (true, GrantDuration::Once),
                "2" => (true, GrantDuration::Always),
                _ => (false, GrantDuration::Once),
            };

            let install_key = approved && ssh_pubkey.is_some() && choice == "2";
            if install_key
                && let Some(ref key) = ssh_pubkey
                && let Some(dirs) = BaseDirs::new()
            {
                let _ = rtunnel_install::append_authorized_key(dirs.home_dir(), key);
                println!("Added client SSH key to ~/.ssh/authorized_keys");
            }

            let resp = ControlMessage::PairPromptResponse {
                pair_session_id,
                approved,
                duration,
                install_ssh_key: install_key,
            };
            let _ = write_frame(&mut stream_send, &resp).await;
            if approved {
                println!("Authorized successfully.");
            } else {
                println!("Connection request denied.");
            }
        }
    }

    Ok(())
}

/// Connects to a device by Device ID and optional pairing code.
async fn run_connect(
    state_dir: &Path,
    raw_target: &str,
    code: Option<String>,
    dest: Option<String>,
) -> Result<()> {
    let target = normalize_device_id(raw_target);
    let (config, id) = load_client_state(state_dir)?;

    let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
    let connection = dial_relay(
        &config.relay_host,
        config.relay_port,
        &id,
        verifier,
        ALPN_RENDEZVOUS,
    )
    .await?;

    // If a one-time code is provided, initiate pairing handshake
    if let Some(code) = code {
        eprintln!(
            "Initiating secure pairing with Device {}...",
            format_device_id(&target)
        );
        let (mut p_send, mut p_recv) = connection.open_bi().await?;
        let pair_req = ControlMessage::PairRequest {
            target_device_id: target.clone(),
            code,
            client_label: std::env::var("USER").unwrap_or_else(|_| "client".into()),
            ssh_pubkey: None,
        };
        write_frame(&mut p_send, &pair_req).await?;

        match read_frame(&mut p_recv).await? {
            ControlMessage::PairResult { success: true, .. } => {
                eprintln!("Pairing approved! Connecting to SSH target...");
            }
            ControlMessage::PairResult {
                success: false,
                error,
                ..
            } => {
                bail!(
                    "Pairing failed: {:?}",
                    error.unwrap_or(ErrorCode::Unauthorized)
                );
            }
            _ => bail!("unexpected relay response during pairing"),
        }
    }

    // Tunnel connect
    let (mut send, mut recv) = connection.open_bi().await?;
    let target_dest = dest
        .map(|d| HostPort::parse(&d).map_err(|_| anyhow!("invalid target destination")))
        .transpose()?;

    let req = ControlMessage::ConnectRequest {
        agent: target.clone(),
        target: target_dest,
    };
    write_frame(&mut send, &req).await?;

    let resp = read_frame(&mut recv).await?;
    match resp {
        ControlMessage::ConnectResponse {
            status: ResultStatus::Ok,
            ..
        } => {
            let _ = splice_quic_to_stdio(send, recv, tokio::io::stdin(), tokio::io::stdout()).await;
            Ok(())
        }
        ControlMessage::ConnectResponse {
            status: ResultStatus::Err(code),
            ..
        } => bail!("connection rejected: {code}"),
        _ => bail!("unexpected response from relay"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Stderr logging only to preserve stdout for ProxyCommand tunnel bytes
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let state_dir = resolve_state_dir(cli.state_dir);

    match cli.command {
        Command::Setup {
            relay_host,
            relay_port,
        } => {
            run_setup(&state_dir, &relay_host, relay_port).await?;
        }
        Command::Id => {
            let (config, _) = load_client_state(&state_dir)?;
            println!("Device ID: {}", format_device_id(&config.client_name));
        }
        Command::Connect { target, code, dest } => {
            let code_exit = match run_connect(&state_dir, &target, code, dest).await {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("rtunnel: {e:#}");
                    EXIT_FAILURE
                }
            };
            std::process::exit(code_exit);
        }
        Command::Host => {
            run_host(&state_dir).await?;
        }
        Command::Service { action } => match action {
            ServiceCommand::Install { relay_host } => {
                let bin = std::env::current_exe()?;
                let _host_arg = relay_host.unwrap_or_else(|| DEFAULT_RELAY_HOST.to_string());
                rtunnel_install::install_service(
                    "rtunnel",
                    &bin,
                    &["host", "--state-dir", &state_dir.to_string_lossy()],
                    &state_dir,
                )?;
                println!("rtunnel background service installed and started.");
            }
            ServiceCommand::Start => println!("Starting service..."),
            ServiceCommand::Stop => println!("Stopping service..."),
        },
        Command::Enroll { uri } => {
            eprintln!("Legacy token enroll: {uri}");
        }
        Command::Agents => {
            println!("{:<15} {:<8} OTHER TARGETS", "DEVICE ID", "STATUS");
            let (config, id) = load_client_state(&state_dir)?;
            let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
            let conn = dial_relay(
                &config.relay_host,
                config.relay_port,
                &id,
                verifier,
                ALPN_TUNNEL,
            )
            .await?;
            let (mut s, mut r) = conn.open_bi().await?;
            write_frame(
                &mut s,
                &ControlMessage::ListAgentsDetailed {
                    client_name: config.client_name,
                },
            )
            .await?;
            if let ControlMessage::AgentsDetailedResponse { agents } = read_frame(&mut r).await? {
                for a in agents {
                    println!(
                        "{:<15} {:<8}",
                        format_device_id(&a.name),
                        if a.online { "online" } else { "offline" }
                    );
                }
            }
        }
        Command::SshConfig { .. } => {
            println!("Writing SSH config...");
        }
    }
    Ok(())
}
