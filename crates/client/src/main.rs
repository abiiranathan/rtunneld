#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
#[cfg(not(windows))]
use directories::ProjectDirs;
use quinn::Connection;
use rand::Rng;
use rtunnel_agent::{AgentConfig, AgentRunner};
use rtunnel_client::ClientConfig;
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, TofuServerVerifier, generate_identity,
    hex_encode, is_valid_name, load_identity, save_identity,
};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_RENDEZVOUS, AgentDetail, ControlMessage, ErrorCode, GrantDuration, HostPort,
    ResultStatus, format_device_id, normalize_device_id,
};
use rtunnel_transport::{
    create_client_endpoint, make_client_config, read_frame, splice_quic_to_stdio, write_frame,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
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

/// Lifetime of the host's ephemeral pairing code.
const PAIRING_CODE_TTL_SECS: u32 = 900;

#[derive(Parser, Debug)]
#[command(
    name = "rtunnel",
    version = env!("RTUNNEL_VERSION"),
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
        /// Optional pinned SPKI relay fingerprint. If omitted, Trust On First Use (TOFU) is used.
        #[arg(long)]
        relay_fingerprint: Option<String>,
    },
    /// Print the local Device ID and state directory.
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
    /// Run the background host daemon for this device.
    Host {
        /// Local destination that inbound sessions may dial (defaults to SSH).
        #[arg(long, default_value = "127.0.0.1:22")]
        target: String,
    },
    /// Manage the background system service (systemd/launchd/Windows Service).
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
    /// Install this binary, configure OpenSSH, and optionally enroll.
    Install {
        /// Optional enrollment URI; the client is enrolled after installation.
        uri: Option<String>,
        /// Directory to install into. Defaults to `/usr/local/bin` for root,
        /// `~/.local/bin` for other Unix users, and
        /// `%LOCALAPPDATA%\Programs\rtunnel` on Windows.
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        /// Do not add the rtunnel snippet directory to `~/.ssh/config`.
        #[arg(long)]
        no_ssh_config: bool,
        /// Do not create OpenSSH host entries for granted agents after enrolling.
        #[arg(long)]
        no_ssh_hosts: bool,
        /// Do not add the install directory to the user `PATH` (Windows).
        #[arg(long)]
        no_path: bool,
    },
    /// Enroll this client using a one-time token URI.
    Enroll {
        /// Enrollment URI of the form `rtunnel://<host>:<port>/?fp=<fingerprint>&token=<token>`.
        uri: String,
    },
    /// Query relay for accessible devices.
    Agents,
    /// Generate OpenSSH host config blocks.
    SshConfig {
        agent: Option<String>,
        target: Option<String>,
        #[arg(long)]
        write: bool,
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
        /// Local destination that inbound sessions may dial.
        #[arg(long, default_value = "127.0.0.1:22")]
        target: String,
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
        .context("client configuration missing; run 'rtunnel setup' or 'rtunnel enroll' first")?;
    let id = load_identity(state_dir)
        .context("client identity key missing; run 'rtunnel setup' or 'rtunnel enroll' first")?;
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

    let handshake_context = if alpn == ALPN_RENDEZVOUS {
        "relay TLS/QUIC handshake failed; the relay must support rtunnel-rendezvous/1 \
         (upgrade rtunneld and restart it without deleting its state directory)"
    } else {
        "relay TLS/QUIC handshake failed; verify the relay address and pinned fingerprint"
    };

    endpoint
        .connect_with(client_config, relay_addr, host)?
        .await
        .context(handshake_context)
}

fn default_client_bin_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let dirs = BaseDirs::new().context("cannot determine home directory")?;
        Ok(dirs.data_local_dir().join("Programs").join("rtunnel"))
    }

    #[cfg(not(windows))]
    {
        if rtunnel_install::is_root() {
            return Ok(PathBuf::from(rtunnel_install::DEFAULT_BIN_DIR));
        }
        let dirs = BaseDirs::new().context("cannot determine home directory")?;
        Ok(dirs.home_dir().join(".local").join("bin"))
    }
}

async fn install_client(
    state_dir: &Path,
    uri: Option<&str>,
    bin_dir: Option<PathBuf>,
    no_ssh_config: bool,
    no_ssh_hosts: bool,
    no_path: bool,
) -> Result<()> {
    let bin_dir = match bin_dir {
        Some(dir) => dir,
        None => default_client_bin_dir()?,
    };
    let bin_path = bin_dir.join(rtunnel_install::executable_name("rtunnel"));
    let installed = rtunnel_install::install_self(&bin_path)
        .with_context(|| format!("failed to install {}", bin_path.display()))?;
    println!("Installed rtunnel at {}", installed.display());

    if !no_ssh_config {
        let home = BaseDirs::new()
            .map(|dirs| dirs.home_dir().to_path_buf())
            .context("cannot determine home directory")?;
        let snippets = rtunnel_install::configure_ssh_include(&home)
            .context("failed to configure the OpenSSH include")?;
        println!("OpenSSH snippets directory: {}", snippets.display());
    }

    let installed_dir = installed
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    if !no_path && !rtunnel_install::is_dir_on_path(&installed_dir) {
        #[cfg(windows)]
        match rtunnel_install::add_to_user_path(&installed_dir) {
            Ok(true) => println!(
                "Added {} to your user PATH. Restart your terminal (or sign out) to use 'rtunnel'.",
                installed_dir.display()
            ),
            Ok(false) => println!(
                "{} is already in your user PATH. Restart your terminal (or sign out) to use 'rtunnel'.",
                installed_dir.display()
            ),
            Err(error) => eprintln!(
                "warning: could not update the user PATH ({error}); add {} manually",
                installed_dir.display()
            ),
        }

        #[cfg(not(windows))]
        eprintln!(
            "warning: {} is not on PATH; add it to your shell profile",
            installed_dir.display()
        );
    }

    if let Some(uri) = uri {
        enroll(state_dir, uri).await?;

        if !no_ssh_config && !no_ssh_hosts {
            match write_all_ssh_configs(state_dir).await {
                Ok(hosts) if hosts.is_empty() => println!(
                    "No agent grants found yet; run 'rtunnel ssh-config --all --write' after a grant is added."
                ),
                Ok(hosts) => {
                    println!("Configured SSH hosts for: {}", hosts.join(", "));
                    println!("Connect with: ssh <user>@{}", hosts[0]);
                }
                Err(e) => eprintln!(
                    "warning: could not create SSH host entries yet ({e:#}); run 'rtunnel ssh-config --all --write' after the agent is online"
                ),
            }
        }
    } else {
        println!("Enroll with: rtunnel enroll \"rtunnel://...\" or run 'rtunnel setup'");
    }

    Ok(())
}

async fn enroll(state_dir: &Path, uri: &str) -> Result<()> {
    eprintln!("Parsing enrollment URI...");
    let parsed_uri = EnrollmentUri::parse(uri).context("invalid enrollment URI")?;
    rtunnel_install::create_private_dir(state_dir)
        .with_context(|| format!("cannot create state directory {}", state_dir.display()))?;

    let id = generate_identity("client")?;
    save_identity(state_dir, &id)?;

    let verifier = Arc::new(PinnedServerVerifier::new(&parsed_uri.relay_fingerprint));
    let connection = dial_relay(
        &parsed_uri.host,
        parsed_uri.port,
        &id,
        verifier,
        ALPN_ENROLL,
    )
    .await
    .context("relay connection failed during enrollment")?;

    let (mut send, mut recv) = connection.open_bi().await?;
    let enroll_msg = ControlMessage::Enroll {
        token: parsed_uri.token,
    };
    write_frame(&mut send, &enroll_msg).await?;

    let (name, role) = match read_frame(&mut recv).await? {
        ControlMessage::EnrollAck { name, role } => (name, role),
        ControlMessage::Error { code, message } => {
            bail!("relay rejected enrollment: {code} - {message}");
        }
        _ => bail!("unexpected relay response during enrollment"),
    };

    if role != "client" {
        bail!("token authorized for role '{role}', expected 'client'");
    }

    let config = ClientConfig {
        relay_host: parsed_uri.host,
        relay_port: parsed_uri.port,
        relay_fingerprint: parsed_uri.relay_fingerprint,
        client_name: name,
    };
    config.save(state_dir)?;

    eprintln!("Client enrolled successfully as '{}'.", config.client_name);
    eprintln!("Config written to {}", state_dir.display());
    Ok(())
}

/// .
///
/// # Errors
///
/// This function will return an error if .
async fn run_setup(
    state_dir: &Path,
    relay_host: &str,
    relay_port: u16,
    relay_fingerprint: Option<String>,
) -> Result<()> {
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
    let observed_fp = Arc::new(std::sync::Mutex::new(None));
    let verifier = Arc::new(TofuServerVerifier::new_with_optional(
        relay_fingerprint,
        Arc::clone(&observed_fp),
    ));
    let client_config = make_client_config(
        &id.certificate_der,
        &id.private_key_pem,
        verifier,
        // Setup only speaks the rendezvous protocol. Offering the tunnel ALPN
        // here would let a server that prefers tunnel negotiate it instead,
        // and the unregistered identity would then be rejected.
        vec![ALPN_RENDEZVOUS.to_vec()],
    )?;

    let relay_addr = lookup_host((relay_host, relay_port))
        .await
        .with_context(|| format!("cannot resolve relay address {relay_host}:{relay_port}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("relay host {relay_host}:{relay_port} has no IPv4 address"))?;

    let connection = endpoint
        .connect_with(client_config, relay_addr, relay_host)?
        .await
        .context(
            "relay TLS/QUIC handshake failed; verify --relay-fingerprint and ensure the \
             relay runs an rtunneld build that supports the rtunnel-rendezvous/1 ALPN \
             (upgrade the relay and restart it without deleting its state directory)",
        )?;

    let captured_relay_fp = observed_fp
        .lock()
        .map_err(|_| anyhow!("mutex poisoned"))?
        .clone()
        .ok_or_else(|| anyhow!("failed to capture relay certificate fingerprint"))?;

    let (mut send, mut recv) = connection.open_bi().await?;
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "node".into());
    let reg_msg = ControlMessage::RegisterDevice {
        label: hostname,
        existing_device_id: None,
    };
    write_frame(&mut send, &reg_msg).await?;
    let _ = send.finish();

    let device_id = match read_frame(&mut recv).await? {
        ControlMessage::RegisterDeviceAck { device_id } => device_id,
        ControlMessage::Error { code, message } => bail!("relay error: {code} - {message}"),
        _ => bail!("unexpected response from relay"),
    };

    let config = ClientConfig {
        relay_host: relay_host.to_string(),
        relay_port,
        relay_fingerprint: captured_relay_fp.clone(),
        client_name: device_id.clone(),
    };
    config.save(state_dir)?;

    // Configure SSH include
    if let Some(dirs) = BaseDirs::new() {
        let _ = rtunnel_install::configure_ssh_include(dirs.home_dir());
    }

    println!();
    println!("Setup Complete!");
    println!("--------------------------------------------------");
    println!(
        "Your Device ID:            {}",
        format_device_id(&device_id)
    );
    println!("Pinned Relay Fingerprint:  {captured_relay_fp}");
    println!("State Directory:           {}", state_dir.display());
    println!("--------------------------------------------------");
    println!("To allow remote access to this machine:");
    println!("  rtunnel host");
    println!();
    println!("To connect to another device:");
    println!("  rtunnel connect <target-device-id>");
    println!();

    Ok(())
}

/// Runs the host daemon: one tunnel connection for target sessions and one
/// rendezvous connection for interactive pairing prompts.
async fn run_host(state_dir: &Path, target: &str) -> Result<()> {
    let (mut config, id) = load_client_state(state_dir)?;
    let target = HostPort::parse(target)
        .map_err(|_| anyhow!("invalid host target; expected host:port"))?
        .to_string();

    // Generate a fresh 6-digit one-time access code. The host rotates it after
    // every pairing prompt and on the TTL below, because the relay consumes a
    // code as soon as it verifies one.
    let (mut code_str, mut code_hash) = generate_pairing_code();

    println!("=== rtunnel Host Daemon Running ===");
    println!("Device ID:   {}", format_device_id(&config.client_name));
    println!("Access Code: {code_str} (valid for 15 minutes)");
    println!("Allowed target: {target}");
    println!("Ready for inbound connections. Press Ctrl+C to exit.\n");

    // The tunnel connection serves SSH bytes and advertises the allowlist.
    // AgentRunner owns reconnection, so the host keeps working across restarts.
    let agent_config = AgentConfig {
        relay_host: config.relay_host.clone(),
        relay_port: config.relay_port,
        relay_fingerprint: config.relay_fingerprint.clone(),
        agent_name: config.client_name.clone(),
        allowed_targets: vec![target],
        max_sessions: 64,
    };
    let agent_id = id.clone();
    tokio::spawn(async move {
        if let Err(e) = AgentRunner::new(agent_config, agent_id).run().await {
            eprintln!("rtunnel: host tunnel stopped: {e}");
        }
    });

    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        match run_host_rendezvous(state_dir, &mut config, &id, &mut code_hash, &mut code_str).await
        {
            Ok(()) => eprintln!("rtunnel: relay closed the host rendezvous connection"),
            Err(e) => eprintln!("rtunnel: host rendezvous connection failed: {e:#}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
    }
}

/// Registers this device, publishes the pairing code, and serves pairing
/// prompts until the rendezvous connection closes.
async fn run_host_rendezvous(
    state_dir: &Path,
    config: &mut ClientConfig,
    id: &KeyMaterial,
    code_hash: &mut String,
    code_str: &mut String,
) -> Result<()> {
    let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
    let connection = dial_relay(
        &config.relay_host,
        config.relay_port,
        id,
        verifier,
        ALPN_RENDEZVOUS,
    )
    .await?;

    // Register first: this is what makes the rendezvous connection addressable
    // for pairing prompts. Setup registered the identity earlier, so the relay
    // returns the same Device ID for the existing fingerprint.
    let (mut reg_send, mut reg_recv) = connection.open_bi().await?;
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "node".into());
    let reg_msg = ControlMessage::RegisterDevice {
        label: hostname,
        existing_device_id: Some(config.client_name.clone()),
    };
    write_frame(&mut reg_send, &reg_msg).await?;
    let device_id = match read_frame(&mut reg_recv).await? {
        ControlMessage::RegisterDeviceAck { device_id } => device_id,
        ControlMessage::Error { code, message } => {
            bail!("relay rejected host registration: {code} - {message}");
        }
        _ => bail!("unexpected relay response to host registration"),
    };
    if device_id != config.client_name {
        println!(
            "Relay assigned Device ID {}; updating local configuration.",
            format_device_id(&device_id)
        );
        config.client_name.clone_from(&device_id);
        config.save(state_dir)?;
    }

    // Publish the one-time access code (the relay stores only its hash).
    publish_pairing_code(&connection, code_hash).await?;
    println!("Host online. Access Code: {code_str} (valid for 15 minutes)");

    // Refresh the code before the relay's TTL expires so an idle host always
    // has a usable code to show.
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(u64::from(
        PAIRING_CODE_TTL_SECS,
    )));
    refresh.tick().await;

    // Only pairing prompts are expected on this connection. SSH target streams
    // use the separate tunnel connection owned by AgentRunner.
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                rotate_pairing_code(&connection, code_hash, code_str).await?;
            }
            accepted = connection.accept_bi() => {
                let Ok((stream_send, mut stream_recv)) = accepted else {
                    break;
                };
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
                    if let Err(e) = handle_pair_prompt(
                        stream_send,
                        pair_session_id,
                        &client_id,
                        &client_label,
                        &sas,
                        ssh_pubkey,
                    )
                    .await
                    {
                        eprintln!("rtunnel: failed to answer pairing prompt: {e:#}");
                    }

                    // The relay consumes the code while verifying it, even if
                    // the operator denies the request. Publish a replacement so
                    // the code shown in this terminal never goes stale.
                    rotate_pairing_code(&connection, code_hash, code_str).await?;
                    refresh.reset();
                }
            }
        }
    }

    Ok(())
}

/// Generates a random 6-digit access code and its SHA-256 hash.
fn generate_pairing_code() -> (String, String) {
    let access_code: u32 = rand::thread_rng().gen_range(100_000..=999_999);
    let code = access_code.to_string();
    let hash = hex_encode(&Sha256::digest(code.as_bytes()));
    (code, hash)
}

/// Publishes the current pairing-code hash on the rendezvous connection.
async fn publish_pairing_code(connection: &Connection, code_hash: &str) -> Result<()> {
    let (mut send, _recv) = connection.open_bi().await?;
    let set_code = ControlMessage::SetPairingCode {
        code_hash: code_hash.to_owned(),
        ttl_secs: PAIRING_CODE_TTL_SECS,
    };
    write_frame(&mut send, &set_code).await?;
    Ok(())
}

/// Rotates the local code, publishes it, and prints the new value.
async fn rotate_pairing_code(
    connection: &Connection,
    code_hash: &mut String,
    code_str: &mut String,
) -> Result<()> {
    let (new_code, new_hash) = generate_pairing_code();
    publish_pairing_code(connection, &new_hash).await?;
    *code_hash = new_hash;
    *code_str = new_code;
    println!("New Access Code: {code_str} (valid for 15 minutes)");
    Ok(())
}

/// Prompts the local operator and returns their decision to the relay.
async fn handle_pair_prompt(
    mut stream_send: quinn::SendStream,
    pair_session_id: String,
    client_id: &str,
    client_label: &str,
    sas: &str,
    ssh_pubkey: Option<String>,
) -> Result<()> {
    println!("--------------------------------------------------");
    println!("INCOMING PAIRING REQUEST");
    println!(
        "Connecting Device: {} ({})",
        client_label,
        format_device_id(client_id)
    );
    println!("Authentication Code (SAS): [{sas}]");
    println!("Verify this code matches the one on the connecting device.");
    if ssh_pubkey.is_some() {
        println!("Client requested SSH Public Key authorization.");
    }
    println!("--------------------------------------------------");
    print!("Authorize this device? [1] Allow Once, [2] Always Allow, [3] Deny: ");
    let _ = std::io::stdout().flush();

    let input = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await
    .context("pairing prompt task failed")?
    .context("cannot read pairing decision from stdin")?;
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
    write_frame(&mut stream_send, &resp).await?;
    if approved {
        println!("Authorized successfully.");
    } else {
        println!("Connection request denied.");
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

        // The relay sends the SAS first so both operators can compare it while
        // the host is still deciding, then sends the final PairResult.
        loop {
            match read_frame(&mut p_recv).await? {
                ControlMessage::PairPending { sas, .. } => {
                    eprintln!("--------------------------------------------------");
                    eprintln!("PAIRING REQUEST SENT");
                    eprintln!("Authentication Code (SAS): [{sas}]");
                    eprintln!("Confirm this matches the code shown on the host.");
                    eprintln!("--------------------------------------------------");
                }
                ControlMessage::PairResult { success: true, .. } => {
                    eprintln!("Pairing approved! Connecting to SSH target...");
                    break;
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
                other => bail!("unexpected relay response during pairing: {other:?}"),
            }
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

async fn fetch_agents(state_dir: &Path) -> Result<Vec<AgentDetail>> {
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

    let (mut send, mut recv) = connection.open_bi().await?;
    let req = ControlMessage::ListAgentsDetailed {
        client_name: config.client_name.clone(),
    };
    write_frame(&mut send, &req).await?;

    match read_frame(&mut recv).await? {
        ControlMessage::AgentsDetailedResponse { agents } => Ok(agents),
        ControlMessage::Error { .. } => {
            let (mut send, mut recv) = connection.open_bi().await?;
            let req = ControlMessage::ListAgents {
                client_name: config.client_name,
            };
            write_frame(&mut send, &req).await?;
            match read_frame(&mut recv).await? {
                ControlMessage::ListAgentsResponse { agents } => Ok(agents
                    .into_iter()
                    .map(|a| AgentDetail {
                        name: a.name,
                        online: a.online,
                        targets: Vec::new(),
                    })
                    .collect()),
                other => bail!("unexpected response from relay: {other:?}"),
            }
        }
        other => bail!("unexpected response from relay: {other:?}"),
    }
}

/// Prints every granted device, its online status, and its advertised targets.
async fn list_agents(state_dir: &Path) -> Result<()> {
    let agents = fetch_agents(state_dir).await?;

    println!(
        "{:<24} {:<8} {:<20} OTHER TARGETS",
        "DEVICE ID", "STATUS", "DEFAULT TARGET"
    );
    for a in agents {
        let status = if a.online { "online" } else { "offline" };
        let default = a
            .targets
            .first()
            .map_or_else(|| String::from("-"), Clone::clone);
        let others = if a.targets.len() > 1 {
            a.targets[1..].join(", ")
        } else {
            String::from("-")
        };
        println!(
            "{:<24} {status:<8} {default:<20} {others}",
            format_device_id(&a.name)
        );
    }
    Ok(())
}

/// Looks up a device's advertised targets, warning instead of failing when the
/// relay is unreachable or predates target discovery.
async fn resolve_agent_targets(state_dir: &Path, agent: &str) -> Vec<String> {
    match fetch_agents(state_dir).await {
        Ok(agents) => agents
            .into_iter()
            .find(|a| a.name == agent)
            .map_or_else(Vec::new, |a| a.targets),
        Err(e) => {
            eprintln!(
                "warning: could not discover targets for '{agent}' ({e:#}); using the default target"
            );
            Vec::new()
        }
    }
}

/// Prints OpenSSH host entries for one device, discovering targets when omitted.
async fn print_ssh_config(state_dir: &Path, agent: &str, target: Option<&str>) -> Result<()> {
    if !is_valid_name(agent) {
        bail!("device ID or agent name must match [a-z0-9-]{{1,63}}");
    }

    let hosts = if let Some(dest) = target {
        HostPort::parse(dest)
            .map_err(|_| anyhow!("invalid target host:port specification: {dest}"))?;
        vec![SshHost {
            alias: agent.to_string(),
            agent: agent.to_string(),
            target: Some(dest.to_string()),
        }]
    } else {
        ssh_hosts(agent, &resolve_agent_targets(state_dir, agent).await)
    };

    print!("{}", render_snippets(&hosts));
    Ok(())
}

/// Writes OpenSSH snippets for one device, or for every granted device with `--all`.
async fn write_ssh_config(
    state_dir: &Path,
    agent: Option<&str>,
    target: Option<&str>,
    all: bool,
) -> Result<()> {
    if all && (agent.is_some() || target.is_some()) {
        bail!("--all writes every granted device and cannot be combined with a device or target");
    }

    let planned: Vec<(String, Vec<SshHost>)> = if all {
        fetch_agents(state_dir)
            .await?
            .into_iter()
            .map(|a| (a.name.clone(), ssh_hosts(&a.name, &a.targets)))
            .collect()
    } else {
        let agent = agent.context("a device ID or agent name is required (or use --all)")?;
        if !is_valid_name(agent) {
            bail!("device ID or agent name must match [a-z0-9-]{{1,63}}");
        }

        let hosts = if let Some(dest) = target {
            HostPort::parse(dest)
                .map_err(|_| anyhow!("invalid target host:port specification: {dest}"))?;
            vec![SshHost {
                alias: agent.to_string(),
                agent: agent.to_string(),
                target: Some(dest.to_string()),
            }]
        } else {
            ssh_hosts(agent, &resolve_agent_targets(state_dir, agent).await)
        };
        vec![(agent.to_string(), hosts)]
    };

    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("cannot determine home directory")?;
    let snippets = rtunnel_install::configure_ssh_include(&home)
        .context("failed to configure the OpenSSH include")?;

    if planned.is_empty() {
        println!("No granted devices found; nothing to write.");
        return Ok(());
    }

    for (name, hosts) in planned {
        let path = write_agent_snippet(&snippets, &name, &hosts)?;
        println!("Wrote {}", path.display());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SshHost {
    alias: String,
    agent: String,
    target: Option<String>,
}

fn ssh_config_snippet(host_alias: &str, agent: &str, target: Option<&str>) -> String {
    let target_suffix = target.map_or(String::new(), |dest| format!(" {dest}"));
    format!("Host {host_alias}\n    ProxyCommand rtunnel connect {agent}{target_suffix}\n")
}

fn target_alias(agent: &str, target: &str, used: &mut BTreeSet<String>) -> Option<String> {
    let hp = HostPort::parse(target).ok()?;
    let mut base = hp.host.to_ascii_lowercase();
    if hp.port != 22 {
        base.push('-');
        base.push_str(&hp.port.to_string());
    }

    if base.is_empty()
        || base.len() > 253
        || base == agent
        || base.contains(':')
        || base
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '*' | '?' | '!'))
    {
        return None;
    }

    let mut alias = base.clone();
    if used.contains(&alias) {
        alias = format!("{agent}-{base}");
    }
    let mut suffix = 2_u32;
    while used.contains(&alias) {
        alias = format!("{agent}-{base}-{suffix}");
        suffix += 1;
    }
    used.insert(alias.clone());
    Some(alias)
}

fn ssh_hosts(agent: &str, targets: &[String]) -> Vec<SshHost> {
    let mut used = BTreeSet::from([agent.to_string()]);
    let mut hosts = vec![SshHost {
        alias: agent.to_string(),
        agent: agent.to_string(),
        target: None,
    }];

    for target in targets.iter().skip(1) {
        if let Some(alias) = target_alias(agent, target, &mut used) {
            hosts.push(SshHost {
                alias,
                agent: agent.to_string(),
                target: Some(target.clone()),
            });
        }
    }
    hosts
}

fn render_snippets(hosts: &[SshHost]) -> String {
    hosts
        .iter()
        .map(|host| ssh_config_snippet(&host.alias, &host.agent, host.target.as_deref()))
        .collect()
}

fn write_agent_snippet(snippets: &Path, agent: &str, hosts: &[SshHost]) -> Result<PathBuf> {
    if !is_valid_name(agent) {
        bail!("refusing to write a snippet for invalid agent name '{agent}'");
    }
    let path = snippets.join(format!("{agent}.conf"));
    std::fs::write(&path, render_snippets(hosts))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

async fn write_all_ssh_configs(state_dir: &Path) -> Result<Vec<String>> {
    let agents = fetch_agents(state_dir).await?;
    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("cannot determine home directory")?;
    let snippets = rtunnel_install::configure_ssh_include(&home)
        .context("failed to configure the OpenSSH include")?;

    let mut written = Vec::new();
    for agent in agents {
        if !is_valid_name(&agent.name) {
            continue;
        }
        write_agent_snippet(
            &snippets,
            &agent.name,
            &ssh_hosts(&agent.name, &agent.targets),
        )?;
        written.push(agent.name);
    }
    Ok(written)
}

/// Installs `rtunnel host` as a platform background service.
fn install_host_service(state_dir: &Path, target: &str) -> Result<()> {
    let bin = std::env::current_exe()?;
    let state_dir_arg = state_dir.to_string_lossy().into_owned();
    let target = HostPort::parse(target)
        .map_err(|_| anyhow!("invalid host target; expected host:port"))?
        .to_string();
    rtunnel_install::install_service(
        "rtunnel",
        &bin,
        &["host", "--state-dir", &state_dir_arg, "--target", &target],
        state_dir,
    )?;
    println!("rtunnel background service installed and started.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

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
            relay_fingerprint,
        } => {
            run_setup(&state_dir, &relay_host, relay_port, relay_fingerprint).await?;
        }
        Command::Id => {
            let (config, _) = load_client_state(&state_dir)?;
            println!("Device ID: {}", format_device_id(&config.client_name));
            println!("State directory: {}", state_dir.display());
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
        Command::Host { target } => {
            run_host(&state_dir, &target).await?;
        }
        Command::Service { action } => match action {
            ServiceCommand::Install {
                relay_host: _,
                target,
            } => install_host_service(&state_dir, &target)?,
            ServiceCommand::Start => {
                rtunnel_install::start_service("rtunnel")?;
                println!("rtunnel service started.");
            }
            ServiceCommand::Stop => {
                rtunnel_install::stop_service("rtunnel")?;
                println!("rtunnel service stopped.");
            }
        },
        Command::Install {
            uri,
            bin_dir,
            no_ssh_config,
            no_ssh_hosts,
            no_path,
        } => {
            install_client(
                &state_dir,
                uri.as_deref(),
                bin_dir,
                no_ssh_config,
                no_ssh_hosts,
                no_path,
            )
            .await?;
        }
        Command::Enroll { uri } => {
            enroll(&state_dir, &uri).await?;
        }
        Command::Agents => {
            list_agents(&state_dir).await?;
        }
        Command::SshConfig {
            agent,
            target,
            write,
            all,
        } => {
            if write {
                write_ssh_config(&state_dir, agent.as_deref(), target.as_deref(), all).await?;
            } else {
                if all {
                    bail!("--all is only meaningful together with --write");
                }
                let agent = agent.context("a device ID or agent name is required")?;
                print_ssh_config(&state_dir, &agent, target.as_deref()).await?;
            }
        }
    }
    Ok(())
}
