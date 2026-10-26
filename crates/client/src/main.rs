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
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, TofuServerVerifier, generate_identity,
    is_valid_name, load_identity, save_identity,
};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_RENDEZVOUS, ALPN_TUNNEL, AgentDetail, ControlMessage, ErrorCode,
    GrantDuration, HostPort, ResultStatus, format_device_id, normalize_device_id,
};
use rtunnel_transport::{
    create_client_endpoint, make_client_config, read_frame, splice_quic_to_stdio, write_frame,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
        /// Optional pinned SPKI relay fingerprint. If omitted, Trust On First Use (TOFU) is used.
        #[arg(long)]
        relay_fingerprint: Option<String>,
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

    endpoint
        .connect_with(client_config, relay_addr, host)?
        .await
        .context("relay TLS/QUIC handshake failed")
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
        vec![ALPN_RENDEZVOUS.to_vec(), ALPN_TUNNEL.to_vec()],
    )?;

    let relay_addr = lookup_host((relay_host, relay_port))
        .await
        .with_context(|| format!("cannot resolve relay address {relay_host}:{relay_port}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("relay host {relay_host}:{relay_port} has no IPv4 address"))?;

    let connection = endpoint
        .connect_with(client_config, relay_addr, relay_host)?
        .await
        .context("relay TLS/QUIC handshake failed")?;

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

async fn fetch_agents(state_dir: &Path) -> Result<Vec<AgentDetail>> {
    let (config, id) = load_client_state(state_dir)?;

    let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
    let connection = dial_relay(
        &config.relay_host,
        config.relay_port,
        &id,
        verifier,
        ALPN_TUNNEL,
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
            ServiceCommand::Install { relay_host: _ } => {
                let bin = std::env::current_exe()?;
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
            println!("{:<15} {:<8}", "DEVICE ID", "STATUS");
            let agents = fetch_agents(&state_dir).await?;
            for a in agents {
                println!(
                    "{:<15} {:<8}",
                    format_device_id(&a.name),
                    if a.online { "online" } else { "offline" }
                );
            }
        }
        Command::SshConfig { .. } => {
            println!("Writing SSH config...");
        }
    }
    Ok(())
}
