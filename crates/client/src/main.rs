#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use directories::{BaseDirs, ProjectDirs};
use quinn::Connection;
use rtunnel_client::ClientConfig;
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, generate_identity, is_valid_name,
    load_identity, save_identity,
};
use rtunnel_proto::{ALPN_ENROLL, ALPN_TUNNEL, ControlMessage, HostPort, ResultStatus};
use rtunnel_transport::{
    create_client_endpoint, make_client_config, read_frame, splice_quic_to_stdio, write_frame,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::lookup_host;
use tracing_subscriber::EnvFilter;

/// Wildcard IPv4 address with an OS-assigned port for the local QUIC endpoint.
/// A typed constant, so there is no string parsing that could fail at runtime.
const BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Exit code used for every failure of the `connect` subcommand.
const EXIT_FAILURE: i32 = 1;

#[derive(Parser, Debug)]
#[command(name = "rtunnel", version, about = "Client CLI for rtunnel QUIC relay")]
struct Cli {
    /// Override the default configuration and state directory (`~/.config/rtunnel`).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll this client using a one-time token URI.
    Enroll {
        /// Enrollment URI of the form `rtunnel://<host>:<port>/?fp=<fingerprint>&token=<token>`.
        uri: String,
    },
    /// Connect to an agent and bridge stdin/stdout for use as OpenSSH `ProxyCommand`.
    Connect {
        /// Name of the target agent.
        agent: String,
        /// Optional destination host:port on the agent LAN (defaults to agent's first allowed target).
        target: Option<String>,
    },
    /// Query the relay for granted agents and their online status.
    Agents,
    /// Print a ready-to-paste OpenSSH configuration block.
    SshConfig {
        /// Name of the target agent.
        agent: String,
        /// Optional destination host:port on the agent LAN (defaults to port 22).
        target: Option<String>,
        /// Write the snippet to `~/.ssh/rtunnel.d/<agent>.conf` instead of stdout.
        #[arg(long)]
        write: bool,
    },
    /// Install this binary, configure OpenSSH, and optionally enroll.
    Install {
        /// Optional enrollment URI; the client is enrolled after installation.
        uri: Option<String>,
        /// Directory to install into. Defaults to `/usr/local/bin` for root and
        /// `~/.local/bin` for unprivileged users.
        #[arg(long)]
        bin_dir: Option<PathBuf>,
        /// Do not add the rtunnel snippet directory to `~/.ssh/config`.
        #[arg(long)]
        no_ssh_config: bool,
    },
}

fn resolve_state_dir(override_dir: Option<PathBuf>) -> PathBuf {
    override_dir.unwrap_or_else(|| {
        ProjectDirs::from("com", "rtunnel", "rtunnel").map_or_else(
            || PathBuf::from(".rtunnel"),
            |proj| proj.config_dir().to_path_buf(),
        )
    })
}

/// Loads the enrolled client's configuration and identity from `state_dir`.
fn load_client_state(state_dir: &Path) -> Result<(ClientConfig, KeyMaterial)> {
    let config = ClientConfig::load(state_dir)
        .context("client configuration missing; run 'rtunnel enroll <uri>' first")?;
    let id = load_identity(state_dir)
        .context("client identity key missing; run 'rtunnel enroll <uri>' first")?;
    Ok((config, id))
}

/// Resolves the relay, then opens a QUIC connection to it using the pinned
/// `verifier` and the given ALPN protocol.
async fn dial_relay(
    host: &str,
    port: u16,
    id: &KeyMaterial,
    verifier: Arc<PinnedServerVerifier>,
    alpn: &[u8],
) -> Result<Connection> {
    // Resolve through the system resolver so hostnames work, not only IP literals.
    let relay_addr = lookup_host((host, port))
        .await
        .with_context(|| format!("cannot resolve relay address {host}:{port}"))?
        // The local endpoint is bound to an IPv4 socket.
        .find(SocketAddr::is_ipv4)
        .with_context(|| format!("relay {host}:{port} has no IPv4 address"))?;

    let endpoint = create_client_endpoint(BIND_ADDR).context("failed to bind local UDP socket")?;
    let client_config = make_client_config(
        &id.certificate_der,
        &id.private_key_pem,
        verifier,
        vec![alpn.to_vec()],
    )
    .context("client TLS configuration error")?;

    // The endpoint driver keeps running while connections are alive, so it is
    // safe to drop our endpoint handle on return.
    endpoint
        .connect_with(client_config, relay_addr, host)
        .with_context(|| format!("failed to dial relay at {relay_addr}"))?
        .await
        .context("relay handshake failed")
}

/// Enrolls this client with the relay using the one-time token in `uri`.
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

/// `ProxyCommand` entry point. stdout carries ONLY tunnel bytes, so every
/// diagnostic goes to stderr. The caller maps an `Err` to a one-line message
/// and a non-zero exit status.
async fn connect(state_dir: &Path, agent: String, target: Option<&str>) -> Result<()> {
    let (config, id) = load_client_state(state_dir)?;

    let target = target
        .map(|t| {
            HostPort::parse(t).map_err(|_| anyhow!("invalid target host:port specification: {t}"))
        })
        .transpose()?;

    let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
    let connection = dial_relay(
        &config.relay_host,
        config.relay_port,
        &id,
        verifier,
        ALPN_TUNNEL,
    )
    .await?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("failed to open bidirectional QUIC stream")?;

    let req = ControlMessage::ConnectRequest { agent, target };
    write_frame(&mut send, &req)
        .await
        .context("failed to send ConnectRequest")?;

    let resp = read_frame(&mut recv)
        .await
        .context("failed to read ConnectResponse from relay")?;

    match resp {
        ControlMessage::ConnectResponse {
            status: ResultStatus::Ok,
            ..
        } => {
            // The connection is accepted and the target dialed. Hand stdin/stdout
            // directly to raw QUIC stream splicing. The result is intentionally
            // ignored: a peer closing the pipe ends the session and is not a failure.
            let _ = splice_quic_to_stdio(send, recv, tokio::io::stdin(), tokio::io::stdout()).await;
            Ok(())
        }
        ControlMessage::ConnectResponse {
            status: ResultStatus::Err(code),
            ..
        } => bail!("connection rejected: {code}"),
        ControlMessage::Error { code, message } => bail!("relay error: {code} - {message}"),
        _ => bail!("unexpected control frame from relay"),
    }
}

/// Prints the agents granted to this client and whether each is online.
async fn list_agents(state_dir: &Path) -> Result<()> {
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
    let req = ControlMessage::ListAgents {
        client_name: config.client_name,
    };
    write_frame(&mut send, &req).await?;

    let ControlMessage::ListAgentsResponse { agents } = read_frame(&mut recv).await? else {
        bail!("unexpected response from relay");
    };

    println!("{:<24} STATUS", "AGENT");
    for a in agents {
        let status = if a.online { "online" } else { "offline" };
        println!("{:<24} {status}", a.name);
    }
    Ok(())
}

/// Returns the default installation directory for the client binary.
fn default_client_bin_dir() -> Result<PathBuf> {
    if rtunnel_install::is_root() {
        return Ok(PathBuf::from(rtunnel_install::DEFAULT_BIN_DIR));
    }

    let dirs = BaseDirs::new().context("cannot determine home directory")?;
    Ok(dirs.home_dir().join(".local").join("bin"))
}

/// Installs the running client binary and prepares the user's SSH environment.
async fn install_client(
    state_dir: &Path,
    uri: Option<&str>,
    bin_dir: Option<PathBuf>,
    no_ssh_config: bool,
) -> Result<()> {
    let bin_dir = match bin_dir {
        Some(dir) => dir,
        None => default_client_bin_dir()?,
    };
    let bin_path = bin_dir.join("rtunnel");
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
    if let Some(path_var) = std::env::var_os("PATH") {
        let on_path = std::env::split_paths(&path_var).any(|entry| entry == installed_dir);
        if !on_path {
            eprintln!(
                "warning: {} is not on PATH; add it to your shell profile",
                installed_dir.display()
            );
        }
    }

    if let Some(uri) = uri {
        enroll(state_dir, uri).await?;
    } else {
        println!("Enroll with: rtunnel enroll \"rtunnel://...\"");
    }
    println!("Add an SSH host with: rtunnel ssh-config <agent>");

    Ok(())
}

/// Builds an OpenSSH `Host` block that proxies through `rtunnel connect`.
fn ssh_config_snippet(agent: &str, target: Option<&str>) -> String {
    let target_suffix = target.map_or(String::new(), |dest| format!(" {dest}"));
    format!("Host {agent}\n    ProxyCommand rtunnel connect {agent}{target_suffix}\n")
}

/// Prints an OpenSSH `Host` block that proxies through `rtunnel connect`.
fn print_ssh_config(agent: &str, target: Option<&str>) {
    print!("{}", ssh_config_snippet(agent, target));
}

/// Writes an OpenSSH snippet into `~/.ssh/rtunnel.d/<agent>.conf`.
fn write_ssh_config(agent: &str, target: Option<&str>) -> Result<()> {
    if !is_valid_name(agent) {
        bail!("agent name must match [a-z0-9-]{{1,63}}");
    }
    if let Some(dest) = target {
        HostPort::parse(dest)
            .map_err(|_| anyhow!("invalid target host:port specification: {dest}"))?;
    }

    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .context("cannot determine home directory")?;
    let snippets = rtunnel_install::configure_ssh_include(&home)
        .context("failed to configure the OpenSSH include")?;
    let path = snippets.join(format!("{agent}.conf"));
    std::fs::write(&path, ssh_config_snippet(agent, target))
        .with_context(|| format!("failed to write {}", path.display()))?;

    println!("Wrote {}", path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls 0.23. An Err only means a
    // provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // CRUCIAL: All logging and tracing MUST go exclusively to stderr!
    // stdout is reserved strictly for raw tunnel stream bytes during `connect`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let state_dir = resolve_state_dir(cli.state_dir);

    match cli.command {
        Command::Enroll { uri } => enroll(&state_dir, &uri).await,
        Command::Connect { agent, target } => {
            // ProxyCommand contract: a clean one-line error on stderr and a
            // non-zero exit. We exit explicitly (also on success) because the
            // blocking stdin reader would otherwise stall runtime shutdown.
            let code = match connect(&state_dir, agent, target.as_deref()).await {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("rtunnel: {e:#}");
                    EXIT_FAILURE
                }
            };
            std::process::exit(code);
        }
        Command::Agents => list_agents(&state_dir).await,
        Command::SshConfig {
            agent,
            target,
            write,
        } => {
            if write {
                write_ssh_config(&agent, target.as_deref())?;
            } else {
                print_ssh_config(&agent, target.as_deref());
            }
            Ok(())
        }
        Command::Install {
            uri,
            bin_dir,
            no_ssh_config,
        } => install_client(&state_dir, uri.as_deref(), bin_dir, no_ssh_config).await,
    }
}
