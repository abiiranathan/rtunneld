#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use quinn::Connection;
use rtunnel_client::ClientConfig;
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, generate_identity, load_identity,
    save_identity,
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
    std::fs::create_dir_all(state_dir)
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

/// Prints an OpenSSH `Host` block that proxies through `rtunnel connect`.
fn print_ssh_config(agent: &str, target: Option<&str>) {
    println!("Host {agent}");
    match target {
        Some(dest) => println!("    ProxyCommand rtunnel connect {agent} {dest}"),
        None => println!("    ProxyCommand rtunnel connect {agent}"),
    }
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
        Command::SshConfig { agent, target } => {
            print_ssh_config(&agent, target.as_deref());
            Ok(())
        }
    }
}
