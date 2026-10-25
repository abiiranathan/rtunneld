#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rtunnel_client::ClientConfig;
use rtunnel_identity::{
    EnrollmentUri, PinnedServerVerifier, generate_identity, load_identity, save_identity,
};
use rtunnel_proto::{ALPN_ENROLL, ALPN_TUNNEL, ControlMessage, HostPort, ResultStatus};
use rtunnel_transport::{
    create_client_endpoint, make_client_config, read_frame, splice_quic_to_stdio, write_frame,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rtunnel", version, about = "Client CLI for rtunnel QUIC relay")]
struct Cli {
    /// Override the default configuration and state directory (~/.config/rtunnel).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll this client using a one-time token URI.
    Enroll {
        /// Enrollment URI of the form rtunnel://<host>:<port>/?fp=<fingerprint>&token=<token>
        uri: String,
    },
    /// Connect to an agent and bridge stdin/stdout for use as OpenSSH ProxyCommand.
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
    if let Some(dir) = override_dir {
        return dir;
    }
    if let Some(proj) = ProjectDirs::from("com", "rtunnel", "rtunnel") {
        proj.config_dir().to_path_buf()
    } else {
        PathBuf::from(".rtunnel")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls 0.23
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
        Command::Enroll { uri } => {
            eprintln!("Parsing enrollment URI...");
            let parsed_uri = EnrollmentUri::parse(&uri).context("invalid enrollment URI")?;
            std::fs::create_dir_all(&state_dir)?;

            let id = generate_identity("client")?;
            save_identity(&state_dir, &id)?;

            let relay_addr: SocketAddr = format!("{}:{}", parsed_uri.host, parsed_uri.port)
                .parse()
                .context("invalid relay address")?;

            let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap())?;
            let verifier = Arc::new(PinnedServerVerifier::new(&parsed_uri.relay_fingerprint));
            let client_config = make_client_config(
                &id.certificate_der,
                &id.private_key_pem,
                verifier,
                vec![ALPN_ENROLL.to_vec()],
            )?;

            let connection = endpoint
                .connect_with(client_config, relay_addr, &parsed_uri.host)?
                .await
                .context("relay TLS handshake failed during enrollment")?;

            let (mut send, mut recv) = connection.open_bi().await?;
            let enroll_msg = ControlMessage::Enroll {
                token: parsed_uri.token,
            };
            write_frame(&mut send, &enroll_msg).await?;

            let ack = match read_frame(&mut recv).await? {
                ControlMessage::EnrollAck { name, role } => (name, role),
                ControlMessage::Error { code, message } => {
                    bail!("relay rejected enrollment: {code} - {message}");
                }
                _ => bail!("unexpected relay response during enrollment"),
            };

            if ack.1 != "client" {
                bail!("token authorized for role '{}', expected 'client'", ack.1);
            }

            let config = ClientConfig {
                relay_host: parsed_uri.host,
                relay_port: parsed_uri.port,
                relay_fingerprint: parsed_uri.relay_fingerprint,
                client_name: ack.0.clone(),
            };
            config.save(&state_dir)?;

            eprintln!("Client enrolled successfully as '{}'.", ack.0);
            eprintln!("Config written to {}", state_dir.display());
        }
        Command::Connect { agent, target } => {
            // ProxyCommand entry point. stdout carries ONLY tunnel bytes.
            // On failure, exit non-zero with a clean one-line human-readable error to stderr.
            let config = match ClientConfig::load(&state_dir) {
                Ok(cfg) => cfg,
                Err(_) => {
                    eprintln!(
                        "rtunnel: client configuration missing; run 'rtunnel enroll <uri>' first"
                    );
                    std::process::exit(1);
                }
            };
            let id = match load_identity(&state_dir) {
                Ok(id) => id,
                Err(_) => {
                    eprintln!(
                        "rtunnel: client identity key missing; run 'rtunnel enroll <uri>' first"
                    );
                    std::process::exit(1);
                }
            };

            let relay_addr: SocketAddr =
                match format!("{}:{}", config.relay_host, config.relay_port).parse() {
                    Ok(addr) => addr,
                    Err(_) => {
                        eprintln!(
                            "rtunnel: invalid relay address in configuration: {}:{}",
                            config.relay_host, config.relay_port
                        );
                        std::process::exit(1);
                    }
                };

            let endpoint = match create_client_endpoint("0.0.0.0:0".parse().unwrap()) {
                Ok(ep) => ep,
                Err(e) => {
                    eprintln!("rtunnel: failed to bind local UDP socket: {e}");
                    std::process::exit(1);
                }
            };

            let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
            let client_config = match make_client_config(
                &id.certificate_der,
                &id.private_key_pem,
                verifier,
                vec![ALPN_TUNNEL.to_vec()],
            ) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("rtunnel: client TLS configuration error: {e}");
                    std::process::exit(1);
                }
            };

            let connecting =
                match endpoint.connect_with(client_config, relay_addr, &config.relay_host) {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("rtunnel: failed to dial relay at {relay_addr}: {e}");
                        std::process::exit(1);
                    }
                };

            let connection = match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("rtunnel: relay handshake failed: {e}");
                    std::process::exit(1);
                }
            };

            let (mut send, mut recv) = match connection.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    eprintln!("rtunnel: failed to open bidirectional QUIC stream: {e}");
                    std::process::exit(1);
                }
            };

            let target_hostport = if let Some(ref t) = target {
                match HostPort::parse(t) {
                    Ok(hp) => Some(hp),
                    Err(_) => {
                        eprintln!("rtunnel: invalid target host:port specification: {t}");
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };

            let req = ControlMessage::ConnectRequest {
                agent,
                target: target_hostport,
            };

            if let Err(e) = write_frame(&mut send, &req).await {
                eprintln!("rtunnel: failed to send ConnectRequest: {e}");
                std::process::exit(1);
            }

            let resp = match read_frame(&mut recv).await {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!("rtunnel: failed to read ConnectResponse from relay: {e}");
                    std::process::exit(1);
                }
            };

            match resp {
                ControlMessage::ConnectResponse { status, .. } => match status {
                    ResultStatus::Ok => {
                        // The connection is accepted and target dialed.
                        // Hand over stdin/stdout directly to raw QUIC stream splicing.
                        let stdin = tokio::io::stdin();
                        let stdout = tokio::io::stdout();
                        let _ = splice_quic_to_stdio(send, recv, stdin, stdout).await;
                        std::process::exit(0);
                    }
                    ResultStatus::Err(code) => {
                        eprintln!("rtunnel: connection rejected: {code}");
                        std::process::exit(1);
                    }
                },
                ControlMessage::Error { code, message } => {
                    eprintln!("rtunnel: relay error: {code} - {message}");
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("rtunnel: unexpected control frame from relay");
                    std::process::exit(1);
                }
            }
        }
        Command::Agents => {
            let config = ClientConfig::load(&state_dir)
                .context("failed to load client config; run 'enroll' first")?;
            let id = load_identity(&state_dir)
                .context("failed to load client identity; run 'enroll' first")?;

            let relay_addr: SocketAddr = format!("{}:{}", config.relay_host, config.relay_port)
                .parse()
                .context("invalid relay address")?;

            let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap())?;
            let verifier = Arc::new(PinnedServerVerifier::new(&config.relay_fingerprint));
            let client_config = make_client_config(
                &id.certificate_der,
                &id.private_key_pem,
                verifier,
                vec![ALPN_TUNNEL.to_vec()],
            )?;

            let connection = endpoint
                .connect_with(client_config, relay_addr, &config.relay_host)?
                .await
                .context("failed to connect to relay")?;

            let (mut send, mut recv) = connection.open_bi().await?;
            let req = ControlMessage::ListAgents {
                client_name: config.client_name,
            };
            write_frame(&mut send, &req).await?;

            let resp = read_frame(&mut recv).await?;
            let ControlMessage::ListAgentsResponse { agents } = resp else {
                bail!("unexpected response from relay");
            };

            println!("{:<24} STATUS", "AGENT");
            for a in agents {
                let status = if a.online { "online" } else { "offline" };
                println!("{:<24} {}", a.name, status);
            }
        }
        Command::SshConfig { agent, target } => {
            println!("Host {agent}");
            if let Some(dest) = target {
                println!("    ProxyCommand rtunnel connect {agent} {dest}");
            } else {
                println!("    ProxyCommand rtunnel connect {agent}");
            }
        }
    }
    Ok(())
}
