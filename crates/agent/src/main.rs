#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rtunnel_agent::{AgentConfig, AgentRunner};
use rtunnel_identity::{
    EnrollmentUri, PinnedServerVerifier, generate_identity, load_identity, save_identity,
};
use rtunnel_proto::{ALPN_ENROLL, ControlMessage};
use rtunnel_transport::{create_client_endpoint, make_client_config, read_frame, write_frame};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rtunnel-agent", version, about = "Agent daemon for rtunnel")]
struct Cli {
    #[arg(long, default_value = "/var/lib/rtunnel-agent")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll this agent with a relay URI.
    Enroll {
        uri: String,
        #[arg(long, default_value = "127.0.0.1:22")]
        allowed_target: Vec<String>,
    },
    /// Run the agent connector daemon.
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Enroll {
            uri,
            allowed_target,
        } => {
            let parsed_uri = EnrollmentUri::parse(&uri).context("invalid enrollment URI")?;
            std::fs::create_dir_all(&cli.state_dir)?;

            let id = generate_identity("agent")?;
            save_identity(&cli.state_dir, &id)?;

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
                .context("handshake failed with relay during enrollment")?;

            let (mut send, mut recv) = connection.open_bi().await?;
            let enroll_msg = ControlMessage::Enroll {
                token: parsed_uri.token,
            };
            write_frame(&mut send, &enroll_msg).await?;

            let ack = match read_frame(&mut recv).await? {
                ControlMessage::EnrollAck { name, role } => (name, role),
                ControlMessage::Error { code, message } => {
                    bail!("enrollment failed: {code} - {message}");
                }
                _ => bail!("unexpected relay response during enrollment"),
            };

            if ack.1 != "agent" {
                bail!("token authorized for role '{}', expected 'agent'", ack.1);
            }

            let config = AgentConfig {
                relay_host: parsed_uri.host,
                relay_port: parsed_uri.port,
                relay_fingerprint: parsed_uri.relay_fingerprint,
                agent_name: ack.0.clone(),
                allowed_targets: allowed_target,
                max_sessions: 64,
            };
            config.save(&cli.state_dir)?;

            println!("Agent enrolled successfully as '{}'.", ack.0);
            println!("State saved to {}", cli.state_dir.display());
        }
        Command::Run => {
            let config = AgentConfig::load(&cli.state_dir)
                .context("failed to load agent config; run 'enroll' first")?;
            let id = load_identity(&cli.state_dir)
                .context("failed to load agent identity; run 'enroll' first")?;
            let runner = AgentRunner::new(config, id);
            runner
                .run()
                .await
                .map_err(anyhow::Error::msg)
                .context("agent runner failed to start")?;
        }
    }
    Ok(())
}
