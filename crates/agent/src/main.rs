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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// Hardened systemd unit embedded at build time so `install` needs no checkout.
const AGENT_UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/rtunnel-agent.service");

#[derive(Parser, Debug)]
#[command(name = "rtunnel-agent", version, about = "Agent daemon for rtunnel")]
struct Cli {
    #[arg(long, global = true, default_value = "/var/lib/rtunnel-agent")]
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
    /// Install this binary and a hardened systemd unit.
    Install {
        /// Optional enrollment URI; the agent is enrolled before the service starts.
        uri: Option<String>,
        #[arg(long, default_value = "/usr/local/bin")]
        bin_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:22")]
        allowed_target: Vec<String>,
        /// Install the unit without enabling or starting the service.
        #[arg(long)]
        no_start: bool,
    },
}

/// Enrolls this agent and persists its identity and configuration.
async fn enroll_agent(
    state_dir: &Path,
    uri: &str,
    allowed_targets: Vec<String>,
) -> Result<AgentConfig> {
    let parsed_uri = EnrollmentUri::parse(uri).context("invalid enrollment URI")?;
    rtunnel_install::create_private_dir(state_dir)
        .with_context(|| format!("failed to prepare {}", state_dir.display()))?;

    let id = generate_identity("agent")?;
    save_identity(state_dir, &id)?;

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
        allowed_targets,
        max_sessions: 64,
    };
    config.save(state_dir)?;

    println!("Agent enrolled successfully as '{}'.", ack.0);
    println!("State saved to {}", state_dir.display());

    Ok(config)
}

/// Installs the running agent binary, writes its systemd unit, and starts it.
async fn install_agent(
    state_dir: &Path,
    uri: Option<&str>,
    allowed_targets: Vec<String>,
    bin_dir: &Path,
    no_start: bool,
) -> Result<()> {
    rtunnel_install::ensure_root()
        .context("installing the agent service requires root; rerun with sudo")?;
    rtunnel_install::validate_unit_path(state_dir)?;

    let bin_dir = std::path::absolute(bin_dir).context("invalid binary directory")?;
    let bin_path = bin_dir.join("rtunnel-agent");
    rtunnel_install::validate_unit_path(&bin_path)?;
    let installed = rtunnel_install::install_self(&bin_path)
        .with_context(|| format!("failed to install {}", bin_path.display()))?;

    rtunnel_install::create_private_dir(state_dir)
        .with_context(|| format!("failed to prepare {}", state_dir.display()))?;

    let config = if let Some(uri) = uri {
        Some(enroll_agent(state_dir, uri, allowed_targets).await?)
    } else if state_dir.join("config.toml").exists() {
        Some(AgentConfig::load(state_dir).context("failed to load existing agent config")?)
    } else {
        None
    };

    if config.is_none() && !no_start {
        bail!("agent is not enrolled; pass an enrollment URI or use --no-start");
    }

    let exec_start = format!(
        "{} run --state-dir {}",
        installed.display(),
        state_dir.display()
    );
    let unit = rtunnel_install::render_unit(AGENT_UNIT_TEMPLATE, &exec_start, state_dir);
    let unit_path = rtunnel_install::install_unit("rtunnel-agent.service", &unit)
        .context("failed to install rtunnel-agent.service")?;

    println!("Installed rtunnel-agent at {}", installed.display());
    println!("Systemd unit: {}", unit_path.display());

    if let Some(config) = &config {
        println!("Agent name: {}", config.agent_name);
        println!("Allowed targets: {}", config.allowed_targets.join(", "));
    }

    if no_start {
        println!("Service not started (--no-start).");
        println!(
            "Load and start it later with: systemctl daemon-reload && systemctl enable --now rtunnel-agent.service"
        );
    } else {
        rtunnel_install::enable_service("rtunnel-agent.service", true)
            .context("failed to enable or start rtunnel-agent.service")?;
        println!("rtunnel-agent.service is enabled and running.");
    }

    if config.is_none() {
        println!("Enroll this agent with:");
        println!("  rtunnel-agent enroll \"rtunnel://...\" --allowed-target 127.0.0.1:22");
    }

    Ok(())
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
            enroll_agent(&cli.state_dir, &uri, allowed_target).await?;
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
        Command::Install {
            uri,
            bin_dir,
            allowed_target,
            no_start,
        } => {
            install_agent(
                &cli.state_dir,
                uri.as_deref(),
                allowed_target,
                &bin_dir,
                no_start,
            )
            .await?;
        }
    }
    Ok(())
}
