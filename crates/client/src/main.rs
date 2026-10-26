#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
#[cfg(not(windows))]
use directories::ProjectDirs;
use quinn::Connection;
use rtunnel_client::ClientConfig;
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, generate_identity, is_valid_name,
    load_identity, save_identity,
};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_TUNNEL, AgentDetail, ControlMessage, HostPort, ResultStatus,
};
use rtunnel_transport::{
    create_client_endpoint, make_client_config, read_frame, splice_quic_to_stdio, write_frame,
};
use std::collections::BTreeSet;
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
    /// Override the default configuration and state directory
    /// (`~/.config/rtunnel`, or `%APPDATA%\rtunnel` on Windows).
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
    /// Print or write ready-to-paste OpenSSH configuration blocks.
    SshConfig {
        /// Name of the target agent. Omit when using `--all`.
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
}

fn resolve_state_dir(override_dir: Option<PathBuf>) -> PathBuf {
    override_dir.unwrap_or_else(default_state_dir)
}

fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // `%APPDATA%\rtunnel` is the conventional per-user application data
        // location and avoids the duplicated organization/application path
        // produced by `ProjectDirs`.
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

/// Queries the relay for granted agents and their advertised targets.
///
/// Relays from before target discovery reject `ListAgentsDetailed`, so the
/// client falls back to the original `ListAgents` query and reports no targets.
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
            // Revision 1 relay: retry with the original query on a fresh stream.
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

/// Prints the agents granted to this client, their status, and their targets.
async fn list_agents(state_dir: &Path) -> Result<()> {
    let agents = fetch_agents(state_dir).await?;

    println!(
        "{:<24} {:<8} {:<20} OTHER TARGETS",
        "AGENT", "STATUS", "DEFAULT TARGET"
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
        println!("{:<24} {status:<8} {default:<20} {others}", a.name);
    }
    Ok(())
}

/// Returns the default installation directory for the client binary.
fn default_client_bin_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let dirs = BaseDirs::new().context("cannot determine home directory")?;
        // Per-user program directory, which does not require elevation.
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

/// Installs the running client binary and prepares the user's SSH environment.
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
        println!("Enroll with: rtunnel enroll \"rtunnel://...\"");
    }
    println!("Add SSH hosts later with: rtunnel ssh-config --all --write");

    Ok(())
}

/// One generated OpenSSH host entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SshHost {
    /// `Host` line value.
    alias: String,
    /// Agent that terminates the tunnel.
    agent: String,
    /// Explicit target, or `None` to use the agent's default target.
    target: Option<String>,
}

/// Builds an OpenSSH `Host` block that proxies through `rtunnel connect`.
fn ssh_config_snippet(host_alias: &str, agent: &str, target: Option<&str>) -> String {
    let target_suffix = target.map_or(String::new(), |dest| format!(" {dest}"));
    format!("Host {host_alias}\n    ProxyCommand rtunnel connect {agent}{target_suffix}\n")
}

/// Derives a short, stable SSH alias for an advertised target.
///
/// `winbox:22` becomes `winbox`; a non-standard port becomes `winbox-3389`.
/// Names that collide with the agent name or another alias are prefixed and,
/// if needed, numbered.
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

/// Builds every host entry for an agent: its default plus one alias per target.
fn ssh_hosts(agent: &str, targets: &[String]) -> Vec<SshHost> {
    let mut used = BTreeSet::from([agent.to_string()]);
    let mut hosts = vec![SshHost {
        alias: agent.to_string(),
        agent: agent.to_string(),
        target: None,
    }];

    // The first target is already covered by the target-less `Host <agent>`
    // entry. Skipping it avoids aliases such as `Host 127.0.0.1` that would
    // shadow an unrelated local destination.
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

/// Renders host entries as OpenSSH configuration text.
fn render_snippets(hosts: &[SshHost]) -> String {
    hosts
        .iter()
        .map(|host| ssh_config_snippet(&host.alias, &host.agent, host.target.as_deref()))
        .collect()
}

/// Writes an agent's host entries to `~/.ssh/rtunnel.d/<agent>.conf`.
fn write_agent_snippet(snippets: &Path, agent: &str, hosts: &[SshHost]) -> Result<PathBuf> {
    if !is_valid_name(agent) {
        bail!("refusing to write a snippet for invalid agent name '{agent}'");
    }
    let path = snippets.join(format!("{agent}.conf"));
    std::fs::write(&path, render_snippets(hosts))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

/// Looks up an agent's advertised targets, warning instead of failing when the
/// relay is unreachable or predates target discovery.
async fn resolve_agent_targets(state_dir: &Path, agent: &str) -> Vec<String> {
    match fetch_agents(state_dir).await {
        Ok(agents) => agents
            .into_iter()
            .find(|a| a.name == agent)
            .map_or_else(Vec::new, |a| a.targets),
        Err(e) => {
            eprintln!(
                "warning: could not discover targets for '{agent}' ({e:#}); using the agent default"
            );
            Vec::new()
        }
    }
}

/// Prints OpenSSH host entries for one agent, discovering targets when omitted.
async fn print_ssh_config(state_dir: &Path, agent: &str, target: Option<&str>) -> Result<()> {
    if !is_valid_name(agent) {
        bail!("agent name must match [a-z0-9-]{{1,63}}");
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

/// Writes OpenSSH snippets for one agent, or for every granted agent with `--all`.
async fn write_ssh_config(
    state_dir: &Path,
    agent: Option<&str>,
    target: Option<&str>,
    all: bool,
) -> Result<()> {
    if all && (agent.is_some() || target.is_some()) {
        bail!("--all writes every granted agent and cannot be combined with an agent or target");
    }

    let planned: Vec<(String, Vec<SshHost>)> = if all {
        fetch_agents(state_dir)
            .await?
            .into_iter()
            .map(|a| (a.name.clone(), ssh_hosts(&a.name, &a.targets)))
            .collect()
    } else {
        let agent = agent.context("an agent name is required (or use --all)")?;
        if !is_valid_name(agent) {
            bail!("agent name must match [a-z0-9-]{{1,63}}");
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
        println!("No granted agents found; nothing to write.");
        return Ok(());
    }

    for (name, hosts) in planned {
        let path = write_agent_snippet(&snippets, &name, &hosts)?;
        println!("Wrote {}", path.display());
    }
    Ok(())
}

/// Writes snippets for every granted agent, returning the agent names written.
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
            all,
        } => {
            if write {
                write_ssh_config(&state_dir, agent.as_deref(), target.as_deref(), all).await?;
            } else {
                if all {
                    bail!("--all requires --write");
                }
                let agent = agent.context("an agent name is required")?;
                print_ssh_config(&state_dir, &agent, target.as_deref()).await?;
            }
            Ok(())
        }
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
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SshHost, render_snippets, ssh_config_snippet, ssh_hosts};

    fn target(value: &str) -> String {
        value.to_string()
    }

    #[test]
    fn builds_default_and_target_aliases() {
        let hosts = ssh_hosts("clinic-a", &[target("winbox:22"), target("nas:445")]);

        assert_eq!(
            hosts[0],
            SshHost {
                alias: "clinic-a".into(),
                agent: "clinic-a".into(),
                target: None,
            }
        );
        // The first target is the default and is reached through `clinic-a`.
        assert!(!hosts.iter().any(|host| host.alias == "winbox"));
        assert!(
            hosts.iter().any(|host| {
                host.alias == "nas-445" && host.target.as_deref() == Some("nas:445")
            })
        );
    }

    #[test]
    fn single_target_only_creates_the_default_entry() {
        let hosts = ssh_hosts("winbox", &[target("winbox:22")]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "winbox");
        assert!(hosts[0].target.is_none());
    }

    #[test]
    fn duplicate_aliases_are_numbered() {
        let hosts = ssh_hosts(
            "agent",
            &[
                target("winbox:22"),
                target("winbox:22"),
                target("winbox:22"),
            ],
        );
        let aliases: Vec<&str> = hosts.iter().map(|host| host.alias.as_str()).collect();
        assert_eq!(aliases, vec!["agent", "winbox", "agent-winbox"]);
    }

    #[test]
    fn ipv6_targets_do_not_create_aliases() {
        let hosts = ssh_hosts("agent", &[target("127.0.0.1:22"), target("[::1]:22")]);
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn renders_proxy_command() {
        assert_eq!(
            ssh_config_snippet("winbox", "clinic-a", Some("winbox:22")),
            "Host winbox\n    ProxyCommand rtunnel connect clinic-a winbox:22\n"
        );
    }

    #[test]
    fn renders_all_hosts() {
        let hosts = ssh_hosts("clinic-a", &[target("winbox:22"), target("nas:445")]);
        let rendered = render_snippets(&hosts);
        assert!(rendered.contains("Host clinic-a\n"));
        assert!(rendered.contains("Host nas-445\n"));
        assert!(rendered.contains("ProxyCommand rtunnel connect clinic-a nas:445\n"));
    }
}
