use anyhow::Result;
use clap::{Parser, Subcommand};
use rtunnel_relay::SqliteStore;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "rtunneld", version, about = "Relay process for rtunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize the relay state directory.
    Init {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Start the relay service.
    Serve {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Manage enrollment tokens.
    Token {
        #[command(subcommand)]
        action: TokenCommand,
    },
    /// Manage grants.
    Grant {
        #[command(subcommand)]
        action: GrantCommand,
    },
    /// List registered peers.
    PeersList {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    /// Revoke a peer.
    Revoke {
        name: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum TokenCommand {
    Create {
        role: String,
        name: String,
        ttl: String,
    },
    List {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    Revoke {
        token: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum GrantCommand {
    Add {
        client: String,
        agent: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    Remove {
        client: String,
        agent: String,
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
    List {
        #[arg(long, default_value = "/var/lib/rtunnel")]
        state_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { state_dir } => {
            std::fs::create_dir_all(&state_dir)?;
            println!("relay state initialized at {}", state_dir.display());
        }
        Command::Serve { state_dir } => {
            let _db = SqliteStore::open(state_dir.join("rtunnel.db"))?;
            println!("relay starting");
        }
        Command::Token { action } => match action {
            TokenCommand::Create { role, name, ttl } => {
                println!("token for {role} {name} ttl={ttl}");
            }
            TokenCommand::List { .. } => println!("token list"),
            TokenCommand::Revoke { .. } => println!("token revoked"),
        },
        Command::Grant { action } => match action {
            GrantCommand::Add { client, agent, .. } => println!("grant {client} -> {agent}"),
            GrantCommand::Remove { client, agent, .. } => {
                println!("removed grant {client} -> {agent}");
            }
            GrantCommand::List { .. } => println!("grant list"),
        },
        Command::PeersList { .. } => println!("peers list"),
        Command::Revoke { name, .. } => println!("revoked {name}"),
    }
    Ok(())
}
