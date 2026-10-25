use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rtunnel", version, about = "Client for a QUIC relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll this client with a relay URI.
    Enroll { uri: String },
    /// Outline a connection to an agent.
    Connect {
        agent: String,
        target: Option<String>,
    },
    /// List known agents.
    Agents,
    /// Print SSH config for a host alias.
    SshConfig {
        agent: String,
        target: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll { uri } => println!("enrolling client with {uri}"),
        Command::Connect { agent, target } => {
            if let Some(dest) = target {
                println!("connecting to {agent} via {dest}");
            } else {
                println!("connecting to {agent}");
            }
        }
        Command::Agents => println!("agents"),
        Command::SshConfig { agent, target } => {
            let dest = target.as_deref().unwrap_or("22");
            println!("Host {agent}");
            println!("    ProxyCommand rtunnel connect {agent} {dest}");
        }
    }
}
