use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rtunnel-agent", version, about = "Agent process for rtunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll this agent with a relay URI.
    Enroll { uri: String },
    /// Run the agent connector loop.
    Run,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll { uri } => println!("enrolling agent with {uri}"),
        Command::Run => println!("agent running"),
    }
}
