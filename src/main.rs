use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use masque::auth;
use masque::config::{self, ServerConfig};
use masque::server::Server;

/// MASQUE proxy server (CONNECT / CONNECT-UDP / CONNECT-IP over HTTP/3).
#[derive(Parser)]
#[command(name = "masque-server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Config file path.
    #[arg(short, long, default_value = "masque.toml")]
    config: PathBuf,

    /// Override listen address.
    #[arg(short, long)]
    listen: Option<String>,

    /// TLS certificate path.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key path.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Increase log verbosity (repeatable: -v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Command {
    /// Read a password from standard input and print an Argon2id PHC hash.
    HashPassword,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if matches!(cli.command, Some(Command::HashPassword)) {
        let mut password = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut password)?;
        if password.ends_with('\n') {
            password.pop();
            if password.ends_with('\r') {
                password.pop();
            }
        }
        if password.chars().any(char::is_control) {
            anyhow::bail!("password must not contain control characters");
        }
        println!("{}", auth::hash_password(password.as_bytes())?);
        return Ok(());
    }

    // Logging
    let default_filter = match cli.verbose {
        0 => "masque=info",
        1 => "masque=debug",
        _ => "masque=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    // Load config
    let mut cfg = if cli.config.exists() {
        let toml_str = std::fs::read_to_string(&cli.config)?;
        config::parse_toml(&toml_str)?
    } else {
        info!(path = %cli.config.display(), "config file not found, using defaults");
        ServerConfig::default()
    };

    // CLI overrides
    if let Some(listen) = cli.listen {
        cfg.server.listen_addr = listen.parse()?;
    }
    if let Some(cert) = cli.cert {
        cfg.tls.cert_path = cert;
    }
    if let Some(key) = cli.key {
        cfg.tls.key_path = key;
    }

    info!(?cfg, "configuration loaded");

    let mut server = Server::bind(cfg).await?;
    server.run().await
}
