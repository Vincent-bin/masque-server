use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use masque::auth;
use masque::config::{self, ServerConfig};
use masque::enroll;
use masque::server::{Server, validate_config};

/// MASQUE proxy server (CONNECT / CONNECT-UDP / CONNECT-IP over HTTP/3).
#[derive(Parser)]
#[command(name = "masque-server", version)]
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
    /// Validate the configuration without binding sockets or creating a TUN.
    CheckConfig,
    /// Generate a client key pair for `auth.mode = "client_cert"`.
    ///
    /// Prints the `[[clients]]` block to add to the server config, and the JSON
    /// configuration for the client. Nothing is written to the server config
    /// automatically: enrolling a client is a deliberate act.
    EnrollClient {
        /// Label for this client, used in the server's logs.
        #[arg(long)]
        name: String,

        /// Address:port clients dial. The IP is written to JSON; the port is
        /// printed as the client's --connect-port argument.
        #[arg(long)]
        endpoint: SocketAddr,

        /// Fixed tunnel IPv4 for this client, inside `ip_proxy.ipv4_pool`.
        ///
        /// Required for clients that configure their own tunnel interface
        /// instead of reading the `ADDRESS_ASSIGN` capsule.
        #[arg(long)]
        ipv4: Option<Ipv4Addr>,

        /// Fixed tunnel IPv6 for this client, inside `ip_proxy.ipv6_pool`.
        #[arg(long)]
        ipv6: Option<Ipv6Addr>,

        /// Write the client JSON here instead of printing it.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
}

/// How a listener's authentication reads in `check-config` output.
///
/// Deliberately the effective answer rather than the configured `mode`:
/// `enabled = false` turns any mode off, and reporting the mode it would have
/// used would describe a listener that demands nothing as if it demanded
/// something.
fn auth_label(auth: &config::AuthSection) -> &'static str {
    if auth.client_cert_enabled() {
        "client_cert"
    } else if auth.basic_enabled() {
        "basic"
    } else {
        "disabled"
    }
}

fn usque_port_instruction(port: u16) -> String {
    format!("# Start usque with --connect-port {port} (short form: -P {port}).")
}

/// Generate and print one client enrollment.
fn enroll_client(
    cert_path: &Path,
    name: &str,
    endpoint: SocketAddr,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    tun_mtu: usize,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let pair = enroll::generate_client_key()?;
    let server_key = enroll::server_public_key_pem(cert_path)?;

    let client_json = Zeroizing::new(enroll::client_config_json(
        &pair.private_key_b64,
        &server_key,
        endpoint.ip(),
        ipv4,
        ipv6,
    ));

    println!("# Add to the server config, then reload or restart the server:\n");
    print!(
        "{}",
        enroll::clients_toml_block(name, &pair.public_key_b64, ipv4, ipv6)
    );

    match out {
        Some(path) => {
            enroll::write_client_config(&path, client_json.as_str())?;
            println!("\n# Client configuration written to {}", path.display());
        }
        None => {
            println!("\n# Client configuration (contains the private key — treat as a secret):\n");
            print!("{}", client_json.as_str());
        }
    }

    // usque's JSON schema stores only the endpoint IP; its connection port is
    // a launch flag. Always print it so a non-443 deployment cannot silently
    // fall back to the client's default port.
    println!("\n{}", usque_port_instruction(endpoint.port()));

    // The same enrollment, spelled for mihomo-style clients. Emitted alongside
    // rather than behind a flag: the encodings differ in ways that are easy to
    // get subtly wrong by hand, and a wrong key only shows up as a handshake
    // failure much later.
    println!(
        "\n# Or, for a mihomo-style client, add to its config.yaml \
         (also contains the private key):\n"
    );
    print!(
        "{}",
        Zeroizing::new(enroll::mihomo_proxy_yaml(
            name,
            &pair.private_key_b64,
            &enroll::pem_to_base64_der(&server_key),
            endpoint,
            ipv4,
            ipv6,
            tun_mtu,
        ))
        .as_str()
    );

    if ipv4.is_none() && ipv6.is_none() {
        eprintln!(
            "\nwarning: no fixed address was pinned. Clients that configure their tunnel \
             interface from this file rather than from the ADDRESS_ASSIGN capsule need \
             --ipv4 and/or --ipv6, or the two sides will disagree and every packet will \
             be dropped."
        );
    }

    Ok(())
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

    // Load config.
    let config_exists = cli.config.exists();
    if matches!(cli.command, Some(Command::CheckConfig)) && !config_exists {
        anyhow::bail!("configuration file not found: {}", cli.config.display());
    }
    let mut cfg = if config_exists {
        let toml_str = std::fs::read_to_string(&cli.config)?;
        config::parse_toml(&toml_str)?
    } else {
        info!(path = %cli.config.display(), "config file not found, using defaults");
        ServerConfig::default()
    };

    // CLI overrides
    if let Some(listen) = cli.listen {
        // `[[listeners]]` is the whole list of sockets, so `[server].listen_addr`
        // is not one of them and overriding it would change nothing. Silently
        // accepting the flag would be the worst outcome: it is reached for to
        // narrow a server's exposure, and appearing to work while the
        // configured listeners stay bound is exactly the failure it was meant
        // to prevent.
        if !cfg.listeners.is_empty() {
            anyhow::bail!(
                "--listen cannot choose among the {} listeners configured in {}; \
                 edit the [[listeners]] entry instead",
                cfg.listeners.len(),
                cli.config.display()
            );
        }
        cfg.server.listen_addr = listen.parse()?;
    }
    if let Some(cert) = cli.cert {
        cfg.tls.cert_path = cert;
    }
    if let Some(key) = cli.key {
        cfg.tls.key_path = key;
    }

    // Enrollment only needs the server certificate, so it runs off the same
    // config the server would use rather than asking for the path again.
    if let Some(Command::EnrollClient {
        name,
        endpoint,
        ipv4,
        ipv6,
        out,
    }) = cli.command
    {
        return enroll_client(
            &cfg.tls.cert_path,
            &name,
            endpoint,
            ipv4,
            ipv6,
            cfg.ip_proxy.tun_mtu,
            out,
        );
    }

    if matches!(cli.command, Some(Command::CheckConfig)) {
        validate_config(&cfg)?;
        println!(
            "configuration is compatible with masque-server {}: {}",
            env!("CARGO_PKG_VERSION"),
            cli.config.display()
        );
        // Which sockets come up, and what each demands of a client. Worth
        // printing for one listener and necessary for several: `[auth]` is only
        // the default a listener may inherit, so reading it alone would
        // describe one mode for a server that runs two.
        for listener in cfg.resolved_listeners() {
            println!(
                "listener {} auth={} shards={}",
                listener.listen_addr,
                auth_label(&listener.auth),
                listener.shards
            );
        }
        return Ok(());
    }

    info!(?cfg, "configuration loaded");

    // Pass the path so SIGHUP can re-read the [[clients]] roster. Only a
    // config that was actually loaded from disk is reloadable; defaults have
    // no file to re-read.
    let reload_path = cli.config.exists().then_some(cli.config);
    let mut server = Server::bind_with_reload(cfg, reload_path).await?;
    server.run().await
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::{Cli, usque_port_instruction};

    #[test]
    fn cli_reports_the_package_version() {
        assert_eq!(
            Cli::command().get_version(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn enrollment_preserves_a_non_default_endpoint_port_as_a_client_flag() {
        let instruction = usque_port_instruction(8449);
        assert!(instruction.contains("--connect-port 8449"));
        assert!(instruction.contains("-P 8449"));
    }

    #[test]
    fn check_config_subcommand_is_available() {
        assert!(Cli::command().find_subcommand("check-config").is_some());
    }
}
