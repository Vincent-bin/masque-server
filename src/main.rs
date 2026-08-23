use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use masque::auth;
use masque::config::{self, ServerConfig};
use masque::config_edit;
use masque::enroll;
use masque::host;
use masque::server::{Server, validate_config};

/// MASQUE proxy server (CONNECT, CONNECT-UDP, and CONNECT-IP over HTTP/2 or
/// HTTP/3).
#[derive(Parser)]
#[command(name = "masque-server", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Config file path.
    #[arg(short, long, default_value = "masque.toml")]
    config: PathBuf,

    /// TLS certificate path.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key path.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Increase log verbosity (repeatable: -v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Log encoding for stderr/journald.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum LogFormat {
    /// Human-readable logs for terminals and `journalctl`.
    Text,
    /// Newline-delimited JSON for log collectors.
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Read a password from standard input and print an Argon2id PHC hash.
    HashPassword,
    /// Validate the configuration without binding sockets or creating a TUN.
    CheckConfig,
    /// Validate the configuration and inspect CONNECT-IP host prerequisites.
    ///
    /// This is read-only. It checks Linux forwarding switches and looks for
    /// TUN, route, firewall, and NAT evidence without changing any of them.
    Doctor,
    /// Generate a client key pair for a listener using client-certificate auth.
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
    /// Append a `[[listeners]]` block to the configuration file.
    ///
    /// Anything not given as a flag is prompted for when standard input is a
    /// terminal, and required otherwise, so the same command serves an operator
    /// and a provisioning script.
    ///
    /// Before writing, the merged file is validated the way `check-config`
    /// validates one, and the new address is bound once to see that it is free.
    /// Whatever fails, the file is left exactly as it was. The bind test
    /// describes the moment it ran, so it narrows the risk of the restart
    /// rather than removing it: check that the server came up afterwards.
    ///
    /// A new socket is bound at startup, so a restart is required — SIGHUP
    /// reloads TLS material and the active `[[clients]]` roster, not listeners.
    AddListener {
        /// Address and port for the new socket, for example `0.0.0.0:4443`.
        #[arg(long)]
        listen_addr: Option<SocketAddr>,

        /// HTTP transport for this socket. Defaults to http3 for scripted use.
        #[arg(long, value_enum)]
        transport: Option<TransportArg>,

        /// Authentication this socket demands. One mode per listener: the mode
        /// decides which TLS context is built before clients connect.
        #[arg(long, value_enum)]
        mode: Option<AuthModeArg>,

        /// Event loops for this listener. Defaults to 1.
        #[arg(long)]
        shards: Option<usize>,

        /// Basic username.
        #[arg(long)]
        username: Option<String>,

        /// Argon2id PHC hash, as printed by `hash-password`.
        #[arg(long, conflicts_with = "password_stdin")]
        password_hash: Option<String>,

        /// Read the password from standard input and hash it here.
        #[arg(long)]
        password_stdin: bool,

        /// Write `enabled = false`. Anyone who reaches the socket may use the
        /// proxy, so this is for a listener on a trusted network only.
        ///
        /// Conflicts with `--mode`: a listener that demands nothing has no
        /// authentication mode to pick, and writing one down would describe a
        /// requirement that is not enforced.
        #[arg(long, conflicts_with_all = ["mode", "username", "password_hash", "password_stdin"])]
        disable_auth: bool,

        /// Do not try to bind the new address before writing it.
        ///
        /// The bind test is what catches an address something else already
        /// holds. Skip it when the address only becomes available later, for
        /// example a floating address, or when the service runs in another
        /// network namespace.
        #[arg(long)]
        no_bind_check: bool,

        /// Print the block that would be appended and leave the file alone.
        #[arg(long)]
        dry_run: bool,

        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },
}

/// `--mode` on the command line.
///
/// Separate from [`config::AuthMode`] so the configuration model stays free of
/// command-line parsing; the two are mapped in one place below.
#[derive(Clone, Copy, clap::ValueEnum)]
enum AuthModeArg {
    /// RFC 7617 `Proxy-Authorization`, checked per request.
    Basic,
    /// A TLS client certificate, matched against the `[[clients]]` roster.
    ///
    /// Accepts the configuration file's own spelling as well: an operator who
    /// has read `mode = "client_cert"` should not have to discover that the
    /// flag wants a hyphen.
    #[value(alias = "client_cert")]
    ClientCert,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum TransportArg {
    Http3,
    Http2,
}

impl From<TransportArg> for config::ListenerTransport {
    fn from(transport: TransportArg) -> Self {
        match transport {
            TransportArg::Http3 => Self::Http3,
            TransportArg::Http2 => Self::Http2,
        }
    }
}

impl From<AuthModeArg> for config::AuthMode {
    fn from(mode: AuthModeArg) -> Self {
        match mode {
            AuthModeArg::Basic => config::AuthMode::Basic,
            AuthModeArg::ClientCert => config::AuthMode::ClientCert,
        }
    }
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
    format!(
        "# Start usque with --connect-port {port} (short form: -P {port}); add --http2 for an HTTP/2 listener."
    )
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
        0 => "masque=info,masque_server=info",
        1 => "masque=debug,masque_server=debug",
        _ => "masque=trace,masque_server=trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    match cli.log_format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init(),
    }

    // Load config.
    let config_exists = cli.config.exists();
    if matches!(
        cli.command,
        Some(Command::CheckConfig | Command::Doctor | Command::AddListener { .. })
    ) && !config_exists
    {
        anyhow::bail!("configuration file not found: {}", cli.config.display());
    }

    // Editing runs before the load below on purpose: it re-reads the file
    // itself, and validates it exactly as the service will read it rather than
    // with this invocation's --cert/--key overrides applied.
    if let Some(Command::AddListener {
        listen_addr,
        transport,
        mode,
        shards,
        username,
        password_hash,
        password_stdin,
        disable_auth,
        no_bind_check,
        dry_run,
        yes,
    }) = cli.command
    {
        return config_edit::add_listener(
            &cli.config,
            config_edit::AddListener {
                listen_addr,
                transport: transport.map(Into::into),
                mode: mode.map(Into::into),
                shards,
                username,
                password_hash,
                password_stdin,
                disable_auth,
                no_bind_check,
                dry_run,
                assume_yes: yes,
            },
        );
    }
    let mut cfg = if config_exists {
        let toml_str = std::fs::read_to_string(&cli.config)?;
        config::parse_toml(&toml_str)?
    } else {
        info!(path = %cli.config.display(), "config file not found, using defaults");
        ServerConfig::default()
    };

    // CLI overrides
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
        let listeners = validate_config(&cfg)?;
        info!(
            path = %cli.config.display(),
            listeners = listeners.len(),
            "configuration validated"
        );
        println!(
            "configuration is compatible with masque-server {}: {}",
            env!("CARGO_PKG_VERSION"),
            cli.config.display()
        );
        // Which sockets come up, and what each demands of a client. Worth
        // printing for one listener and necessary for several: authentication
        // belongs to each listener, so there is no single server-wide mode.
        //
        // Reported from the validated plan rather than the parsed file, so the
        // shard count is the resolved one — `shards = 0` means one per core and
        // a large value is capped, neither of which the file shows.
        for listener in listeners {
            println!(
                "listener {} transport={} auth={} shards={}",
                listener.listen_addr,
                listener.transport.as_str(),
                auth_label(&listener.auth),
                listener.shards
            );
        }
        if let Some(addr) = cfg.observability.listen_addr {
            println!("observability {addr} health=/healthz ready=/readyz metrics=/metrics");
        }
        return Ok(());
    }

    if matches!(cli.command, Some(Command::Doctor)) {
        validate_config(&cfg)?;
        println!(
            "configuration is compatible with masque-server {}: {}",
            env!("CARGO_PKG_VERSION"),
            cli.config.display()
        );
        println!("CONNECT-IP host diagnostics (read-only):");
        let report = host::diagnose_connect_ip(&cfg.ip_proxy);
        for check in report.checks() {
            println!("[{}] {}: {}", check.level.label(), check.name, check.detail);
        }
        println!(
            "diagnostic result: {} error(s), {} warning(s); no system settings were changed",
            report.error_count(),
            report.warning_count()
        );
        std::io::stdout().flush()?;
        if report.has_errors() {
            anyhow::bail!("CONNECT-IP host prerequisites are not ready");
        }
        return Ok(());
    }

    if cfg.ip_proxy.enabled {
        let report = host::diagnose_connect_ip_startup(&cfg.ip_proxy);
        for check in report.checks().iter().filter(|check| {
            matches!(
                check.level,
                host::DiagnosticLevel::Warning | host::DiagnosticLevel::Error
            )
        }) {
            warn!(
                check = check.name,
                detail = %check.detail,
                diagnostic_level = check.level.label(),
                "CONNECT-IP host diagnostic"
            );
        }
        info!(
            tun = %cfg.ip_proxy.tun_name,
            ipv4_pool = %cfg.ip_proxy.ipv4_pool,
            ipv6_pool = %cfg.ip_proxy.ipv6_pool,
            "CONNECT-IP host routing, firewall, and optional NAT remain operator-managed; run `masque-server doctor` to inspect them"
        );
    }

    info!(?cfg, "configuration loaded");

    // Pass the path so SIGHUP can re-read TLS material and the active
    // [[clients]] roster. Only a config that was actually loaded from disk is
    // reloadable; defaults have no file to re-read.
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
        assert!(instruction.contains("--http2"));
    }

    #[test]
    fn check_config_subcommand_is_available() {
        assert!(Cli::command().find_subcommand("check-config").is_some());
    }

    #[test]
    fn doctor_subcommand_is_available() {
        assert!(Cli::command().find_subcommand("doctor").is_some());
    }
}
