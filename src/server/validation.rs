//! Startup configuration and listener validation shared with check-config.

use super::*;

/// Configuration state prepared without opening sockets or creating a TUN
/// device.
///
/// Keeping this as the single startup-validation path means `check-config`
/// and a real server start reject the same authentication, TLS, QUIC,
/// target-policy, and address-pool mistakes.
pub(super) struct ValidatedServerConfig {
    pub(super) clients: ClientRegistry,
    pub(super) tls: Arc<tls::SharedTlsIdentity>,
    pub(super) listeners: Vec<ListenerPlan>,
    pub(super) total_shards: usize,
    pub(super) address_pool: AddressPool,
}

/// One listener after its shard count has been resolved.
pub(super) struct ListenerPlan {
    pub(super) listener: ResolvedListener,
}

/// Whether any listener authenticates with a client certificate.
///
/// The roster, and the reload that replaces it, belong to the server rather
/// than to a listener, so both are governed by this rather than by one
/// listener's mode.
pub(super) fn any_client_cert_listener(config: &ServerConfig) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener.auth.client_cert_enabled())
}

pub(super) fn listener_auth_label(listener: &ResolvedListener) -> &'static str {
    if listener.auth.client_cert_enabled() {
        "client_cert"
    } else if listener.auth.basic_enabled() {
        "basic"
    } else {
        "disabled"
    }
}

pub(super) fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.is_loopback(), |ip| ip.is_loopback()),
    }
}

/// Shards that verify passwords, which is what the verification budget rations.
///
/// A client-certificate listener's shards hold no `BasicAuthenticator` and
/// never reach that path, so counting them would let a large certificate
/// deployment widen what unauthenticated callers can demand of a small Basic
/// one.
pub(super) fn basic_shard_count(listeners: &[ListenerPlan]) -> usize {
    listeners
        .iter()
        .filter(|plan| plan.listener.auth.basic_enabled())
        .map(|plan| plan.listener.shards)
        .sum()
}

/// Expand the configured listeners into one plan each, rejecting the
/// combinations that cannot be served.
pub(super) fn plan_listeners(config: &ServerConfig) -> anyhow::Result<Vec<ListenerPlan>> {
    if config.listeners.is_empty() {
        anyhow::bail!("at least one [[listeners]] entry is required");
    }

    let mut plans: Vec<ListenerPlan> = Vec::with_capacity(config.listeners.len());
    let mut total_shards = 0usize;

    for listener in &config.listeners {
        // Two listeners over one address is not merely a bind failure to let
        // the kernel report. A listener with more than one shard opens its
        // socket with SO_REUSEPORT, so a second listener on the same address
        // would join that load-balancing group and the kernel would hand it
        // connections meant for a different authentication mode.
        //
        // Wildcards count: `0.0.0.0` claims every IPv4 address on its port, and
        // `::` claims everything on its port. An overlapping pair is refused
        // rather than left to fail at bind time with an EADDRINUSE that says
        // nothing about which two listeners disagreed.
        let conflict = plans.iter().find_map(|plan| {
            if plan.listener.transport != listener.transport {
                return None;
            }
            let existing = plan.listener.listen_addr;
            listen_address_conflict(existing, listener.listen_addr)
                .map(|conflict| (existing, conflict))
        });
        if let Some((existing, conflict)) = conflict {
            let new = listener.listen_addr;
            match conflict {
                AddressConflict::Identical => anyhow::bail!(
                    "two listeners are configured for {existing}; \
                     each listener needs its own address"
                ),
                AddressConflict::SameAddress => anyhow::bail!(
                    "listeners {existing} and {new} are the same address written two ways; \
                     each listener needs its own address"
                ),
                AddressConflict::WildcardCovers => anyhow::bail!(
                    "listeners {existing} and {new} overlap; a wildcard address claims every \
                     address of its family on that port, and :: may claim IPv4 as well"
                ),
            }
        }

        // "One per core" has no single answer once the cores are shared between
        // listeners, and quietly giving every listener a full set would
        // oversubscribe the machine by the number of listeners.
        if listener.transport == ListenerTransport::Http2 && listener.shards != 1 {
            anyhow::bail!(
                "HTTP/2 listener {} must use shards = 1; one Tokio accept loop already \
                 dispatches its TCP connections across the runtime",
                listener.listen_addr
            );
        }

        if listener.transport == ListenerTransport::Http3
            && listener.shards == 0
            && config.listeners.len() > 1
        {
            anyhow::bail!(
                "listener {} uses shards = 0 (one per core), which has no meaning \
                 alongside other listeners; give each listener an explicit count",
                listener.listen_addr
            );
        }

        let shards = if listener.transport == ListenerTransport::Http3 {
            resolve_shard_count(listener.shards)
        } else {
            1
        };
        // Sharing one address needs SO_REUSEPORT, which only Linux provides in
        // the load-balancing form this depends on.
        if listener.transport == ListenerTransport::Http3
            && shards > 1
            && !cfg!(target_os = "linux")
        {
            anyhow::bail!(
                "listener {} asks for {shards} shards, which needs SO_REUSEPORT; \
                 that is Linux only, so set shards = 1",
                listener.listen_addr
            );
        }

        if listener.transport == ListenerTransport::Http3 {
            total_shards += shards;
        }
        plans.push(ListenerPlan {
            listener: ResolvedListener {
                listen_addr: listener.listen_addr,
                transport: listener.transport,
                shards,
                max_datagram_size: listener.max_datagram_size,
                tcp_targets: listener
                    .tcp_targets
                    .as_ref()
                    .map(crate::policy::TargetRestrictions::from_section)
                    .transpose()
                    .with_context(|| format!("listener {} tcp_targets", listener.listen_addr))?,
                udp_targets: listener
                    .udp_targets
                    .as_ref()
                    .map(crate::policy::TargetRestrictions::from_section)
                    .transpose()
                    .with_context(|| format!("listener {} udp_targets", listener.listen_addr))?,
                auth: listener.auth.clone(),
            },
        });
    }

    // Every shard costs two cross-shard queues in each direction and a slice of
    // the shared verification budget, so the cap is on the total rather than on
    // any one listener's share of it.
    if total_shards > MAX_SHARDS {
        anyhow::bail!(
            "{} listeners ask for {total_shards} shards in total, more than the \
             {MAX_SHARDS} this server runs",
            plans.len()
        );
    }

    Ok(plans)
}

/// Build only the roster selected by the active authentication mode.
///
/// Keeping this decision separate from binding makes the "ignored outside
/// client_cert" contract testable without opening sockets or loading TLS keys.
pub(super) fn active_client_registry(
    config: &ServerConfig,
    any_client_cert: bool,
) -> anyhow::Result<ClientRegistry> {
    if !any_client_cert {
        return Ok(ClientRegistry::default());
    }

    let clients = ClientRegistry::from_config(&config.clients)?;
    if clients.is_empty() {
        anyhow::bail!(
            "listener auth.mode = \"client_cert\" needs at least one [[clients]] entry; \
             run `masque-server enroll-client` to create one"
        );
    }
    Ok(clients)
}

/// Validate everything in a server configuration that does not require a
/// live listener or a TUN device.
///
/// This is intentionally side-effect-free so installers can qualify an
/// existing configuration with a candidate binary before replacing the
/// running version. Runtime-only failures such as an occupied UDP port or a
/// missing kernel TUN device are still reported when the server starts.
/// Returns the listeners the server would actually run, with their shard counts
/// resolved — `shards = 0` expanded to one per core and the cap applied — so a
/// caller reports what will run rather than what was asked for.
pub fn validate_config(config: &ServerConfig) -> anyhow::Result<Vec<ResolvedListener>> {
    let validated = validate_server_config(config)?;
    Ok(validated
        .listeners
        .iter()
        .map(|plan| plan.listener.clone())
        .collect())
}

pub(super) fn validate_server_config(
    config: &ServerConfig,
) -> anyhow::Result<ValidatedServerConfig> {
    let listeners = plan_listeners(config)?;
    let any_client_cert = any_client_cert_listener(config);

    // Validate both global policies before any listener binds or TUN setup.
    // Check disabled proxies too, so a malformed deny cannot be enabled later.
    TargetPolicy::new(
        &config.tcp_proxy.allow_targets,
        &config.tcp_proxy.deny_targets,
    )
    .context("tcp_proxy")?;
    TargetPolicy::new(
        &config.udp_proxy.allow_targets,
        &config.udp_proxy.deny_targets,
    )
    .context("udp_proxy")?;

    if !(1..=MAX_CONFIGURED_CONNECTIONS).contains(&config.server.max_connections) {
        anyhow::bail!(
            "server.max_connections ({}) must be between 1 and {}",
            config.server.max_connections,
            MAX_CONFIGURED_CONNECTIONS
        );
    }
    if !(1..=MAX_CONFIGURED_CONNECTIONS_PER_IP).contains(&config.server.max_connections_per_ip) {
        anyhow::bail!(
            "server.max_connections_per_ip ({}) must be between 1 and {}",
            config.server.max_connections_per_ip,
            MAX_CONFIGURED_CONNECTIONS_PER_IP
        );
    }
    if !(1..=MAX_PENDING_AUTH_GLOBAL).contains(&config.server.max_pending_auth_per_ip) {
        anyhow::bail!(
            "server.max_pending_auth_per_ip ({}) must be between 1 and {}",
            config.server.max_pending_auth_per_ip,
            MAX_PENDING_AUTH_GLOBAL
        );
    }
    if !(1..=MAX_TUNNELS_PER_CONNECTION).contains(&config.server.max_tunnels_per_connection) {
        anyhow::bail!(
            "server.max_tunnels_per_connection ({}) must be between 1 and {}",
            config.server.max_tunnels_per_connection,
            MAX_TUNNELS_PER_CONNECTION
        );
    }
    const MAX_TARGET_CONNECT_TIMEOUT_SECS: u64 = 300;
    if !(1..=MAX_TARGET_CONNECT_TIMEOUT_SECS).contains(&config.tcp_proxy.connect_timeout_secs) {
        anyhow::bail!(
            "tcp_proxy.connect_timeout_secs ({}) must be between 1 and {}",
            config.tcp_proxy.connect_timeout_secs,
            MAX_TARGET_CONNECT_TIMEOUT_SECS
        );
    }
    if !(1..=MAX_TARGET_CONNECT_TIMEOUT_SECS).contains(&config.udp_proxy.connect_timeout_secs) {
        anyhow::bail!(
            "udp_proxy.connect_timeout_secs ({}) must be between 1 and {}",
            config.udp_proxy.connect_timeout_secs,
            MAX_TARGET_CONNECT_TIMEOUT_SECS
        );
    }
    if config.quic.retry_connection_threshold == 0 {
        anyhow::bail!("quic.retry_connection_threshold must be at least 1");
    }
    if !(1..=300).contains(&config.quic.retry_token_ttl_secs) {
        anyhow::bail!(
            "quic.retry_token_ttl_secs ({}) must be between 1 and 300",
            config.quic.retry_token_ttl_secs
        );
    }

    if let Some(addr) = config.observability.listen_addr
        && !is_loopback(addr.ip())
    {
        anyhow::bail!(
            "observability.listen_addr ({addr}) must use a loopback address; \
             run Prometheus locally or forward the endpoint securely"
        );
    }

    // Surface a bad credential or active roster configuration first. A roster
    // outside client-cert mode is deliberately not parsed or allowed to
    // reserve pool addresses: the configuration contract says it is ignored.
    let clients = active_client_registry(config, any_client_cert)?;
    if any_client_cert {
        info!(
            clients = clients.len(),
            "client certificate authentication enabled"
        );
    } else if !config.clients.is_empty() {
        warn!(
            "[[clients]] entries are ignored unless a listener has auth.mode = \
             \"client_cert\" and auth.enabled = true"
        );
    }

    // Credentials are per listener, so a mistake in the second one has to name
    // the listener it came from or it cannot be found in a multi-listener file.
    for plan in &listeners {
        let addr = plan.listener.listen_addr;
        if plan.listener.auth.stealth && !plan.listener.auth.basic_enabled() {
            anyhow::bail!("listener {addr} auth.stealth requires enabled Basic authentication");
        }
        if plan.listener.auth.basic_enabled() {
            BasicAuthenticator::from_section(&plan.listener.auth)
                .with_context(|| format!("listener {addr}"))?;
        } else if !plan.listener.auth.client_cert_enabled() {
            warn!(%addr, "proxy authentication is disabled on this listener");
        }
    }

    // Flow-control autotuning only ever grows a window toward its ceiling, so
    // a ceiling below the advertised initial credit is a config mistake.
    if config.quic.max_connection_window < config.quic.initial_max_data {
        anyhow::bail!(
            "quic.max_connection_window ({}) must be at least quic.initial_max_data ({})",
            config.quic.max_connection_window,
            config.quic.initial_max_data
        );
    }
    if config.quic.max_stream_window < config.quic.initial_max_stream_data {
        anyhow::bail!(
            "quic.max_stream_window ({}) must be at least \
             quic.initial_max_stream_data ({})",
            config.quic.max_stream_window,
            config.quic.initial_max_stream_data
        );
    }
    if config.quic.max_connection_window > MAX_QUIC_CONNECTION_WINDOW {
        anyhow::bail!(
            "quic.max_connection_window ({}) must not exceed {} bytes",
            config.quic.max_connection_window,
            MAX_QUIC_CONNECTION_WINDOW
        );
    }
    if config.quic.max_stream_window > MAX_QUIC_STREAM_WINDOW {
        anyhow::bail!(
            "quic.max_stream_window ({}) must not exceed {} bytes",
            config.quic.max_stream_window,
            MAX_QUIC_STREAM_WINDOW
        );
    }
    if !(1..=MAX_QUIC_STREAMS_BIDI).contains(&config.quic.initial_max_streams_bidi) {
        anyhow::bail!(
            "quic.initial_max_streams_bidi ({}) must be between 1 and {}",
            config.quic.initial_max_streams_bidi,
            MAX_QUIC_STREAMS_BIDI
        );
    }
    for (name, value) in [
        ("dgram_recv_queue_len", config.quic.dgram_recv_queue_len),
        ("dgram_send_queue_len", config.quic.dgram_send_queue_len),
    ] {
        if !(1..=MAX_QUIC_DATAGRAM_QUEUE_LEN).contains(&value) {
            anyhow::bail!(
                "quic.{name} ({value}) must be between 1 and {MAX_QUIC_DATAGRAM_QUEUE_LEN}"
            );
        }
    }

    if !(quiche::MIN_CLIENT_INITIAL_LEN..=MAX_DATAGRAM_SIZE)
        .contains(&config.quic.max_datagram_size)
    {
        anyhow::bail!(
            "quic.max_datagram_size ({}) must be between {} and {} bytes",
            config.quic.max_datagram_size,
            quiche::MIN_CLIENT_INITIAL_LEN,
            MAX_DATAGRAM_SIZE
        );
    }
    for plan in &listeners {
        let Some(max_datagram_size) = plan.listener.max_datagram_size else {
            continue;
        };
        if plan.listener.transport != ListenerTransport::Http3 {
            anyhow::bail!(
                "listener {} max_datagram_size is an HTTP/3-only override; use \
                 http2.max_datagram_size for an HTTP/2 listener",
                plan.listener.listen_addr
            );
        }
        if !(quiche::MIN_CLIENT_INITIAL_LEN..=MAX_DATAGRAM_SIZE).contains(&max_datagram_size) {
            anyhow::bail!(
                "listener {} max_datagram_size ({max_datagram_size}) must be between {} and {} bytes",
                plan.listener.listen_addr,
                quiche::MIN_CLIENT_INITIAL_LEN,
                MAX_DATAGRAM_SIZE
            );
        }
    }

    for (name, size) in [
        ("udp_recv_buffer_size", config.quic.udp_recv_buffer_size),
        ("udp_send_buffer_size", config.quic.udp_send_buffer_size),
    ] {
        if size > 16 * 1024 * 1024 {
            anyhow::bail!(
                "quic.{name} must be between 0 and 16777216 bytes (0 keeps the OS default)"
            );
        }
    }

    if !(1..=MAX_HTTP2_STREAM_WINDOW).contains(&config.http2.initial_stream_window) {
        anyhow::bail!(
            "http2.initial_stream_window ({}) must be between 1 and {MAX_HTTP2_STREAM_WINDOW}",
            config.http2.initial_stream_window
        );
    }
    if !(1..=MAX_HTTP2_CONNECTION_WINDOW).contains(&config.http2.initial_connection_window) {
        anyhow::bail!(
            "http2.initial_connection_window ({}) must be between 1 and {MAX_HTTP2_CONNECTION_WINDOW}",
            config.http2.initial_connection_window
        );
    }
    if !(1..=MAX_HTTP2_CONCURRENT_STREAMS).contains(&config.http2.max_concurrent_streams) {
        anyhow::bail!(
            "http2.max_concurrent_streams ({}) must be between 1 and {}",
            config.http2.max_concurrent_streams,
            MAX_HTTP2_CONCURRENT_STREAMS
        );
    }
    if !(1..=MAX_HTTP2_HEADER_LIST_SIZE).contains(&config.http2.max_header_list_size) {
        anyhow::bail!(
            "http2.max_header_list_size ({}) must be between 1 and {}",
            config.http2.max_header_list_size,
            MAX_HTTP2_HEADER_LIST_SIZE
        );
    }
    if !(1..=MAX_HTTP2_SEND_BUFFER_SIZE).contains(&config.http2.max_send_buffer_size) {
        anyhow::bail!(
            "http2.max_send_buffer_size ({}) must be between 1 and {}",
            config.http2.max_send_buffer_size,
            MAX_HTTP2_SEND_BUFFER_SIZE
        );
    }
    const MAX_HTTP2_DATA_FRAME_BUDGET: usize = 16 * 1024 * 1024;
    if !(1..=MAX_HTTP2_DATA_FRAME_BUDGET).contains(&config.http2.data_frame_budget) {
        anyhow::bail!(
            "http2.data_frame_budget ({}) must be between 1 and \
             {MAX_HTTP2_DATA_FRAME_BUDGET}",
            config.http2.data_frame_budget
        );
    }
    if !(1..=65_527).contains(&config.http2.max_datagram_size) {
        anyhow::bail!(
            "http2.max_datagram_size ({}) must be between 1 and 65527 bytes",
            config.http2.max_datagram_size
        );
    }

    if config.ip_proxy.enabled && !(1..=u16::MAX as usize).contains(&config.ip_proxy.tun_mtu) {
        anyhow::bail!(
            "ip_proxy.tun_mtu ({}) must be between 1 and {}",
            config.ip_proxy.tun_mtu,
            u16::MAX
        );
    }

    if config.ip_proxy.enabled
        && config
            .ip_proxy
            .connect_protocols
            .iter()
            .any(|p| p == "connect-ip")
    {
        crate::uri::validate_ip_template(&config.ip_proxy.uri_template)
            .context("invalid ip_proxy.uri_template")?;
    }

    let mut address_pool = AddressPool::new(&config.ip_proxy.ipv4_pool, &config.ip_proxy.ipv6_pool)
        .map_err(|e| anyhow::anyhow!("address pool: {e}"))?;

    // Withhold every pinned address from dynamic allocation up front, so a
    // client that connects while a pinned peer is offline cannot take it.
    if config.ip_proxy.enabled {
        for (addr, owner) in clients.static_reservations() {
            address_pool.reserve_static(addr, owner).map_err(|e| {
                anyhow::anyhow!(
                    "client address {addr} cannot be reserved ({e}); pinned addresses \
                     must lie inside ip_proxy.ipv4_pool / ipv6_pool and must not be the \
                     pool's gateway address"
                )
            })?;
        }
    }

    // Build and discard the protocol configurations. This loads and matches
    // the certificate/key pair and exercises the same quiche setters a shard
    // will use, but has no network or device side effects.
    //
    // Once per listener rather than once per server: the authentication mode
    // decides which of two TLS contexts is built, so validating one listener's
    // would say nothing about another's.
    let tls = Arc::new(tls::SharedTlsIdentity::new(tls::TlsIdentity::load(
        &config.tls,
    )?));
    for plan in &listeners {
        let client_certs = plan
            .listener
            .auth
            .client_cert_enabled()
            .then(|| Arc::new(SharedRoster::new(clients.clone())));
        match plan.listener.transport {
            ListenerTransport::Http3 => {
                build_quic_config(
                    config,
                    plan.listener
                        .effective_quic_max_datagram_size(config.quic.max_datagram_size),
                    client_certs,
                    Arc::clone(&tls),
                )
                .with_context(|| format!("listener {}", plan.listener.listen_addr))?;
            }
            ListenerTransport::Http2 => {
                http2::build_acceptor(client_certs, Arc::clone(&tls))
                    .with_context(|| format!("listener {}", plan.listener.listen_addr))?;
            }
        }
    }
    if listeners
        .iter()
        .any(|plan| plan.listener.transport == ListenerTransport::Http3)
    {
        build_h3_config()?;
    }

    let total_shards = listeners
        .iter()
        .filter(|plan| plan.listener.transport == ListenerTransport::Http3)
        .map(|plan| plan.listener.shards)
        .sum();
    Ok(ValidatedServerConfig {
        clients,
        tls,
        listeners,
        total_shards,
        address_pool,
    })
}
