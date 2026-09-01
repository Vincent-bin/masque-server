//! Edits to an existing configuration file.
//!
//! Adding a listener is the one routine change to a deployed configuration
//! that has to be right the first time. A second socket is normally added to
//! serve a second authentication mode, and every way of getting it wrong — an
//! address that overlaps the running listener, a Basic listener without
//! credentials, a certificate listener with an empty roster — shows up as a
//! server that refuses to start. By then the listener that used to work is down
//! too, because both live in one process.
//!
//! So the edit is validated before anything is written: the merged text is
//! parsed, run through the same [`validate_config`] the server and
//! `check-config` use, and the new address is probed by binding it. What that
//! rules out is everything a configuration can be wrong about, plus the one
//! runtime condition that is worth catching here — an address already in use.
//! It is not a promise that the next start succeeds: the probe describes this
//! moment, and the port can be taken, or an interface removed, between the edit
//! and the restart. Verify the service after restarting it.
//!
//! The edit is a text append rather than a re-serialisation of the parsed
//! model. A deployed `masque.toml` is mostly comments explaining the tuning
//! knobs, and a round trip through `toml::to_string` would delete all of them.
//!
//! Concurrency is handled twice over, because losing another operator's edit is
//! silent and unrecoverable: an advisory lock keeps two of these commands off
//! one file, and the file is compared against what was read immediately before
//! it is replaced. The comparison catches ordinary editors and scripts that do
//! not honour the lock; like every portable compare-then-rename sequence, it
//! cannot control an uncooperative writer racing the final system call.

use std::fs::OpenOptions;
use std::io::{IsTerminal, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};
use zeroize::Zeroizing;

use crate::auth;
use crate::config::{
    self, AuthMode, AuthSection, BasicUser, ListenerSection, ListenerTransport, ServerConfig,
};
use crate::enroll::{self, ClientEndpoint, toml_string};
use crate::server::validate_config;

/// Bytes of entropy in a generated password, matching the installer's.
const GENERATED_PASSWORD_BYTES: usize = 24;

/// The first port offered for a second listener, when the operator has not
/// named one. Only a starting point: the suggestion walks upward past every
/// port the file already uses.
const SUGGESTED_PORT: u16 = 4443;

/// What the operator asked for on the command line.
///
/// Every optional field is prompted for when standard input is a terminal, and
/// required otherwise, so one code path serves both an interactive operator and
/// a provisioning script.
#[derive(Debug, Default)]
pub struct AddListener {
    pub listen_addr: Option<SocketAddr>,
    pub transport: Option<ListenerTransport>,
    pub mode: Option<AuthMode>,
    pub shards: Option<usize>,
    pub max_datagram_size: Option<usize>,
    pub username: Option<String>,
    pub password_hash: Option<String>,
    /// Read the password from standard input and hash it.
    pub password_stdin: bool,
    /// Optionally emit the client half of this newly created credential.
    pub client_output: Option<BasicClientOutput>,
    /// Write `enabled = false`, for a listener on a trusted network.
    pub disable_auth: bool,
    /// Hide failed Basic authentication behind an ordinary 404 response.
    pub stealth: bool,
    /// Do not try to bind the new address before writing it.
    pub no_bind_check: bool,
    /// Print the block that would be appended and leave the file alone.
    pub dry_run: bool,
    /// Skip the confirmation prompt.
    pub assume_yes: bool,
}

/// Select one Basic listener. The address is normally enough; transport
/// disambiguates the valid case where TCP/H2 and UDP/H3 share a numeric port.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicListenerSelector {
    pub listen_addr: Option<SocketAddr>,
    pub transport: Option<ListenerTransport>,
}

/// Add a user or replace one user's password hash.
#[derive(Debug, Default)]
pub struct BasicUserPassword {
    pub selector: BasicListenerSelector,
    pub username: String,
    pub password_hash: Option<String>,
    pub password_stdin: bool,
    pub client_output: Option<BasicClientOutput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicClientFormat {
    Surge,
}

#[derive(Debug)]
pub struct BasicClientOutput {
    pub format: BasicClientFormat,
    pub endpoint: ClientEndpoint,
    pub name: Option<String>,
    pub out: Option<PathBuf>,
}

/// Append one `[[listeners]]` block to `config_path`.
///
/// The configuration is re-read here rather than taken from the caller, and
/// `--cert` / `--key` overrides are deliberately not applied: what is validated
/// has to be the file exactly as the service will read it.
pub fn add_listener(config_path: &Path, request: AddListener) -> anyhow::Result<()> {
    // Held until this function returns, so a prompt that waits for an operator
    // cannot overlap with a second run of this command. A dry run changes
    // nothing and takes no lock, so it still works on a read-only copy.
    let _lock = (!request.dry_run)
        .then(|| EditLock::acquire(config_path))
        .transpose()?;

    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config = config::parse_toml(&text)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    // A file that is already invalid cannot say whether the new listener is the
    // thing that broke it, and appending to it would produce a file that still
    // does not start.
    validate_config(&config).with_context(|| {
        format!(
            "{} is not a valid configuration on its own, so a new listener cannot be \
             validated against it; nothing was written",
            config_path.display()
        )
    })?;

    // A piped password owns standard input, so there is no terminal left to
    // prompt on and every other value has to come from a flag.
    let interactive = std::io::stdin().is_terminal() && !request.password_stdin;

    let transport = match request.transport {
        Some(transport) => transport,
        None if interactive => prompt_transport(&config)?,
        None => ListenerTransport::Http3,
    };

    let listen_addr = match request.listen_addr {
        Some(addr) => addr,
        None if interactive => prompt_listen_addr(&config, transport)?,
        None => bail!("--listen-addr is required when standard input is not a terminal"),
    };

    let mode = match request.mode {
        Some(mode) => mode,
        None if request.disable_auth => AuthMode::Basic,
        None if interactive => prompt_mode(&config)?,
        None => bail!("--mode is required when standard input is not a terminal"),
    };

    // Credentials belong to one mode. Silently dropping them would leave an
    // operator believing a certificate listener also accepts a password.
    if mode == AuthMode::ClientCert
        && (request.username.is_some() || request.password_hash.is_some() || request.password_stdin)
    {
        bail!(
            "--username, --password-hash, and --password-stdin apply to --mode basic; \
             a client_cert listener authenticates against the [[clients]] roster, so \
             enroll the client instead"
        );
    }
    if request.client_output.is_some() {
        ensure!(
            !request.disable_auth && mode == AuthMode::Basic,
            "client configuration output applies only to an authenticated Basic listener"
        );
        ensure!(
            transport == ListenerTransport::Http3,
            "Surge MASQUE client output requires an HTTP/3 listener"
        );
    }
    if request.stealth {
        ensure!(
            !request.disable_auth && mode == AuthMode::Basic,
            "--stealth applies only to an authenticated Basic listener"
        );
    }

    let shards = match (transport, request.shards) {
        (ListenerTransport::Http2, Some(1) | None) => 1,
        (ListenerTransport::Http2, Some(shards)) => {
            bail!("HTTP/2 listeners must use --shards 1, not {shards}")
        }
        (ListenerTransport::Http3, Some(shards)) => shards,
        (ListenerTransport::Http3, None) if interactive => prompt_shards()?,
        (ListenerTransport::Http3, None) => 1,
    };
    if transport == ListenerTransport::Http2 && request.max_datagram_size.is_some() {
        bail!(
            "--max-datagram-size applies only to an HTTP/3 listener; use \
             [http2].max_datagram_size for HTTP/2"
        );
    }

    let mut resolved_password: Option<ResolvedUserPassword> = None;
    let auth = if request.disable_auth {
        AuthSection {
            enabled: false,
            mode,
            stealth: false,
            username: String::new(),
            password_hash: String::new(),
            users: Vec::new(),
        }
    } else {
        match mode {
            AuthMode::ClientCert => AuthSection {
                enabled: true,
                mode,
                stealth: false,
                username: String::new(),
                password_hash: String::new(),
                users: Vec::new(),
            },
            AuthMode::Basic => {
                let username = match request.username.clone() {
                    Some(username) => {
                        auth::check_username(&username)?;
                        username
                    }
                    None if interactive => prompt_username()?,
                    None => bail!("--username is required when standard input is not a terminal"),
                };
                let resolved =
                    resolve_password(&request, interactive, request.client_output.is_some())?;
                let password_hash = resolved.password_hash.clone();
                resolved_password = Some(resolved);
                AuthSection {
                    enabled: true,
                    mode,
                    stealth: request.stealth,
                    username: String::new(),
                    password_hash: String::new(),
                    users: vec![BasicUser {
                        username,
                        password_hash,
                    }],
                }
            }
        }
    };

    let listener = ListenerSection {
        listen_addr,
        transport,
        shards,
        max_datagram_size: request.max_datagram_size,
        auth,
    };

    let block = listener_toml_block(&listener);
    let merged = append_block(&text, &block);
    verify_merge(&config, &listener, &merged)?;

    // The same check `check-config` runs, on the file as it would be after the
    // edit: address overlap with an existing listener, a shard count that
    // cannot be honoured, an unusable password hash, a certificate listener
    // with no roster behind it.
    validate_config(&config::parse_toml(&merged)?).with_context(|| {
        format!(
            "the new listener would not start alongside the existing ones; \
             {} is unchanged",
            config_path.display()
        )
    })?;

    if !request.no_bind_check {
        probe_listen_addr(listen_addr, transport).with_context(|| {
            format!(
                "the new listener would not bind, and a listener that cannot bind stops \
                 the whole server — including the sockets that work today; {} is unchanged \
                 (pass --no-bind-check if the address only becomes available later)",
                config_path.display()
            )
        })?;
    }

    if request.dry_run {
        print!("{block}");
        eprintln!("# --dry-run: {} was not modified", config_path.display());
        return Ok(());
    }

    if interactive && !request.assume_yes {
        eprint!(
            "\n{block}\nAppend this listener to {}? [Y/n] ",
            config_path.display()
        );
        if !read_confirmation()? {
            eprintln!("nothing was written");
            return Ok(());
        }
    }

    // Deliver the only copy before committing the hash. In particular, a
    // broken pipe or full redirected output must leave the configuration
    // untouched instead of installing a credential the operator never saw.
    if let Some(password) = resolved_password
        .as_ref()
        .filter(|resolved| resolved.generated)
        .and_then(|resolved| resolved.plaintext.as_ref())
    {
        let username = listener
            .auth
            .users
            .first()
            .map(|user| user.username.as_str())
            .unwrap_or(&listener.auth.username);
        print_generated_password(username, password)?;
    }
    if let Some(output) = request.client_output.as_ref() {
        let username = listener
            .auth
            .users
            .first()
            .map(|user| user.username.as_str())
            .unwrap_or(&listener.auth.username);
        let password = resolved_password
            .as_ref()
            .and_then(|resolved| resolved.plaintext.as_ref())
            .context("client output requires a plaintext password")?;
        deliver_basic_client_config(output, username, password)?;
    }

    write_in_place(config_path, &text, &merged)?;

    println!(
        "added listener {listen_addr} transport={} auth={} shards={shards} to {}",
        transport.as_str(),
        auth_label(&listener.auth),
        config_path.display()
    );
    // A new socket is bound at startup, so unlike a roster change this cannot
    // be picked up by the running process. The unit the installer writes is
    // `masque`, not the program name.
    println!(
        "restart the server to bind it (systemd: systemctl restart masque), then check \
         that it came up; SIGHUP reloads TLS material and active Basic/certificate credentials"
    );
    if listen_addr.port() != 0 {
        println!(
            "the firewall has to allow {} {} as well",
            match transport {
                ListenerTransport::Http3 => "UDP",
                ListenerTransport::Http2 => "TCP",
            },
            listen_addr.port()
        );
    }

    Ok(())
}

/// Print Basic usernames without exposing password hashes.
pub fn list_basic_users(config_path: &Path, selector: BasicListenerSelector) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config = config::parse_toml(&text)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    validate_config(&config)?;

    let indices = if selector.listen_addr.is_none() && selector.transport.is_none() {
        config
            .listeners
            .iter()
            .enumerate()
            .filter_map(|(index, listener)| listener.auth.basic_enabled().then_some(index))
            .collect::<Vec<_>>()
    } else {
        vec![select_basic_listener(&config, selector)?]
    };
    if indices.is_empty() {
        bail!("the configuration has no Basic listener");
    }

    for index in indices {
        let listener = &config.listeners[index];
        println!(
            "listener {} transport={}",
            listener.listen_addr,
            listener.transport.as_str()
        );
        for (username, _) in effective_basic_users(&listener.auth) {
            println!("  {username}");
        }
    }
    Ok(())
}

/// Add one independently revocable credential to a Basic listener.
pub fn add_basic_user(config_path: &Path, request: BasicUserPassword) -> anyhow::Result<()> {
    edit_basic_user(config_path, UserEdit::Add(request))
}

/// Replace one Basic user's Argon2id hash.
pub fn set_basic_user_password(
    config_path: &Path,
    request: BasicUserPassword,
) -> anyhow::Result<()> {
    edit_basic_user(config_path, UserEdit::SetPassword(request))
}

/// Remove one Basic credential. The final user cannot be removed because that
/// would make the listener fail closed on its next reload or restart.
pub fn remove_basic_user(
    config_path: &Path,
    selector: BasicListenerSelector,
    username: String,
) -> anyhow::Result<()> {
    edit_basic_user(config_path, UserEdit::Remove { selector, username })
}

enum UserEdit {
    Add(BasicUserPassword),
    SetPassword(BasicUserPassword),
    Remove {
        selector: BasicListenerSelector,
        username: String,
    },
}

impl UserEdit {
    fn selector(&self) -> BasicListenerSelector {
        match self {
            Self::Add(request) | Self::SetPassword(request) => request.selector,
            Self::Remove { selector, .. } => *selector,
        }
    }

    fn username(&self) -> &str {
        match self {
            Self::Add(request) | Self::SetPassword(request) => &request.username,
            Self::Remove { username, .. } => username,
        }
    }
}

fn edit_basic_user(config_path: &Path, edit: UserEdit) -> anyhow::Result<()> {
    auth::check_username(edit.username())?;
    let _lock = EditLock::acquire(config_path)?;
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config = config::parse_toml(&text)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    validate_config(&config).with_context(|| {
        format!(
            "{} is not a valid configuration; no user was changed",
            config_path.display()
        )
    })?;
    let listener_index = select_basic_listener(&config, edit.selector())?;
    let client_output = match &edit {
        UserEdit::Add(request) => request.client_output.as_ref(),
        UserEdit::SetPassword(_) | UserEdit::Remove { .. } => None,
    };
    if client_output.is_some() {
        ensure!(
            config.listeners[listener_index].transport == ListenerTransport::Http3,
            "Surge MASQUE client output requires an HTTP/3 listener"
        );
    }
    let mut expected = config.clone();
    let expected_auth = &mut expected.listeners[listener_index].auth;
    migrate_legacy_basic_user(expected_auth);
    let username = edit.username().to_owned();
    let existing_position = expected_auth
        .users
        .iter()
        .position(|user| user.username == username);

    // Reject a semantic mistake before prompting for or hashing a password.
    // This matters interactively, and avoids spending an Argon2 slot locally
    // for an edit that can never be committed.
    match &edit {
        UserEdit::Add(_) => {
            ensure!(
                existing_position.is_none(),
                "Basic user {username:?} already exists; use set-password to replace its password"
            );
            ensure!(
                expected_auth.users.len() < auth::MAX_BASIC_USERS_PER_LISTENER,
                "a Basic listener may configure at most {} users",
                auth::MAX_BASIC_USERS_PER_LISTENER
            );
        }
        UserEdit::SetPassword(_) => {
            ensure!(
                existing_position.is_some(),
                "Basic user {username:?} does not exist"
            );
        }
        UserEdit::Remove { .. } => {
            ensure!(
                existing_position.is_some(),
                "Basic user {username:?} does not exist"
            );
            ensure!(
                expected_auth.users.len() > 1,
                "cannot remove the final Basic user from a listener"
            );
        }
    }

    let resolved_password = match &edit {
        UserEdit::Add(request) | UserEdit::SetPassword(request) => {
            Some(resolve_user_password(request, client_output.is_some())?)
        }
        UserEdit::Remove { .. } => None,
    };
    let replacement_hash = resolved_password
        .as_ref()
        .map(|resolved| resolved.password_hash.clone());

    match &edit {
        UserEdit::Add(_) => {
            expected_auth.users.push(BasicUser {
                username: username.clone(),
                password_hash: replacement_hash
                    .as_ref()
                    .expect("password edits resolve a hash")
                    .clone(),
            });
        }
        UserEdit::SetPassword(_) => {
            let user = &mut expected_auth.users
                [existing_position.expect("set-password checked that the user exists")];
            user.password_hash = replacement_hash
                .as_ref()
                .expect("password edits resolve a hash")
                .clone();
        }
        UserEdit::Remove { .. } => {
            expected_auth
                .users
                .remove(existing_position.expect("remove-user checked that the user exists"));
        }
    }

    let mut document = text
        .parse::<DocumentMut>()
        .context("failed to parse configuration as an editable TOML document")?;
    let auth_table = editable_auth_table(&mut document, listener_index)?;
    let users = canonical_users_table(auth_table)?;
    match &edit {
        UserEdit::Add(_) => {
            users.push(basic_user_table(
                &username,
                replacement_hash
                    .as_deref()
                    .expect("password edits resolve a hash"),
            ));
        }
        UserEdit::SetPassword(_) => {
            let table = users
                .iter_mut()
                .find(|table| table_username(table) == Some(username.as_str()))
                .with_context(|| format!("Basic user {username:?} does not exist"))?;
            table["password_hash"] = value(
                replacement_hash
                    .as_deref()
                    .expect("password edits resolve a hash"),
            );
        }
        UserEdit::Remove { .. } => {
            let position = users
                .iter()
                .position(|table| table_username(table) == Some(username.as_str()))
                .with_context(|| format!("Basic user {username:?} does not exist"))?;
            users.remove(position);
        }
    }

    let merged = document.to_string();
    let parsed = config::parse_toml(&merged)
        .context("the edited configuration would not parse; nothing was written")?;
    ensure!(
        parsed == expected,
        "the user edit would have changed unrelated configuration; nothing was written"
    );
    validate_config(&parsed).context("the edited configuration is invalid; nothing was written")?;

    // As with add-listener, deliver a generated secret before committing the
    // only usable representation of it (the hash) to disk.
    if let Some(password) = resolved_password
        .as_ref()
        .filter(|resolved| resolved.generated)
        .and_then(|resolved| resolved.plaintext.as_ref())
    {
        print_generated_password(&username, password)?;
    }
    if let Some(output) = client_output {
        let password = resolved_password
            .as_ref()
            .and_then(|resolved| resolved.plaintext.as_ref())
            .context("client output requires a plaintext password")?;
        deliver_basic_client_config(output, &username, password)?;
    }
    write_in_place(config_path, &text, &merged)?;

    let action = match edit {
        UserEdit::Add(_) => "added",
        UserEdit::SetPassword(_) => "updated password for",
        UserEdit::Remove { .. } => "removed",
    };
    let listener = &parsed.listeners[listener_index];
    println!(
        "{action} Basic user {username} on listener {} transport={} in {}",
        listener.listen_addr,
        listener.transport.as_str(),
        config_path.display()
    );
    println!(
        "reload the service to apply it without dropping tunnels (systemd: systemctl reload masque)"
    );
    Ok(())
}

struct ResolvedUserPassword {
    password_hash: String,
    plaintext: Option<Zeroizing<String>>,
    generated: bool,
}

fn resolve_user_password(
    request: &BasicUserPassword,
    retain_plaintext: bool,
) -> anyhow::Result<ResolvedUserPassword> {
    ensure!(
        !(request.password_hash.is_some() && request.password_stdin),
        "--password-hash conflicts with --password-stdin"
    );
    if let Some(hash) = &request.password_hash {
        ensure!(
            !retain_plaintext,
            "--password-hash cannot be combined with client configuration output because the plaintext password is unavailable"
        );
        return Ok(ResolvedUserPassword {
            password_hash: hash.clone(),
            plaintext: None,
            generated: false,
        });
    }
    if request.password_stdin {
        let mut password = Zeroizing::new(String::new());
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut password)?;
        let password = Zeroizing::new(trim_newline(&password).to_owned());
        check_password(&password)?;
        let password_hash = auth::hash_password(password.as_bytes())?;
        return Ok(ResolvedUserPassword {
            password_hash,
            plaintext: retain_plaintext.then_some(password),
            generated: false,
        });
    }
    if std::io::stdin().is_terminal()
        && let Some(password) = prompt_password(true)?
    {
        let password_hash = auth::hash_password(password.as_bytes())?;
        return Ok(ResolvedUserPassword {
            password_hash,
            plaintext: retain_plaintext.then_some(password),
            generated: false,
        });
    }

    let password = generate_password()?;
    Ok(ResolvedUserPassword {
        password_hash: auth::hash_password(password.as_bytes())?,
        plaintext: Some(password),
        generated: true,
    })
}

fn deliver_basic_client_config(
    output: &BasicClientOutput,
    username: &str,
    password: &str,
) -> anyhow::Result<()> {
    let name = output
        .name
        .clone()
        .unwrap_or_else(|| enroll::default_surge_proxy_name(&output.endpoint));
    let contents = Zeroizing::new(match output.format {
        BasicClientFormat::Surge => {
            enroll::surge_proxy_config(&name, &output.endpoint, username, password)?
        }
    });
    if let Some(path) = &output.out {
        enroll::write_client_config(path, &contents)?;
        println!(
            "Surge client configuration written to {} (contains the plaintext password)",
            path.display()
        );
        return Ok(());
    }

    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    writeln!(
        writer,
        "\n# Surge client configuration (contains the plaintext password):"
    )?;
    writer.write_all(contents.as_bytes())?;
    writer
        .flush()
        .context("failed to print the client configuration; configuration is unchanged")
}

fn select_basic_listener(
    config: &ServerConfig,
    selector: BasicListenerSelector,
) -> anyhow::Result<usize> {
    let matches = config
        .listeners
        .iter()
        .enumerate()
        .filter(|(_, listener)| {
            listener.auth.basic_enabled()
                && selector
                    .listen_addr
                    .is_none_or(|addr| listener.listen_addr == addr)
                && selector
                    .transport
                    .is_none_or(|transport| listener.transport == transport)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [index] => Ok(*index),
        [] => bail!("no Basic listener matches the requested address and transport"),
        _ => bail!(
            "more than one Basic listener matches; select one with --listen-addr and, when \
             TCP and UDP share a numeric address, --transport"
        ),
    }
}

fn effective_basic_users(auth: &AuthSection) -> Vec<(&str, &str)> {
    if auth.users.is_empty() {
        vec![(auth.username.as_str(), auth.password_hash.as_str())]
    } else {
        auth.users
            .iter()
            .map(|user| (user.username.as_str(), user.password_hash.as_str()))
            .collect()
    }
}

fn migrate_legacy_basic_user(auth: &mut AuthSection) {
    if auth.users.is_empty() {
        auth.users.push(BasicUser {
            username: std::mem::take(&mut auth.username),
            password_hash: std::mem::take(&mut auth.password_hash),
        });
    }
}

fn editable_auth_table(
    document: &mut DocumentMut,
    listener_index: usize,
) -> anyhow::Result<&mut Table> {
    document
        .get_mut("listeners")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|listeners| listeners.get_mut(listener_index))
        .and_then(|listener| listener.get_mut("auth"))
        .and_then(Item::as_table_mut)
        .with_context(|| format!("listener {} has no editable auth table", listener_index + 1))
}

fn canonical_users_table(auth: &mut Table) -> anyhow::Result<&mut ArrayOfTables> {
    let legacy_username = auth
        .get("username")
        .and_then(Item::as_str)
        .map(str::to_owned);
    let legacy_hash = auth
        .get("password_hash")
        .and_then(Item::as_str)
        .map(str::to_owned);

    if !auth.contains_key("users") {
        auth.insert("users", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let users = auth
        .get_mut("users")
        .and_then(Item::as_array_of_tables_mut)
        .context("listeners.auth.users is not an array of tables")?;

    match (legacy_username, legacy_hash) {
        (Some(username), Some(password_hash)) => {
            users.push(basic_user_table(&username, &password_hash));
            auth.remove("username");
            auth.remove("password_hash");
        }
        (None, None) => {}
        _ => bail!("legacy Basic username and password_hash must be configured together"),
    }
    Ok(auth
        .get_mut("users")
        .and_then(Item::as_array_of_tables_mut)
        .expect("users table was created above"))
}

fn basic_user_table(username: &str, password_hash: &str) -> Table {
    let mut table = Table::new();
    table["username"] = value(username);
    table["password_hash"] = value(password_hash);
    table
}

fn table_username(table: &Table) -> Option<&str> {
    table.get("username").and_then(Item::as_str)
}

/// Deliver a generated credential and make output failure observable before
/// its hash is committed to the configuration.
fn print_generated_password(username: &str, password: &str) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "generated password for {username}: {password}")
        .context("failed to print the generated password; configuration is unchanged")?;
    writeln!(
        output,
        "copy this password now; the configuration has not been written yet"
    )
    .context("failed to print the generated password notice; configuration is unchanged")?;
    output
        .flush()
        .context("failed to flush the generated password; configuration is unchanged")?;
    Ok(())
}

/// Bind the new address once, before it is written down.
///
/// `validate_config` is deliberately side-effect-free and therefore silent
/// about the one failure that hurts most here: an address something else
/// already holds. The server binds every listener at startup and exits if one
/// fails, so writing an occupied address turns the next restart into an outage
/// of the listeners that were working.
///
/// This is a probe, not a reservation. The port is free at this instant; a
/// service started in between can still take it.
fn probe_listen_addr(addr: SocketAddr, transport: ListenerTransport) -> anyhow::Result<()> {
    // Port 0 asks the kernel for whichever port is free at startup, so there is
    // nothing to probe and no address to be in use.
    if addr.port() == 0 {
        return Ok(());
    }

    // Deliberately without SO_REUSEPORT: a listener that binds with it would
    // join an existing group and silently take a share of another socket's
    // traffic, which is exactly what has to be reported rather than allowed.
    let result = match transport {
        ListenerTransport::Http3 => std::net::UdpSocket::bind(addr).map(drop),
        ListenerTransport::Http2 => std::net::TcpListener::bind(addr).map(drop),
    };
    match result {
        Ok(()) => Ok(()),
        // A privileged port without the privilege to bind it says nothing about
        // the server, which holds CAP_NET_BIND_SERVICE. Report and continue.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "warning: cannot test {addr} as this user ({e}); the service binds it with \
                 CAP_NET_BIND_SERVICE, so this was not checked"
            );
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("failed to bind {addr}")),
    }
}

/// How a listener's authentication reads once `enabled` is taken into account.
fn auth_label(auth: &AuthSection) -> &'static str {
    if auth.client_cert_enabled() {
        "client_cert"
    } else if auth.basic_enabled() {
        "basic"
    } else {
        "disabled"
    }
}

/// Render the `[[listeners]]` block for a new listener.
///
/// Credentials are emitted only for the mode that reads them: a `username` left
/// beside `mode = "client_cert"` would look like a live Basic credential to
/// whoever reads the file next.
pub fn listener_toml_block(listener: &ListenerSection) -> String {
    let mut block = String::from("# Added by `masque-server add-listener`.\n");
    block.push_str("[[listeners]]\n");
    block.push_str(&format!(
        "listen_addr = {}\n",
        toml_string(&listener.listen_addr.to_string())
    ));
    block.push_str(&format!(
        "transport = {}\n",
        toml_string(listener.transport.as_str())
    ));
    block.push_str(&format!("shards = {}\n", listener.shards));
    if let Some(max_datagram_size) = listener.max_datagram_size {
        block.push_str(&format!("max_datagram_size = {max_datagram_size}\n"));
    }
    block.push_str("\n[listeners.auth]\n");

    if !listener.auth.enabled {
        block.push_str("# Anyone who can reach this socket can use the proxy.\n");
        block.push_str("enabled = false\n");
        return block;
    }

    block.push_str("enabled = true\n");
    match listener.auth.mode {
        AuthMode::Basic => {
            block.push_str("mode = \"basic\"\n");
            if listener.auth.stealth {
                block.push_str("stealth = true\n");
            }
            for (username, password_hash) in effective_basic_users(&listener.auth) {
                block.push_str("\n[[listeners.auth.users]]\n");
                block.push_str(&format!("username = {}\n", toml_string(username)));
                block.push_str(&format!("password_hash = {}\n", toml_string(password_hash)));
            }
        }
        AuthMode::ClientCert => {
            block.push_str("mode = \"client_cert\"\n");
        }
    }
    block
}

/// Append `block` to `text`, separated by exactly one blank line.
fn append_block(text: &str, block: &str) -> String {
    let mut merged = text.trim_end().to_owned();
    if !merged.is_empty() {
        merged.push_str("\n\n");
    }
    merged.push_str(block);
    merged
}

/// Confirm that the merged text differs from the original by exactly one
/// listener.
///
/// The append is textual, so this is what rules out the ways text and TOML
/// disagree — a stray `[[listeners]]` inside a multi-line string, a file whose
/// last table would swallow the new keys, an unterminated array.
fn verify_merge(
    original: &ServerConfig,
    listener: &ListenerSection,
    merged: &str,
) -> anyhow::Result<()> {
    let parsed = config::parse_toml(merged)
        .context("the edited configuration would not parse; nothing was written")?;

    let mut without_new = parsed.clone();
    let appended = without_new.listeners.pop();

    ensure!(
        appended.as_ref() == Some(listener) && &without_new == original,
        "the edit would have changed more than the new listener; nothing was written"
    );
    Ok(())
}

// ── Password handling ─────────────────────────────────────────────────

/// Settle on the Argon2id hash to write, and the plaintext to show once when
/// this command was the thing that invented it.
fn resolve_password(
    request: &AddListener,
    interactive: bool,
    retain_plaintext: bool,
) -> anyhow::Result<ResolvedUserPassword> {
    if let Some(hash) = &request.password_hash {
        ensure!(
            !retain_plaintext,
            "--password-hash cannot be combined with client configuration output because the plaintext password is unavailable"
        );
        return Ok(ResolvedUserPassword {
            password_hash: hash.clone(),
            plaintext: None,
            generated: false,
        });
    }

    if request.password_stdin {
        let mut password = Zeroizing::new(String::new());
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut password)?;
        let password = Zeroizing::new(trim_newline(&password).to_owned());
        check_password(&password)?;
        return Ok(ResolvedUserPassword {
            password_hash: auth::hash_password(password.as_bytes())?,
            plaintext: retain_plaintext.then_some(password),
            generated: false,
        });
    }

    if interactive {
        let password = prompt_password(!request.dry_run)?;
        if let Some(password) = password {
            return Ok(ResolvedUserPassword {
                password_hash: auth::hash_password(password.as_bytes())?,
                plaintext: retain_plaintext.then_some(password),
                generated: false,
            });
        }
    }

    // A dry run returns before generated credentials are delivered, so
    // inventing one here would emit a hash without the only password copy.
    if request.dry_run {
        bail!(
            "--dry-run cannot generate a Basic password because its output would contain a \
             hash without the only copy of the password; provide --password-hash or \
             --password-stdin"
        );
    }

    // Nothing was supplied. A generated password is the safe default — the
    // alternative is a listener that cannot start — but it exists only in this
    // output, so the caller prints it exactly once.
    let password = generate_password()?;
    Ok(ResolvedUserPassword {
        password_hash: auth::hash_password(password.as_bytes())?,
        plaintext: Some(password),
        generated: true,
    })
}

/// A random password, hex encoded, matching what the installer generates.
fn generate_password() -> anyhow::Result<Zeroizing<String>> {
    use ring::rand::SecureRandom as _;

    let mut bytes = Zeroizing::new([0u8; GENERATED_PASSWORD_BYTES]);
    ring::rand::SystemRandom::new()
        .fill(&mut bytes[..])
        .map_err(|_| anyhow::anyhow!("the system random number generator is unavailable"))?;

    let mut password = Zeroizing::new(String::with_capacity(GENERATED_PASSWORD_BYTES * 2));
    for byte in bytes.iter() {
        password.push_str(&format!("{byte:02x}"));
    }
    Ok(password)
}

fn check_password(password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        bail!("the password must not be empty");
    }
    if password.chars().any(char::is_control) {
        bail!("the password must not contain control characters");
    }
    Ok(())
}

fn trim_newline(value: &str) -> &str {
    let value = value.strip_suffix('\n').unwrap_or(value);
    value.strip_suffix('\r').unwrap_or(value)
}

// ── Prompts ───────────────────────────────────────────────────────────
//
// Prompts and their echoes go to standard error, so `--dry-run | tee` and the
// final summary on standard output stay usable in a pipeline.

fn prompt_listen_addr(
    config: &ServerConfig,
    transport: ListenerTransport,
) -> anyhow::Result<SocketAddr> {
    let suggestion = suggest_listen_addr(config, transport);
    prompt_until_valid(
        "Listen address (ip:port)",
        &suggestion.to_string(),
        |line| {
            line.parse::<SocketAddr>().map_err(|e| {
                anyhow::anyhow!("{e}; write an address and port, for example 0.0.0.0:4443")
            })
        },
    )
}

/// An address the file does not already use.
///
/// Same IP as the first listener, because that is the interface the operator
/// already decided to expose, and the first free port at or above the
/// suggestion. Overlap is refused later anyway; this only keeps the default
/// from being one that would be.
fn suggest_listen_addr(config: &ServerConfig, transport: ListenerTransport) -> SocketAddr {
    let mut addr = config
        .listeners
        .first()
        .map(|listener| listener.listen_addr)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], SUGGESTED_PORT)));

    let used = |port: u16| {
        config
            .listeners
            .iter()
            .any(|listener| listener.transport == transport && listener.listen_addr.port() == port)
    };

    let mut port = SUGGESTED_PORT;
    while used(port) && port < u16::MAX {
        port += 1;
    }
    addr.set_port(port);
    addr
}

fn prompt_transport(config: &ServerConfig) -> anyhow::Result<ListenerTransport> {
    let suggestion = if config
        .listeners
        .iter()
        .any(|listener| listener.transport == ListenerTransport::Http2)
    {
        "http3"
    } else {
        "http2"
    };
    prompt_until_valid("Transport (http3 | http2)", suggestion, |line| match line {
        "http3" | "h3" => Ok(ListenerTransport::Http3),
        "http2" | "h2" => Ok(ListenerTransport::Http2),
        other => bail!("unknown transport {other:?}; write http3 or http2"),
    })
}

fn prompt_mode(config: &ServerConfig) -> anyhow::Result<AuthMode> {
    // Suggest the mode the file does not serve yet: a second listener is
    // almost always added to accept the other kind of client.
    let suggestion = if config
        .listeners
        .iter()
        .any(|listener| listener.auth.client_cert_enabled())
    {
        "basic"
    } else {
        "client_cert"
    };

    prompt_until_valid(
        "Authentication mode (basic | client_cert)",
        suggestion,
        |line| match line {
            "basic" => Ok(AuthMode::Basic),
            "client_cert" | "client-cert" | "cert" => Ok(AuthMode::ClientCert),
            other => bail!("unknown mode {other:?}; write basic or client_cert"),
        },
    )
}

fn prompt_shards() -> anyhow::Result<usize> {
    prompt_until_valid("Event loops for this listener (shards)", "1", |line| {
        let shards: usize = line.parse().context("shards must be a whole number")?;
        ensure!(
            shards > 0,
            "shards must be at least 1 alongside other listeners"
        );
        Ok(shards)
    })
}

fn prompt_username() -> anyhow::Result<String> {
    prompt_until_valid("Basic authentication username", "masque", |line| {
        auth::check_username(line)?;
        Ok(line.to_owned())
    })
}

/// Read a password twice without echoing it, or `None` when generation is
/// allowed and the operator leaves it empty.
fn prompt_password(allow_generate: bool) -> anyhow::Result<Option<Zeroizing<String>>> {
    let prompt = if allow_generate {
        "Password (empty to generate a strong one): "
    } else {
        "Password (--dry-run requires an explicit password): "
    };
    let password = read_hidden_line(prompt)?;
    if password.is_empty() {
        if !allow_generate {
            bail!(
                "--dry-run cannot generate a Basic password because its output would contain a \
                 hash without the only copy of the password; provide --password-hash or \
                 --password-stdin"
            );
        }
        return Ok(None);
    }
    check_password(&password)?;

    let repeat = read_hidden_line("Repeat password: ")?;
    if repeat.as_str() != password.as_str() {
        bail!("the passwords did not match; nothing was written");
    }
    Ok(Some(password))
}

fn read_confirmation() -> anyhow::Result<bool> {
    let line = read_line()?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    ))
}

/// Prompt until `parse` accepts an answer, reporting each rejection in place.
fn prompt_until_valid<T>(
    label: &str,
    default: &str,
    parse: impl Fn(&str) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    loop {
        eprint!("{label} [{default}]: ");
        let line = read_line()?;
        let answer = if line.trim().is_empty() {
            default
        } else {
            line.trim()
        };
        match parse(answer) {
            Ok(value) => return Ok(value),
            Err(e) => eprintln!("  {e:#}"),
        }
    }
}

fn read_line() -> anyhow::Result<String> {
    std::io::stderr().flush()?;
    let mut line = String::new();
    // End of input during a prompt means the caller is not answering, and
    // looping on it forever would spin.
    if std::io::stdin().read_line(&mut line)? == 0 {
        bail!("standard input ended before the question was answered; nothing was written");
    }
    Ok(line)
}

#[cfg(unix)]
fn read_hidden_line(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    use std::os::fd::AsRawFd as _;

    /// Restores the terminal on every exit path, including an error return.
    struct EchoOff {
        fd: i32,
        saved: libc::termios,
        active: bool,
    }

    impl EchoOff {
        fn restore(&mut self) -> std::io::Result<()> {
            if !self.active {
                return Ok(());
            }
            // SAFETY: `saved` was filled by tcgetattr on this descriptor.
            if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            self.active = false;
            Ok(())
        }
    }

    impl Drop for EchoOff {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    eprint!("{prompt}");
    std::io::stderr().flush()?;

    let fd = std::io::stdin().as_raw_fd();
    let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: writes a termios into our own uninitialised storage.
    if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "failed to inspect terminal settings; refusing to read a password that might echo",
        );
    }
    // SAFETY: tcgetattr returned success, so the value is initialised.
    let saved = unsafe { saved.assume_init() };
    let mut quiet = saved;
    quiet.c_lflag &= !libc::ECHO;
    // SAFETY: `quiet` is a complete termios for this descriptor.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to disable terminal echo; no password was read");
    }
    let mut guard = EchoOff {
        fd,
        saved,
        active: true,
    };

    let mut line = Zeroizing::new(String::new());
    if std::io::stdin().read_line(&mut line)? == 0 {
        bail!("standard input ended before the password was entered; nothing was written");
    }
    guard
        .restore()
        .context("failed to restore terminal echo; configuration is unchanged")?;
    // The newline the operator typed was not echoed, so the next output would
    // otherwise continue on the prompt's line.
    eprintln!();
    Ok(Zeroizing::new(trim_newline(&line).to_owned()))
}

#[cfg(not(unix))]
fn read_hidden_line(_prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    bail!(
        "hidden password input is unavailable on this platform; use --password-stdin or \
         --password-hash so the password is not echoed"
    )
}

// ── Writing ───────────────────────────────────────────────────────────

/// Replace a configuration file with new contents, atomically, provided it is
/// still the file that was read.
///
/// Written to a sibling temporary file and renamed, so a crash or a full disk
/// leaves the previous configuration intact rather than a half-written one that
/// the next start would reject. Mode and ownership are carried over: the file
/// holds a password hash, and a service that runs as another user still has to
/// be able to read it.
///
/// `expected` is the text this edit was built on. Anything that changed the
/// file since — an editor, a script appending `[[clients]]`, an operator on
/// another session — would be silently discarded by the rename, so it aborts
/// instead. The advisory lock does not cover this: it binds only other runs of
/// this command.
fn write_in_place(path: &Path, expected: &str, contents: &str) -> anyhow::Result<()> {
    // Follow symlinks rather than replacing them: an operator who points
    // /etc/masque/masque.toml at a file kept elsewhere means to edit the target.
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("failed to resolve {}", path.display()))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "masque.toml".into());
    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;

    let temp = TempPath(dir.join(format!(".{name}.new.{}", std::process::id())));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        // Owner-only until the original file's mode is applied below, so the
        // password hash is never briefly world-readable.
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp.0)
        .with_context(|| format!("failed to create {}", temp.0.display()))?;

    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", temp.0.display()))?;
    #[cfg(unix)]
    preserve_owner(&file, &metadata)?;
    file.set_permissions(metadata.permissions())
        .with_context(|| format!("failed to set the mode of {}", temp.0.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", temp.0.display()))?;
    drop(file);

    // Keep this comparison after the new file is completely prepared and as
    // close to rename as portable APIs allow. Checking before the potentially
    // slow write and fsync would leave a much wider window in which an editor
    // could make a change that the rename then silently discards.
    let current = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to re-read {}", path.display()))?;
    if current != expected {
        bail!(
            "{} changed while this edit was being prepared, and applying it would discard \
             that change; nothing was written, so run the command again",
            path.display()
        );
    }

    std::fs::rename(&temp.0, &path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    temp.keep();

    // Make the rename itself durable, so a crash cannot resurrect the old file.
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Give the replacement the owner the original had.
///
/// Only matters when the editor is root and the file belongs to the service
/// user: a configuration the service cannot read is a server that will not
/// start, which is exactly what this command exists to prevent.
#[cfg(unix)]
fn preserve_owner(file: &std::fs::File, original: &std::fs::Metadata) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let current = file.metadata()?;
    if current.uid() == original.uid() && current.gid() == original.gid() {
        return Ok(());
    }

    // SAFETY: a descriptor we own, with ids read from the file being replaced.
    let changed = unsafe { libc::fchown(file.as_raw_fd(), original.uid(), original.gid()) };
    if changed != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "failed to keep the configuration file's owner; run this as root or as the \
             file's owner",
        );
    }
    Ok(())
}

/// An advisory lock held for one edit, from the first read to the rename.
///
/// Two operators adding a listener at the same time would each read the file,
/// each validate their own listener against it, and the second rename would
/// drop the first listener without any error. The window is as long as an
/// interactive session, so it is wide enough to hit.
///
/// The lock lives beside the configuration rather than on it: the file itself
/// is replaced by a rename, so a lock taken on its inode would stop describing
/// the path halfway through. `flock` is released by the kernel when the process
/// exits, so an interrupted edit cannot leave the file locked; the lock file is
/// left in place, since unlinking it is what makes such schemes racy.
struct EditLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl EditLock {
    #[cfg(unix)]
    fn acquire(config_path: &Path) -> anyhow::Result<Self> {
        use std::os::fd::AsRawFd as _;

        let path = lock_path(config_path);
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open the edit lock {}", path.display()))?;

        // SAFETY: a descriptor this function owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!(
                    "another masque-server is editing {}; finish or cancel it first",
                    config_path.display()
                );
            }
            return Err(error).with_context(|| format!("failed to lock {}", path.display()));
        }

        Ok(Self { file })
    }

    /// Without `flock` there is no lock to take, and the compare-and-swap in
    /// [`write_in_place`] is what keeps a concurrent edit from being lost.
    #[cfg(not(unix))]
    fn acquire(_config_path: &Path) -> anyhow::Result<Self> {
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for EditLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        // SAFETY: our own descriptor, still open until this returns.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(unix)]
fn lock_path(config_path: &Path) -> PathBuf {
    let name = config_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "masque.toml".into());
    config_path.with_file_name(format!(".{name}.lock"))
}

/// A temporary file that is removed unless the rename claimed it.
struct TempPath(PathBuf);

impl TempPath {
    fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_CONFIG: &str = r#"# A deployed file is mostly comments.
[tls]
cert_path = "certs/server.crt"

[[listeners]]
listen_addr = "0.0.0.0:443"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$hash"
"#;

    fn client_cert_listener(port: u16) -> ListenerSection {
        ListenerSection {
            listen_addr: format!("0.0.0.0:{port}").parse().unwrap(),
            transport: config::ListenerTransport::Http3,
            shards: 1,
            max_datagram_size: None,
            auth: AuthSection {
                enabled: true,
                mode: AuthMode::ClientCert,
                stealth: false,
                username: String::new(),
                password_hash: String::new(),
                users: Vec::new(),
            },
        }
    }

    #[test]
    fn appended_listener_parses_back_to_what_was_asked_for() {
        let listener = client_cert_listener(4443);
        let merged = append_block(BASIC_CONFIG, &listener_toml_block(&listener));

        let parsed = config::parse_toml(&merged).unwrap();
        assert_eq!(parsed.listeners.len(), 2);
        assert_eq!(parsed.listeners[1], listener);
        assert!(listener_toml_block(&listener).contains("transport = \"http3\""));
    }

    #[test]
    fn listener_block_preserves_an_http3_datagram_size_override() {
        let mut listener = client_cert_listener(4443);
        listener.max_datagram_size = Some(1200);
        let block = listener_toml_block(&listener);
        assert!(block.contains("max_datagram_size = 1200"));

        let parsed = config::parse_toml(&append_block(BASIC_CONFIG, &block)).unwrap();
        assert_eq!(parsed.listeners[1], listener);
    }

    /// The edit is textual, so the comments an operator relies on must survive
    /// it. That is the whole reason the file is not re-serialised.
    #[test]
    fn appending_keeps_the_existing_text_and_its_comments() {
        let merged = append_block(
            BASIC_CONFIG,
            &listener_toml_block(&client_cert_listener(4443)),
        );
        assert!(merged.starts_with("# A deployed file is mostly comments.\n"));
        assert!(merged.contains("username = \"alice\""));
    }

    #[test]
    fn a_basic_listener_carries_its_own_credentials() {
        let listener = ListenerSection {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            transport: config::ListenerTransport::Http3,
            shards: 2,
            max_datagram_size: None,
            auth: AuthSection {
                enabled: true,
                mode: AuthMode::Basic,
                stealth: false,
                username: String::new(),
                password_hash: String::new(),
                users: vec![BasicUser {
                    username: "bob".into(),
                    password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$hash".into(),
                }],
            },
        };
        let parsed =
            config::parse_toml(&append_block(BASIC_CONFIG, &listener_toml_block(&listener)))
                .unwrap();
        assert_eq!(parsed.listeners[1], listener);
    }

    /// A certificate listener reads no username or password, and leaving one in
    /// the file would read as a live Basic credential.
    #[test]
    fn a_certificate_listener_writes_no_credentials() {
        let block = listener_toml_block(&client_cert_listener(4443));
        assert!(!block.contains("username"));
        assert!(!block.contains("password_hash"));
    }

    #[test]
    fn a_disabled_listener_states_only_that_it_is_disabled() {
        let listener = ListenerSection {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            transport: config::ListenerTransport::Http3,
            shards: 1,
            max_datagram_size: None,
            auth: AuthSection {
                enabled: false,
                mode: AuthMode::Basic,
                stealth: false,
                username: String::new(),
                password_hash: String::new(),
                users: Vec::new(),
            },
        };
        let block = listener_toml_block(&listener);
        assert!(block.contains("enabled = false"));
        assert!(!block.contains("mode ="));

        let parsed = config::parse_toml(&append_block(BASIC_CONFIG, &block)).unwrap();
        assert!(!parsed.listeners[1].auth.enabled);
    }

    /// A file that does not end in a newline is still a valid TOML file, and
    /// appending to it must not glue the block onto its last line.
    #[test]
    fn appending_repairs_a_missing_trailing_newline() {
        let without_newline = BASIC_CONFIG.trim_end();
        let merged = append_block(
            without_newline,
            &listener_toml_block(&client_cert_listener(4443)),
        );
        assert!(config::parse_toml(&merged).is_ok());
        assert!(merged.contains("$hash\"\n\n# Added by"));
    }

    #[test]
    fn the_merge_check_accepts_exactly_one_new_listener() {
        let original = config::parse_toml(BASIC_CONFIG).unwrap();
        let listener = client_cert_listener(4443);
        let merged = append_block(BASIC_CONFIG, &listener_toml_block(&listener));
        verify_merge(&original, &listener, &merged).unwrap();
    }

    /// The guard against a textual append that changes something else: here the
    /// block lands on a file whose parsed form no longer matches.
    #[test]
    fn the_merge_check_rejects_a_changed_original() {
        let original = config::parse_toml(BASIC_CONFIG).unwrap();
        let listener = client_cert_listener(4443);
        let tampered = append_block(
            &BASIC_CONFIG.replace("username = \"alice\"", "username = \"mallory\""),
            &listener_toml_block(&listener),
        );

        let error = verify_merge(&original, &listener, &tampered).unwrap_err();
        assert!(
            error.to_string().contains("more than the new listener"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_suggested_port_skips_the_ports_already_in_use() {
        let mut config = config::parse_toml(BASIC_CONFIG).unwrap();
        config.listeners.push(client_cert_listener(SUGGESTED_PORT));
        assert_eq!(
            suggest_listen_addr(&config, ListenerTransport::Http3).port(),
            SUGGESTED_PORT + 1
        );
        assert_eq!(
            suggest_listen_addr(&config, ListenerTransport::Http3).ip(),
            config.listeners[0].listen_addr.ip()
        );
    }

    #[test]
    fn generated_passwords_are_hex_and_unique() {
        let first = generate_password().unwrap();
        let second = generate_password().unwrap();
        assert_eq!(first.len(), GENERATED_PASSWORD_BYTES * 2);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first.as_str(), second.as_str());
    }

    /// A directory of this test's own, since these tests write files and run in
    /// parallel inside one process.
    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("masque-edit-{}-{label}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The file holds a password hash, so an edit must not widen who can read
    /// it — and must not narrow it either, or the service loses access.
    #[cfg(unix)]
    #[test]
    fn rewriting_keeps_the_original_file_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("mode");
        let path = dir.join("masque.toml");
        std::fs::write(&path, BASIC_CONFIG).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        write_in_place(&path, BASIC_CONFIG, "replaced\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replaced\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The rename is a whole-file replacement, so anything written between the
    /// read and the write would be discarded without a trace. Refuse instead.
    #[test]
    fn rewriting_refuses_a_file_that_changed_since_it_was_read() {
        let dir = scratch_dir("concurrent");
        let path = dir.join("masque.toml");
        std::fs::write(&path, BASIC_CONFIG).unwrap();

        let by_someone_else = format!("{BASIC_CONFIG}\n[[clients]]\nname = \"phone\"\n");
        std::fs::write(&path, &by_someone_else).unwrap();

        let error = write_in_place(&path, BASIC_CONFIG, "replaced\n").unwrap_err();
        assert!(
            error.to_string().contains("changed while this edit"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            by_someone_else,
            "the other edit must survive"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two operators editing at once is the case the compare-and-swap above
    /// reports late and this reports early, before either has typed anything.
    #[cfg(unix)]
    #[test]
    fn one_edit_locks_out_another() {
        let dir = scratch_dir("lock");
        let path = dir.join("masque.toml");
        std::fs::write(&path, BASIC_CONFIG).unwrap();

        let held = EditLock::acquire(&path).unwrap();
        let error = EditLock::acquire(&path)
            .err()
            .expect("a second edit must not take the lock");
        assert!(
            error
                .to_string()
                .contains("another masque-server is editing"),
            "unexpected error: {error}"
        );

        drop(held);
        EditLock::acquire(&path).expect("the lock is released with the edit");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `validate_config` cannot see an occupied port, and a listener that fails
    /// to bind takes the whole server down with it at the next start.
    #[test]
    fn the_bind_probe_reports_an_address_already_in_use() {
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap();
        assert!(probe_listen_addr(addr, ListenerTransport::Http3).is_err());

        drop(occupied);
        probe_listen_addr(addr, ListenerTransport::Http3).expect("a free address passes");
    }

    #[test]
    fn the_http2_bind_probe_checks_tcp() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap();
        assert!(probe_listen_addr(addr, ListenerTransport::Http2).is_err());

        drop(occupied);
        probe_listen_addr(addr, ListenerTransport::Http2).expect("a free TCP address passes");
    }

    /// Port 0 has nothing to probe: the kernel picks a free port when the
    /// server binds, which is a different port every time.
    #[test]
    fn the_bind_probe_accepts_an_ephemeral_port() {
        probe_listen_addr("127.0.0.1:0".parse().unwrap(), ListenerTransport::Http3).unwrap();
    }
}
