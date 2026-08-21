//! `add-listener` edits a deployed configuration file, so the guarantee under
//! test is what survives the edit: the file either gains exactly one working
//! listener, or is left byte for byte as it was.

use std::io::Write as _;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::x509::{X509Builder, X509NameBuilder};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static SEQUENCE: AtomicU32 = AtomicU32::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "masque-add-listener-{}-{nonce}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn write_server_identity(dir: &Path) -> (PathBuf, PathBuf) {
    let key = p256_key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();

    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();

    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert.build().to_pem().unwrap()).unwrap();
    std::fs::write(
        &key_path,
        key.ec_key().unwrap().private_key_to_pem().unwrap(),
    )
    .unwrap();
    (cert_path, key_path)
}

/// A single Basic listener, with the comments a deployed file carries and a
/// roster entry ready for a certificate listener.
fn basic_config_text(cert_path: &Path, key_path: &Path, with_client: bool) -> String {
    let password_hash = masque::auth::hash_password(b"correct horse battery staple").unwrap();
    let roster = if with_client {
        format!(
            "\n[[clients]]\nname = \"laptop\"\npublic_key = \"{}\"\n",
            STANDARD.encode(p256_key().public_key_to_der().unwrap())
        )
    } else {
        String::new()
    };

    format!(
        r#"# Deployed configuration. The comments explain the tuning knobs.
[tls]
cert_path = "{}"
key_path = "{}"

[ip_proxy]
enabled = false

[[listeners]]
listen_addr = "127.0.0.1:8449"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"
username = "alice"
password_hash = "{password_hash}"
{roster}"#,
        cert_path.display(),
        key_path.display()
    )
}

struct Fixture {
    _dir: TempDir,
    config_path: PathBuf,
    original: String,
}

impl Fixture {
    fn new(with_client: bool) -> Self {
        let dir = TempDir::new();
        let (cert_path, key_path) = write_server_identity(dir.path());
        let config_path = dir.path().join("masque.toml");
        let original = basic_config_text(&cert_path, &key_path, with_client);
        std::fs::write(&config_path, &original).unwrap();
        Self {
            _dir: dir,
            config_path,
            original,
        }
    }

    fn add_listener(&self, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_masque-server"));
        command
            .arg("--config")
            .arg(&self.config_path)
            .arg("add-listener")
            .args(args);
        command.output().unwrap()
    }

    fn text(&self) -> String {
        std::fs::read_to_string(&self.config_path).unwrap()
    }

    fn config(&self) -> masque::config::ServerConfig {
        masque::config::parse_toml(&self.text()).unwrap()
    }

    fn assert_unchanged(&self) {
        assert_eq!(
            self.text(),
            self.original,
            "a rejected edit must leave the file exactly as it was"
        );
    }
}

#[test]
fn adds_a_certificate_listener_beside_a_basic_one() {
    let fixture = Fixture::new(true);
    let output =
        fixture.add_listener(&["--listen-addr", "127.0.0.1:8450", "--mode", "client-cert"]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = fixture.config();
    assert_eq!(config.listeners.len(), 2);
    assert_eq!(
        config.listeners[1].listen_addr.to_string(),
        "127.0.0.1:8450"
    );
    assert!(config.listeners[1].auth.client_cert_enabled());
    assert_eq!(config.listeners[1].shards, 1);
    // The first listener is untouched, comments and all.
    assert!(config.listeners[0].auth.basic_enabled());
    assert!(fixture.text().starts_with("# Deployed configuration."));

    // The edited file is what the server would read, so the preflight it ships
    // with has to agree.
    let check = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&fixture.config_path)
        .arg("check-config")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(check.status.success(), "check-config rejected the edit");
    assert!(stdout.contains("listener 127.0.0.1:8450 transport=http3 auth=client_cert shards=1"));
}

#[test]
fn adds_a_basic_listener_with_a_password_read_from_stdin() {
    let fixture = Fixture::new(false);
    let mut child = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&fixture.config_path)
        .arg("add-listener")
        .args([
            "--listen-addr",
            "127.0.0.1:8451",
            "--mode",
            "basic",
            "--username",
            "bob",
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a-strong-password\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = fixture.config();
    assert_eq!(config.listeners.len(), 2);
    assert_eq!(config.listeners[1].auth.username, "bob");
    assert!(
        config.listeners[1]
            .auth
            .password_hash
            .starts_with("$argon2id$"),
        "the password must be written as an Argon2id hash, never in the clear"
    );
    assert!(
        !fixture.text().contains("a-strong-password"),
        "the plaintext password must not reach the file"
    );
}

/// Without a flag or a terminal there is no password to write, and a Basic
/// listener with none cannot start. One is generated and printed instead — the
/// same choice the installer makes.
#[test]
fn generates_a_password_when_a_script_supplies_none() {
    let fixture = Fixture::new(false);
    let output = fixture.add_listener(&[
        "--listen-addr",
        "127.0.0.1:8452",
        "--mode",
        "basic",
        "--username",
        "carol",
    ]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("generated password for carol:"),
        "the generated password is the only copy, so it has to be printed: {stdout}"
    );
    assert!(
        stdout.find("generated password for carol:") < stdout.find("added listener"),
        "the only password copy must be delivered before its hash is committed: {stdout}"
    );
    assert!(
        fixture.config().listeners[1]
            .auth
            .password_hash
            .starts_with("$argon2id$")
    );
}

/// A dry-run block is often redirected for review or provisioning. Generating
/// a password but returning before printing its only copy would make that block
/// impossible to authenticate to.
#[test]
fn dry_run_refuses_to_generate_an_unrecoverable_password() {
    let fixture = Fixture::new(false);
    let output = fixture.add_listener(&[
        "--listen-addr",
        "127.0.0.1:8461",
        "--mode",
        "basic",
        "--username",
        "dave",
        "--dry-run",
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--dry-run cannot generate a Basic password"),
        "unexpected diagnostic: {stderr}"
    );
    fixture.assert_unchanged();
}

#[test]
fn refuses_an_address_that_overlaps_the_existing_listener() {
    let fixture = Fixture::new(true);
    let output =
        fixture.add_listener(&["--listen-addr", "127.0.0.1:8449", "--mode", "client-cert"]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("two listeners are configured for"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_unchanged();
}

#[test]
fn adds_http2_on_the_same_numeric_port_as_http3() {
    let fixture = Fixture::new(true);
    let output = fixture.add_listener(&[
        "--transport",
        "http2",
        "--listen-addr",
        "127.0.0.1:8449",
        "--mode",
        "client-cert",
        "--no-bind-check",
    ]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = fixture.config();
    assert_eq!(
        config.listeners[1].transport,
        masque::config::ListenerTransport::Http2
    );
    assert_eq!(
        config.listeners[1].listen_addr,
        config.listeners[0].listen_addr
    );
    assert_eq!(config.listeners[1].shards, 1);
    assert!(fixture.text().contains("transport = \"http2\""));
}

/// A certificate listener with an empty roster is refused at startup, so
/// writing one would produce a file that takes the working listener down with
/// it at the next restart.
#[test]
fn refuses_a_certificate_listener_with_no_roster() {
    let fixture = Fixture::new(false);
    let output =
        fixture.add_listener(&["--listen-addr", "127.0.0.1:8453", "--mode", "client-cert"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("enroll-client"),
        "the error has to name the fix: {stderr}"
    );
    fixture.assert_unchanged();
}

/// The configuration file spells this mode `client_cert`, so the flag takes
/// that spelling too rather than insisting on clap's hyphenated form.
#[test]
fn mode_accepts_the_configuration_files_spelling() {
    let fixture = Fixture::new(true);
    let output =
        fixture.add_listener(&["--listen-addr", "127.0.0.1:8456", "--mode", "client_cert"]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.config().listeners[1].auth.client_cert_enabled());
}

/// `check-config` cannot see an occupied port, so writing one would turn the
/// next restart into an outage of the listeners that work today.
#[test]
fn refuses_an_address_that_is_already_bound() {
    let fixture = Fixture::new(true);
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap().to_string();

    let output = fixture.add_listener(&["--listen-addr", &addr, "--mode", "client-cert"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("would not bind"),
        "unexpected diagnostic: {stderr}"
    );
    fixture.assert_unchanged();
}

/// The bind test is a probe of this moment, so an address that only exists
/// later — a floating address, another network namespace — has to remain
/// writable on purpose.
#[test]
fn skips_the_bind_test_when_told_to() {
    let fixture = Fixture::new(true);
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap().to_string();

    let output = fixture.add_listener(&[
        "--listen-addr",
        &addr,
        "--mode",
        "client-cert",
        "--no-bind-check",
    ]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.config().listeners.len(), 2);
}

/// A certificate listener reads no password, so accepting one would leave the
/// operator believing the socket also takes those credentials.
#[test]
fn refuses_credentials_that_the_chosen_mode_ignores() {
    let fixture = Fixture::new(true);
    let output = fixture.add_listener(&[
        "--listen-addr",
        "127.0.0.1:8457",
        "--mode",
        "client-cert",
        "--username",
        "bob",
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("apply to --mode basic"),
        "unexpected diagnostic: {stderr}"
    );
    fixture.assert_unchanged();
}

/// A listener that demands nothing has no authentication mode, and writing one
/// down would describe a requirement nothing enforces.
#[test]
fn refuses_a_mode_alongside_disabled_authentication() {
    let fixture = Fixture::new(true);
    let output = fixture.add_listener(&[
        "--listen-addr",
        "127.0.0.1:8458",
        "--mode",
        "basic",
        "--disable-auth",
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "unexpected diagnostic: {stderr}"
    );
    fixture.assert_unchanged();
}

#[test]
fn writes_a_listener_that_demands_nothing_when_asked() {
    let fixture = Fixture::new(true);
    let output = fixture.add_listener(&["--listen-addr", "127.0.0.1:8459", "--disable-auth"]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = fixture.config();
    assert!(!config.listeners[1].auth.enabled);

    let check = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&fixture.config_path)
        .arg("check-config")
        .output()
        .unwrap();
    assert!(check.status.success());
    assert!(
        String::from_utf8_lossy(&check.stdout)
            .contains("listener 127.0.0.1:8459 transport=http3 auth=disabled shards=1")
    );
}

/// One edit at a time. Two operators would each validate against the file they
/// read, and the second rename would drop the first listener without an error.
#[cfg(unix)]
#[test]
fn refuses_to_edit_a_file_another_edit_holds() {
    use std::os::fd::AsRawFd as _;

    let fixture = Fixture::new(true);
    let lock_path = fixture.config_path.with_file_name(".masque.toml.lock");
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    // SAFETY: a descriptor this test owns, released when the file is dropped.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );

    let output =
        fixture.add_listener(&["--listen-addr", "127.0.0.1:8460", "--mode", "client-cert"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("another masque-server is editing"),
        "unexpected diagnostic: {stderr}"
    );
    fixture.assert_unchanged();
}

#[test]
fn dry_run_prints_the_block_without_touching_the_file() {
    let fixture = Fixture::new(true);
    let output = fixture.add_listener(&[
        "--listen-addr",
        "127.0.0.1:8454",
        "--mode",
        "client-cert",
        "--dry-run",
    ]);

    assert!(
        output.status.success(),
        "add-listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[[listeners]]"));
    assert!(stdout.contains("listen_addr = \"127.0.0.1:8454\""));
    fixture.assert_unchanged();
}

/// Prompting needs a terminal. A script that leaves a value out gets an error
/// naming the flag, not a command that blocks forever waiting on a pipe.
#[test]
fn requires_flags_when_standard_input_is_not_a_terminal() {
    let fixture = Fixture::new(true);
    let output = fixture.add_listener(&["--mode", "client-cert"]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--listen-addr is required"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_unchanged();
}

#[test]
fn reports_a_missing_configuration_file_instead_of_creating_one() {
    let dir = TempDir::new();
    let missing = dir.path().join("absent.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&missing)
        .arg("add-listener")
        .args(["--listen-addr", "127.0.0.1:8455", "--mode", "client-cert"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("configuration file not found"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!missing.exists());
}
