//! The installer depends on `check-config` being a complete, side-effect-free
//! preflight for an already deployed configuration.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::Command;
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
        // The tests share a process and run in parallel, so the clock alone
        // does not separate them: two that start within the same nanosecond
        // would build the same path and the second `create_dir` would fail.
        static SEQUENCE: AtomicU32 = AtomicU32::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "masque-check-config-{}-{nonce}-{}",
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

fn config_text(
    listen_addr: std::net::SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    cc_algorithm: &str,
) -> String {
    format!(
        r#"[tls]
cert_path = "{}"
key_path = "{}"

[quic]
cc_algorithm = "{cc_algorithm}"

[ip_proxy]
enabled = false

[[listeners]]
listen_addr = "{listen_addr}"
shards = 1

[listeners.auth]
enabled = false
"#,
        cert_path.display(),
        key_path.display()
    )
}

/// The packaged template is the source for fresh installs, so schema changes
/// must fail locally instead of first appearing in a release archive.
#[test]
fn packaged_config_uses_the_current_listener_schema() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/config/masque.toml");
    let text = std::fs::read_to_string(path).unwrap();
    let config = masque::config::parse_toml(&text).unwrap();

    assert_eq!(config.listeners.len(), 1);
    assert_eq!(config.listeners[0].listen_addr.to_string(), "0.0.0.0:443");
    assert!(config.listeners[0].auth.basic_enabled());
}

#[test]
fn check_config_validates_without_binding_the_listen_port() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        config_text(
            occupied.local_addr().unwrap(),
            &cert_path,
            &key_path,
            "cubic",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "check-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("configuration is compatible"));
}

#[test]
fn json_log_format_emits_machine_parseable_events() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        config_text(
            "127.0.0.1:0".parse().unwrap(),
            &cert_path,
            &key_path,
            "cubic",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--log-format")
        .arg("json")
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        !events.is_empty(),
        "validation should emit at least one event"
    );
    assert!(
        events
            .iter()
            .all(|event| event["fields"]["message"].is_string())
    );
}

/// A preflight deliberately has no network side effects, so an ephemeral port
/// does not exist yet. Report the configured `:0`; the live `listening` log is
/// what reports the address selected by the kernel.
#[test]
fn check_config_keeps_an_ephemeral_port_unresolved() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        config_text(
            "127.0.0.1:0".parse().unwrap(),
            &cert_path,
            &key_path,
            "cubic",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "check-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("listener 127.0.0.1:0 transport=http3 auth=disabled shards=1"),
        "check-config must not invent a runtime port: {stdout}"
    );
}

#[test]
fn check_config_reports_a_loopback_observability_endpoint() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    let mut config = config_text(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        "cubic",
    );
    config.push_str("\n[observability]\nlisten_addr = \"127.0.0.1:9090\"\n");
    std::fs::write(&config_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "check-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(
            "observability 127.0.0.1:9090 health=/healthz ready=/readyz metrics=/metrics"
        )
    );
}

#[test]
fn check_config_rejects_a_public_observability_endpoint() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    let mut config = config_text(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        "cubic",
    );
    config.push_str("\n[observability]\nlisten_addr = \"0.0.0.0:9090\"\n");
    std::fs::write(&config_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must use a loopback address"));
}

/// A roster-ready public key, in the base64 SubjectPublicKeyInfo DER form
/// `enroll-client` prints.
fn public_key_b64(key: &PKey<Private>) -> String {
    STANDARD.encode(key.public_key_to_der().unwrap())
}

/// A two-listener file, with the credentials each mode needs.
fn dual_listener_config_text(
    basic_addr: &str,
    cert_addr: &str,
    cert_path: &Path,
    key_path: &Path,
) -> String {
    let client_public_key = public_key_b64(&p256_key());
    // `check-config` parses the PHC string, so a placeholder will not do.
    let password_hash = masque::auth::hash_password(b"correct horse battery staple").unwrap();
    format!(
        r#"[tls]
cert_path = "{}"
key_path = "{}"

[ip_proxy]
enabled = false

[[listeners]]
listen_addr = "{basic_addr}"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"
username = "alice"
password_hash = "{password_hash}"

[[listeners]]
listen_addr = "{cert_addr}"
shards = 1

[listeners.auth]
enabled = true
mode = "client_cert"

[[clients]]
name = "laptop"
public_key = "{client_public_key}"
"#,
        cert_path.display(),
        key_path.display()
    )
}

/// The installer's preflight has to understand the multi-listener form, or an
/// operator who splits their authentication modes cannot qualify an upgrade.
#[test]
fn check_config_accepts_two_listeners_with_different_authentication_modes() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        dual_listener_config_text("127.0.0.1:8449", "127.0.0.1:8450", &cert_path, &key_path),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "check-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Two listeners on one address is not a bind failure to discover at startup:
/// a multi-shard listener uses SO_REUSEPORT, so the kernel would hand the
/// second one connections meant for a different authentication mode.
#[test]
fn check_config_rejects_two_listeners_on_the_same_address() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        dual_listener_config_text("127.0.0.1:8449", "127.0.0.1:8449", &cert_path, &key_path),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("two listeners are configured for"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The 0.2 single-listener keys are deliberately not accepted by the 0.3
/// configuration model. A stale deployment must fail preflight instead of
/// appearing to run while silently selecting different defaults.
#[test]
fn check_config_rejects_legacy_single_listener_configuration() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"[server]
listen_addr = "127.0.0.1:8449"
shards = 1

[tls]
cert_path = "{}"
key_path = "{}"

[auth]
enabled = false
"#,
            cert_path.display(),
            key_path.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown field"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The reported shard count is the one that will run, not the one written down.
/// `shards = 0` means "one per core", so echoing the file back would tell an
/// operator the server runs no event loops at all.
#[test]
fn check_config_reports_the_resolved_shard_count() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"[tls]
cert_path = "{}"
key_path = "{}"

[ip_proxy]
enabled = false

[[listeners]]
listen_addr = "127.0.0.1:8449"
shards = 0

[listeners.auth]
enabled = false
"#,
            cert_path.display(),
            key_path.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    // Sharding needs SO_REUSEPORT, so the resolved count is one per core on
    // Linux and exactly one elsewhere. Either way it is never the configured 0.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "check-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("listener 127.0.0.1:8449 transport=http3 auth=disabled shards="),
        "unexpected listener line: {stdout}"
    );
    assert!(
        !stdout.contains("shards=0"),
        "the configured 0 must not be reported as the shard count: {stdout}"
    );
}

#[test]
fn check_config_rejects_an_unknown_congestion_controller() {
    let dir = TempDir::new();
    let (cert_path, key_path) = write_server_identity(dir.path());
    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        config_text(
            "127.0.0.1:8449".parse().unwrap(),
            &cert_path,
            &key_path,
            "not-a-controller",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(&config_path)
        .arg("check-config")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown quic.cc_algorithm"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
