//! The installer depends on `check-config` being a complete, side-effect-free
//! preflight for an already deployed configuration.

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "masque-check-config-{}-{nonce}",
            std::process::id()
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
        r#"[server]
listen_addr = "{listen_addr}"
shards = 1

[tls]
cert_path = "{}"
key_path = "{}"

[auth]
enabled = false

[quic]
cc_algorithm = "{cc_algorithm}"

[ip_proxy]
enabled = false
"#,
        cert_path.display(),
        key_path.display()
    )
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
