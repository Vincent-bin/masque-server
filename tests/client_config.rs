use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn run(args: &[&str], password: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("client-config")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(password).unwrap();
    child.wait_with_output().unwrap()
}

fn unused_path(name: &str) -> PathBuf {
    static SEQUENCE: AtomicU32 = AtomicU32::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "masque-client-config-{}-{nonce}-{}-{name}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn client_config_writes_a_private_importable_surge_file() {
    let path = unused_path("surge.conf");
    let output = run(
        &[
            "surge",
            "--endpoint",
            "proxy.example:8449",
            "--username",
            "alice",
            "--name",
            "phone",
            "--out",
            path.to_str().unwrap(),
        ],
        b"secret, with spaces\n",
    );
    assert!(
        output.status.success(),
        "client-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[Proxy]\nphone = masque, proxy.example, 8449, username=alice, password=\"secret, with spaces\"\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn client_config_refuses_to_replace_an_existing_file() {
    let path = unused_path("existing.conf");
    std::fs::write(&path, "keep me").unwrap();
    let output = run(
        &[
            "surge",
            "--endpoint",
            "proxy.example:8449",
            "--username",
            "alice",
            "--out",
            path.to_str().unwrap(),
        ],
        b"secret\n",
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn client_config_stdout_is_explicitly_marked_as_secret() {
    let output = run(
        &[
            "surge",
            "--endpoint",
            "[2001:db8::1]:443",
            "--username",
            "alice",
        ],
        b"secret\n",
    );
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("password=secret"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("plaintext password"));
}

#[test]
fn relay_tls_names_are_independent_and_injection_is_rejected() {
    let args = [
        "surge",
        "--endpoint",
        "203.0.113.9:443",
        "--username",
        "alice",
        "--sni",
        "edge.example.com",
        "--server-cert-verify-name",
        "proxy.example.com",
    ];
    let output = run(&args, b"secret\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("masque, 203.0.113.9, 443"));
    assert!(text.contains("sni=edge.example.com, server-cert-verify-name=proxy.example.com"));
    let invalid = run(
        &[
            "surge",
            "--endpoint",
            "proxy.example:443",
            "--username",
            "alice",
            "--sni",
            "good.example, skip-cert-verify=true",
        ],
        b"secret\n",
    );
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
}
