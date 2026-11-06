//! Private, live configuration evidence. Only keyed fingerprints cross the
//! owner-only local socket; no credentials, paths or configuration are sent.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use ring::{hmac, rand::SecureRandom as _};
use serde::{Deserialize, Serialize};

use crate::config::ServerConfig;

const MAX_RESPONSE: u64 = 16 * 1024;

#[derive(Clone, Serialize, Deserialize)]
struct Section {
    digest: [u8; 32],
    reloadable: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    version: String,
    key: [u8; 32],
    config_file: Option<[u8; 32]>,
    sections: BTreeMap<String, Section>,
}

pub(crate) struct LoadedConfig(Mutex<Snapshot>);

impl LoadedConfig {
    pub(crate) fn new(
        config: &ServerConfig,
        path: Option<&Path>,
        tls: [u8; 32],
    ) -> anyhow::Result<Self> {
        let mut key = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("cannot seed local status fingerprints"))?;
        let mut snapshot = Snapshot {
            version: env!("CARGO_PKG_VERSION").into(),
            key,
            config_file: None,
            sections: BTreeMap::new(),
        };
        snapshot.config_file = path
            .map(|path| file_digest(&snapshot.key, path))
            .transpose()?;
        snapshot.sections = sections(&snapshot.key, config, tls)?;
        Ok(Self(Mutex::new(snapshot)))
    }

    /// Prepare evidence before any reload snapshot is changed. A failed reload
    /// leaves both effective configuration and evidence on the previous state.
    pub(crate) fn prepare_reload(
        &self,
        config: &ServerConfig,
        tls: [u8; 32],
    ) -> anyhow::Result<Snapshot> {
        let mut snapshot = self
            .0
            .lock()
            .expect("loaded configuration poisoned")
            .clone();
        for (name, section) in sections(&snapshot.key, config, tls)? {
            if section.reloadable {
                snapshot.sections.insert(name, section);
            }
        }
        Ok(snapshot)
    }

    pub(crate) fn commit_reload(&self, snapshot: Snapshot) {
        *self.0.lock().expect("loaded configuration poisoned") = snapshot;
    }
}

fn digest(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes)
        .as_ref()
        .try_into()
        .unwrap()
}

fn file_digest(key: &[u8; 32], path: &Path) -> anyhow::Result<[u8; 32]> {
    let path = std::fs::canonicalize(path).context("configuration file cannot be resolved")?;
    Ok(digest(key, path.as_os_str().as_encoded_bytes()))
}

fn sections(
    key: &[u8; 32],
    config: &ServerConfig,
    tls: [u8; 32],
) -> anyhow::Result<BTreeMap<String, Section>> {
    let mut value = serde_json::to_value(config)?;
    // Ignore disabled authentication material and the obsolete stealth switch.
    let credentials: Vec<_> = config.listeners.iter().map(|listener| {
        if listener.auth.basic_enabled() {
            if listener.auth.users.is_empty() {
                serde_json::json!([{"username": listener.auth.username, "password_hash": listener.auth.password_hash}])
            } else { serde_json::json!(listener.auth.users) }
        } else { serde_json::json!([]) }
    }).collect();
    for listener in value["listeners"].as_array_mut().unwrap() {
        let auth = listener["auth"].as_object_mut().unwrap();
        for field in ["users", "username", "password_hash", "stealth"] {
            auth.remove(field);
        }
    }
    if !config
        .listeners
        .iter()
        .any(|listener| listener.auth.client_cert_enabled())
    {
        value["clients"] = serde_json::json!([]);
    }
    value["basic_credentials"] = serde_json::json!(credentials);
    value["tls_identity"] = serde_json::json!(tls);
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| {
            let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
            Ok((
                name.clone(),
                Section {
                    digest: digest(key, &bytes),
                    reloadable: matches!(
                        name.as_str(),
                        "clients" | "basic_credentials" | "tls_identity"
                    ),
                },
            ))
        })
        .collect()
}

impl Snapshot {
    pub(crate) fn compare(
        &self,
        path: &Path,
        config: &ServerConfig,
        tls: [u8; 32],
    ) -> anyhow::Result<Vec<(String, &'static str)>> {
        anyhow::ensure!(
            self.version == env!("CARGO_PKG_VERSION"),
            "running version differs; configuration comparison unavailable"
        );
        anyhow::ensure!(
            self.config_file == Some(file_digest(&self.key, path)?),
            "selected file is not the running process's configuration file"
        );
        let disk = sections(&self.key, config, tls)?;
        anyhow::ensure!(
            self.sections.len() == disk.len(),
            "runtime status schema differs"
        );
        disk.into_iter()
            .map(|(name, section)| {
                let loaded = self
                    .sections
                    .get(&name)
                    .context("runtime status section missing")?;
                let state = if loaded.digest == section.digest {
                    "applied"
                } else if section.reloadable {
                    "reload required"
                } else {
                    "restart required"
                };
                Ok((name, state))
            })
            .collect()
    }
}

#[cfg(unix)]
mod socket {
    use super::*;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt as _;

    pub struct StatusServer {
        task: tokio::task::JoinHandle<()>,
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl Drop for StatusServer {
        fn drop(&mut self) {
            self.task.abort();
            if std::fs::symlink_metadata(&self.path)
                .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    pub(crate) async fn start(
        path: &Path,
        state: Arc<LoadedConfig>,
    ) -> anyhow::Result<StatusServer> {
        // SAFETY: geteuid takes no pointers and only returns the process identity.
        let uid = unsafe { libc::geteuid() };
        let parent = path
            .parent()
            .context("status socket needs a private parent directory")?;
        let metadata =
            std::fs::symlink_metadata(parent).context("status socket parent is unavailable")?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "status socket parent must be an owner-only directory (0700)"
        );
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket() && metadata.uid() == uid,
                    "refusing to replace a non-owned status socket"
                );
                match tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::UnixStream::connect(path),
                )
                .await
                {
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?
                    }
                    _ => anyhow::bail!("status socket is already in use or unavailable"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener =
            tokio::net::UnixListener::bind(path).context("cannot bind local status socket")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(path)?;
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let bytes = {
                    let snapshot = state.0.lock().expect("loaded configuration poisoned");
                    serde_json::to_vec(&*snapshot).expect("fixed runtime status schema serializes")
                };
                // One bounded writer, no spawned task or input buffer per peer.
                let _ =
                    tokio::time::timeout(Duration::from_secs(1), stream.write_all(&bytes)).await;
            }
        });
        Ok(StatusServer {
            task,
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(crate) async fn read(path: &Path) -> anyhow::Result<Snapshot> {
        use tokio::io::AsyncReadExt as _;
        let metadata =
            std::fs::symlink_metadata(path).context("no accessible local runtime status socket")?;
        anyhow::ensure!(
            metadata.file_type().is_socket() && metadata.mode() & 0o077 == 0,
            "runtime status socket is not private"
        );
        let stream = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::UnixStream::connect(path),
        )
        .await
        .context("runtime status connection timed out")?
        .context("runtime status process is unavailable")?;
        let mut bytes = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            stream.take(MAX_RESPONSE + 1).read_to_end(&mut bytes),
        )
        .await
        .context("runtime status read timed out")??;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_RESPONSE,
            "runtime status response exceeded limit"
        );
        serde_json::from_slice(&bytes).context("invalid runtime status response")
    }
}

#[cfg(unix)]
pub use socket::StatusServer;
#[cfg(unix)]
pub(crate) use socket::{read, start};
