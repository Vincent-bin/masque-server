//! Reloadable server TLS identity shared by HTTP/2 and HTTP/3 listeners.
//!
//! The BoringSSL context itself stays attached to the listener for its whole
//! lifetime. A ClientHello callback copies the current certificate chain and
//! private key into each new TLS connection instead. Replacing the shared
//! snapshot therefore affects new handshakes without touching established
//! HTTP/2 or QUIC connections.

use std::sync::{Arc, LazyLock, RwLock};

use anyhow::Context as _;
use boring::error::ErrorStack;
use boring::ex_data::Index;
use boring::pkey::{PKey, Private};
use boring::ssl::{SelectCertError, Ssl, SslContextBuilder, SslRef};
use boring::x509::X509;
use foreign_types::ForeignTypeRef as _;
use tracing::warn;

use crate::config::TlsSection;

/// Disable TLS 1.3 Early Data on a server context, even if a future quiche
/// default or refactor starts enabling it elsewhere.
///
/// MASQUE CONNECT requests create network side effects and are not replay
/// safe. Session resumption remains enabled; only 0-RTT application data is
/// refused, so every CONNECT waits for the peer's Finished message.
pub(super) fn disable_early_data(builder: &mut SslContextBuilder) {
    unsafe {
        // SAFETY: `builder.as_ptr()` is the live, uniquely configured SSL_CTX
        // owned by this builder. BoringSSL only flips a context boolean and
        // neither retains the pointer nor transfers ownership.
        boring_sys::SSL_CTX_set_early_data_enabled(builder.as_ptr(), 0);
    }
}

/// One completely parsed and matched server certificate chain and private key.
///
/// Keeping parsed BoringSSL objects rather than file paths is what makes a
/// reload atomic: an ACME hook can replace the two files independently, but a
/// handshake observes either this whole snapshot or the next whole snapshot,
/// never one file from each.
pub(super) struct TlsIdentity {
    leaf: X509,
    chain: Vec<X509>,
    private_key: PKey<Private>,
}

impl TlsIdentity {
    /// Read and validate one PEM certificate chain/private-key pair.
    pub(super) fn load(config: &TlsSection) -> anyhow::Result<Self> {
        let certificate_pem = std::fs::read(&config.cert_path).with_context(|| {
            format!(
                "failed to read tls.cert_path {}",
                config.cert_path.display()
            )
        })?;
        let mut certificates = X509::stack_from_pem(&certificate_pem).with_context(|| {
            format!(
                "failed to parse PEM certificates from tls.cert_path {}",
                config.cert_path.display()
            )
        })?;
        if certificates.is_empty() {
            anyhow::bail!(
                "tls.cert_path {} contains no PEM certificate",
                config.cert_path.display()
            );
        }
        let leaf = certificates.remove(0);

        let private_key_pem = std::fs::read(&config.key_path).with_context(|| {
            format!("failed to read tls.key_path {}", config.key_path.display())
        })?;
        let private_key = PKey::private_key_from_pem(&private_key_pem).with_context(|| {
            format!(
                "failed to parse PEM private key from tls.key_path {}",
                config.key_path.display()
            )
        })?;
        let public_key = leaf.public_key().with_context(|| {
            format!(
                "failed to read the public key from tls.cert_path {}",
                config.cert_path.display()
            )
        })?;
        if !public_key.public_eq(&private_key) {
            anyhow::bail!(
                "tls.key_path {} does not match tls.cert_path {}",
                config.key_path.display(),
                config.cert_path.display()
            );
        }

        let identity = Self {
            leaf,
            chain: certificates,
            private_key,
        };

        // Exercise the exact per-connection installation path during startup
        // and reload. This keeps `check-config` complete and prevents a parsed
        // but unusable identity from failing every future handshake instead.
        let context = SslContextBuilder::new(boring::ssl::SslMethod::tls())
            .context("failed to create TLS identity validation context")?
            .build();
        let mut ssl = Ssl::new(&context).context("failed to create TLS identity validator")?;
        identity
            .install(&mut ssl, 0)
            .context("failed to install the TLS certificate chain and private key")?;

        Ok(identity)
    }

    /// Copy this identity into one fresh SSL connection.
    fn install(&self, ssl: &mut SslRef, generation: u64) -> Result<(), ErrorStack> {
        ssl.set_certificate(&self.leaf)?;
        ssl.set_private_key(&self.private_key)?;
        for certificate in &self.chain {
            ssl.add_chain_cert(certificate)?;
        }

        // BoringSSL evaluates the session ID context after this callback when
        // deciding whether to resume a ticket. Advancing it on every successful
        // SIGHUP forces tickets issued under the previous TLS/roster snapshot
        // through one full handshake, while tickets minted afterwards remain
        // resumable. This matters both for certificate rotation and immediate
        // client-certificate revocation.
        let session_context = generation.to_be_bytes();
        let installed = unsafe {
            // SAFETY: `ssl` is a live SSL object owned by this callback and
            // BoringSSL copies the bounded context bytes before returning.
            boring_sys::SSL_set_session_id_context(
                ssl.as_ptr(),
                session_context.as_ptr(),
                session_context.len(),
            )
        };
        if installed != 1 {
            return Err(ErrorStack::get());
        }
        Ok(())
    }
}

/// One identity and the session namespace that belongs to it.
struct TlsSnapshot {
    identity: TlsIdentity,
    generation: u64,
}

/// The TLS identity selected by new handshakes.
pub(super) struct SharedTlsIdentity {
    current: RwLock<Arc<TlsSnapshot>>,
}

impl SharedTlsIdentity {
    pub(super) fn new(identity: TlsIdentity) -> Self {
        Self {
            current: RwLock::new(Arc::new(TlsSnapshot {
                identity,
                generation: 0,
            })),
        }
    }

    fn load(&self) -> Arc<TlsSnapshot> {
        Arc::clone(&self.current.read().expect("TLS identity poisoned"))
    }

    /// Install a fully validated identity and return its generation.
    pub(super) fn replace(&self, identity: TlsIdentity) -> u64 {
        let mut current = self.current.write().expect("TLS identity poisoned");
        let generation = current.generation.wrapping_add(1);
        *current = Arc::new(TlsSnapshot {
            identity,
            generation,
        });
        generation
    }
}

/// One SSL connection may process a ClientHello more than once, for example
/// after a TLS HelloRetryRequest. Pin the first identity to that SSL object so
/// a concurrent reload cannot change half of one handshake or append the same
/// intermediate chain twice.
static INSTALLED_IDENTITY: LazyLock<Index<Ssl, Arc<TlsSnapshot>>> =
    LazyLock::new(|| Ssl::new_ex_index().expect("failed to reserve TLS identity index"));

/// Make every new connection select the current shared TLS identity.
pub(super) fn configure_dynamic_identity(
    builder: &mut SslContextBuilder,
    identities: Arc<SharedTlsIdentity>,
) {
    // Allocate the ex-data index while building the listener, never lazily
    // inside the first ClientHello callback where a panic would cross the TLS
    // callback boundary.
    let installed_identity = *INSTALLED_IDENTITY;
    builder.set_select_certificate_callback(move |mut client_hello| {
        let ssl = client_hello.ssl_mut();
        if ssl.ex_data(installed_identity).is_some() {
            return Ok(());
        }

        let snapshot = identities.load();
        if let Err(error) = snapshot.identity.install(ssl, snapshot.generation) {
            warn!(%error, "failed to install the current TLS identity for a new connection");
            return Err(SelectCertError::ERROR);
        }
        ssl.set_ex_data(installed_identity, snapshot);
        Ok(())
    });
}
