//! Linux trust discovery mirrors rustls-native-certs 0.8.5 and openssl-probe 0.2.1.
//! Kept local because shared honk TLS uses a different verification policy.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use quinn::rustls::{self, ClientConfig, RootCertStore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    WebPkiSupportedAlgorithms, ring, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

pub(in crate::proxy::nowhere) fn config(
    config: &honk_config::node::NowhereConfig,
) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut client = if let Some(pin) = &config.tls.pin_sha256 {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pin {
                digest: crate::tls::parse_pin_sha256(pin).context("invalid Nowhere pin")?,
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth()
    } else {
        let (file, dirs) = native_paths();
        builder
            .with_root_certificates(load_roots(file.as_deref(), &dirs)?)
            .with_no_client_auth()
    };
    client.alpn_protocols = vec![b"nw3".to_vec()];
    client.enable_early_data = false;
    Ok(Arc::new(client))
}

fn native_paths() -> (Option<PathBuf>, Vec<PathBuf>) {
    let file = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
    let dirs = std::env::var_os("SSL_CERT_DIR")
        .map(|raw| {
            std::env::split_paths(&raw)
                .filter(|path| !path.as_os_str().is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // rustls-native-certs uses only explicit paths when either override is nonempty.
    if file.is_some() || !dirs.is_empty() {
        return (file, dirs);
    }
    let file = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ssl/cert.pem",
        "/opt/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/cacert.pem",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists());
    let dirs = [
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/etc/security/certificates",
    ]
    .into_iter()
    .map(PathBuf::from)
    .filter(|path| path.exists())
    .collect();
    (file, dirs)
}

pub(super) fn load_roots(file: Option<&Path>, dirs: &[PathBuf]) -> anyhow::Result<RootCertStore> {
    use std::os::unix::fs::MetadataExt;
    let mut certificates = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Some(file) = file {
        if let Ok(meta) = std::fs::metadata(file) {
            seen.insert((meta.dev(), meta.ino()));
        }
        load_file(file, &mut certificates)?;
    }
    for dir in dirs {
        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("opening native root directory {}", dir.display()))?
        {
            let path = entry?.path();
            let meta = match std::fs::metadata(&path) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("reading native root metadata"),
            };
            if meta.is_file() && seen.insert((meta.dev(), meta.ino())) {
                load_file(&path, &mut certificates)?;
            }
        }
    }
    certificates.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
    certificates.dedup();
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .context("invalid native root certificate")?;
    }
    if roots.is_empty() {
        bail!("no native trust roots available");
    }
    Ok(roots)
}

fn load_file(path: &Path, certificates: &mut Vec<CertificateDer<'static>>) -> anyhow::Result<()> {
    for cert in CertificateDer::pem_file_iter(path)
        .with_context(|| format!("opening native root {}", path.display()))?
    {
        certificates.push(cert.context("invalid native root PEM")?);
    }
    Ok(())
}

#[derive(Debug)]
struct Pin {
    digest: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}
impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref()).as_slice() != self.digest {
            return Err(rustls::Error::General(
                "Nowhere certificate pin mismatch".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, sig, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, sig, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
