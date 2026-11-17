use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use honk_config::node::NowhereConfig;
use quinn::rustls::{self, ClientConfig, HandshakeKind, RootCertStore, ServerConfig};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{policy, stream};

struct Identity {
    root: CertificateDer<'static>,
    root_pem: String,
    leaf: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Identity {
    fn new(names: &[&str]) -> Self {
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let root = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let mut leaf = rcgen::CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf.signed_by(&key, &issuer).unwrap();
        Self {
            root: root.der().clone(),
            root_pem: root.pem(),
            leaf: leaf.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn server(&self) -> Arc<ServerConfig> {
        let mut server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![self.leaf.clone()],
                PrivateKeyDer::Pkcs8(self.key.clone().into()),
            )
            .unwrap();
        server.alpn_protocols = vec![b"nw3".to_vec()];
        server.send_tls13_tickets = 4;
        server.max_early_data_size = 1024;
        Arc::new(server)
    }

    fn pin_config(&self) -> Arc<ClientConfig> {
        let mut config = NowhereConfig::default();
        config.tls.pin_sha256 = Some(
            Sha256::digest(self.leaf.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        policy::config(&config).unwrap()
    }
}

fn rooted_config(path: &Path) -> Arc<ClientConfig> {
    let roots = policy::load_roots(Some(path), &[]).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"nw3".to_vec()];
    config.enable_early_data = false;
    Arc::new(config)
}

#[test]
fn native_roots_combine_bundle_and_directories_with_file_and_der_deduplication() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let first = Identity::new(&["localhost"]);
    let second = Identity::new(&["localhost"]);
    let bundle = directory.path().join("bundle.pem");
    std::fs::write(&bundle, &first.root_pem).unwrap();
    let certs = directory.path().join("certs");
    std::fs::create_dir(&certs).unwrap();
    symlink(&bundle, certs.join("alias.0")).unwrap();
    std::fs::hard_link(&bundle, certs.join("hardlink.0")).unwrap();
    std::fs::write(certs.join("duplicate.unusual"), &first.root_pem).unwrap();
    std::fs::write(certs.join("second.no_extension"), &second.root_pem).unwrap();
    std::fs::write(certs.join("notes"), "not a PEM certificate\n").unwrap();
    symlink(certs.join("missing"), certs.join("dangling.0")).unwrap();
    let nested = certs.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("bad.pem"), invalid_der()).unwrap();

    let loaded = policy::load_roots(Some(&bundle), std::slice::from_ref(&certs)).unwrap();
    let mut certificates = vec![first.root, second.root];
    certificates.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
    let mut expected = RootCertStore::empty();
    for certificate in certificates {
        expected.add(certificate).unwrap();
    }
    assert_eq!(loaded.roots, expected.roots);
}

#[test]
fn native_roots_load_all_directories_and_accept_nonunicode_file_paths() {
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir().unwrap();
    let first = Identity::new(&["localhost"]);
    let second = Identity::new(&["localhost"]);
    let file = directory
        .path()
        .join(std::ffi::OsString::from_vec(b"root-\xff.pem".to_vec()));
    std::fs::write(&file, &first.root_pem).unwrap();
    assert_eq!(policy::load_roots(Some(&file), &[]).unwrap().len(), 1);
    let one = directory.path().join("one");
    let two = directory.path().join("two");
    std::fs::create_dir(&one).unwrap();
    std::fs::create_dir(&two).unwrap();
    std::fs::write(one.join("first"), first.root_pem).unwrap();
    std::fs::write(two.join("second"), second.root_pem).unwrap();
    assert_eq!(policy::load_roots(None, &[one, two]).unwrap().len(), 2);
}

fn invalid_der() -> &'static str {
    "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
}

#[test]
fn native_roots_reject_empty_missing_and_invalid_explicit_sources() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("roots.pem");
    assert!(policy::load_roots(None, &[]).is_err());
    assert!(policy::load_roots(Some(&path), &[]).is_err());
    assert!(policy::load_roots(Some(Path::new("")), &[]).is_err());
    assert!(policy::load_roots(None, std::slice::from_ref(&path)).is_err());
    std::fs::write(&path, "").unwrap();
    assert!(policy::load_roots(Some(&path), &[]).is_err());
    assert!(policy::load_roots(None, &[directory.path().to_owned()]).is_err());
    let identity = Identity::new(&["localhost"]);
    for bad in [
        invalid_der(),
        "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
    ] {
        std::fs::write(&path, format!("{}{bad}", identity.root_pem)).unwrap();
        assert!(policy::load_roots(Some(&path), &[]).is_err());
        assert!(policy::load_roots(None, &[directory.path().to_owned()]).is_err());
    }
}

#[test]
fn native_roots_fail_if_a_configured_directory_is_missing_even_with_a_valid_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let identity = Identity::new(&["localhost"]);
    let bundle = directory.path().join("roots.pem");
    std::fs::write(&bundle, identity.root_pem).unwrap();
    assert!(policy::load_roots(Some(&bundle), &[directory.path().join("missing")]).is_err());
}

struct Handshake {
    client_kind: HandshakeKind,
    server_kind: HandshakeKind,
    exporter: [u8; 32],
}

async fn exchange(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
) -> io::Result<Handshake> {
    assert!(!client.enable_early_data);
    let name = ServerName::try_from(name.to_owned()).unwrap();
    let (client_io, server_io) = tokio::io::duplex(1024);
    let client = async {
        let mut tls = stream::Stream::connect(client, name, client_io).await?;
        assert_eq!(tls.session.alpn_protocol(), Some(&b"nw3"[..]));
        assert_eq!(
            tls.session.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert!(!tls.session.is_early_data_accepted());
        let kind = tls.session.handshake_kind().unwrap();
        let exporter = tls
            .session
            .export_keying_material(
                [0u8; 32],
                super::super::wire::EXPORTER.as_bytes(),
                Some(&[]),
            )
            .unwrap();
        tls.write_all(b"ping").await?;
        tls.flush().await?;
        let mut reply = [0; 4];
        tls.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"pong");
        let mut tail = Vec::new();
        tls.read_to_end(&mut tail).await?;
        assert!(tail.is_empty());
        Ok::<_, io::Error>((kind, exporter))
    };
    let server = async {
        let mut tls = tokio_rustls::TlsAcceptor::from(server)
            .accept(server_io)
            .await?;
        assert!(tls.get_mut().1.early_data().is_none());
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"nw3"[..]));
        let kind = tls.get_ref().1.handshake_kind().unwrap();
        let exporter = tls
            .get_ref()
            .1
            .export_keying_material(
                [0u8; 32],
                super::super::wire::EXPORTER.as_bytes(),
                Some(&[]),
            )
            .unwrap();
        let mut request = [0; 4];
        tls.read_exact(&mut request).await?;
        assert_eq!(&request, b"ping");
        tls.write_all(b"pong").await?;
        tls.shutdown().await?;
        Ok::<_, io::Error>((kind, exporter))
    };
    let (client, server) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .expect("local TLS handshake or transfer stalled");
    let (client_kind, exporter) = client?;
    let (server_kind, peer_exporter) = server?;
    assert_eq!(exporter, peer_exporter);
    Ok(Handshake {
        client_kind,
        server_kind,
        exporter,
    })
}

#[tokio::test]
async fn native_ca_accepts_dns_and_ip_sans_but_rejects_wrong_names_and_other_cas() {
    let identity = Identity::new(&["localhost", "127.0.0.1"]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("roots.pem");
    std::fs::write(&path, &identity.root_pem).unwrap();
    let config = rooted_config(&path);
    let server = identity.server();
    for name in ["localhost", "127.0.0.1"] {
        let result = exchange(Arc::clone(&config), Arc::clone(&server), name)
            .await
            .unwrap();
        assert_eq!(result.client_kind, HandshakeKind::Full);
    }
    for name in ["wrong.example", "127.0.0.2"] {
        assert!(
            exchange(Arc::clone(&config), Arc::clone(&server), name)
                .await
                .is_err()
        );
    }
    let other = Identity::new(&["localhost"]);
    assert!(exchange(config, other.server(), "localhost").await.is_err());
}

#[tokio::test]
async fn configured_pin_replaces_native_ca_and_name_validation_but_wrong_pin_fails() {
    let identity = Identity::new(&["only.other.example"]);
    let config = identity.pin_config();
    assert!(!config.enable_early_data);
    exchange(config, identity.server(), "localhost")
        .await
        .unwrap();
    let mut wrong = NowhereConfig::default();
    wrong.tls.pin_sha256 = Some("00".repeat(32));
    assert!(
        exchange(
            policy::config(&wrong).unwrap(),
            identity.server(),
            "localhost"
        )
        .await
        .is_err()
    );
    wrong.tls.pin_sha256 = Some("not-a-sha256".to_owned());
    assert!(policy::config(&wrong).is_err());
}

#[tokio::test]
async fn resumed_tls_reuses_tickets_without_early_data_and_derives_a_fresh_exporter() {
    let identity = Identity::new(&["localhost"]);
    let client = identity.pin_config();
    let server = identity.server();
    let first = exchange(Arc::clone(&client), Arc::clone(&server), "localhost")
        .await
        .unwrap();
    assert_eq!(first.client_kind, HandshakeKind::Full);
    assert_eq!(first.server_kind, HandshakeKind::Full);
    let second = exchange(client, server, "localhost").await.unwrap();
    assert_eq!(second.client_kind, HandshakeKind::Resumed);
    assert_eq!(second.server_kind, HandshakeKind::Resumed);
    assert_ne!(first.exporter, second.exporter);
}

#[tokio::test]
async fn separate_policy_configs_cannot_inherit_another_clients_session_or_pin() {
    let identity = Identity::new(&["localhost"]);
    let server = identity.server();
    let first = exchange(identity.pin_config(), Arc::clone(&server), "localhost")
        .await
        .unwrap();
    assert_eq!(first.client_kind, HandshakeKind::Full);
    let independent = exchange(identity.pin_config(), Arc::clone(&server), "localhost")
        .await
        .unwrap();
    assert_eq!(independent.client_kind, HandshakeKind::Full);
    let mut wrong = NowhereConfig::default();
    wrong.tls.pin_sha256 = Some("00".repeat(32));
    assert!(
        exchange(policy::config(&wrong).unwrap(), server, "localhost")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_ca_sessions_resume_but_a_fresh_trust_store_cannot_reuse_them() {
    let identity = Identity::new(&["localhost"]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("roots.pem");
    std::fs::write(&path, &identity.root_pem).unwrap();
    let client = rooted_config(&path);
    let server = identity.server();
    let first = exchange(Arc::clone(&client), Arc::clone(&server), "localhost")
        .await
        .unwrap();
    assert_eq!(first.client_kind, HandshakeKind::Full);
    let resumed = exchange(client, Arc::clone(&server), "localhost")
        .await
        .unwrap();
    assert_eq!(resumed.client_kind, HandshakeKind::Resumed);
    let other = Identity::new(&["localhost"]);
    std::fs::write(&path, other.root_pem).unwrap();
    assert!(
        exchange(rooted_config(&path), server, "localhost")
            .await
            .is_err()
    );
}

#[test]
fn native_policy_honors_process_root_overrides_and_pin_bypasses_invalid_roots() {
    const MODE: &str = "HONK_NOWHERE_TLS_POLICY_CASE";
    const FIXTURE: &str = "HONK_NOWHERE_TLS_POLICY_FIXTURE";
    if let Ok(mode) = std::env::var(MODE) {
        let directory = std::path::PathBuf::from(std::env::var_os(FIXTURE).unwrap());
        let identity = Identity {
            root: std::fs::read(directory.join("root.der")).unwrap().into(),
            root_pem: std::fs::read_to_string(directory.join("roots.pem")).unwrap(),
            leaf: std::fs::read(directory.join("leaf.der")).unwrap().into(),
            key: std::fs::read(directory.join("key.der")).unwrap(),
        };
        let mut config = NowhereConfig::default();
        if mode.starts_with("pin-") {
            let digest = Sha256::digest(identity.leaf.as_ref());
            config.tls.pin_sha256 = Some(if mode == "pin-wrong" {
                "00".repeat(32)
            } else {
                digest.iter().map(|byte| format!("{byte:02x}")).collect()
            });
        }
        let client = policy::config(&config);
        if mode == "invalid-roots" {
            assert!(client.is_err());
            return;
        }
        let client = client.unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(exchange(client, identity.server(), "localhost"));
        assert_eq!(
            result.is_ok(),
            mode != "pin-wrong" && mode != "untrusted-ca"
        );
        return;
    }

    let identity = Identity::new(&["localhost"]);
    let other = Identity::new(&["localhost"]);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::write(root.join("root.der"), identity.root).unwrap();
    std::fs::write(root.join("roots.pem"), &identity.root_pem).unwrap();
    std::fs::write(root.join("leaf.der"), identity.leaf).unwrap();
    std::fs::write(root.join("key.der"), identity.key).unwrap();
    std::fs::write(root.join("other.pem"), other.root_pem).unwrap();
    std::fs::write(root.join("empty.pem"), "").unwrap();
    std::fs::write(root.join("bad.pem"), invalid_der()).unwrap();
    std::fs::create_dir(root.join("certs")).unwrap();
    std::fs::write(root.join("certs/root.pem"), identity.root_pem).unwrap();
    let test = format!(
        "{}::native_policy_honors_process_root_overrides_and_pin_bypasses_invalid_roots",
        module_path!().split_once("::").unwrap().1
    );
    for (mode, file, dir) in [
        ("native-file", Some("roots.pem"), None),
        ("native-dir", None, Some("certs")),
        ("native-both", Some("roots.pem"), Some("certs")),
        ("invalid-roots", Some("missing.pem"), None),
        ("invalid-roots", Some("empty.pem"), None),
        ("invalid-roots", Some("bad.pem"), None),
        ("invalid-roots", Some("roots.pem"), Some("missing")),
        ("untrusted-ca", Some("other.pem"), None),
        ("pin-valid", Some("bad.pem"), Some("missing")),
        ("pin-wrong", Some("roots.pem"), None),
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &test, "--nocapture"])
            .env(MODE, mode)
            .env(FIXTURE, root)
            .env_remove("SSL_CERT_FILE")
            .env_remove("SSL_CERT_DIR");
        if let Some(file) = file {
            command.env("SSL_CERT_FILE", root.join(file));
        }
        if let Some(dir) = dir {
            command.env("SSL_CERT_DIR", root.join(dir));
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed;"),
            "case {mode}, file={file:?}, dir={dir:?}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn quic_tls_resumes_without_zero_rtt_and_rejects_a_different_pin() {
    fn handshake(
        config: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
    ) -> Result<(HandshakeKind, [u8; 32]), rustls::Error> {
        assert!(!config.enable_early_data);
        let mut client = rustls::quic::ClientConnection::new(
            config,
            rustls::quic::Version::V1,
            ServerName::try_from("localhost").unwrap(),
            vec![1, 0],
        )?;
        assert!(client.zero_rtt_keys().is_none());
        let mut server =
            rustls::quic::ServerConnection::new(server, rustls::quic::Version::V1, vec![2, 0])?;
        for _ in 0..32 {
            let mut flight = Vec::new();
            let client_keys = client.write_hs(&mut flight);
            let mut progressed = !flight.is_empty() || client_keys.is_some();
            if !flight.is_empty() {
                server.read_hs(&flight)?;
            }
            flight.clear();
            let server_keys = server.write_hs(&mut flight);
            progressed |= !flight.is_empty() || server_keys.is_some();
            if !flight.is_empty() {
                client.read_hs(&flight)?;
            }
            if !progressed {
                assert!(!client.is_handshaking() && !server.is_handshaking());
                assert!(client.tls13_tickets_received() > 0);
                assert!(!client.is_early_data_accepted());
                assert!(server.zero_rtt_keys().is_none());
                assert_eq!(client.alpn_protocol(), Some(&b"nw3"[..]));
                assert_eq!(client.handshake_kind(), server.handshake_kind());
                let kind = client.handshake_kind().unwrap();
                let client = rustls::quic::Connection::from(client);
                let server = rustls::quic::Connection::from(server);
                let label = super::super::wire::EXPORTER.as_bytes();
                let exporter = client.export_keying_material([0; 32], label, Some(&[]))?;
                assert_eq!(
                    exporter,
                    server.export_keying_material([0; 32], label, Some(&[]))?
                );
                return Ok((kind, exporter));
            }
        }
        panic!("QUIC TLS handshake did not finish within 32 flights");
    }
    let identity = Identity::new(&["localhost"]);
    let client = identity.pin_config();
    let mut server = (*identity.server()).clone();
    server.max_early_data_size = u32::MAX;
    let server = Arc::new(server);
    let first = handshake(Arc::clone(&client), Arc::clone(&server)).unwrap();
    assert_eq!(first.0, HandshakeKind::Full);
    let second = handshake(client, Arc::clone(&server)).unwrap();
    assert_eq!(second.0, HandshakeKind::Resumed);
    assert_ne!(first.1, second.1);
    assert_eq!(
        handshake(identity.pin_config(), Arc::clone(&server))
            .unwrap()
            .0,
        HandshakeKind::Full
    );
    let mut wrong = NowhereConfig::default();
    wrong.tls.pin_sha256 = Some("00".repeat(32));
    assert!(handshake(policy::config(&wrong).unwrap(), server).is_err());
}
