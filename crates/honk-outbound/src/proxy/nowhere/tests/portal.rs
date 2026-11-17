use super::*;
use std::process::{Child, Command, Stdio};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub(in crate::proxy::nowhere) struct Portal(Child);
impl Drop for Portal {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(in crate::proxy::nowhere) async fn start(
    bin: &str,
    morph: bool,
) -> (Portal, tempfile::TempDir, u16, String) {
    use sha2::{Digest, Sha256};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let crt = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&crt, cert.cert.pem()).unwrap();
    std::fs::write(&key, cert.signing_key.serialize_pem()).unwrap();
    let pin = Sha256::digest(cert.cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    drop((tcp, udp));
    let child = Command::new(bin)
        .arg(format!(
            "portal://{KEY}@127.0.0.1:{port}?morph={}&tls=2&crt={}&key={}",
            u8::from(morph),
            crt.display(),
            key.display()
        ))
        .env("NOW_HANDSHAKE_TIMEOUT", "1s")
        .env("NOW_FLOW_SETUP_TIMEOUT", "2s")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut portal = Portal(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            portal.0.try_wait().unwrap().is_none(),
            "official Portal exited during startup"
        );
        if TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "official Portal startup timed out"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (portal, directory, port, pin)
}

#[tokio::test]
#[ignore = "requires official Nowhere 3.3.0 executable in HONK_NOWHERE_BIN"]
async fn official_portal_tls_quic_morph_tcp_udp_matrix() {
    let binary = std::env::var("HONK_NOWHERE_BIN").expect("HONK_NOWHERE_BIN is required");
    for morph in [false, true] {
        let (_portal, _directory, port, pin) = start(&binary, morph).await;
        for carrier in ["tcp", "udp"] {
            let node = Node::from_share_link(&format!(
                "nowhere://{KEY}@127.0.0.1:{port}?net={carrier}&morph={}&sni=localhost&pin={pin}",
                u8::from(morph)
            ))
            .unwrap();
            let generation = Arc::new(
                crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                    .unwrap(),
            );
            let registry = crate::proxy::ProxyRegistry::default_resolver().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = listener.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut payload = Vec::new();
                stream.read_to_end(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = registry
                .dial_runtime(
                    Arc::clone(&generation),
                    node.id,
                    target,
                    None,
                    Duration::from_secs(4),
                )
                .await
                .unwrap_or_else(|error| panic!("TCP net={carrier} morph={morph}: {error:#}"))
                .stream;
            let payload = vec![0xa5; 65536];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            timeout_at(
                Instant::now() + Duration::from_secs(4),
                stream.read_to_end(&mut reply),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply, payload, "TCP net={carrier} morph={morph}");
            drop(stream);
            echo.await.unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = socket.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut buf = vec![0; 65535];
                for _ in 0..5 {
                    let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                    socket.send_to(&buf[..len], peer).await.unwrap();
                }
            });
            let transport = registry
                .dial_udp_transport_runtime(
                    Arc::clone(&generation),
                    node.id,
                    target,
                    None,
                    Duration::from_secs(4),
                )
                .await
                .unwrap_or_else(|error| panic!("UDP net={carrier} morph={morph}: {error:#}"));
            assert!(!transport.allows_full_cone_replies());
            for size in [0, 1, 1200, 5000, 60000] {
                let payload = vec![0x5a; size];
                transport.send_packet(&payload).await.unwrap();
                let mut buf = vec![0; 65535];
                let (len, peer) = timeout_at(
                    Instant::now() + Duration::from_secs(4),
                    transport.recv_packet(&mut buf),
                )
                .await
                .unwrap_or_else(|_| panic!("UDP timeout net={carrier} morph={morph} size={size}"))
                .unwrap_or_else(|error| {
                    panic!("UDP read net={carrier} morph={morph} size={size}: {error}")
                });
                assert_eq!(peer, target);
                assert_eq!(&buf[..len], &payload);
            }
            drop(transport);
            echo.await.unwrap();
            generation.shutdown().await;
            eprintln!(
                "official Portal passed: net={carrier} morph={morph}, TCP half-close and UDP 0/1/1200/5000/60000 bytes"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires official Nowhere 3.3.0 executable in HONK_NOWHERE_BIN"]
async fn official_portal_rejects_wrong_key_pin_morph_and_untrusted_ca() {
    let binary = std::env::var("HONK_NOWHERE_BIN").expect("HONK_NOWHERE_BIN is required");
    for morph in [false, true] {
        let (_portal, _directory, port, pin) = start(&binary, morph).await;
        for carrier in ["tcp", "udp"] {
            for fault in ["key", "pin", "morph", "ca"] {
                let key = if fault == "key" {
                    "1123456789abcdef0123456789abcdef"
                } else {
                    KEY
                };
                let configured_morph = if fault == "morph" { !morph } else { morph };
                let pin_query = match fault {
                    "pin" => format!("&pin={}", "f".repeat(64)),
                    "ca" => String::new(),
                    _ => format!("&pin={pin}"),
                };
                let node = Node::from_share_link(&format!("nowhere://{key}@127.0.0.1:{port}?net={carrier}&morph={}&sni=localhost{pin_query}",u8::from(configured_morph))).unwrap();
                let result = NowhereHandler
                    .dial(
                        &node,
                        "127.0.0.1:1".parse().unwrap(),
                        None,
                        Duration::from_millis(300),
                    )
                    .await;
                assert!(
                    result.is_err(),
                    "accepted {fault} net={carrier} morph={morph}"
                );
            }
        }
    }
}
