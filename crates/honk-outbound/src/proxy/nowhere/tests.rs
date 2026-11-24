use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) mod portal;

const KEY: &str = "0123456789abcdef0123456789abcdef";

fn config() -> honk_config::node::NowhereConfig {
    honk_config::node::NowhereConfig {
        key: KEY.into(),
        ..Default::default()
    }
}

#[test]
fn authentication_matches_independent_hmac_vectors() {
    let exporter = std::array::from_fn(|i| i as u8);
    assert_eq!(
        wire::auth(&wire::auth_key(KEY), 1, &exporter),
        [
            0x1a, 0x26, 0xd8, 0xeb, 0x72, 0xea, 0xd8, 0xa2, 0x23, 0xb5, 0x4f, 0xd1, 0xf0, 0x4f,
            0x8e, 0x32
        ]
    );
    assert_eq!(
        wire::auth(&wire::auth_key(KEY), 2, &exporter),
        [
            0x7c, 0xbb, 0x32, 0x3b, 0xd0, 0x19, 0xbb, 0x51, 0x37, 0x0c, 0x92, 0xa5, 0x0a, 0x36,
            0xa0, 0x8f
        ]
    );
    assert_ne!(
        wire::auth(&wire::auth_key(KEY), 1, &exporter),
        wire::auth(&wire::auth_key(KEY), 1, &[0; 32])
    );
}

#[test]
fn environment_defaults_limits_and_carrier_specific_policy() {
    let default = Settings::read(&config(), |_| Ok(None)).unwrap();
    assert_eq!(default.handshake, Duration::from_millis(9100));
    assert_eq!(default.setup, Duration::from_secs(20));
    assert_eq!(default.shutdown, Duration::from_secs(5));
    assert_eq!(default.tcp_read, Duration::from_secs(30));
    assert_eq!(default.queue_bytes, 4 * 1024 * 1024);
    for (name, value) in [
        ("NOW_TCP_DATA_BUF_SIZE", "0"),
        ("NOW_TCP_DATA_BUF_SIZE", "invalid"),
        ("NOW_TCP_READ_TIMEOUT", "invalid"),
        ("NOW_TCP_DIAL_TIMEOUT", "invalid"),
        ("NOW_UDP_DIAL_TIMEOUT", "invalid"),
        ("NOW_SHUTDOWN_TIMEOUT", "invalid"),
        ("NOW_RELOAD_INTERVAL", "invalid"),
        ("NOW_SERVICE_COOLDOWN", "invalid"),
        ("NOW_HANDSHAKE_TIMEOUT", "0s"),
        ("NOW_FLOW_SETUP_TIMEOUT", "bogus"),
        ("NOW_UDP_IDLE_TIMEOUT", "999999999999999999999999s"),
        ("NOW_QUIC_UDP_QUEUE_BYTES", "0"),
        ("NOW_TRANSPORT_MEMORY_PROFILE", "unknown"),
        ("NOW_MORPH_TCP_PRELUDE", "unknown"),
    ] {
        assert!(
            Settings::read(&config(), |key| Ok((key == name).then(|| value.into()))).is_err(),
            "{name}"
        );
    }
    let profile = Settings::read(&config(), |key| {
        Ok(match key {
            "NOW_TRANSPORT_MEMORY_PROFILE" => Some("memory".into()),
            "NOW_HANDSHAKE_TIMEOUT" => Some("250ms".into()),
            "NOW_MORPH_UDP_PRELUDE" => Some("irrelevant".into()),
            _ => None,
        })
    })
    .unwrap();
    assert_eq!(profile.handshake, Duration::from_millis(250));
    assert_eq!(profile.connection_window, 16 << 20);
    let mut disabled = config();
    disabled.morph = false;
    assert!(
        Settings::read(&disabled, |key| Ok(
            (key == "NOW_MORPH_TCP_PRELUDE").then(|| "bad".into())
        ))
        .is_ok()
    );
}

#[test]
fn targets_and_flow_ids_match_nw3_layouts() {
    assert_eq!(
        wire::request("192.0.2.1:443".parse().unwrap(), None, false)
            .unwrap()
            .as_ref(),
        &[0, 1, 192, 0, 2, 1, 1, 187]
    );
    assert_eq!(
        wire::request("192.0.2.1:53".parse().unwrap(), Some("dns.example"), true)
            .unwrap()
            .as_ref(),
        [vec![1, 3, 11], b"dns.example".to_vec(), vec![0, 53]]
            .concat()
            .as_slice()
    );
    assert!(wire::request("192.0.2.1:0".parse().unwrap(), None, false).is_err());
    for name in [
        "bad..example",
        "-bad.example",
        "bad_.example",
        "bad.example.",
    ] {
        assert!(wire::request("127.0.0.1:53".parse().unwrap(), Some(name), true).is_err());
    }
    assert_eq!(datagram::flow_id(0).unwrap(), 1);
    assert_eq!(datagram::flow_id(4).unwrap(), 2);
    assert_eq!(datagram::flow_id(4294967288).unwrap(), 0x3fff_ffff);
    for raw in [1, 2, 3, 4294967292, u64::MAX] {
        assert!(datagram::flow_id(raw).is_err());
    }
}

#[test]
fn request_stack_encoder_preserves_official_ascii_domain_bytes() {
    let target = "[2001:db8::1]:65535".parse().unwrap();
    assert_eq!(
        wire::request(target, None, true).unwrap().as_ref(),
        &[
            1, 4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 255
        ]
    );
    let request = wire::request(target, Some("DNS.Example"), false).unwrap();
    assert_eq!(&request[..3], &[0, 3, 11]);
    assert_eq!(&request[3..14], b"DNS.Example");
    assert_eq!(&request[14..], &[255, 255]);
    assert!(wire::request(target, Some("bücher.example"), true).is_err());
    for domain in ["127.0.0.1", "1.2.3", "xn--bcher-kva.example"] {
        let request = wire::request(target, Some(domain), true).unwrap();
        assert_eq!(&request[3..request.len() - 2], domain.as_bytes());
    }
    let domain = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(domain.len(), 253);
    let request = wire::request(target, Some(&domain), true).unwrap();
    assert_eq!(request.len(), 258);
    assert_eq!(&request[..3], &[1, 3, 253]);
    assert_eq!(&request[3..256], domain.as_bytes());
    assert_eq!(&request[256..], &[255, 255]);
    assert!(wire::request(target, Some(&format!("{domain}a")), true).is_err());
    assert!(wire::request(target, Some(&format!("{}.example", "a".repeat(64))), true).is_err());
}

#[tokio::test]
async fn setup_results_do_not_authorize_unknown_codes() {
    for code in 0..=255 {
        let mut bytes = &[code][..];
        let result = wire::ready(&mut bytes).await;
        assert_eq!(result.is_ok(), code == 0);
        if code == 2 {
            assert!(crate::proxy::packet_rejection(result.as_ref().unwrap_err()).is_some());
        }
        if code == 3 {
            assert!(crate::proxy::target_failure(result.as_ref().unwrap_err()));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn fragmentation_out_of_order_duplicates_conflicts_and_budget_cleanup() {
    use tokio::sync::Semaphore;
    let budget = Arc::new(Semaphore::new(10000));
    let mut assembly = datagram::Reassembly::default();
    let payload = vec![0x55; 3500];
    let frames: Vec<_> = datagram::fragments(2, 1, &payload, 1200).unwrap().collect();
    assert_eq!(frames.len(), 3);
    assert!(assembly.receive(frames[2].clone(), &budget).is_none());
    assert_eq!(budget.available_permits(), 6500);
    assert!(assembly.receive(frames[2].clone(), &budget).is_none());
    assert!(assembly.receive(frames[0].clone(), &budget).is_none());
    let packet = assembly.receive(frames[1].clone(), &budget).unwrap();
    assert_eq!(packet.bytes.as_ref(), payload);
    assert_eq!(budget.available_permits(), 6500);
    drop(packet);
    assert_eq!(budget.available_permits(), 10000);
    assembly.receive(frames[0].clone(), &budget);
    let mut conflict = frames[0].to_vec();
    conflict[12] ^= 1;
    assert!(assembly.receive(conflict.into(), &budget).is_none());
    assert_eq!(budget.available_permits(), 10000);
    assembly.receive(frames[0].clone(), &budget);
    tokio::time::advance(Duration::from_secs(10) + Duration::from_nanos(1)).await;
    assembly.expire(tokio::time::Instant::now());
    assert_eq!(budget.available_permits(), 10000);
    let empty = assembly
        .receive(bytes::Bytes::from_static(&[0, 0, 0, 2]), &budget)
        .unwrap();
    assert!(empty.bytes.is_empty());
    assert_eq!(budget.available_permits(), 9999);
    drop(empty);
    assert!(datagram::fragments(2, 1, &vec![0; 65536], 1200).is_err());
    let small = Arc::new(Semaphore::new(100));
    assert!(assembly.receive(frames[0].clone(), &small).is_none());
    assert_eq!(small.available_permits(), 100);
}

#[tokio::test(start_paused = true)]
async fn reassembly_expiry_preserves_each_packets_original_deadline() {
    use tokio::sync::Semaphore;
    let budget = Arc::new(Semaphore::new(10000));
    let mut assembly = datagram::Reassembly::default();
    let first: Vec<_> = datagram::fragments(2, 1, &[1; 2000], 1200)
        .unwrap()
        .collect();
    let second: Vec<_> = datagram::fragments(2, 2, &[2; 2000], 1200)
        .unwrap()
        .collect();
    assert!(assembly.receive(first[0].clone(), &budget).is_none());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(assembly.receive(second[0].clone(), &budget).is_none());
    drop(assembly.receive(first[1].clone(), &budget).unwrap());
    tokio::time::advance(Duration::from_secs(8)).await;
    assembly.expire(Instant::now());
    assert_eq!(budget.available_permits(), 8000);
    tokio::time::advance(Duration::from_secs(2) - Duration::from_nanos(1)).await;
    assembly.expire(Instant::now());
    assert_eq!(budget.available_permits(), 8000);
    tokio::time::advance(Duration::from_nanos(1)).await;
    assembly.expire(Instant::now());
    assert_eq!(budget.available_permits(), 8000);
    tokio::time::advance(Duration::from_nanos(1)).await;
    assembly.expire(Instant::now());
    assert_eq!(budget.available_permits(), 10000);
    assert!(assembly.receive(first[0].clone(), &budget).is_none());
    assembly = datagram::Reassembly::default();
    assert_eq!(budget.available_permits(), 10000);
    assert!(assembly.receive(second[0].clone(), &budget).is_none());
    tokio::time::advance(Duration::from_secs(10) + Duration::from_nanos(1)).await;
    assembly.expire(Instant::now());
    assert_eq!(budget.available_permits(), 10000);
}

#[test]
fn reassembly_maximum_fragment_count_counts_only_unique_parts() {
    use tokio::sync::Semaphore;
    let budget = Arc::new(Semaphore::new(65535));
    let mut assembly = datagram::Reassembly::default();
    let payload: Vec<_> = (0..65535).map(|i| i as u8).collect();
    let frames: Vec<_> = datagram::fragments(2, 1, &payload, 270).unwrap().collect();
    assert_eq!(frames.len(), 255);
    for frame in frames.iter().skip(1).rev() {
        assert!(assembly.receive(frame.clone(), &budget).is_none());
        assert!(assembly.receive(frame.clone(), &budget).is_none());
    }
    let packet = assembly.receive(frames[0].clone(), &budget).unwrap();
    assert_eq!(packet.bytes.as_ref(), payload);
    assert_eq!(budget.available_permits(), 0);
    drop(packet);
    assert_eq!(budget.available_permits(), 65535);
}

#[test]
fn fragment_iterator_preserves_wire_bytes_and_exact_remaining_count() {
    let mut data = datagram::fragments(0x01020304, 0, b"abc", 7).unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data.size_hint(), (1, Some(1)));
    assert_eq!(
        data.next().unwrap().as_ref(),
        &[1, 2, 3, 4, b'a', b'b', b'c']
    );
    assert_eq!(data.len(), 0);
    assert!(data.next().is_none());
    let empty: Vec<_> = datagram::fragments(2, 0, b"", 4).unwrap().collect();
    assert_eq!(empty[0].as_ref(), &[0, 0, 0, 2]);
    let payload = [0x55; 65535];
    let mut fragments = datagram::fragments(2, 0x01020304, &payload, 270).unwrap();
    assert_eq!(fragments.len(), 255);
    let mut recovered = Vec::new();
    for index in 0..255 {
        assert_eq!(fragments.len(), 255 - index);
        assert_eq!(fragments.size_hint(), (255 - index, Some(255 - index)));
        let frame = fragments.next().unwrap();
        assert_eq!(&frame[..8], &[0x40, 0, 0, 2, 1, 2, 3, 4]);
        assert_eq!(&frame[8..12], &[index as u8, 255, 255, 255]);
        recovered.extend_from_slice(&frame[12..]);
    }
    assert_eq!(recovered, payload);
    assert_eq!(fragments.len(), 0);
    assert!(fragments.next().is_none());
    assert!(fragments.next().is_none());
    for (size, mtu, packet) in [(65536, 1200, 1), (13, 12, 1), (256, 13, 1), (20, 16, 0)] {
        assert!(datagram::fragments(2, packet, &vec![0; size], mtu).is_err());
    }
}

pub(super) async fn independent_tls_peer(
    code: u8,
    alpn: bool,
    udp: Option<bool>,
) -> (Node, tokio::task::JoinHandle<Vec<u8>>) {
    independent_tls_peer_with_reply(code, alpn, udp, false).await
}

pub(super) async fn independent_tls_peer_with_reply(
    code: u8,
    alpn: bool,
    udp: Option<bool>,
    prior_reply: bool,
) -> (Node, tokio::task::JoinHandle<Vec<u8>>) {
    use boring::pkey::PKey;
    use boring::ssl::{AlpnError, SslAcceptor, SslMethod, SslVersion};
    use boring::x509::X509;
    use sha2::{Digest, Sha256};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin: String = Sha256::digest(cert.cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.cert.pem().as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(
            &PKey::private_key_from_pem(cert.signing_key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    if alpn {
        acceptor.set_alpn_select_callback(|_, offered| {
            boring::ssl::select_next_proto(b"\x03nw3", offered).ok_or(AlpnError::NOACK)
        });
    }
    let acceptor = acceptor.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = match tokio_boring::accept(&acceptor, socket).await {
            Ok(tls) => tls,
            Err(_) => return Vec::new(),
        };
        let mut request = [0; 24];
        if tls.read_exact(&mut request).await.is_err() {
            return Vec::new();
        }
        let mut exporter = [0; 32];
        tls.ssl()
            .export_keying_material(&mut exporter, wire::EXPORTER, Some(&[]))
            .unwrap();
        // Verify against independent HMAC composition, including the stream target.
        let salt = Sha256::digest(b"nowhere/nw3/auth-root");
        let root = wire::hmac(&salt, KEY.as_bytes());
        let key = wire::hmac(&root, b"vector-authentication\x01");
        let tag = wire::hmac(&key, &[vec![1], exporter.to_vec()].concat());
        assert_eq!(&request[..16], &tag[..16]);
        assert_eq!(
            &request[16..],
            &[u8::from(udp.is_some()), 1, 192, 0, 2, 1, 1, 187]
        );
        tls.write_all(&[code]).await.unwrap();
        tls.flush().await.unwrap();
        if let Some(torn) = udp {
            if prior_reply {
                tls.write_all(&[0, 0]).await.unwrap();
            }
            tls.write_all(&[0]).await.unwrap();
            tls.flush().await.unwrap();
            if torn {
                tokio::time::sleep(if prior_reply {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(150)
                })
                .await;
            }
            let _ = tls
                .write_all(&[0, 0, 5, b'h', b'e', b'l', b'l', b'o'])
                .await;
            let _ = tls.flush().await;
            let mut response = Vec::new();
            let _ = tls.read_to_end(&mut response).await;
            return response;
        }
        let mut payload = Vec::new();
        tls.read_to_end(&mut payload).await.ok();
        if code == 0 {
            tls.write_all(&payload).await.unwrap();
            tls.shutdown().await.unwrap();
        }
        payload
    });
    let node = Node::from_share_link(&format!(
        "nowhere://{KEY}@127.0.0.1:{port}?morph=0&sni=wrong.example&pin={pin}"
    ))
    .unwrap();
    (node, peer)
}

#[tokio::test]
async fn tls_waits_for_ready_preserves_half_close_and_requires_alpn() {
    for (code, alpn) in [
        (0, true),
        (1, true),
        (2, true),
        (3, true),
        (4, true),
        (255, true),
        (0, false),
    ] {
        let (node, peer) = independent_tls_peer(code, alpn, None).await;
        let result = NowhereHandler
            .dial(
                &node,
                "192.0.2.1:443".parse().unwrap(),
                None,
                Duration::from_secs(2),
            )
            .await;
        if code == 0 && alpn {
            let mut stream = result.unwrap().stream;
            stream.write_all(b"half-close payload").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            timeout_at(
                Instant::now() + Duration::from_secs(2),
                stream.read_to_end(&mut reply),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(reply, b"half-close payload");
        } else {
            assert!(result.is_err());
        }
        let payload = peer.await.unwrap();
        assert_eq!(!payload.is_empty(), code == 0 && alpn);
    }
}

#[test]
fn invalid_runtime_environment_rejects_nowhere_at_admission() {
    const CHILD: &str = "HONK_NOWHERE_ENV_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "proxy::nowhere::tests::invalid_runtime_environment_rejects_nowhere_at_admission",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("NOW_FLOW_SETUP_TIMEOUT", "invalid-duration")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let node = Node::from_share_link(&format!("nowhere://{KEY}@localhost:2000")).unwrap();
    let error = crate::runtime::OutboundRuntimeRegistry::build(&[node])
        .err()
        .unwrap();
    assert!(error.to_string().contains("NOW_FLOW_SETUP_TIMEOUT"));
    let other = Node::from_share_link("socks5://localhost:2000").unwrap();
    assert!(crate::runtime::OutboundRuntimeRegistry::build(&[other]).is_ok());
}

#[tokio::test]
async fn tls_udp_empty_packets_and_interrupted_frames() {
    for torn in [false, true] {
        let (node, peer) = independent_tls_peer(0, true, Some(torn)).await;
        let transport = NowhereHandler
            .dial_udp_transport(
                &node,
                "192.0.2.1:443".parse().unwrap(),
                None,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        let mut bytes = [0; 64];
        if torn {
            assert!(
                tokio::time::timeout(Duration::from_millis(50), transport.recv_packet(&mut bytes))
                    .await
                    .is_err()
            );
            transport.send_packet(b"after cancellation").await.unwrap();
            assert_eq!(transport.recv_packet(&mut bytes).await.unwrap().0, 0);
            let (len, _) = transport.recv_packet(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..len], b"hello");
        } else {
            assert_eq!(transport.recv_packet(&mut bytes).await.unwrap().0, 0);
            let (len, _) = transport.recv_packet(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..len], b"hello");
            assert!(transport.send_packet(&vec![0; 65536]).await.is_err());
            transport.send_packet(b"").await.unwrap();
        }
        drop(transport);
        let response = peer.await.unwrap();
        assert_eq!(
            response,
            if torn {
                [vec![0, 18], b"after cancellation".to_vec()].concat()
            } else {
                vec![0, 0]
            }
        );
    }
}

#[test]
#[ignore = "manual same-host performance measurement"]
fn cached_connection_credentials_benchmark() {
    use std::hint::black_box;
    let exporter = [0x31; 32];
    let cached_auth = wire::auth_key(KEY);
    let cached_morph = morph::MorphKeys::derive(KEY.as_bytes(), Default::default());
    for round in 0..7 {
        for cached in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let started = std::time::Instant::now();
            for _ in 0..10000 {
                let (auth_key, morph_keys) = if cached {
                    (black_box(cached_auth), black_box(cached_morph.clone()))
                } else {
                    (
                        wire::auth_key(black_box(KEY)),
                        morph::MorphKeys::derive(black_box(KEY.as_bytes()), Default::default()),
                    )
                };
                let tag = wire::auth(&auth_key, 1, black_box(&exporter));
                assert_eq!(tag, wire::auth(&cached_auth, 1, &exporter));
                assert_eq!(morph_keys.udp_keys(), cached_morph.udp_keys());
                black_box((tag, morph_keys));
            }
            println!(
                "credentials,{round},{cached},{}",
                started.elapsed().as_nanos()
            );
        }
    }
}
