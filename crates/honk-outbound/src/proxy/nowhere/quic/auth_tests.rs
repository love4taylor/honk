use super::*;
use sha2::{Digest, Sha256};

const KEY: &str = "0123456789abcdef0123456789abcdef";
const REQUEST: [u8; 8] = [0, 1, 127, 0, 0, 1, 1, 187];

fn fixture() -> (quinn::Endpoint, Arc<Client>) {
    fixture_with(|_| {}, |_| Ok(None))
}

fn fixture_with(
    configure: impl FnOnce(&mut quinn::TransportConfig),
    env: impl FnMut(&str) -> anyhow::Result<Option<String>>,
) -> (quinn::Endpoint, Arc<Client>) {
    let (mut config, cert) =
        crate::quic::testutil::server_config_with_cert(&[b"nw3"], true).unwrap();
    let mut transport = quinn::TransportConfig::default();
    configure(&mut transport);
    config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let pin: String = Sha256::digest(cert)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let node = Node::from_share_link(&format!(
        "nowhere://{KEY}@{}?net=udp&morph=0&sni=localhost&pin={pin}",
        endpoint.local_addr().unwrap()
    ))
    .unwrap();
    let settings = Settings::read(node.nowhere().unwrap(), env).unwrap();
    let client = Client::new(&node, Arc::new(settings)).unwrap();
    (endpoint, client)
}

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("peer operation timed out")
}

async fn first_request(peer: &Connection) -> (quinn::SendStream, quinn::RecvStream) {
    first_request_with(peer, &REQUEST).await
}

async fn first_request_with(
    peer: &Connection,
    request: &[u8; 8],
) -> (quinn::SendStream, quinn::RecvStream) {
    let (send, mut recv) = bounded(peer.accept_bi()).await.unwrap();
    assert_eq!(u64::from(recv.id()), 0);
    let mut bytes = [0; 24];
    bounded(recv.read_exact(&mut bytes)).await.unwrap();
    let mut exporter = [0; 32];
    peer.export_keying_material(&mut exporter, wire::EXPORTER.as_bytes(), b"")
        .unwrap();
    assert_eq!(&bytes[..16], wire::auth(&wire::auth_key(KEY), 2, &exporter));
    assert_eq!(&bytes[16..], request);
    (send, recv)
}

#[tokio::test]
async fn warm_opens_no_stream_and_first_business_stream_carries_authentication() {
    let (endpoint, client) = fixture();
    let accepting = tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
    let (_, _state) = bounded(client.connection(Duration::from_secs(2)))
        .await
        .unwrap();
    let peer = accepting.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), peer.accept_bi())
            .await
            .is_err()
    );
    let task = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
                .await
        }
    });
    let (mut send, recv) = first_request(&peer).await;
    send.write_all(&[0]).await.unwrap();
    let stream = bounded(task).await.unwrap().unwrap();
    drop(stream);
    client.quic.as_ref().unwrap().force_close().await;
    bounded(peer.closed()).await;
    drop((send, recv));
}

#[tokio::test]
async fn concurrent_first_flow_waits_for_explicit_setup_result() {
    let (endpoint, client) = fixture();
    let accepting = tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
    bounded(client.connection(Duration::from_secs(2)))
        .await
        .unwrap();
    let peer = accepting.await.unwrap();
    let first = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
                .await
        }
    });
    let (mut send, recv) = first_request(&peer).await;
    let second = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
                .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), peer.accept_bi())
            .await
            .is_err()
    );
    send.write_all(&[0]).await.unwrap();
    let (mut second_send, mut second_recv) = bounded(peer.accept_bi()).await.unwrap();
    assert_eq!(u64::from(second_recv.id()), 4);
    let mut request = [0; 8];
    bounded(second_recv.read_exact(&mut request)).await.unwrap();
    assert_eq!(request, REQUEST);
    second_send.write_all(&[0]).await.unwrap();
    let streams = (
        bounded(first).await.unwrap().unwrap(),
        bounded(second).await.unwrap().unwrap(),
    );
    client.quic.as_ref().unwrap().force_close().await;
    drop((streams, send, recv, second_send, second_recv));
}

#[tokio::test]
async fn target_refusal_authenticates_carrier_without_replaying_request() {
    let (endpoint, client) = fixture();
    let peer = tokio::spawn(async move {
        let peer = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, recv) = first_request(&peer).await;
        send.write_all(&[3]).await.unwrap();
        let (mut next_send, mut next_recv) = bounded(peer.accept_bi()).await.unwrap();
        assert_eq!(u64::from(next_recv.id()), 4);
        let mut request = [0; 8];
        bounded(next_recv.read_exact(&mut request)).await.unwrap();
        assert_eq!(request, REQUEST);
        next_send.write_all(&[0]).await.unwrap();
        bounded(peer.closed()).await;
        drop((send, recv, next_send, next_recv));
    });
    let error = client
        .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
        .await
        .err()
        .unwrap();
    assert!(
        error
            .downcast_ref::<crate::proxy::TargetFailure>()
            .is_some()
    );
    let stream = client
        .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    client.quic.as_ref().unwrap().force_close().await;
    bounded(peer).await.unwrap();
    drop(stream);
}

#[tokio::test]
async fn cancelled_first_setup_closes_unauthenticated_carrier() {
    let (endpoint, client) = fixture();
    let accepting = tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
    bounded(client.connection(Duration::from_secs(2)))
        .await
        .unwrap();
    let peer = accepting.await.unwrap();
    let first = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
                .await
        }
    });
    let streams = first_request(&peer).await;
    first.abort();
    assert!(matches!(first.await, Err(error) if error.is_cancelled()));
    bounded(peer.closed()).await;
    client.quic.as_ref().unwrap().force_close().await;
    drop(streams);
}

#[tokio::test]
async fn server_initiated_stream_closes_nowhere_carrier() {
    let (endpoint, client) = fixture();
    let accepting = tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
    bounded(client.connection(Duration::from_secs(2)))
        .await
        .unwrap();
    let peer = accepting.await.unwrap();
    let first = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
                .await
        }
    });
    let (mut first_send, first_recv) = first_request(&peer).await;
    first_send.write_all(&[0]).await.unwrap();
    let stream = bounded(first).await.unwrap().unwrap();
    let (mut send, recv) = bounded(peer.open_bi()).await.unwrap();
    send.write_all(&[1]).await.unwrap();
    bounded(peer.closed()).await;
    client.quic.as_ref().unwrap().force_close().await;
    drop((send, recv, first_send, first_recv, stream));
}

#[tokio::test]
async fn force_close_includes_released_carrier_and_rejects_new_dials() {
    let (endpoint, client) = fixture();
    let accepting = tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
    let (connection, state) = bounded(client.connection(Duration::from_secs(2)))
        .await
        .unwrap();
    let peer = accepting.await.unwrap();
    let carrier = client.quic.as_ref().unwrap();
    carrier.release_cached().await;
    assert!(connection.close_reason().is_none());
    bounded(carrier.force_close()).await;
    bounded(peer.closed()).await;
    assert!(client.connection(Duration::from_secs(2)).await.is_err());
    drop(state);
}

#[tokio::test]
async fn udp_registers_before_setup_and_activates_only_after_ready() {
    for cancel in [false, true] {
        let (endpoint, client) = fixture();
        let accepting =
            tokio::spawn(async move { endpoint.accept().await.unwrap().await.unwrap() });
        let (_, state) = bounded(client.connection(Duration::from_secs(2)))
            .await
            .unwrap();
        let peer = accepting.await.unwrap();
        let target = "127.0.0.1:443".parse().unwrap();
        let mut request = REQUEST;
        request[0] = 1;
        let task = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .quic_udp(&request, target, Instant::now() + Duration::from_secs(2))
                    .await
            }
        });
        let (mut send, recv) = first_request_with(&peer, &request).await;
        let flow = state.flows.lock().get(&1).unwrap().upgrade().unwrap();
        assert!(!flow.ready.load(Ordering::Acquire));
        flow.receive(
            bytes::Bytes::from_static(&[0, 0, 0, 1, 99]),
            &state.budget,
            &state.reassembly,
        );
        assert!(flow.queue.lock().is_empty());
        assert_eq!(state.flows.lock().len(), 1);
        assert_eq!(
            state.budget.available_permits(),
            client.settings.queue_bytes
        );
        if cancel {
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            bounded(peer.closed()).await;
        } else {
            send.write_all(&[0]).await.unwrap();
            let transport = bounded(task).await.unwrap().unwrap();
            assert!(flow.ready.load(Ordering::Acquire));
            peer.send_datagram(bytes::Bytes::from_static(&[0, 0, 0, 1, 7, 8, 9]))
                .unwrap();
            let mut payload = [0; 3];
            let (len, source) = bounded(transport.recv_packet(&mut payload)).await.unwrap();
            assert_eq!((len, source, payload), (3, target, [7, 8, 9]));
            drop(transport);
        }
        assert_eq!(
            state.budget.available_permits(),
            client.settings.queue_bytes
        );
        assert!(state.flows.lock().is_empty());
        client.quic.as_ref().unwrap().force_close().await;
        drop((send, recv));
    }
}

#[tokio::test]
async fn blocked_stream_open_obeys_handshake_and_remaining_setup_deadlines() {
    for setup in [Duration::from_millis(50), Duration::from_secs(2)] {
        let (endpoint, client) = fixture_with(
            |transport| {
                transport.max_concurrent_bidi_streams(1u32.into());
            },
            |name| Ok((name == "NOW_HANDSHAKE_TIMEOUT").then(|| "200ms".into())),
        );
        let peer_task = tokio::spawn(async move {
            let peer = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, recv) = first_request(&peer).await;
            send.write_all(&[0]).await.unwrap();
            bounded(peer.closed()).await;
            drop((endpoint, send, recv));
        });
        let original = client
            .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let start = Instant::now();
        let result = tokio::time::timeout(
            setup.min(client.settings.handshake) + Duration::from_millis(400),
            client.quic_flow(&REQUEST, start + setup),
        )
        .await
        .expect("stream admission ignored its shorter handshake/setup budget");
        let error = result.unwrap_err();
        assert!(
            error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
        assert!(start.elapsed() >= setup.min(client.settings.handshake) / 2);
        client.quic.as_ref().unwrap().force_close().await;
        bounded(peer_task).await.unwrap();
        drop(original);
    }
}

#[tokio::test]
async fn exhausted_carrier_uses_configured_absolute_drain_timeout() {
    use std::sync::atomic::AtomicUsize;
    for shutdown in [Duration::from_millis(150), Duration::from_millis(450)] {
        let (endpoint, client) = fixture_with(
            |_| {},
            |name| {
                Ok((name == "NOW_SHUTDOWN_TIMEOUT").then(|| format!("{}ms", shutdown.as_millis())))
            },
        );
        let accepting = tokio::spawn(async move {
            let first = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, recv) = first_request(&first).await;
            send.write_all(&[0]).await.unwrap();
            let second = endpoint.accept().await.unwrap().await.unwrap();
            (endpoint, first, second, send, recv)
        });
        let original = client
            .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let (old, old_state) = client.connection(Duration::from_secs(2)).await.unwrap();
        let checks = AtomicUsize::new(0);
        let started = Instant::now();
        let error = client
            .open_flow_checked(Instant::now() + Duration::from_secs(2), |raw| {
                if checks.fetch_add(1, Ordering::Relaxed) == 0 {
                    anyhow::bail!("injected derived-ID exhaustion");
                }
                datagram::flow_id(raw)
            })
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error.downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        ));
        assert_eq!(checks.load(Ordering::Relaxed), 1);
        let opening = client
            .open_flow(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let peers = bounded(accepting).await.unwrap();
        assert!(old_state.draining.load(Ordering::Acquire));
        assert_ne!(old.stable_id(), opening.state.conn.stable_id());
        assert!(old.close_reason().is_none());
        tokio::time::timeout(shutdown + Duration::from_millis(600), old.closed())
            .await
            .expect("old carrier ignored configured drain timeout");
        assert!(started.elapsed() >= shutdown);
        assert!(opening.state.conn.close_reason().is_none());
        client.quic.as_ref().unwrap().force_close().await;
        drop((peers, opening, original, old_state));
    }
}

#[tokio::test]
async fn stream_open_rechecks_draining_before_business_admission() {
    let (endpoint, client) = fixture();
    let accepting = tokio::spawn(async move {
        let first = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, recv) = first_request(&first).await;
        send.write_all(&[0]).await.unwrap();
        let second = endpoint.accept().await.unwrap().await.unwrap();
        (endpoint, first, second, send, recv)
    });
    let original = client
        .quic_flow(&REQUEST, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let (old, old_state) = client.connection(Duration::from_secs(2)).await.unwrap();
    let opening = client
        .open_flow_checked(Instant::now() + Duration::from_secs(2), |raw| {
            old_state.draining.store(true, Ordering::Release);
            datagram::flow_id(raw)
        })
        .await
        .unwrap();
    assert_ne!(old.stable_id(), opening.state.conn.stable_id());
    assert!(old.close_reason().is_none());
    let peers = bounded(accepting).await.unwrap();
    client.quic.as_ref().unwrap().force_close().await;
    drop((peers, opening, original, old_state));
}

#[tokio::test]
async fn ready_udp_drop_sends_close_once_without_reflecting_peer_close() {
    for closure in ["local", "peer_datagram", "peer_control"] {
        let (endpoint, client) = fixture();
        let accepting = tokio::spawn(async move {
            let peer = endpoint.accept().await.unwrap().await.unwrap();
            (endpoint, peer)
        });
        let task = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                let mut request = REQUEST;
                request[0] = 1;
                client
                    .quic_udp(
                        &request,
                        "127.0.0.1:443".parse().unwrap(),
                        Instant::now() + Duration::from_secs(2),
                    )
                    .await
            }
        });
        let (endpoint, peer) = bounded(accepting).await.unwrap();
        let mut request = REQUEST;
        request[0] = 1;
        let (mut send, recv) = first_request_with(&peer, &request).await;
        send.write_all(&[0]).await.unwrap();
        let udp = bounded(task).await.unwrap().unwrap();
        let close = bytes::Bytes::copy_from_slice(&(0x8000_0000 | udp.id).to_be_bytes());
        if closure != "local" {
            if closure == "peer_datagram" {
                peer.send_datagram(close.clone()).unwrap();
            } else {
                send.finish().unwrap();
            }
            let mut payload = [0; 1];
            assert!(bounded(udp.recv_packet(&mut payload)).await.is_err());
        }
        drop(udp);
        if closure == "local" {
            assert_eq!(bounded(peer.read_datagram()).await.unwrap(), close);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(150), peer.read_datagram())
                .await
                .is_err(),
            "UDP close was reflected or sent twice"
        );
        client.quic.as_ref().unwrap().force_close().await;
        drop((endpoint, send, recv));
    }
}
