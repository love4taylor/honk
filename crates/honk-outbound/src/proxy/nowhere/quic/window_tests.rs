use super::*;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn receive_windows_follow_fixed_official_profile_after_first_result() {
    for (profile, stream, connection) in [
        ("memory", 4 << 20, 8 << 20),
        ("balanced", 8 << 20, 16 << 20),
        ("throughput", 16 << 20, 32 << 20),
    ] {
        let (config, cert) =
            crate::quic::testutil::server_config_with_cert(&[b"nw3"], true).unwrap();
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let pin: String = Sha256::digest(cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let node = Node::from_share_link(&format!(
            "nowhere://0123456789abcdef0123456789abcdef@{}?net=udp&morph=0&sni=localhost&pin={pin}",
            endpoint.local_addr().unwrap()
        ))
        .unwrap();
        let settings = Settings::read(node.nowhere().unwrap(), |name| {
            Ok((name == "NOW_TRANSPORT_MEMORY_PROFILE").then(|| profile.to_owned()))
        })
        .unwrap();
        let client = Client::new(&node, Arc::new(settings)).unwrap();
        let quality = Arc::new(crate::transport_quality::TransportQuality::default());
        quality.enable();
        client.quic.as_ref().unwrap().enable_metrics(quality).await;
        let accepting = tokio::spawn(async move {
            let peer = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = peer.accept_bi().await.unwrap();
            let mut request = [0; 24];
            recv.read_exact(&mut request).await.unwrap();
            send.write_all(&[3]).await.unwrap();
            peer.closed().await;
            drop((endpoint, send, recv));
        });
        let (conn, _state) = client.connection(Duration::from_secs(2)).await.unwrap();
        let stats = conn.stats().flow_control;
        assert_eq!(
            stats.receive_window,
            64 * 1024,
            "{profile} before authentication"
        );
        assert_eq!(stats.stream_receive_window, stream);
        assert_eq!(stats.send_window, connection);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            conn.stats().flow_control.receive_window,
            64 * 1024,
            "telemetry changed unauthenticated window"
        );
        let error = client
            .quic_flow(
                &[0, 1, 127, 0, 0, 1, 1, 187],
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .err()
            .unwrap();
        assert!(
            error
                .downcast_ref::<crate::proxy::TargetFailure>()
                .is_some()
        );
        assert_eq!(conn.stats().flow_control.receive_window, connection);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let stats = conn.stats().flow_control;
        assert_eq!(
            stats.receive_window, connection,
            "{profile} fixed window changed by telemetry"
        );
        assert_eq!(stats.stream_receive_window, stream);
        assert_eq!(stats.send_window, connection);
        client.quic.as_ref().unwrap().force_close().await;
        tokio::time::timeout(Duration::from_secs(2), accepting)
            .await
            .unwrap()
            .unwrap();
    }
}
