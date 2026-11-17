use super::*;

#[test]
fn authenticated_prelude_binds_identity_counter_nonce_and_shape() {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    let client = ClientPrelude::default();
    let first = client.allocate().unwrap();
    let second = client.allocate().unwrap();
    assert!(first.is_valid());
    assert_eq!(first.identity, second.identity);
    assert_eq!(second.counter, first.counter + 1);
    let nonce = [0x12; NONCE_LEN];
    let mut prelude = [0xa5; TCP_PRELUDE_LEN];
    keys.encode_prelude(&mut prelude, &nonce, first);
    assert!(keys.decode_prelude(&prelude, &nonce) == Some(first));
    assert!(prelude[32..].iter().all(|byte| byte & 0x80 == 0x80));
    for index in 0..TCP_PRELUDE_LEN {
        let mut changed = prelude;
        changed[index] ^= 1;
        assert!(keys.decode_prelude(&changed, &nonce).is_none());
    }
    assert!(keys.decode_prelude(&prelude, &[0x13; NONCE_LEN]).is_none());
    let wrong = MorphKeys::derive(b"1123456789abcdef0123456789abcdef");
    assert!(wrong.decode_prelude(&prelude, &nonce).is_none());
}

#[tokio::test]
async fn udp_socket_transform_interoperates_and_preserves_datagram_boundaries() {
    use quinn::udp::Transmit;
    use std::{net::UdpSocket, sync::Arc};
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef");
    let runtime = quinn::default_runtime().unwrap();
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    raw.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let local = raw.local_addr().unwrap();
    let remote = peer.local_addr().unwrap();
    let client = udp::wrap_morph_client_udp_socket(
        raw,
        Some(keys.clone()),
        runtime.as_ref(),
        PreludePolicy::Fade,
    )
    .unwrap();
    let server = udp::wrap_morph_udp_socket(
        runtime.wrap_udp_socket(peer).unwrap(),
        Some(keys),
        udp::UdpRole::Server,
        PreludePolicy::Fade,
    )
    .unwrap();
    let payload = b"segmented QUIC packet";
    async fn send(
        socket: &Arc<dyn quinn::AsyncUdpSocket>,
        destination: std::net::SocketAddr,
        payload: &[u8],
    ) {
        let mut poller = Arc::clone(socket).create_io_poller();
        std::future::poll_fn(|cx| {
            std::task::ready!(poller.as_mut().poll_writable(cx))?;
            match socket.try_send(&Transmit {
                destination,
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            }) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::task::Poll::Pending
                }
                result => std::task::Poll::Ready(result),
            }
        })
        .await
        .unwrap();
    }
    send(&client, remote, payload).await;
    async fn receive(socket: &Arc<dyn quinn::AsyncUdpSocket>) -> Vec<u8> {
        let mut bytes = [0; 2048];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let n = std::future::poll_fn(|cx| {
            socket.poll_recv(cx, &mut [std::io::IoSliceMut::new(&mut bytes)], &mut meta)
        })
        .await
        .unwrap();
        assert_eq!(n, 1);
        bytes[..meta[0].len].to_vec()
    }
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), receive(&server))
            .await
            .unwrap(),
        payload
    );
    send(&server, local, payload).await;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), receive(&client))
            .await
            .unwrap(),
        payload
    );
}
