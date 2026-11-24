use super::*;

#[test]
fn aes_matches_official_tcp_and_udp_vectors() {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef", NowhereCipher::Aes);
    let nonce = std::array::from_fn(|index| index as u8);
    let plain = std::array::from_fn::<_, 37, _>(|index| index as u8);
    for (key, offset, expected) in [
        (
            &keys.tcp_c2s,
            0,
            "8e59faa695f33a1a5ffc8369938132d677a1536e730205de8b4767a560fd155b7ed13833e3",
        ),
        (
            &keys.tcp_s2c,
            0,
            "17a4869bfb790fa12b676b42a6ad4f40f8eaff0566051e81313ca1a59486b0f766ba989ce2",
        ),
        (
            &keys.tcp_c2s,
            (1 << 40) + 19,
            "dda378cb6a89ab5e74c5081119eb5fe3a06c0ee6563feacd15afa86af9b77425f0519188a2",
        ),
    ] {
        let mut stream = cipher::TcpCipher::new(keys.cipher, key, &nonce);
        stream.try_seek(offset).unwrap();
        let mut actual = plain;
        let (first, second) = actual.split_at_mut(21);
        stream.try_apply_keystream(first).unwrap();
        stream.try_apply_keystream(second).unwrap();
        assert_eq!(hex(&actual), expected);
    }

    for (key, expected) in [
        (
            &keys.udp_c2s,
            "4378463322b3680c1d1ad62068c536c0fc5e1eac063187dcb2cf48d0ab609405aa9f4fea6b",
        ),
        (
            &keys.udp_s2c,
            "2813cf0312ebdcc2beb4ff955b4667eb3ab282761d5d5ecc3b1b111d8531262cb6ea62744a",
        ),
    ] {
        let mut actual = [0; 37];
        cipher::apply_datagram(keys.cipher, key, &nonce, &plain, &mut actual).unwrap();
        assert_eq!(hex(&actual), expected);
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

#[test]
fn authenticated_prelude_binds_identity_counter_nonce_and_shape() {
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef", NowhereCipher::ChaCha);
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
    let wrong = MorphKeys::derive(b"1123456789abcdef0123456789abcdef", NowhereCipher::ChaCha);
    assert!(wrong.decode_prelude(&prelude, &nonce).is_none());
}

#[tokio::test]
async fn udp_socket_transform_interoperates_and_preserves_datagram_boundaries() {
    for cipher in [NowhereCipher::ChaCha, NowhereCipher::Aes] {
        udp_socket_round_trip(cipher).await;
    }
}

async fn udp_socket_round_trip(cipher: NowhereCipher) {
    use quinn::udp::Transmit;
    use std::{net::UdpSocket, sync::Arc};
    let keys = MorphKeys::derive(b"0123456789abcdef0123456789abcdef", cipher);
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
