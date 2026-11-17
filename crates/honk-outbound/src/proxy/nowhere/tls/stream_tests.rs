use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use quinn::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use super::stream::Stream;
use crate::proxy::PacketTransport;

#[derive(Clone, Copy, Default)]
enum WriteMode {
    #[default]
    Ready,
    Pending,
    Zero,
}

struct Script {
    write_mode: WriteMode,
    max_write: usize,
    pending_writes: usize,
    shutdown_blocked: bool,
    shutdown_calls: usize,
    read_calls: usize,
    ciphertext: Vec<u8>,
    write_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
}

#[derive(Clone)]
struct Control(Arc<Mutex<Script>>);

impl Control {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Script {
            write_mode: WriteMode::Ready,
            max_write: 7,
            pending_writes: 0,
            shutdown_blocked: false,
            shutdown_calls: 0,
            read_calls: 0,
            ciphertext: Vec::new(),
            write_waker: None,
            shutdown_waker: None,
        })))
    }

    fn write_mode(&self, mode: WriteMode) {
        let waker = {
            let mut script = self.0.lock().unwrap();
            script.write_mode = mode;
            script.write_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn block_shutdown(&self, blocked: bool) {
        let waker = {
            let mut script = self.0.lock().unwrap();
            script.shutdown_blocked = blocked;
            script.shutdown_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct ScriptIo {
    inner: DuplexStream,
    control: Control,
}

impl AsyncRead for ScriptIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.control.0.lock().unwrap().read_calls += 1;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ScriptIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let limit = {
            let mut script = self.control.0.lock().unwrap();
            match script.write_mode {
                WriteMode::Pending => {
                    script.pending_writes += 1;
                    script.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                WriteMode::Zero => return Poll::Ready(Ok(0)),
                WriteMode::Ready => script.max_write.min(buf.len()),
            }
        };
        match Pin::new(&mut self.inner).poll_write(cx, &buf[..limit]) {
            Poll::Ready(Ok(len)) => {
                self.control
                    .0
                    .lock()
                    .unwrap()
                    .ciphertext
                    .extend_from_slice(&buf[..len]);
                Poll::Ready(Ok(len))
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut script = self.control.0.lock().unwrap();
            script.shutdown_calls += 1;
            if script.shutdown_blocked {
                script.shutdown_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type Peer = tokio_rustls::server::TlsStream<DuplexStream>;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("TLS fixture stalled")
}

async fn connected() -> (Stream<ScriptIo>, Peer, Control) {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert.der().clone()],
            PrivateKeyDer::Pkcs8(identity.signing_key.serialize_der().into()),
        )
        .unwrap();
    server.alpn_protocols = vec![b"nw3".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(identity.cert.der().clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"nw3".to_vec()];
    client.enable_early_data = false;
    let control = Control::new();
    let (client_io, server_io) = tokio::io::duplex(4096);
    let client_io = ScriptIo {
        inner: client_io,
        control: control.clone(),
    };
    let client = Stream::connect(
        Arc::new(client),
        ServerName::try_from("localhost").unwrap(),
        client_io,
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let (client, server) =
        bounded(async { tokio::join!(client, acceptor.accept(server_io)) }).await;
    (client.unwrap(), server.unwrap(), control)
}

async fn assert_pending(mut future: Pin<&mut impl Future>) {
    assert!(std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await);
}

#[tokio::test]
async fn fatal_read_error_remains_visible_to_flush() {
    bounded(async {
        let (mut client, mut peer, _) = connected().await;
        peer.get_mut()
            .0
            .write_all(&[23, 3, 3, 0, 1, 0])
            .await
            .unwrap();
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            client.flush().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    })
    .await;
}

#[tokio::test]
async fn short_writes_and_cancelled_pending_write_preserve_exact_plaintext() {
    bounded(async {
        let (mut client, mut peer, control) = connected().await;
        let payload: Vec<u8> = (0..131_091).map(|index| (index % 251) as u8).collect();
        control.write_mode(WriteMode::Pending);
        let accepted = client.write(&payload).await.unwrap();
        assert!(accepted > 0 && accepted < payload.len());
        let mut blocked = Box::pin(client.write(&payload[accepted..]));
        assert_pending(blocked.as_mut()).await;
        drop(blocked);
        assert!(control.0.lock().unwrap().pending_writes >= 2);
        control.write_mode(WriteMode::Ready);
        let sending = async {
            client.write_all(&payload[accepted..]).await.unwrap();
            client.flush().await.unwrap();
            client.shutdown().await.unwrap();
        };
        let receiving = async {
            let mut received = Vec::new();
            peer.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
        };
        tokio::join!(sending, receiving);
    })
    .await;
}

#[tokio::test]
async fn zero_ciphertext_write_is_write_zero() {
    let (mut client, _peer, control) = connected().await;
    control.write_mode(WriteMode::Zero);
    let error = bounded(client.write_all(b"payload")).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
}

#[tokio::test]
async fn zero_capacity_read_does_not_poll_transport_or_end_the_stream() {
    bounded(async {
        let (mut client, mut peer, control) = connected().await;
        let calls = control.0.lock().unwrap().read_calls;
        let mut empty = [];
        let mut buf = ReadBuf::new(&mut empty);
        std::future::poll_fn(|cx| Pin::new(&mut client).poll_read(cx, &mut buf))
            .await
            .unwrap();
        assert!(buf.filled().is_empty());
        assert_eq!(control.0.lock().unwrap().read_calls, calls);
        peer.write_all(b"after-empty-read").await.unwrap();
        peer.flush().await.unwrap();
        let mut payload = [0; 16];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"after-empty-read");
    })
    .await;
}

#[tokio::test]
async fn cancelled_shutdown_resumes_once_and_keeps_read_half_open() {
    bounded(async {
        let (mut client, mut peer, control) = connected().await;
        let start = control.0.lock().unwrap().ciphertext.len();
        control.write_mode(WriteMode::Pending);
        control.block_shutdown(true);
        let mut closing = Box::pin(client.shutdown());
        assert_pending(closing.as_mut()).await;
        drop(closing);
        assert_eq!(control.0.lock().unwrap().ciphertext.len(), start);
        assert_eq!(
            client.write(b"after-close").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );

        control.write_mode(WriteMode::Ready);
        let mut closing = Box::pin(client.shutdown());
        std::future::poll_fn(|cx| {
            assert!(closing.as_mut().poll(cx).is_pending());
            if control.0.lock().unwrap().shutdown_calls > 0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        drop(closing);
        let sent = control.0.lock().unwrap().ciphertext[start..].to_vec();
        assert_eq!(sent[0], 23);
        assert_eq!(
            sent.len(),
            5 + usize::from(u16::from_be_bytes([sent[3], sent[4]]))
        );
        control.block_shutdown(false);
        client.shutdown().await.unwrap();
        assert_eq!(&control.0.lock().unwrap().ciphertext[start..], &sent);

        let mut request = Vec::new();
        peer.read_to_end(&mut request).await.unwrap();
        assert!(request.is_empty());
        peer.write_all(b"tail-after-half-close").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"tail-after-half-close");
        client.shutdown().await.unwrap();
        assert_eq!(&control.0.lock().unwrap().ciphertext[start..], &sent);
    })
    .await;
}

#[tokio::test]
async fn peer_payload_precedes_clean_or_truncated_tls_eof() {
    bounded(async {
        for clean in [false, true] {
            let (mut client, mut peer, _) = connected().await;
            peer.write_all(b"payload-before-eof").await.unwrap();
            peer.flush().await.unwrap();
            if clean {
                peer.shutdown().await.unwrap();
            } else {
                peer.get_mut().0.shutdown().await.unwrap();
            }
            let mut payload = [0; 18];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload-before-eof");
            if clean {
                assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            } else {
                assert_eq!(
                    client.read(&mut [0]).await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn truncated_handshake_cannot_publish_a_stream() {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(identity.cert.der().clone()).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let (client_io, mut peer) = tokio::io::duplex(4096);
    peer.shutdown().await.unwrap();
    let error = bounded(Stream::connect(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        client_io,
    ))
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn peer_key_update_preserves_following_payload_and_client_writes() {
    bounded(async {
        let (mut client, mut peer, _) = connected().await;
        peer.get_mut().1.refresh_traffic_keys().unwrap();
        peer.write_all(b"updated-key-payload").await.unwrap();
        peer.flush().await.unwrap();
        let mut payload = [0; 19];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"updated-key-payload");
        client.write_all(b"after-key-update").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0; 16];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"after-key-update");
    })
    .await;
}

#[tokio::test]
async fn udp_send_drains_ciphertext_with_an_independent_pending_receiver() {
    bounded(async {
        let (client, mut peer, control) = connected().await;
        let udp = Arc::new(super::Udp::new(
            client,
            "127.0.0.1:53".parse().unwrap(),
            Duration::from_secs(1),
            crate::runtime::TaskScope::default(),
        ));
        udp.send_packet_confirmed(b"first").await.unwrap();
        let mut frame = [0; 7];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x00\x05first");

        let (ready, waiting) = tokio::sync::oneshot::channel();
        let receiver = tokio::spawn({
            let udp = Arc::clone(&udp);
            async move {
                let mut buf = [0; 8];
                let mut recv = Box::pin(udp.recv_packet(&mut buf));
                assert_pending(recv.as_mut()).await;
                ready.send(()).unwrap();
                recv.await
            }
        });
        waiting.await.unwrap();
        control.write_mode(WriteMode::Pending);
        let (blocked, sending) = tokio::sync::oneshot::channel();
        let sender = tokio::spawn({
            let udp = Arc::clone(&udp);
            async move {
                let mut send = Box::pin(udp.send_packet(b"later"));
                assert_pending(send.as_mut()).await;
                blocked.send(()).unwrap();
                send.await
            }
        });
        sending.await.unwrap();
        assert!(control.0.lock().unwrap().pending_writes > 0);
        control.write_mode(WriteMode::Ready);
        sender.await.unwrap().unwrap();
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x00\x05later");
        receiver.abort();
        assert!(receiver.await.unwrap_err().is_cancelled());
    })
    .await;
}

#[tokio::test]
async fn udp_cancelled_flush_poison_prevents_a_later_frame() {
    bounded(async {
        let (client, mut peer, control) = connected().await;
        let udp = super::Udp::new(
            client,
            "127.0.0.1:53".parse().unwrap(),
            Duration::from_secs(1),
            crate::runtime::TaskScope::default(),
        );
        udp.send_packet_confirmed(b"first").await.unwrap();
        let mut frame = [0; 7];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x00\x05first");
        control.write_mode(WriteMode::Pending);
        let mut send = Box::pin(udp.send_packet(b"cancel"));
        assert_pending(send.as_mut()).await;
        drop(send);
        control.write_mode(WriteMode::Ready);
        let error = udp.send_packet(b"later").await.unwrap_err();
        assert!(
            error
                .get_ref()
                .unwrap()
                .is::<crate::proxy::FrameInterrupted>()
        );
        assert!(udp.partial_frame()[1].load(std::sync::atomic::Ordering::Acquire));
    })
    .await;
}
