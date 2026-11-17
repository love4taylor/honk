use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use async_trait::async_trait;
use bytes::Buf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::time::timeout;

use super::{Client, morph, wire};
use crate::proxy::{FramePoison, PacketTransport};

mod policy;
mod stream;
pub(super) use policy::config;

type Stream = stream::Stream<morph::MorphTcpStream<tokio::net::TcpStream>>;

impl Client {
    pub(super) async fn tls_flow(&self, request: &[u8]) -> anyhow::Result<Stream> {
        let address = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        self.tls_flow_dial(
            request,
            crate::util::connect_outbound(&address, self.settings.handshake),
        )
        .await
    }

    async fn tls_flow_dial(
        &self,
        request: &[u8],
        dial: impl std::future::Future<Output = io::Result<tokio::net::TcpStream>>,
    ) -> anyhow::Result<Stream> {
        let tcp = timeout(self.settings.handshake, dial).await??;
        let mut stream = timeout(self.settings.handshake, async {
            let tcp = morph::MorphTcpStream::connect(
                tcp,
                self.morph_keys.clone(),
                &self.prelude,
                self.settings.prelude,
            )
            .await?;
            let name = quinn::rustls::pki_types::ServerName::try_from(
                self.config
                    .tls
                    .sni
                    .as_deref()
                    .unwrap_or(&self.host)
                    .to_owned(),
            )?;
            let stream = Stream::connect(Arc::clone(&self.tls), name, tcp).await?;
            if stream.session.alpn_protocol() != Some(b"nw3") {
                anyhow::bail!("Nowhere requires negotiated nw3 ALPN");
            }
            Ok::<_, anyhow::Error>(stream)
        })
        .await??;
        let exporter =
            stream
                .session
                .export_keying_material([0; 32], wire::EXPORTER.as_bytes(), Some(&[]))?;
        stream
            .write_all(&wire::auth(&self.auth_key, 1, &exporter))
            .await?;
        stream.write_all(request).await?;
        stream.flush().await?;
        wire::ready(&mut stream).await?;
        Ok(stream)
    }
}

pub(super) struct Udp<S: AsyncRead + AsyncWrite + Unpin + Send + 'static = Stream> {
    reader: Mutex<Reader<ReadHalf<S>>>,
    writer: Arc<Mutex<WriteHalf<S>>>,
    poison: FramePoison,
    terminal: AtomicU8,
    target: SocketAddr,
    reading: Arc<AtomicBool>,
    writing: Arc<AtomicBool>,
    shutdown: std::time::Duration,
    scope: crate::runtime::TaskScope,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> std::fmt::Debug for Udp<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NowhereTlsUdp")
            .field("target", &self.target)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Udp<S> {
    pub(super) fn new(
        stream: S,
        target: SocketAddr,
        shutdown: std::time::Duration,
        scope: crate::runtime::TaskScope,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let reading = Arc::new(AtomicBool::new(false));
        let mut reader = Reader::new(reader);
        reader.progress = Some(Arc::clone(&reading));
        Self {
            reader: Mutex::new(reader),
            writer: Arc::new(Mutex::new(writer)),
            poison: FramePoison::default(),
            terminal: AtomicU8::new(0),
            target,
            reading,
            writing: Arc::new(AtomicBool::new(false)),
            shutdown,
            scope,
        }
    }
    pub(super) fn partial_frame(&self) -> [Arc<AtomicBool>; 2] {
        [Arc::clone(&self.reading), Arc::clone(&self.writing)]
    }
    pub(super) async fn write_packet(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(crate::proxy::PacketRejection::InvalidSize.into());
        }
        let mut writer = self.writer.lock().await;
        self.check()?;
        let frame = self.poison.begin(None)?;
        self.writing.store(true, Ordering::Release);
        let header = (data.len() as u16).to_be_bytes();
        let mut packet = Buf::chain(&header[..], data);
        writer.write_all_buf(&mut packet).await?;
        writer.flush().await?;
        frame.complete();
        self.writing.store(false, Ordering::Release);
        Ok(())
    }
    pub(super) async fn read_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        self.check()?;
        let len = match reader.read_packet().await {
            Ok(len) => len,
            Err(error) => {
                self.terminal.store(1, Ordering::Release);
                return Err(error);
            }
        };
        if len > buf.len() {
            return Err(crate::proxy::PacketRejection::InvalidSize.into());
        }
        buf[..len].copy_from_slice(&reader.payload);
        Ok((len, self.target))
    }
    fn terminal_error(&self) -> io::Error {
        io::ErrorKind::ConnectionAborted.into()
    }
    fn check(&self) -> io::Result<()> {
        if self.terminal.load(Ordering::Acquire) != 0 {
            return Err(self.terminal_error());
        }
        self.poison.check()?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Drop for Udp<S> {
    fn drop(&mut self) {
        let writer = Arc::clone(&self.writer);
        let limit = self.shutdown;
        self.scope.spawn(async move {
            let _ = timeout(limit, async { writer.lock().await.shutdown().await }).await;
        });
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> PacketTransport for Udp<S> {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.write_packet(data).await
    }
    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        self.write_packet(data).await
    }
    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.read_packet(buf).await
    }
}

#[derive(Debug)]
struct Reader<R> {
    stream: R,
    header: [u8; 2],
    header_read: usize,
    payload_len: Option<usize>,
    payload_read: usize,
    payload: Vec<u8>,
    progress: Option<Arc<AtomicBool>>,
}

impl<R: tokio::io::AsyncRead + Unpin> Reader<R> {
    fn new(stream: R) -> Self {
        Self {
            stream,
            header: [0; 2],
            header_read: 0,
            payload_len: None,
            payload_read: 0,
            payload: Vec::new(),
            progress: None,
        }
    }

    async fn read_packet(&mut self) -> io::Result<usize> {
        while self.header_read != self.header.len() {
            let len = self
                .stream
                .read(&mut self.header[self.header_read..])
                .await?;
            if len == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.header_read += len;
            if let Some(progress) = &self.progress {
                progress.store(true, Ordering::Release);
            }
        }
        let len = *self
            .payload_len
            .get_or_insert_with(|| u16::from_be_bytes(self.header) as usize);
        if len > self.payload.capacity() {
            let capacity = self
                .payload
                .capacity()
                .saturating_mul(2)
                .min(u16::MAX as usize)
                .max(len);
            self.payload.reserve_exact(capacity - self.payload.len());
        }
        self.payload.resize(len, 0);
        while self.payload_read != len {
            let received = self
                .stream
                .read(&mut self.payload[self.payload_read..])
                .await?;
            if received == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.payload_read += received;
        }
        self.header_read = 0;
        self.payload_len = None;
        self.payload_read = 0;
        if let Some(progress) = &self.progress {
            progress.store(false, Ordering::Release);
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uot_read_resumes_partial_header_and_payload_after_cancellation() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut reader = Reader::new(stream);
        for (prefix, counter) in [(&[0][..], 1), (&[3, b'a'][..], 2)] {
            peer.write_all(prefix).await.unwrap();
            let mut read = Box::pin(reader.read_packet());
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    read.as_mut().poll(cx).is_pending()
                ))
                .await
            );
            drop(read);
            if counter == 1 {
                assert_eq!(reader.header_read, 1);
            } else {
                assert_eq!(reader.payload_read, 1);
            }
        }
        peer.write_all(b"bc\0\0").await.unwrap();
        assert_eq!(reader.read_packet().await.unwrap(), 3);
        assert_eq!(reader.payload, b"abc");
        assert_eq!(reader.read_packet().await.unwrap(), 0);
        assert!(reader.payload.is_empty());
        peer.shutdown().await.unwrap();
        assert_eq!(
            reader.read_packet().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[cfg(test)]
mod policy_tests;

#[cfg(test)]
mod stage_tests {
    use super::*;
    use quinn::rustls::{self, pki_types::PrivateKeyDer};
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn dialing_and_tls_get_separate_handshake_budgets() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
        .unwrap();
        server.alpn_protocols = vec![b"nw3".to_vec()];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(server))
                .accept(tcp)
                .await
                .unwrap();
            let mut request = [0; 24];
            stream.read_exact(&mut request).await.unwrap();
            let exported = stream
                .get_ref()
                .1
                .export_keying_material([0; 32], wire::EXPORTER.as_bytes(), Some(&[]))
                .unwrap();
            assert_eq!(
                &request[..16],
                wire::auth(
                    &wire::auth_key("0123456789abcdef0123456789abcdef"),
                    1,
                    &exported
                )
            );
            stream.write_all(&[0]).await.unwrap();
            stream.flush().await.unwrap();
        });
        let pin: String = Sha256::digest(cert.cert.der())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let node = honk_config::node::Node::from_share_link(&format!("nowhere://0123456789abcdef0123456789abcdef@{address}?net=tcp&morph=0&sni=localhost&pin={pin}")).unwrap();
        let mut settings =
            super::super::Settings::read(node.nowhere().unwrap(), |_| Ok(None)).unwrap();
        settings.handshake = std::time::Duration::from_millis(400);
        let client = Client::new(&node, Arc::new(settings)).unwrap();
        let dial = async {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            tokio::net::TcpStream::connect(address).await
        };
        let request = wire::request("127.0.0.1:443".parse().unwrap(), None, false).unwrap();
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.tls_flow_dial(&request, dial),
        )
        .await
        .unwrap()
        .unwrap();
        drop(stream);
        peer.await.unwrap();
    }
}

#[cfg(test)]
mod stream_tests;
