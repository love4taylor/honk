use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use honk_config::node::{Node, NowhereConfig};
use quinn::{Connection, VarInt};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::{Duration, Instant, timeout_at};

use super::{Client, datagram, morph, settings::Settings, wire};
use crate::proxy::{PacketTransport, QuicSendToken};
use crate::quic::QuicBiStream;

mod carrier;
pub(super) use carrier::Carrier;

pub(super) fn client(
    node: &Node,
    config: &NowhereConfig,
    settings: &Settings,
    keys: Option<morph::MorphKeys>,
    tls: Arc<quinn::rustls::ClientConfig>,
) -> anyhow::Result<Carrier> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .max_idle_timeout(Some(settings.idle.try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .stream_receive_window(VarInt::from_u64(settings.stream_window)?)
        .receive_window(VarInt::from_u32(64 * 1024))
        .send_window(settings.send_window)
        .datagram_receive_buffer_size(Some(4 * 1024 * 1024))
        .datagram_send_buffer_size(4 * 1024 * 1024)
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    morph::configure_morph_mtu(&mut transport, config.morph);
    let mut quic = quinn::ClientConfig::new(Arc::new(crypto));
    quic.transport_config(Arc::new(transport));
    let policy = settings.prelude;
    let server_name = config
        .tls
        .sni
        .clone()
        .unwrap_or_else(|| node.host().to_owned());
    Ok(
        Carrier::new(node.host(), node.port, server_name, quic).with_endpoint_factory(
            move |ipv6| {
                let bind = if ipv6 { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
                let socket = crate::util::marked_udp_socket(bind)?;
                let runtime = quinn::default_runtime()
                    .ok_or_else(|| io::Error::other("QUIC runtime missing"))?;
                let socket = morph::wrap_morph_client_udp_socket(
                    socket,
                    keys.clone(),
                    runtime.as_ref(),
                    policy,
                )?;
                let endpoint =
                    morph::morph_endpoint_config(keys.is_some()).map_err(io::Error::other)?;
                quinn::Endpoint::new_with_abstract_socket(endpoint, None, socket, runtime)
            },
        ),
    )
}

pub(super) struct State {
    conn: Connection,
    endpoint: Option<crate::runtime::RuntimeEndpoint>,
    auth: Arc<Mutex<Option<[u8; 16]>>>,
    metrics: parking_lot::Mutex<Option<crate::quic::QuicConnectionMonitor>>,
    quality: parking_lot::Mutex<Option<Arc<crate::transport_quality::TransportQuality>>>,
    draining: AtomicBool,
    flows: parking_lot::Mutex<HashMap<u32, Weak<Flow>>>,
    budget: Arc<Semaphore>,
    reassembly: parking_lot::Mutex<datagram::Reassembly>,
    health: Arc<crate::quic::QuicPathHealth>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.conn
            .close(VarInt::from_u32(0), b"Nowhere state retired");
    }
}

impl State {
    fn enable_telemetry(&self) {
        self.health.enable_telemetry();
    }

    fn start(conn: Connection, settings: &Settings) -> Self {
        let health = crate::quic::QuicPathHealth::new(&conn);
        Self {
            conn,
            endpoint: None,
            auth: Arc::new(Mutex::new(None)),
            metrics: parking_lot::Mutex::new(None),
            quality: parking_lot::Mutex::new(None),
            draining: AtomicBool::new(false),
            flows: parking_lot::Mutex::new(HashMap::new()),
            budget: Arc::new(Semaphore::new(settings.queue_bytes)),
            reassembly: parking_lot::Mutex::new(datagram::Reassembly::new(settings.queue_bytes)),
            health,
        }
    }

    fn dispatcher(self: &Arc<Self>) -> anyhow::Result<()> {
        let owner = Arc::downgrade(self);
        let conn = self.conn.clone();
        let admitted = crate::runtime::spawn_owned(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut iterations = 0u8;
            loop {
                iterations = iterations.wrapping_add(1);
                if iterations.is_multiple_of(64) {
                    tokio::task::yield_now().await;
                }
                tokio::select! {
                    received = conn.read_datagram() => {
                        let Ok(frame) = received else { break };
                        if frame.len() < 4 { continue; }
                        let word = u32::from_be_bytes(frame[..4].try_into().unwrap());
                        let id = word & 0x3fff_ffff;
                        if id == 0 || word >> 30 == 3 { continue; }
                        let Some(state) = owner.upgrade() else { break };
                        let flow = state.flows.lock().get(&id).and_then(Weak::upgrade);
                        let Some(flow) = flow.filter(|flow| flow.ready.load(Ordering::Acquire) && !flow.is_closed()) else { continue };
                        if word >> 30 == 2 {
                            if frame.len() == 4 { flow.close(); }
                            continue;
                        }
                        flow.receive(frame, &state.budget, &state.reassembly);
                    }
                    _ = tick.tick() => {
                        let Some(state) = owner.upgrade() else { break };
                        state.reassembly.lock().expire(Instant::now());
                    }
                }
            }
            if let Some(state) = owner.upgrade() {
                let flows: Vec<_> = state
                    .flows
                    .lock()
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect();
                for flow in flows {
                    flow.close();
                }
            }
        });
        if admitted.is_none() {
            self.conn
                .close(VarInt::from_u32(0), b"Nowhere dispatcher unavailable");
            anyhow::bail!("Nowhere runtime is retiring");
        }
        Ok(())
    }
}

struct OpeningFlow {
    state: Arc<State>,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    id: u32,
    auth: Option<FirstAuthentication>,
}

struct FirstAuthentication {
    conn: Connection,
    guard: tokio::sync::OwnedMutexGuard<Option<[u8; 16]>>,
}
impl Drop for FirstAuthentication {
    fn drop(&mut self) {
        if self.guard.is_some() {
            self.conn
                .close(0u32.into(), b"Nowhere authentication cancelled");
        }
    }
}

impl OpeningFlow {
    async fn setup(&mut self, request: &[u8], window: u64) -> anyhow::Result<()> {
        if let Some(auth) = self.auth.as_ref().and_then(|auth| *auth.guard) {
            let mut bytes = [0; 274];
            if request.len() > bytes.len() - auth.len() {
                anyhow::bail!("Nowhere request too large");
            }
            bytes[..16].copy_from_slice(&auth);
            bytes[16..16 + request.len()].copy_from_slice(request);
            self.send
                .as_mut()
                .unwrap()
                .write_all(&bytes[..16 + request.len()])
                .await?;
        } else {
            self.send.as_mut().unwrap().write_all(request).await?;
        }
        let result = self.recv.as_mut().unwrap().read_u8().await?;
        if result > 4 {
            anyhow::bail!("invalid Nowhere setup result");
        }
        if let Some(mut auth) = self.auth.take() {
            *auth.guard = None;
            self.state
                .conn
                .set_receive_window(VarInt::from_u64(window)?);
            let monitor = self.state.conn.clone();
            if crate::runtime::spawn_owned(async move {
                if monitor.accept_bi().await.is_ok() {
                    monitor.close(1u32.into(), b"role direction violation");
                }
            })
            .is_none()
            {
                self.state
                    .conn
                    .close(0u32.into(), b"Nowhere runtime retiring");
                anyhow::bail!("Nowhere runtime is retiring");
            }
        }
        match result {
            0 => Ok(()),
            2 => Err(crate::proxy::PacketRejection::Capacity.into()),
            3 => Err(
                crate::proxy::TargetFailure(anyhow::anyhow!("Nowhere target dial failed")).into(),
            ),
            _ => anyhow::bail!("Nowhere rejected flow setup ({result})"),
        }
    }

    fn into_parts(mut self) -> (Arc<State>, quinn::SendStream, quinn::RecvStream, u32) {
        debug_assert!(self.auth.is_none());
        (
            Arc::clone(&self.state),
            self.send.take().unwrap(),
            self.recv.take().unwrap(),
            self.id,
        )
    }
}

struct ProvisionalFlow(Option<Arc<Flow>>);
impl Drop for ProvisionalFlow {
    fn drop(&mut self) {
        if let Some(flow) = self.0.take() {
            flow.close();
        }
    }
}

impl Client {
    pub(super) async fn connection(
        &self,
        limit: Duration,
    ) -> anyhow::Result<(Connection, Arc<State>)> {
        let carrier = self
            .quic
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Nowhere carrier is TLS"))?;
        carrier
            .connection(&self.settings, self.auth_key, limit)
            .await
    }

    async fn open_flow(&self, deadline: Instant) -> anyhow::Result<OpeningFlow> {
        self.open_flow_checked(deadline, datagram::flow_id).await
    }

    async fn open_flow_checked(
        &self,
        deadline: Instant,
        validate_id: impl Fn(u64) -> anyhow::Result<u32>,
    ) -> anyhow::Result<OpeningFlow> {
        for _ in 0..2 {
            let (conn, state) = self
                .connection(deadline.saturating_duration_since(Instant::now()))
                .await?;
            let guard = timeout_at(deadline, Arc::clone(&state.auth).lock_owned()).await?;
            let auth = if guard.is_some() {
                Some(FirstAuthentication {
                    conn: conn.clone(),
                    guard,
                })
            } else {
                drop(guard);
                None
            };
            if conn.close_reason().is_some() || state.draining.load(Ordering::Acquire) {
                self.quic.as_ref().unwrap().invalidate(&conn).await;
                continue;
            }
            let stream = timeout_at(
                deadline.min(Instant::now() + self.settings.handshake),
                conn.open_bi(),
            )
            .await;
            let (send, recv) = match stream {
                Ok(Ok(stream)) => stream,
                error => {
                    if auth.is_some() {
                        conn.close(0u32.into(), b"Nowhere first stream failed");
                    }
                    match error {
                        Err(error) => return Err(error.into()),
                        Ok(Err(error)) => return Err(error.into()),
                        _ => unreachable!(),
                    }
                }
            };
            if auth.is_some() && u64::from(send.id()) != 0 {
                anyhow::bail!("Nowhere authentication requires Stream 0");
            }
            if let Ok(id) = validate_id(u64::from(send.id())) {
                if state.draining.load(Ordering::Acquire) {
                    self.quic.as_ref().unwrap().invalidate(&conn).await;
                    continue;
                }
                return Ok(OpeningFlow {
                    state,
                    send: Some(send),
                    recv: Some(recv),
                    id,
                    auth,
                });
            }
            if auth.is_some() {
                conn.close(0u32.into(), b"Nowhere invalid first stream");
            }
            if !state.draining.swap(true, Ordering::AcqRel) {
                let draining = conn.clone();
                let shutdown = self.settings.shutdown;
                let admitted = crate::runtime::spawn_owned(async move {
                    tokio::time::sleep(shutdown).await;
                    draining.close(0u32.into(), b"Nowhere flow IDs exhausted");
                });
                if admitted.is_none() {
                    conn.close(0u32.into(), b"Nowhere runtime retiring");
                }
            }
            self.quic.as_ref().unwrap().invalidate(&conn).await;
            return Err(crate::proxy::PacketRejection::Capacity.into());
        }
        Err(crate::proxy::PacketRejection::Capacity.into())
    }

    pub(super) async fn quic_flow(
        &self,
        request: &[u8],
        deadline: Instant,
    ) -> anyhow::Result<QuicBiStream> {
        let carrier = self
            .quic
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Nowhere carrier is TLS"))?;
        carrier
            .scope
            .scope(async {
                let mut opening = self.open_flow(deadline).await?;
                timeout_at(
                    deadline,
                    opening.setup(request, self.settings.connection_window),
                )
                .await??;
                let (state, send, recv, _) = opening.into_parts();
                Ok(QuicBiStream::new(send, recv).with_on_drop(move || {
                    let _state = &state;
                }))
            })
            .await
    }

    pub(super) async fn quic_udp(
        &self,
        request: &[u8],
        target: SocketAddr,
        deadline: Instant,
    ) -> anyhow::Result<Arc<Udp>> {
        let carrier = self
            .quic
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Nowhere carrier is TLS"))?;
        carrier.scope.scope(async {
            let mut opening = self.open_flow(deadline).await?;
            if opening.state.conn.max_datagram_size().is_none() { anyhow::bail!("Nowhere QUIC peer lacks DATAGRAM support"); }
            let state = Arc::clone(&opening.state);
            let id = opening.id;
            // Register before setup, but admit datagrams only after READY.
            let flow = Arc::new(Flow::new(Arc::downgrade(&state), id));
            state.flows.lock().insert(id, Arc::downgrade(&flow));
            let mut provisional = ProvisionalFlow(Some(Arc::clone(&flow)));
            timeout_at(deadline, opening.setup(request, self.settings.connection_window)).await??;
            flow.ready.store(true, Ordering::Release);
            let (_, mut send, mut recv, _) = opening.into_parts();
            let control = Arc::clone(&flow);
            let admitted = crate::runtime::spawn_owned(async move {
                let notified = control.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if control.is_closed() { return; }
                tokio::select! { _ = recv.read_u8() => {}, _ = send.stopped() => {}, _ = notified => {}, }
                control.close();
                let _ = send.finish();
                let _ = recv.stop(0u32.into());
            });
            if admitted.is_none() { anyhow::bail!("Nowhere runtime is retiring"); }
            provisional.0 = None;
            Ok(Arc::new(Udp { state, flow, send_gate: Mutex::new(0), id, target }))
        }).await
    }
}

struct Flow {
    owner: Weak<State>,
    id: u32,
    queue: parking_lot::Mutex<VecDeque<datagram::Packet>>,
    closed: AtomicBool,
    ready: AtomicBool,
    notify: Notify,
    available: Notify,
}
impl Flow {
    fn new(owner: Weak<State>, id: u32) -> Self {
        Self {
            owner,
            id,
            queue: parking_lot::Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            notify: Notify::new(),
            available: Notify::new(),
        }
    }
    fn receive(
        &self,
        frame: bytes::Bytes,
        budget: &Arc<Semaphore>,
        reassembly: &parking_lot::Mutex<datagram::Reassembly>,
    ) {
        let packet = {
            let mut reassembly = reassembly.lock();
            if !self.ready.load(Ordering::Acquire) || self.is_closed() {
                return;
            }
            reassembly.receive(frame, budget)
        };
        if let Some(packet) = packet {
            let mut queue = self.queue.lock();
            if self.is_closed() || queue.len() >= 64 {
                return;
            }
            queue.push_back(packet);
            self.available.notify_one();
        }
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    fn closed_error(&self) -> io::Error {
        io::ErrorKind::ConnectionAborted.into()
    }
    fn check(&self) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        Ok(())
    }
    fn close(&self) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.queue.lock().clear();
        if let Some(state) = self.owner.upgrade() {
            state.reassembly.lock().remove_flow(self.id);
            state.flows.lock().remove(&self.id);
        }
        self.notify.notify_waiters();
        self.available.notify_waiters();
        true
    }
}

pub(super) struct Udp {
    state: Arc<State>,
    flow: Arc<Flow>,
    send_gate: Mutex<u32>,
    id: u32,
    target: SocketAddr,
}
impl std::fmt::Debug for Udp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NowhereQuicUdp")
            .field("target", &self.target)
            .finish()
    }
}
impl Drop for Udp {
    fn drop(&mut self) {
        if self.flow.close()
            && self.flow.ready.load(Ordering::Acquire)
            && self.state.conn.close_reason().is_none()
        {
            let close = (0x8000_0000 | self.id).to_be_bytes();
            let _ = self
                .state
                .conn
                .send_datagram(bytes::Bytes::copy_from_slice(&close));
        }
    }
}

impl Udp {
    pub(super) async fn send_payload(&self, data: &[u8]) -> io::Result<()> {
        let mut packet = self.send_gate.lock().await;
        self.flow.check()?;
        datagram::send_packet(
            self.id,
            &mut packet,
            data,
            || self.state.conn.max_datagram_size(),
            |frame| async move {
                let notified = self.flow.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                self.flow.check()?;
                tokio::select! {
                    result = self.state.conn.send_datagram_wait(frame) => match result {
                        Ok(()) => Ok(datagram::SendOutcome::Sent),
                        Err(quinn::SendDatagramError::TooLarge) => Ok(datagram::SendOutcome::TooLarge),
                        Err(error) => Err(io::Error::other(error)),
                    },
                    _ = notified => Err(self.flow.closed_error()),
                }
            },
        )
        .await?;
        Ok(())
    }
    pub(super) async fn recv_payload(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let packet = loop {
            let notified = self.flow.available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.flow.check()?;
            if let Some(packet) = self.flow.queue.lock().pop_front() {
                break packet;
            }
            notified.await;
        };
        if packet.bytes.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Nowhere receive buffer too small",
            ));
        }
        buf[..packet.bytes.len()].copy_from_slice(&packet.bytes);
        Ok((packet.bytes.len(), self.target))
    }
}

#[async_trait]
impl PacketTransport for Udp {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn send_timeout(&self) -> Duration {
        self.state.health.send_timeout()
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }
    fn record_quic_send_started(&self) -> QuicSendToken {
        self.state.health.record_send_started(&self.state.conn)
    }
    fn record_quic_send_success(&self, token: QuicSendToken) {
        self.state
            .health
            .record_send_success(token, &self.state.conn);
    }
    fn record_quic_send_timeout(&self, token: QuicSendToken) {
        if self
            .state
            .health
            .record_send_timeout(token, &self.state.conn)
        {
            crate::quic::record_quic_send_timeout();
        }
    }
    fn record_quic_send_failure(&self, token: QuicSendToken) {
        self.state.health.record_send_failure(token);
    }
    fn quic_path_stalled(&self) -> bool {
        self.state.health.is_stalled()
    }
    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send_payload(data).await
    }
    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_payload(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    #[tokio::test]
    async fn closing_flow_releases_queued_partial_bytes_and_capacity_before_transport_drop() {
        let (server, addr) = crate::quic::testutil::server_endpoint(&[b"nw3"], true).unwrap();
        let peer = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
        let mut node = Node {
            outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
            ..Default::default()
        };
        node.tls_mut().unwrap().skip_cert_verify = true;
        let config = crate::quic::client_config(&node, &[b"nw3"], Default::default())
            .await
            .unwrap();
        let endpoint = crate::quic::client_endpoint(false).unwrap();
        let conn = endpoint
            .connect_with(config, addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let peer = peer.await.unwrap();
        let settings =
            Settings::read(&honk_config::node::NowhereConfig::default(), |_| Ok(None)).unwrap();
        let state = State::start(conn, &settings);
        let state = Arc::new(state);
        let budget = Arc::new(Semaphore::new(10000));
        let flow = Arc::new(Flow::new(Arc::downgrade(&state), 2));
        flow.ready.store(true, Ordering::Release);
        state.flows.lock().insert(2, Arc::downgrade(&flow));
        flow.receive(
            bytes::Bytes::from_static(&[0, 0, 0, 2, 1, 2, 3]),
            &budget,
            &state.reassembly,
        );
        let frames: Vec<_> = datagram::fragments(2, 1, &vec![0; 3500], 1200)
            .unwrap()
            .collect();
        flow.receive(frames[0].clone(), &budget, &state.reassembly);
        assert_eq!(budget.available_permits(), 6497);
        flow.close();
        assert_eq!(budget.available_permits(), 10000);
        assert!(flow.queue.lock().is_empty());
        assert!(state.flows.lock().is_empty());
        state.health.mark_stalled_for_test();
        assert!(state.health.is_stalled());
        assert_eq!(
            flow.check().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        flow.receive(frames[1].clone(), &budget, &state.reassembly);
        flow.close();
        assert_eq!(budget.available_permits(), 10000);
        endpoint.close(0u32.into(), b"done");
        peer.close(0u32.into(), b"done");
    }
    #[tokio::test]
    #[ignore = "requires pinned official Nowhere executable in HONK_NOWHERE_BIN"]
    async fn official_portal_quic_discovers_mtu_with_and_without_morph() {
        let binary = std::env::var("HONK_NOWHERE_BIN").unwrap();
        for enabled in [false, true] {
            let (_portal, _directory, port, pin) =
                super::super::tests::portal::start(&binary, enabled).await;
            let node = Node::from_share_link(&format!(
                "nowhere://0123456789abcdef0123456789abcdef@127.0.0.1:{port}?net=udp&morph={}&sni=localhost&pin={pin}",
                u8::from(enabled)
            )).unwrap();
            let client = Client::new(
                &node,
                Arc::new(Settings::load(node.nowhere().unwrap()).unwrap()),
            )
            .unwrap();
            let (conn, _) = client.connection(Duration::from_secs(3)).await.unwrap();
            assert!(
                conn.congestion_state()
                    .into_any()
                    .is::<quinn::congestion::Bbr>()
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                while conn.stats().path.current_mtu <= 1252 {
                    assert!(conn.close_reason().is_none());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("official PMTUD did not grow the fixed baseline MTU");
            let mtu = conn.stats().path.current_mtu;
            assert!(mtu <= if enabled { 1440 } else { 1452 });
            println!("official Portal PMTUD morph={enabled}: mtu={mtu}");
            client.quic.as_ref().unwrap().force_close().await;
        }
    }

    #[tokio::test]
    #[ignore = "requires official Nowhere 3.3.0 executable in HONK_NOWHERE_BIN"]
    async fn official_portal_exhaustion_replaces_connection_and_bounds_old_flow_drain() {
        use tokio::io::AsyncWriteExt;
        let binary = std::env::var("HONK_NOWHERE_BIN").unwrap();
        let (_portal, _directory, port, pin) =
            super::super::tests::portal::start(&binary, false).await;
        let node = Node::from_share_link(&format!("nowhere://0123456789abcdef0123456789abcdef@127.0.0.1:{port}?net=udp&morph=0&sni=localhost&pin={pin}")).unwrap();
        let client = Client::new(
            &node,
            Arc::new(Settings::load(node.nowhere().unwrap()).unwrap()),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut payload = [0; 4];
            socket.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"live");
            socket.write_all(&payload).await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut original = client
            .quic_flow(&wire::request(target, None, false).unwrap(), deadline)
            .await
            .unwrap();
        let (old, old_state) = client.connection(Duration::from_secs(2)).await.unwrap();
        let checks = AtomicUsize::new(0);
        let error = client
            .open_flow_checked(deadline, |raw| {
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
        let mut opening = client.open_flow(deadline).await.unwrap();
        let refused = tokio::net::TcpSocket::new_v4().unwrap();
        refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let result = opening
            .setup(
                &wire::request(refused.local_addr().unwrap(), None, false).unwrap(),
                client.settings.connection_window,
            )
            .await;
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<crate::proxy::TargetFailure>()
                .is_some()
        );
        assert!(
            opening.auth.is_none(),
            "a definite refusal authenticates the new carrier"
        );
        let new_state = Arc::clone(&opening.state);
        assert!(old_state.draining.load(Ordering::Acquire));
        assert_ne!(old.stable_id(), new_state.conn.stable_id());
        assert!(old.close_reason().is_none());
        original.write_all(b"live").await.unwrap();
        let mut reply = [0; 4];
        original.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"live");
        echo.await.unwrap();
        tokio::time::timeout(Duration::from_secs(6), old.closed())
            .await
            .expect("exhausted carrier did not close after bounded drain");
        assert!(new_state.conn.close_reason().is_none());
        drop((original, opening));
        client.quic.as_ref().unwrap().force_close().await;
    }
}

#[cfg(test)]
mod auth_tests;

#[cfg(test)]
mod window_tests;
