use super::*;
use crate::runtime::{RuntimeEndpoint, TaskScope};
use crate::transport_quality::{CarrierSample, CarrierSampler, TransportQuality};
use anyhow::Context as _;

type EndpointFactory = dyn Fn(bool) -> io::Result<quinn::Endpoint> + Send + Sync;

pub(in super::super) struct Carrier {
    host: String,
    port: u16,
    name: String,
    config: quinn::ClientConfig,
    factory: Option<Arc<EndpointFactory>>,
    pub(super) scope: TaskScope,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    current: Option<Arc<State>>,
    tracked: Vec<Weak<State>>,
    quality: Option<Arc<TransportQuality>>,
    closed: bool,
}

impl Carrier {
    pub(super) fn new(host: &str, port: u16, name: String, config: quinn::ClientConfig) -> Self {
        Self {
            host: host.into(),
            port,
            name,
            config,
            factory: None,
            scope: TaskScope::capture(),
            cache: Mutex::new(Cache::default()),
        }
    }

    pub(super) fn with_endpoint_factory(
        mut self,
        factory: impl Fn(bool) -> io::Result<quinn::Endpoint> + Send + Sync + 'static,
    ) -> Self {
        self.factory = Some(Arc::new(factory));
        self
    }

    pub(super) async fn connection(
        &self,
        settings: &Settings,
        key: [u8; 32],
        limit: Duration,
    ) -> anyhow::Result<(Connection, Arc<State>)> {
        let deadline = Instant::now() + limit;
        self.scope
            .scope(timeout_at(deadline, async {
                let mut cache = self.cache.lock().await;
                if cache.closed {
                    anyhow::bail!("Nowhere QUIC client is closed");
                }
                cache.tracked.retain(|state| state.strong_count() != 0);
                if let Some(state) = cache.current.as_ref().filter(|state| {
                    state.conn.close_reason().is_none() && !state.draining.load(Ordering::Acquire)
                }) {
                    crate::runtime::start_scoped_dial();
                    if let Some(observer) = crate::runtime::flow_observation::current() {
                        observer.publish(
                            crate::runtime::flow_observation::FlowEvent::TransportAttached {
                                server_addr: Some(state.conn.remote_address()),
                                resolution_location:
                                    crate::runtime::flow_observation::ResolutionLocation::Unknown,
                            },
                        );
                    }
                    return Ok((state.conn.clone(), Arc::clone(state)));
                }
                cache.current = None;
                let (conn, endpoint) = self.dial(deadline, settings.handshake).await?;
                let mut guard = CloseGuard(Some(conn.clone()));
                let data = conn
                    .handshake_data()
                    .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .ok_or_else(|| anyhow::anyhow!("Nowhere QUIC handshake data missing"))?;
                if data.protocol.as_deref() != Some(b"nw3") {
                    anyhow::bail!("Nowhere QUIC requires nw3 without early data");
                }
                let mut exporter = [0; 32];
                conn.export_keying_material(&mut exporter, wire::EXPORTER.as_bytes(), b"")
                    .map_err(|_| anyhow::anyhow!("Nowhere QUIC exporter failed"))?;
                let mut state = State::start(conn.clone(), settings);
                state.endpoint = Some(endpoint);
                state.auth = Arc::new(Mutex::new(Some(wire::auth(&key, 2, &exporter))));
                let state = Arc::new(state);
                state.dispatcher()?;
                if let Some(quality) = &cache.quality {
                    state.enable_metrics(Arc::clone(quality));
                }
                cache.tracked.push(Arc::downgrade(&state));
                cache.current = Some(Arc::clone(&state));
                crate::runtime::flow_observation::milestone(
                    crate::runtime::flow_observation::Milestone::TransportReady,
                );
                guard.0 = None;
                Ok((conn, state))
            }))
            .await?
    }

    async fn dial(
        &self,
        deadline: Instant,
        handshake: Duration,
    ) -> anyhow::Result<(Connection, RuntimeEndpoint)> {
        let (addresses, selection) =
            crate::runtime::flow_observation::observe_resolution(timeout_at(
                deadline.min(Instant::now() + handshake),
                crate::bootstrap::resolve(&self.host),
            ))
            .await;
        let addresses: Vec<_> = addresses?
            .with_context(|| format!("resolve {}", self.host))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .collect();
        let mut last = anyhow::anyhow!("Nowhere server has no address");
        for address in addresses {
            let selection = selection.as_ref();
            let result = crate::runtime::admit_physical_dial(async {
                let endpoint = crate::runtime::new_owned_quic_endpoint(|| {
                    self.factory.as_ref().expect("Nowhere endpoint factory")(address.is_ipv6())
                })?;
                if let Some(selection) = selection {
                    selection.selected_ip(address.ip());
                }
                let mut observation = crate::runtime::flow_observation::TransportAttempt::start(
                    Some(address),
                    crate::runtime::flow_observation::ResolutionLocation::Unknown,
                );
                let result = async {
                    let connecting =
                        endpoint.connect_with(self.config.clone(), address, &self.name)?;
                    let conn = timeout_at(deadline.min(Instant::now() + handshake), connecting)
                        .await?
                        .map_err(|error| crate::proxy::NodeFailure(error.into()))?;
                    Ok::<_, anyhow::Error>((conn, endpoint))
                }
                .await;
                if let Some(observation) = observation.as_mut() {
                    observation.finish(
                        if result.is_ok() {
                            crate::runtime::flow_observation::TransportStatus::Succeeded
                        } else {
                            crate::runtime::flow_observation::TransportStatus::Failed
                        },
                        result.as_ref().err().map(|_| {
                            crate::runtime::flow_observation::TransportError::QuicConnectFailed
                        }),
                    );
                }
                result
            })
            .await;
            match result {
                Ok(pair) => return Ok(pair),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    pub(in super::super) async fn enable_metrics(&self, quality: Arc<TransportQuality>) {
        self.scope
            .scope(async {
                let mut cache = self.cache.lock().await;
                cache.quality = Some(Arc::clone(&quality));
                for state in cache.tracked.iter().filter_map(Weak::upgrade) {
                    state.enable_metrics(Arc::clone(&quality));
                }
            })
            .await;
    }

    pub(super) async fn invalidate(&self, conn: &Connection) {
        let mut cache = self.cache.lock().await;
        if cache
            .current
            .as_ref()
            .is_some_and(|state| state.conn.stable_id() == conn.stable_id())
        {
            cache.current = None;
        }
    }

    pub(in super::super) async fn release_cached(&self) {
        self.cache.lock().await.current = None;
    }

    pub(in super::super) async fn force_close(&self) {
        let mut cache = self.cache.lock().await;
        cache.closed = true;
        for state in cache.tracked.drain(..).filter_map(|state| state.upgrade()) {
            state.conn.close(0u32.into(), b"generation shutdown");
            if let Some(endpoint) = &state.endpoint {
                endpoint.close(0u32.into(), b"generation shutdown");
            }
        }
        cache.current = None;
    }
}

struct CloseGuard(Option<Connection>);
impl Drop for CloseGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            conn.close(0u32.into(), b"Nowhere setup cancelled");
        }
    }
}

impl State {
    fn enable_metrics(self: &Arc<Self>, quality: Arc<TransportQuality>) {
        self.enable_telemetry();
        *self.quality.lock() = Some(Arc::clone(&quality));
        let mut metrics = self.metrics.lock();
        if metrics.is_some() {
            return;
        }
        *metrics = Some(crate::quic::monitor_quic_connection(&self.conn));
        let owner = Arc::downgrade(self);
        let conn = self.conn.clone();
        let _ = crate::runtime::spawn_owned(async move {
            let mut remote = conn.remote_address();
            let mut sampler = CarrierSampler::new(quality, remote.is_ipv6());
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = conn.closed() => break,
                    _ = tick.tick() => {
                        let Some(owner) = owner.upgrade() else { break; };
                        let Some(quality) = owner.quality.lock().clone() else { continue; };
                        let stats = conn.stats();
                        if remote != conn.remote_address() {
                            remote = conn.remote_address();
                            sampler = CarrierSampler::new(quality, remote.is_ipv6());
                        }
                        if stats.frame_rx.handshake_done == 0 { sampler.reset(); continue; }
                        let Some(transmitted) = stats.path.sent_packets.checked_sub(stats.path.sent_plpmtud_probes) else { sampler.reset(); continue; };
                        sampler.observe(CarrierSample {
                            at: std::time::Instant::now(), rtt: Some(stats.path.rtt), acknowledged: Some(stats.path.acked_ack_eliciting_packets), transmitted: Some(transmitted), lost: Some(stats.path.lost_packets), lost_bytes: Some(stats.path.lost_bytes), tx_bytes: Some(stats.flow_control.sent_bytes), rx_bytes: Some(stats.flow_control.received_bytes), tx_datagrams: Some(stats.frame_tx.datagram), rx_datagrams: Some(stats.frame_rx.datagram),
                        });
                    }
                }
            }
        });
    }
}
