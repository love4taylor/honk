//! NW3 client over TLS 1.3 or QUIC, with fixed-target UDP flows.

mod datagram;
mod idle;
mod morph;
mod quic;
pub(crate) mod settings;
mod stream;
mod tls;
mod wire;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use honk_config::node::{Node, NowhereCarrier};
use tokio::time::{Instant, timeout_at};

use super::{
    PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound, ProxyStream,
    TcpOutbound, WarmRequirement, WarmableOutbound,
};
use crate::runtime::NodeRuntime;
use settings::Settings;

struct Client {
    config: honk_config::node::NowhereConfig,
    settings: Arc<Settings>,
    host: String,
    port: u16,
    tls: Arc<quinn::rustls::ClientConfig>,
    scope: crate::runtime::TaskScope,
    prelude: morph::ClientPrelude,
    morph_keys: Option<morph::MorphKeys>,
    auth_key: [u8; 32],
    quic: Option<quic::Carrier>,
}

#[async_trait]
impl crate::runtime::QuicRuntimeClient for Client {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
    async fn enable_metrics(&self, quality: Arc<crate::transport_quality::TransportQuality>) {
        if let Some(quic) = &self.quic {
            quic.enable_metrics(quality).await;
        }
    }
    async fn force_close(&self) {
        if let Some(quic) = &self.quic {
            quic.force_close().await;
        }
    }
    async fn release_warm(&self) {
        if let Some(quic) = &self.quic {
            quic.release_cached().await;
        }
    }
}

impl Client {
    fn new(node: &Node, settings: Arc<Settings>) -> anyhow::Result<Arc<Self>> {
        node.validate_protocol()?;
        let config = node
            .nowhere()
            .ok_or_else(|| anyhow::anyhow!("Nowhere configuration required"))?
            .clone();
        let tls = tls::config(&config)?;
        let morph_keys = config
            .morph
            .then(|| morph::MorphKeys::derive(config.key.as_bytes(), config.cipher, config.grade));
        let quic = if config.carrier == NowhereCarrier::Udp {
            Some(quic::client(
                node,
                &config,
                &settings,
                morph_keys.clone(),
                Arc::clone(&tls),
            )?)
        } else {
            None
        };
        let auth_key = wire::auth_key(&config.key);
        Ok(Arc::new(Self {
            config,
            settings,
            host: node.host().into(),
            port: node.port,
            tls,
            scope: crate::runtime::TaskScope::capture(),
            prelude: morph::ClientPrelude::default(),
            morph_keys,
            auth_key,
            quic,
        }))
    }

    fn deadline(&self, started: Instant, connect_timeout: Duration) -> Instant {
        started + self.settings.setup.min(connect_timeout)
    }

    async fn tcp(
        self: &Arc<Self>,
        target: SocketAddr,
        domain: Option<&str>,
        deadline: Instant,
    ) -> anyhow::Result<ProxyStream> {
        let request = wire::request(target, domain, false)?;
        let stream: Box<dyn super::AsyncReadWrite> = match self.config.carrier {
            NowhereCarrier::Tcp => Box::new(self.tls_flow(&request).await?),
            NowhereCarrier::Udp => Box::new(self.quic_flow(&request, deadline).await?),
        };
        Ok(ProxyStream {
            stream: Box::new(stream::TcpDrain::new(stream, self.settings.tcp_read)),
            target_addr: target,
            target_domain: domain.map(str::to_owned),
        })
    }

    async fn udp(
        self: &Arc<Self>,
        target: SocketAddr,
        domain: Option<&str>,
        deadline: Instant,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let request = wire::request(target, domain, true)?;
        let (transport, partial) = match self.config.carrier {
            NowhereCarrier::Tcp => {
                let transport = Arc::new(tls::Udp::new(
                    self.tls_flow(&request).await?,
                    target,
                    self.settings.handshake,
                    self.scope.clone(),
                ));
                let partial = transport.partial_frame();
                (idle::Transport::Tls(transport), Some(partial))
            }
            NowhereCarrier::Udp => (
                idle::Transport::Quic(self.quic_udp(&request, target, deadline).await?),
                None,
            ),
        };
        self.scope.sync_scope(|| {
            Ok(
                Arc::new(idle::Udp::new(transport, self.settings.idle, partial)?)
                    as Arc<dyn PacketTransport>,
            )
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct NowhereHandler;

impl NowhereHandler {
    async fn runtime_client(runtime: &NodeRuntime) -> anyhow::Result<Arc<Client>> {
        let settings = runtime
            .nowhere_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Nowhere settings missing"))?
            .as_ref()
            .map_err(|message| anyhow::anyhow!("{message}"))?
            .clone();
        runtime
            .quic_client(|| async { Client::new(&runtime.node, settings) })
            .await
    }

    fn detached(runtime: &NodeRuntime) -> anyhow::Result<Arc<Client>> {
        let settings = runtime
            .nowhere_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Nowhere settings missing"))?
            .as_ref()
            .map_err(|message| anyhow::anyhow!("{message}"))?
            .clone();
        runtime
            .task_scope()
            .sync_scope(|| Client::new(&runtime.node, settings))
    }
}

#[async_trait]
impl TcpOutbound for NowhereHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        limit: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let started = Instant::now();
        let client = Client::new(
            node,
            Arc::new(Settings::load(node.nowhere().ok_or_else(|| {
                anyhow::anyhow!("Nowhere configuration required")
            })?)?),
        )?;
        let deadline = client.deadline(started, limit);
        timeout_at(deadline, client.tcp(target, domain, deadline)).await?
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        limit: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let deadline = Instant::now()
            + limit.min(
                runtime
                    .nowhere_settings
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Nowhere settings missing"))?
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .setup,
            );
        timeout_at(deadline, async {
            let client = Self::runtime_client(&runtime).await?;
            client.tcp(target, domain, deadline).await
        })
        .await?
    }
}

#[async_trait]
impl PacketOutbound for NowhereHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        limit: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let started = Instant::now();
        let client = Client::new(
            node,
            Arc::new(Settings::load(node.nowhere().ok_or_else(|| {
                anyhow::anyhow!("Nowhere configuration required")
            })?)?),
        )?;
        let deadline = client.deadline(started, limit);
        timeout_at(deadline, client.udp(target, domain, deadline)).await?
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        limit: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let deadline = Instant::now()
            + limit.min(
                runtime
                    .nowhere_settings
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Nowhere settings missing"))?
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .setup,
            );
        timeout_at(deadline, async {
            let client = Self::runtime_client(&runtime).await?;
            client.udp(target, domain, deadline).await
        })
        .await?
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        limit: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let started = Instant::now();
        let deadline = started + limit;
        timeout_at(deadline, async {
            let client = Self::detached(&runtime)?;
            let deadline = client.deadline(started, limit);
            super::prepare_detached_quic_transport(runtime, client, |client| async move {
                timeout_at(deadline, client.udp(target, domain, deadline)).await?
            })
            .await
        })
        .await?
    }
}

#[async_trait]
impl WarmableOutbound for NowhereHandler {
    async fn warm(
        &self,
        runtime: Arc<NodeRuntime>,
        limit: Duration,
        _: WarmRequirement,
    ) -> anyhow::Result<()> {
        timeout_at(Instant::now() + limit, async {
            let client = Self::runtime_client(&runtime).await?;
            if client.quic.is_some() {
                client.connection(limit).await?;
            }
            Ok(())
        })
        .await?
    }
}

#[async_trait]
impl ProbeableOutbound for NowhereHandler {}

#[cfg(test)]
mod tests;
