use std::time::Duration;

use anyhow::{Context, bail};
use honk_config::node::{NowhereCarrier, NowhereConfig};

use super::wire::hmac;

#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub prelude: super::morph::PreludePolicy,
    pub handshake: Duration,
    pub setup: Duration,
    pub idle: Duration,
    pub shutdown: Duration,
    pub tcp_read: Duration,
    pub queue_bytes: usize,
    pub stream_window: u64,
    pub connection_window: u64,
    pub send_window: u64,
}

impl Settings {
    pub(crate) fn load(config: &NowhereConfig) -> anyhow::Result<Self> {
        Self::read(config, |name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => bail!("{name} must be Unicode"),
        })
    }

    pub(super) fn read(
        config: &NowhereConfig,
        mut env: impl FnMut(&str) -> anyhow::Result<Option<String>>,
    ) -> anyhow::Result<Self> {
        let digest = hmac(config.key.as_bytes(), b"nowhere/handshake-timeout");
        let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
        let mut duration = |name: &str, default| -> anyhow::Result<Duration> {
            let value = match env(name)? {
                Some(raw) => {
                    humantime::parse_duration(&raw).with_context(|| format!("invalid {name}"))?
                }
                None => default,
            };
            if value.is_zero()
                || std::time::Instant::now().checked_add(value).is_none()
                || tokio::time::Instant::now().checked_add(value).is_none()
            {
                bail!("{name} must be positive and fit the timer limit");
            }
            Ok(value)
        };
        let handshake = duration(
            "NOW_HANDSHAKE_TIMEOUT",
            Duration::from_millis(3000 + 100 * (value % 271)),
        )?;
        for name in [
            "NOW_TCP_DIAL_TIMEOUT",
            "NOW_UDP_DIAL_TIMEOUT",
            "NOW_RELOAD_INTERVAL",
            "NOW_SERVICE_COOLDOWN",
        ] {
            duration(name, Duration::from_secs(1))?;
        }
        let shutdown = duration("NOW_SHUTDOWN_TIMEOUT", Duration::from_secs(5))?;
        let tcp_read = duration("NOW_TCP_READ_TIMEOUT", Duration::from_secs(30))?;
        let setup = duration("NOW_FLOW_SETUP_TIMEOUT", Duration::from_secs(20))?;
        let idle = duration("NOW_UDP_IDLE_TIMEOUT", Duration::from_secs(120))?;
        quinn::IdleTimeout::try_from(idle).context("NOW_UDP_IDLE_TIMEOUT exceeds QUIC limit")?;
        if let Some(raw) = env("NOW_TCP_DATA_BUF_SIZE")? {
            let bytes: usize = raw.parse().context("invalid NOW_TCP_DATA_BUF_SIZE")?;
            if bytes == 0 || bytes > isize::MAX as usize {
                bail!("NOW_TCP_DATA_BUF_SIZE exceeds the supported buffer range");
            }
        }
        let queue_bytes = match env("NOW_QUIC_UDP_QUEUE_BYTES")? {
            Some(raw) => raw.parse().context("invalid NOW_QUIC_UDP_QUEUE_BYTES")?,
            None => 4 * 1024 * 1024,
        };
        if queue_bytes == 0
            || queue_bytes > tokio::sync::Semaphore::MAX_PERMITS.min(u32::MAX as usize)
        {
            bail!("NOW_QUIC_UDP_QUEUE_BYTES exceeds the supported reservation range");
        }
        let (stream_window, connection_window, send_window) =
            match env("NOW_TRANSPORT_MEMORY_PROFILE")?.as_deref() {
                None | Some("throughput") => (4 << 20, 32 << 20, 32 << 20),
                Some("balanced") => (4 << 20, 16 << 20, 16 << 20),
                Some("memory") => (4 << 20, 16 << 20, 8 << 20),
                _ => bail!("NOW_TRANSPORT_MEMORY_PROFILE must be memory, balanced or throughput"),
            };
        let mut prelude = super::morph::PreludePolicy::Fade;
        if config.morph {
            let name = match config.carrier {
                NowhereCarrier::Tcp => "NOW_MORPH_TCP_PRELUDE",
                NowhereCarrier::Udp => "NOW_MORPH_UDP_PRELUDE",
            };
            prelude = super::morph::PreludePolicy::parse(
                name,
                env(name)?.ok_or(std::env::VarError::NotPresent),
            )?;
        }
        Ok(Self {
            prelude,
            handshake,
            setup,
            idle,
            shutdown,
            tcp_read,
            queue_bytes,
            stream_window,
            connection_window,
            send_window,
        })
    }
}
