use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::proxy::{PacketRejection, PacketTransport, QuicSendToken};

#[derive(Clone)]
pub(super) enum Transport {
    Tls(Arc<super::tls::Udp>),
    Quic(Arc<super::quic::Udp>),
    #[cfg(test)]
    Test(Arc<tests::Peer>),
}
impl Transport {
    fn erased(&self) -> Arc<dyn PacketTransport> {
        match self {
            Self::Tls(inner) => inner.clone(),
            Self::Quic(inner) => inner.clone(),
            #[cfg(test)]
            Self::Test(inner) => inner.clone(),
        }
    }
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Tls(inner) => inner.write_packet(data).await,
            Self::Quic(inner) => inner.send_payload(data).await,
            #[cfg(test)]
            Self::Test(inner) => inner.send_packet(data).await,
        }
    }
    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Tls(inner) => inner.read_packet(buf).await,
            Self::Quic(inner) => inner.recv_payload(buf).await,
            #[cfg(test)]
            Self::Test(inner) => inner.recv_packet(buf).await,
        }
    }
}

pub(super) struct Udp {
    state: Arc<State>,
    owner: Weak<dyn PacketTransport>,
    target: SocketAddr,
    timeout: Duration,
}
struct State {
    current: Mutex<Current>,
    changed: Arc<Notify>,
}
struct Current {
    transport: Option<Transport>,
    deadline: Instant,
    replied: bool,
    retired: bool,
    partial: Option<[Arc<AtomicBool>; 2]>,
}
struct TimerOwner(Weak<State>);
impl Drop for TimerOwner {
    fn drop(&mut self) {
        let Some(state) = self.0.upgrade() else {
            return;
        };
        let retired = {
            let mut current = state.current.lock();
            if current.transport.is_none() {
                return;
            }
            current.retired = true;
            current.transport.take()
        };
        state.changed.notify_waiters();
        drop(retired);
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.changed.notify_one();
    }
}
impl std::fmt::Debug for Udp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NowhereUdpIdle")
            .field("target", &self.target)
            .finish()
    }
}
impl Udp {
    pub(super) fn new(
        transport: Transport,
        timeout: Duration,
        partial: Option<[Arc<AtomicBool>; 2]>,
    ) -> anyhow::Result<Self> {
        let erased = transport.erased();
        let target = erased.relay_addr();
        let owner = Arc::downgrade(&erased);
        drop(erased);
        let changed = Arc::new(Notify::new());
        let state = Arc::new(State {
            current: Mutex::new(Current {
                transport: Some(transport),
                deadline: Instant::now() + timeout,
                replied: false,
                retired: false,
                partial,
            }),
            changed: Arc::clone(&changed),
        });
        let weak = Arc::downgrade(&state);
        let timer_owner = TimerOwner(weak.clone());
        if crate::runtime::spawn_owned(async move {
            let _timer_owner = timer_owner;
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let Some(state) = weak.upgrade() else { break };
                let deadline = state.current.lock().deadline;
                drop(state);
                tokio::select! {
                    _ = &mut notified => {},
                    _ = tokio::time::sleep_until(deadline) => {
                        let Some(state) = weak.upgrade() else { break };
                        let retired = {
                            let mut current = state.current.lock();
                            if Instant::now() < current.deadline { continue; }
                            current.transport.take()
                        };
                        state.changed.notify_waiters();
                        drop(retired);
                        break;
                    }
                }
            }
        })
        .is_none()
        {
            anyhow::bail!("Nowhere runtime is retiring");
        }
        Ok(Self {
            state,
            owner,
            target,
            timeout,
        })
    }
    fn expired_error(current: &Current) -> io::Error {
        if current.retired
            || current.replied
                && !current
                    .partial
                    .as_ref()
                    .is_some_and(|flags| flags.iter().any(|flag| flag.load(Ordering::Acquire)))
        {
            PacketRejection::Cancelled.into()
        } else {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Nowhere UDP flow idle before reply",
            )
        }
    }
    fn transport(&self) -> io::Result<Transport> {
        let current = self.state.current.lock();
        if Instant::now() >= current.deadline {
            return Err(Self::expired_error(&current));
        }
        current
            .transport
            .clone()
            .ok_or_else(|| Self::expired_error(&current))
    }
    async fn operation<T>(
        &self,
        operation: impl Future<Output = io::Result<T>>,
        reply: bool,
    ) -> io::Result<T> {
        tokio::pin!(operation);
        loop {
            let notified = self.state.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let current = self.state.current.lock();
                if current.transport.is_none() || Instant::now() >= current.deadline {
                    return Err(Self::expired_error(&current));
                }
            }
            tokio::select! {
                biased;
                _ = &mut notified => {},
                result = &mut operation => {
                    let value = result?;
                    {
                        let mut current = self.state.current.lock();
                        if current.transport.is_none() || Instant::now() >= current.deadline {
                            return Err(Self::expired_error(&current));
                        }
                        current.replied |= reply;
                        current.deadline = Instant::now() + self.timeout;
                    }
                    return Ok(value);
                }
            }
        }
    }
}
#[async_trait]
impl PacketTransport for Udp {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn send_timeout(&self) -> Duration {
        self.owner
            .upgrade()
            .map_or(Duration::from_secs(5), |inner| inner.send_timeout())
    }
    fn send_timeout_is_congestion(&self) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|inner| inner.send_timeout_is_congestion())
    }
    fn record_quic_send_started(&self) -> QuicSendToken {
        self.owner
            .upgrade()
            .map_or(QuicSendToken::INACTIVE, |inner| {
                inner.record_quic_send_started()
            })
    }
    fn record_quic_send_success(&self, token: QuicSendToken) {
        if let Some(inner) = self.owner.upgrade() {
            inner.record_quic_send_success(token);
        }
    }
    fn record_quic_send_timeout(&self, token: QuicSendToken) {
        if let Some(inner) = self.owner.upgrade() {
            inner.record_quic_send_timeout(token);
        }
    }
    fn record_quic_send_failure(&self, token: QuicSendToken) {
        if let Some(inner) = self.owner.upgrade() {
            inner.record_quic_send_failure(token);
        }
    }
    fn quic_path_stalled(&self) -> bool {
        self.owner
            .upgrade()
            .is_some_and(|inner| inner.quic_path_stalled())
    }
    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        let transport = self.transport()?;
        self.operation(transport.send(data), false).await
    }
    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        let transport = self.transport()?;
        self.operation(transport.send(data), false).await
    }
    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let transport = self.transport()?;
        self.operation(transport.recv(buf), true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    pub(in crate::proxy::nowhere) struct Peer {
        dropped: Arc<AtomicUsize>,
        block_send: bool,
    }
    impl Drop for Peer {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[async_trait]
    impl PacketTransport for Peer {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:53".parse().unwrap()
        }
        async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
            if self.block_send {
                std::future::pending::<()>().await;
            }
            if data == b"reject" {
                return Err(PacketRejection::InvalidSize.into());
            }
            Ok(())
        }
        async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            if buf.first() == Some(&1) {
                return Ok((0, self.relay_addr()));
            }
            std::future::pending().await
        }
    }
    fn fixture(block_send: bool, partial: Option<[Arc<AtomicBool>; 2]>) -> (Udp, Arc<AtomicUsize>) {
        let dropped = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(Peer {
            dropped: Arc::clone(&dropped),
            block_send,
        });
        (
            Udp::new(Transport::Test(inner), Duration::from_secs(10), partial).unwrap(),
            dropped,
        )
    }
    async fn advance(seconds: u64) {
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::task::yield_now().await;
    }
    #[tokio::test(start_paused = true)]
    async fn unobserved_idle_releases_transport_without_an_io_waiter() {
        let (udp, dropped) = fixture(false, None);
        tokio::task::yield_now().await;
        advance(10).await;
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(
            udp.send_packet(b"late").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[tokio::test(start_paused = true)]
    async fn only_complete_success_refreshes_idle_and_expired_flow_cannot_revive() {
        let (udp, dropped) = fixture(false, None);
        advance(9).await;
        udp.send_packet(b"ok").await.unwrap();
        advance(9).await;
        assert!(udp.send_packet(b"reject").await.is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        advance(1).await;
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(udp.send_packet(b"ok").await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn idle_wakes_pending_operations_and_reply_idle_is_health_neutral() {
        let (udp, dropped) = fixture(true, None);
        udp.recv_packet(&mut [1]).await.unwrap();
        let (send, recv) = tokio::join!(udp.send_packet(b"wait"), async {
            udp.recv_packet(&mut [0]).await
        });
        for error in [send.unwrap_err(), recv.unwrap_err()] {
            assert_eq!(
                crate::proxy::io_packet_rejection(&error),
                Some(PacketRejection::Cancelled)
            );
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
    #[tokio::test(start_paused = true)]
    async fn partial_reliable_frame_keeps_failure_attribution_after_an_earlier_reply() {
        let reading = Arc::new(AtomicBool::new(false));
        let writing = Arc::new(AtomicBool::new(false));
        let (udp, _) = fixture(false, Some([Arc::clone(&reading), writing]));
        udp.recv_packet(&mut [1]).await.unwrap();
        reading.store(true, Ordering::Release);
        let error = udp.recv_packet(&mut [0]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(crate::proxy::io_packet_rejection(&error).is_none());
    }
    #[tokio::test(start_paused = true)]
    async fn dropping_flow_cancels_weak_timer_ownership() {
        let (udp, dropped) = fixture(false, None);
        let state = Arc::downgrade(&udp.state);
        drop(udp);
        tokio::task::yield_now().await;
        assert!(state.upgrade().is_none());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }
    #[cfg(feature = "owned-tasks")]
    #[tokio::test(start_paused = true)]
    async fn closing_owner_before_timer_first_poll_retires_transport() {
        let owner = Arc::new(crate::runtime::TaskOwner::production());
        let (udp, dropped) = owner.task_scope().sync_scope(|| fixture(false, None));
        owner.close().await;
        let error = udp.send_packet(b"late").await.unwrap_err();
        assert_eq!(
            crate::proxy::io_packet_rejection(&error),
            Some(PacketRejection::Cancelled)
        );
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "owned-tasks")]
    #[tokio::test(start_paused = true)]
    async fn closing_owner_wakes_existing_send_and_receive_waiters() {
        let owner = Arc::new(crate::runtime::TaskOwner::production());
        let (udp, dropped) = owner.task_scope().sync_scope(|| fixture(true, None));
        let udp = Arc::new(udp);
        let send = tokio::spawn({
            let udp = Arc::clone(&udp);
            async move { udp.send_packet(b"waiting").await }
        });
        let recv = tokio::spawn({
            let udp = Arc::clone(&udp);
            async move { udp.recv_packet(&mut [0]).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        owner.close().await;
        let (sent, received) =
            tokio::time::timeout(Duration::from_secs(1), async { tokio::join!(send, recv) })
                .await
                .expect("closing the timer owner left an I/O waiter asleep");
        for error in [sent.unwrap().unwrap_err(), received.unwrap().unwrap_err()] {
            assert_eq!(
                crate::proxy::io_packet_rejection(&error),
                Some(PacketRejection::Cancelled)
            );
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "owned-tasks")]
    #[tokio::test(start_paused = true)]
    async fn closed_and_expired_owners_refuse_idle_flow_without_retaining_transport() {
        let owner = Arc::new(crate::runtime::TaskOwner::production());
        let scope = owner.task_scope();
        owner.close().await;
        let mut owner = Some(owner);
        for expired in [false, true] {
            if expired {
                drop(owner.take());
            }
            let dropped = Arc::new(AtomicUsize::new(0));
            let peer = Arc::new(Peer {
                dropped: Arc::clone(&dropped),
                block_send: false,
            });
            let result =
                scope.sync_scope(|| Udp::new(Transport::Test(peer), Duration::from_secs(10), None));
            assert!(result.is_err());
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn successful_empty_receive_refreshes_idle() {
        let (udp, dropped) = fixture(false, None);
        advance(9).await;
        assert_eq!(udp.recv_packet(&mut [1]).await.unwrap().0, 0);
        advance(9).await;
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        advance(1).await;
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let error = udp.send_packet(b"late").await.unwrap_err();
        assert_eq!(
            crate::proxy::io_packet_rejection(&error),
            Some(PacketRejection::Cancelled)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_send_does_not_refresh_idle_or_retain_transport() {
        let (udp, dropped) = fixture(true, None);
        advance(9).await;
        let mut send = Box::pin(udp.send_packet(b"pending"));
        std::future::poll_fn(|cx| {
            assert!(send.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(send);
        advance(1).await;
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(
            udp.send_packet(b"late").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
