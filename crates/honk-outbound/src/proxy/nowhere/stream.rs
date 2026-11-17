//! Absolute drain limit after either direction of a Nowhere TCP flow closes.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

#[derive(Debug)]
pub(super) struct TcpDrain<S> {
    inner: S,
    timeout: Duration,
    waiting: [Option<Waker>; 2],
    drain: Option<Drain>,
}

#[derive(Debug)]
struct Drain {
    timer: Pin<Box<Sleep>>,
    waiting: Arc<DrainWake>,
    waker: Waker,
}

#[derive(Debug)]
struct DrainWake(Mutex<[Option<Waker>; 2]>);

impl Wake for DrainWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let waiting = self
            .0
            .lock()
            .unwrap_or_else(|lock| lock.into_inner())
            .clone();
        for waker in waiting.into_iter().flatten() {
            waker.wake();
        }
    }
}

fn register(slot: &mut Option<Waker>, waker: &Waker) -> bool {
    if slot
        .as_ref()
        .is_none_or(|previous| !previous.will_wake(waker))
    {
        *slot = Some(waker.clone());
        return true;
    }
    false
}

impl<S> TcpDrain<S> {
    pub(super) fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            waiting: [None, None],
            drain: None,
        }
    }

    fn check(&mut self, cx: &mut Context<'_>, write: bool) -> io::Result<()> {
        let side = usize::from(write);
        let changed = register(&mut self.waiting[side], cx.waker());
        let Some(drain) = &mut self.drain else {
            return Ok(());
        };
        if changed {
            let mut waiting = drain
                .waiting
                .0
                .lock()
                .unwrap_or_else(|lock| lock.into_inner());
            register(&mut waiting[side], cx.waker());
        }
        if Instant::now() >= drain.timer.deadline() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Nowhere TCP half-close drain expired",
            ));
        }
        Ok(())
    }

    fn start(&mut self) {
        if self.drain.is_some() {
            return;
        }
        // A split reader can already be pending when the writer closes (and vice versa).
        let waiting = Arc::new(DrainWake(Mutex::new(self.waiting.clone())));
        let waker = Waker::from(Arc::clone(&waiting));
        let mut drain = Drain {
            timer: Box::pin(tokio::time::sleep(self.timeout)),
            waiting,
            waker,
        };
        let _ = drain
            .timer
            .as_mut()
            .poll(&mut Context::from_waker(&drain.waker));
        self.drain = Some(drain);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TcpDrain<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx, false)?;
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() == before {
            // The host's separate client writer may not have completed its shutdown yet.
            self.start();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TcpDrain<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx, true)?;
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.check(cx, true)?;
        Pin::new(&mut self.inner).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx, true)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx, true)?;
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.start();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::advance;

    use super::*;

    const LIMIT: Duration = Duration::from_secs(10);

    #[tokio::test(start_paused = true)]
    async fn shutdown_keeps_download_open_but_progress_does_not_extend_drain() {
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut stream = TcpDrain::new(inner, LIMIT);
        advance(LIMIT * 2).await;
        stream.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        stream.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        for byte in b"abc" {
            advance(Duration::from_secs(3)).await;
            peer.write_all(&[*byte]).await.unwrap();
            let mut received = [0];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, [*byte]);
            stream.shutdown().await.unwrap();
        }
        advance(Duration::from_secs(1)).await;
        peer.write_all(b"late").await.unwrap();
        assert_eq!(
            stream.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test(start_paused = true)]
    async fn read_eof_keeps_upload_open_until_first_eof_deadline() {
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut stream = TcpDrain::new(inner, LIMIT);
        peer.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        advance(Duration::from_secs(7)).await;
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        stream.write_all(b"upload").await.unwrap();
        let mut received = [0; 6];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"upload");
        advance(Duration::from_secs(3)).await;
        assert_eq!(
            stream.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream
                .write_vectored(&[IoSlice::new(b"late")])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.flush().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_capacity_read_is_not_eof() {
        let (inner, mut peer) = tokio::io::duplex(64);
        let mut stream = TcpDrain::new(inner, LIMIT);
        peer.shutdown().await.unwrap();
        let mut bytes = [0; 1];
        let mut full = ReadBuf::new(&mut bytes);
        full.put_slice(b"x");
        std::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut full))
            .await
            .unwrap();
        advance(LIMIT * 2).await;
        stream.write_all(b"live").await.unwrap();
        let mut received = [0; 4];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"live");
    }

    struct ShutdownControl {
        inner: DuplexStream,
        state: Arc<AtomicU8>,
    }

    impl AsyncRead for ShutdownControl {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for ShutdownControl {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.state.load(Ordering::Relaxed) {
                0 => Poll::Pending,
                1 => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                _ => Poll::Ready(Ok(())),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_and_failed_shutdown_do_not_start_drain() {
        let (inner, mut peer) = tokio::io::duplex(64);
        let state = Arc::new(AtomicU8::new(0));
        let mut stream = TcpDrain::new(
            ShutdownControl {
                inner,
                state: Arc::clone(&state),
            },
            LIMIT,
        );
        std::future::poll_fn(|cx| {
            assert!(Pin::new(&mut stream).poll_shutdown(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        advance(LIMIT * 2).await;
        state.store(1, Ordering::Relaxed);
        assert_eq!(
            stream.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        advance(LIMIT * 2).await;
        stream.write_all(b"still live").await.unwrap();
        let mut received = [0; 10];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"still live");
        state.store(2, Ordering::Relaxed);
        stream.shutdown().await.unwrap();
        advance(LIMIT).await;
        assert_eq!(
            stream.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[derive(Default)]
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timer_wakes_reader_registered_before_shutdown_and_current_writer() {
        let (inner, _peer) = tokio::io::duplex(1);
        let state = Arc::new(AtomicU8::new(2));
        let mut stream = TcpDrain::new(ShutdownControl { inner, state }, LIMIT);
        let read_wake = Arc::new(CountWake::default());
        let write_wake = Arc::new(CountWake::default());
        let read_waker = Waker::from(Arc::clone(&read_wake));
        let write_waker = Waker::from(Arc::clone(&write_wake));
        let mut read_cx = Context::from_waker(&read_waker);
        let mut write_cx = Context::from_waker(&write_waker);
        let shutdown_waker = Waker::from(Arc::new(CountWake::default()));
        let mut shutdown_cx = Context::from_waker(&shutdown_waker);
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut read_cx, &mut ReadBuf::new(&mut [0]))
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut shutdown_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"a"),
            Poll::Ready(Ok(1))
        ));
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut write_cx, b"b")
                .is_pending()
        );
        advance(LIMIT).await;
        tokio::task::yield_now().await;
        assert!(read_wake.0.load(Ordering::Relaxed) > 0);
        assert!(write_wake.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut read_cx, &mut ReadBuf::new(&mut [0])),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut write_cx, b"b"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
    }
}
