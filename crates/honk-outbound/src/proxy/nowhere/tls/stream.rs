use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::rustls::{ClientConfig, ClientConnection, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// rustls owns pending ciphertext and plaintext across cancelled I/O futures.
#[derive(Debug)]
pub(in crate::proxy::nowhere) struct Stream<S> {
    pub(super) session: ClientConnection,
    io: S,
    shutdown: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    pub(super) async fn connect(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        io: S,
    ) -> io::Result<Self> {
        let session = ClientConnection::new(config, name).map_err(io::Error::other)?;
        let mut stream = Self {
            session,
            io,
            shutdown: false,
        };
        std::future::poll_fn(|cx| {
            loop {
                let write_pending = match stream.write_tls(cx) {
                    Poll::Ready(Ok(())) => false,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => true,
                };
                let flush_pending = match Pin::new(&mut stream.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => false,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => true,
                };
                if !stream.session.is_handshaking() {
                    return if write_pending || flush_pending {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok::<(), io::Error>(()))
                    };
                }
                match stream.read_tls(cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await?;
        Ok(stream)
    }

    fn write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            let mut writer = WriteAdapter {
                io: &mut self.io,
                cx,
            };
            match self.session.write_tls(&mut writer) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = ReadAdapter {
            io: &mut self.io,
            cx,
        };
        let len = match self.session.read_tls(&mut reader) {
            Ok(len) => len,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Err(error) = self.session.process_new_packets() {
            let _ = self.write_tls(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        Poll::Ready(Ok(len))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.session.reader().read(buf.initialize_unfilled()) {
                Ok(len) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            // Read as well when control writes block; the peer may need to finish its write.
            if let Poll::Ready(Err(error)) = self.write_tls(cx) {
                return Poll::Ready(Err(error));
            }
            ready!(self.read_tls(cx))?;
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let len = self.session.writer().write(buf)?;
            let flushed = self.write_tls(cx);
            if len != 0 {
                if let Poll::Ready(Err(error)) = flushed {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(len));
            }
            ready!(flushed)?;
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.session.writer().flush()?;
        ready!(self.write_tls(cx))?;
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown {
            self.shutdown = true;
            self.session.send_close_notify();
        }
        ready!(self.as_mut().poll_flush(cx))?;
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::NotConnected => {
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

struct ReadAdapter<'a, 'b, S> {
    io: &'a mut S,
    cx: &'a mut Context<'b>,
}
impl<S: AsyncRead + Unpin> Read for ReadAdapter<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
struct WriteAdapter<'a, 'b, S> {
    io: &'a mut S,
    cx: &'a mut Context<'b>,
}
impl<S: AsyncWrite + Unpin> Write for WriteAdapter<'_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
