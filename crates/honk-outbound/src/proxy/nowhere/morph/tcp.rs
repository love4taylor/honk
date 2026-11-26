//! Directional Morph masking for asynchronous TCP streams.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io};

use honk_config::node::NowhereGrade;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::cipher::TcpCipher;
use super::policy::PreludePolicy;
use super::{ClientPrelude, MorphKeys, NONCE_LEN, TCP_PRELUDE_LEN};

pub(super) struct TcpMorph {
    pub(super) read_cipher: TcpCipher,
    pub(super) write_cipher: TcpCipher,
    read_record: Option<RecordState>,
    write_record: Option<RecordState>,
    read_offset: u64,
    write_offset: u64,
    pub(super) write_buffer: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
struct RecordState {
    header: [u8; 5],
    header_len: usize,
    payload_left: usize,
    skip_payload: bool,
}

impl RecordState {
    fn span(&self, available: usize) -> (usize, bool) {
        if self.payload_left == 0 {
            (available.min(self.header.len() - self.header_len), true)
        } else {
            (available.min(self.payload_left), !self.skip_payload)
        }
    }

    fn advance(&mut self, plain: &[u8]) {
        if self.payload_left != 0 {
            self.payload_left -= plain.len();
            return;
        }
        let end = self.header_len + plain.len();
        self.header[self.header_len..end].copy_from_slice(plain);
        self.header_len = end;
        if end == self.header.len() {
            self.header_len = 0;
            self.payload_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            // TLS 1.3 ciphertext records can pass through Core Morph.
            self.skip_payload = self.header[..3] == [23, 3, 3] && self.payload_left <= 18432;
        }
    }

    fn apply(
        &mut self,
        cipher: &mut TcpCipher,
        mut offset: u64,
        mut data: &mut [u8],
        opening: bool,
    ) -> io::Result<()> {
        let mut cipher_position = None;
        while !data.is_empty() {
            let (count, mask) = self.span(data.len());
            let (part, rest) = data.split_at_mut(count);
            if !opening {
                self.advance(part);
            }
            if mask {
                if cipher_position != Some(offset) {
                    cipher.try_seek(offset)?;
                }
                cipher.try_apply_keystream(part)?;
                cipher_position = Some(offset + count as u64);
            }
            if opening {
                self.advance(part);
            }
            offset += count as u64;
            data = rest;
        }
        Ok(())
    }

    fn advance_prefix(&mut self, mut plain: &[u8]) {
        while !plain.is_empty() {
            let (count, _) = self.span(plain.len());
            self.advance(&plain[..count]);
            plain = &plain[count..];
        }
    }
}

pub(crate) struct MorphTcpStream<S> {
    inner: S,
    pub(super) morph: Option<TcpMorph>,
}

impl<S> fmt::Debug for MorphTcpStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MorphTcpStream")
            .field("inner", &self.inner)
            .field("enabled", &self.morph.is_some())
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> MorphTcpStream<S> {
    pub(crate) async fn connect(
        inner: S,
        keys: Option<MorphKeys>,
        identity: &ClientPrelude,
        policy: PreludePolicy,
    ) -> io::Result<Self> {
        let Some(keys) = keys else {
            return Ok(Self { inner, morph: None });
        };
        let mut prelude = policy.generate_tcp()?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        keys.encode_prelude(&mut prelude, &nonce, identity.allocate()?);
        Self::connect_with_bootstrap(inner, keys, prelude, nonce).await
    }

    async fn connect_with_bootstrap(
        mut inner: S,
        keys: MorphKeys,
        prelude: [u8; TCP_PRELUDE_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> io::Result<Self> {
        inner.write_all(&prelude).await?;
        inner.write_all(&nonce).await?;
        Ok(Self::initialized(inner, &keys, nonce, true))
    }

    fn initialized(inner: S, keys: &MorphKeys, nonce: [u8; NONCE_LEN], client: bool) -> Self {
        let (read_key, write_key) = if client {
            (&keys.tcp_s2c, &keys.tcp_c2s)
        } else {
            (&keys.tcp_c2s, &keys.tcp_s2c)
        };
        Self {
            inner,
            morph: Some(TcpMorph {
                read_cipher: TcpCipher::new(keys.cipher, read_key, &nonce),
                write_cipher: TcpCipher::new(keys.cipher, write_key, &nonce),
                read_record: (keys.grade == NowhereGrade::Core).then(RecordState::default),
                write_record: (keys.grade == NowhereGrade::Core).then(RecordState::default),
                read_offset: 0,
                write_offset: 0,
                write_buffer: Vec::new(),
            }),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MorphTcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.morph.is_none() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let state = self.morph.as_ref().unwrap();
        let remaining = state.read_cipher.limit().saturating_sub(state.read_offset);
        if remaining == 0 && buf.remaining() != 0 {
            return Poll::Ready(Err(state.read_cipher.exhausted()));
        }
        let before = buf.filled().len();
        let allowed = usize::try_from(remaining.min(buf.remaining() as u64)).unwrap();
        let unfilled = buf.initialize_unfilled_to(allowed);
        let mut inner_buf = ReadBuf::new(unfilled);
        match Pin::new(&mut self.inner).poll_read(cx, &mut inner_buf) {
            Poll::Ready(Ok(())) => {
                let count = inner_buf.filled().len();
                let state = self.morph.as_mut().unwrap();
                let data = inner_buf.filled_mut();
                if let Some(record) = &mut state.read_record {
                    record.apply(&mut state.read_cipher, state.read_offset, data, true)?;
                } else {
                    state.read_cipher.try_apply_keystream(data)?;
                }
                state.read_offset += count as u64;
                buf.advance(count);
                debug_assert_eq!(buf.filled().len(), before + count);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

pub(crate) trait MorphWriteReady {
    fn poll_morph_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl MorphWriteReady for tokio::net::TcpStream {
    fn poll_morph_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_ready(cx)
    }
}

impl<S: AsyncWrite + MorphWriteReady + Unpin> AsyncWrite for MorphTcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.morph.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, input);
        }
        let this = self.as_mut().get_mut();
        let state = this.morph.as_ref().unwrap();
        let remaining = state
            .write_cipher
            .limit()
            .saturating_sub(state.write_offset);
        if remaining == 0 {
            return Poll::Ready(Err(state.write_cipher.exhausted()));
        }
        let count = usize::try_from(remaining.min(input.len() as u64))
            .expect("count is bounded by usize input length");
        match this.inner.poll_morph_write_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let state = this.morph.as_mut().unwrap();
        if state.write_buffer.len() < count {
            state.write_buffer.resize(count, 0);
        }
        if let Some(record) = &mut state.write_record {
            let output = &mut state.write_buffer[..count];
            let mut next_record = *record;
            output.copy_from_slice(&input[..count]);
            next_record.apply(&mut state.write_cipher, state.write_offset, output, false)?;
            // Only bytes accepted by the socket advance the record parser.
            return match Pin::new(&mut this.inner).poll_write(cx, output) {
                Poll::Ready(Ok(0)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => {
                    if n == count {
                        *record = next_record;
                    } else {
                        record.advance_prefix(&input[..n]);
                    }
                    state.write_offset += n as u64;
                    Poll::Ready(Ok(n))
                }
                other => other,
            };
        }
        state
            .write_cipher
            .try_apply_keystream_b2b(&input[..count], &mut state.write_buffer[..count])?;
        match Pin::new(&mut this.inner).poll_write(cx, &state.write_buffer[..count]) {
            Poll::Ready(Ok(0)) => {
                state.write_cipher.try_seek(state.write_offset)?;
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(n)) => {
                state.write_offset += n as u64;
                if n != count {
                    state.write_cipher.try_seek(state.write_offset)?;
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                state.write_cipher.try_seek(state.write_offset)?;
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                state.write_cipher.try_seek(state.write_offset)?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::node::NowhereCipher;
    use tokio::io::{AsyncReadExt, DuplexStream};

    impl MorphWriteReady for DuplexStream {
        fn poll_morph_write_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn core_tcp_preserves_wire_offsets_across_short_reads_and_writes() {
        for cipher in [NowhereCipher::ChaCha, NowhereCipher::Aes] {
            let keys = MorphKeys::derive(
                b"0123456789abcdef0123456789abcdef",
                cipher,
                NowhereGrade::Core,
            );
            let nonce = [0x12; NONCE_LEN];
            let mut plain = Vec::new();
            let mut clear_ranges = Vec::new();
            for (kind, version, len, clear) in [
                (22, 3, 2u16, false),
                (23, 3, 0, true),
                (23, 3, 18432, true),
                (23, 3, 18433, false),
                (23, 1, 4, false),
                (23, 3, 9, true),
                (21, 3, 2, false),
            ] {
                plain.extend([kind, 3, version]);
                plain.extend(len.to_be_bytes());
                let start = plain.len();
                plain.resize(start + usize::from(len), 0xa5);
                if clear {
                    clear_ranges.push(start..plain.len());
                }
            }
            let mut wire = plain.clone();
            TcpCipher::new(cipher, &keys.tcp_c2s, &nonce)
                .try_apply_keystream(&mut wire)
                .unwrap();
            for range in clear_ranges {
                wire[range.clone()].copy_from_slice(&plain[range]);
            }

            let (client, mut raw) = tokio::io::duplex(3);
            let mut client = MorphTcpStream::initialized(client, &keys, nonce, true);
            assert_eq!(client.write(&plain).await.unwrap(), 3);
            // A cancelled Pending write cannot advance the parser or keep its input.
            std::future::poll_fn(|cx| {
                assert!(
                    Pin::new(&mut client)
                        .poll_write(cx, &[0xff; 32])
                        .is_pending()
                );
                Poll::Ready(())
            })
            .await;
            let mut sent = vec![0; plain.len()];
            raw.read_exact(&mut sent[..3]).await.unwrap();
            let mut offset = 3;
            while offset < plain.len() {
                let end = (offset + 37).min(plain.len());
                let written = client.write(&plain[offset..end]).await.unwrap();
                assert_eq!(written, (end - offset).min(3));
                raw.read_exact(&mut sent[offset..offset + written])
                    .await
                    .unwrap();
                offset += written;
            }
            assert_eq!(sent, wire, "Core TCP transmit for {cipher:?}");

            let (mut raw, server) = tokio::io::duplex(7);
            let mut server = MorphTcpStream::initialized(server, &keys, nonce, false);
            let mut received = vec![0; plain.len()];
            for (input, output) in wire.chunks(7).zip(received.chunks_mut(7)) {
                raw.write_all(input).await.unwrap();
                server.read_exact(output).await.unwrap();
            }
            assert_eq!(received, plain, "Core TCP receive for {cipher:?}");
        }
    }

    #[tokio::test]
    async fn core_tcp_counts_unmasked_payload_toward_stream_limit() {
        const RECORD: [u8; 12] = [23, 3, 3, 0, 7, 1, 2, 3, 4, 5, 6, 7];
        for cipher in [NowhereCipher::ChaCha, NowhereCipher::Aes] {
            let keys = MorphKeys::derive(
                b"0123456789abcdef0123456789abcdef",
                cipher,
                NowhereGrade::Core,
            );
            let nonce = [0x12; NONCE_LEN];
            let (client, server) = tokio::io::duplex(RECORD.len());
            let mut client = MorphTcpStream::initialized(client, &keys, nonce, true);
            let mut server = MorphTcpStream::initialized(server, &keys, nonce, false);
            let tx = client.morph.as_mut().unwrap();
            tx.write_offset = tx.write_cipher.limit() - RECORD.len() as u64;
            let rx = server.morph.as_mut().unwrap();
            rx.read_offset = rx.read_cipher.limit() - RECORD.len() as u64;
            client.write_all(&RECORD).await.unwrap();
            let mut received = [0; RECORD.len()];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, RECORD);
            assert!(client.write(&[0]).await.is_err());
            assert!(server.read(&mut [0]).await.is_err());
        }
    }

    #[tokio::test]
    async fn aes_partial_writes_stay_in_sync_up_to_stream_limit() {
        const PAYLOAD: &[u8] = b"payload ending at the AES stream limit";
        let keys = MorphKeys::derive(
            b"0123456789abcdef0123456789abcdef",
            NowhereCipher::Aes,
            NowhereGrade::Full,
        );
        let nonce = [0x12; NONCE_LEN];
        let (client, server) = tokio::io::duplex(7);
        let mut client = MorphTcpStream::initialized(client, &keys, nonce, true);
        let mut server = MorphTcpStream::initialized(server, &keys, nonce, false);

        let offset = (1 << 48) - PAYLOAD.len() as u64;
        let tx = client.morph.as_mut().unwrap();
        tx.write_offset = offset;
        tx.write_cipher.try_seek(offset).unwrap();
        let rx = server.morph.as_mut().unwrap();
        rx.read_offset = offset;
        rx.read_cipher.try_seek(offset).unwrap();

        let mut got = [0; PAYLOAD.len()];
        let mut offset = 0;
        while offset < PAYLOAD.len() {
            let written = client.write(&PAYLOAD[offset..]).await.unwrap();
            assert_eq!(written, (PAYLOAD.len() - offset).min(7));
            let end = offset + written;
            server.read_exact(&mut got[offset..end]).await.unwrap();
            offset = end;
        }
        assert_eq!(&got, PAYLOAD);
        assert!(client.write(&[0]).await.is_err());
        assert!(server.read(&mut [0]).await.is_err());
        assert_eq!(client.write(&[]).await.unwrap(), 0);
    }
}
