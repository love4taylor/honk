use std::{future::Future, io};

use bytes::Bytes;

use super::fragments;

pub(in crate::proxy::nowhere) enum SendOutcome {
    Sent,
    TooLarge,
}

pub(in crate::proxy::nowhere) async fn send_packet<F, S>(
    flow: u32,
    next_packet_id: &mut u32,
    payload: &[u8],
    mut max_size: impl FnMut() -> Option<usize>,
    mut send: S,
) -> io::Result<()>
where
    F: Future<Output = io::Result<SendOutcome>>,
    S: FnMut(Bytes) -> F,
{
    for _ in 0..2 {
        let mtu =
            max_size().ok_or_else(|| io::Error::other("Nowhere peer lacks DATAGRAM support"))?;
        let packet = if payload.len().saturating_add(4) <= mtu {
            0
        } else {
            take_packet_id(next_packet_id)
        };
        let mut retry = false;
        for frame in fragments(flow, packet, payload, mtu)? {
            match send(frame).await? {
                SendOutcome::Sent => {}
                SendOutcome::TooLarge => {
                    retry = true;
                    break;
                }
            }
        }
        if !retry {
            return Ok(());
        }
    }
    Err(crate::proxy::PacketRejection::InvalidSize.into())
}

fn take_packet_id(next: &mut u32) -> u32 {
    let id = (*next).max(1);
    *next = id.wrapping_add(1).max(1);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    struct Script {
        sizes: RefCell<VecDeque<Option<usize>>>,
        outcomes: RefCell<VecDeque<io::Result<SendOutcome>>>,
        frames: RefCell<Vec<Bytes>>,
    }

    impl Script {
        fn new(sizes: &[Option<usize>], outcomes: Vec<io::Result<SendOutcome>>) -> Self {
            Self {
                sizes: RefCell::new(sizes.iter().copied().collect()),
                outcomes: RefCell::new(outcomes.into()),
                frames: RefCell::new(Vec::new()),
            }
        }

        async fn send(&self, next: &mut u32, payload: &[u8]) -> io::Result<()> {
            send_packet(
                2,
                next,
                payload,
                || {
                    self.sizes
                        .borrow_mut()
                        .pop_front()
                        .expect("unexpected MTU read")
                },
                |frame| {
                    self.frames.borrow_mut().push(frame);
                    std::future::ready(
                        self.outcomes
                            .borrow_mut()
                            .pop_front()
                            .expect("unexpected send"),
                    )
                },
            )
            .await
        }
    }

    #[test]
    fn fragment_packet_id_wrap_skips_zero() {
        let mut next = 0;
        assert_eq!(take_packet_id(&mut next), 1);
        assert_eq!(next, 2);
        next = u32::MAX;
        assert_eq!(take_packet_id(&mut next), u32::MAX);
        assert_eq!(next, 1);
        assert_eq!(take_packet_id(&mut next), 1);
        assert_eq!(next, 2);
    }

    #[tokio::test]
    async fn data_never_consumes_fragment_ids_even_after_mtu_retry() {
        let script = Script::new(
            &[Some(1200), Some(1201)],
            vec![Ok(SendOutcome::TooLarge), Ok(SendOutcome::Sent)],
        );
        let mut next = u32::MAX;
        script.send(&mut next, b"payload").await.unwrap();
        assert_eq!(next, u32::MAX);
        assert!(script.sizes.borrow().is_empty());
        let frames = script.frames.borrow();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], frames[1]);
        assert_eq!(frames[0].as_ref(), b"\0\0\0\x02payload");
    }

    #[tokio::test]
    async fn decreased_mtu_replans_data_as_fragments() {
        let script = Script::new(
            &[Some(24), Some(16)],
            vec![
                Ok(SendOutcome::TooLarge),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
            ],
        );
        let mut next = 0;
        let payload = [0x55; 20];
        script.send(&mut next, &payload).await.unwrap();
        assert_eq!(next, 2);
        let frames = script.frames.borrow();
        assert_eq!(frames.len(), 6);
        assert_eq!(frames[0][0], 0);
        let mut actual = Vec::new();
        for (index, frame) in frames[1..].iter().enumerate() {
            assert!(frame.len() <= 16);
            assert_eq!(
                &frame[..12],
                &[0x40, 0, 0, 2, 0, 0, 0, 1, index as u8, 5, 0, 20]
            );
            actual.extend_from_slice(&frame[12..]);
        }
        assert_eq!(actual, payload);
    }

    #[tokio::test]
    async fn partial_fragment_too_large_retry_uses_a_fresh_nonzero_id() {
        let script = Script::new(
            &[Some(20), Some(16)],
            vec![
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::TooLarge),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
                Ok(SendOutcome::Sent),
            ],
        );
        let mut next = u32::MAX;
        script.send(&mut next, &[0x55; 20]).await.unwrap();
        assert_eq!(next, 2);
        let frames = script.frames.borrow();
        assert_eq!(frames.len(), 7);
        for frame in &frames[..2] {
            assert_eq!(&frame[4..8], &u32::MAX.to_be_bytes());
            assert_eq!(frame[9], 3);
        }
        for frame in &frames[2..] {
            assert_eq!(&frame[4..8], &[0, 0, 0, 1]);
            assert_eq!(frame[9], 5);
        }
    }

    #[test]
    fn cancelled_pending_send_never_starts_another_attempt() {
        use std::task::{Context, Poll, Waker};
        let sends = std::cell::Cell::new(0);
        let reads = std::cell::Cell::new(0);
        let mut next = 7;
        {
            let send = send_packet(
                2,
                &mut next,
                &[0x55; 20],
                || {
                    reads.set(reads.get() + 1);
                    Some(16)
                },
                |_| {
                    sends.set(sends.get() + 1);
                    std::future::pending::<io::Result<SendOutcome>>()
                },
            );
            let mut send = std::pin::pin!(send);
            assert!(matches!(
                send.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
        }
        assert_eq!(sends.get(), 1);
        assert_eq!(reads.get(), 1);
        assert_eq!(next, 8);
    }

    #[tokio::test]
    async fn refusal_is_bounded_and_transport_errors_never_retry() {
        let script = Script::new(
            &[Some(1200), Some(1200)],
            vec![Ok(SendOutcome::TooLarge), Ok(SendOutcome::TooLarge)],
        );
        let error = script.send(&mut 1, b"payload").await.unwrap_err();
        assert_eq!(
            crate::proxy::packet_error_class(&error),
            crate::proxy::PacketErrorClass::Rejected
        );
        assert!(matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<crate::proxy::PacketRejection>()),
            Some(crate::proxy::PacketRejection::InvalidSize)
        ));
        assert_eq!(script.frames.borrow().len(), 2);
        for kind in [io::ErrorKind::ConnectionAborted, io::ErrorKind::Interrupted] {
            let script = Script::new(&[Some(1200)], vec![Err(kind.into())]);
            assert_eq!(
                script.send(&mut 1, b"payload").await.unwrap_err().kind(),
                kind
            );
            assert_eq!(script.frames.borrow().len(), 1);
            assert!(script.sizes.borrow().is_empty());
        }
        let script = Script::new(&[None], vec![]);
        assert!(script.send(&mut 1, b"payload").await.is_err());
        assert!(script.frames.borrow().is_empty());
    }
}
