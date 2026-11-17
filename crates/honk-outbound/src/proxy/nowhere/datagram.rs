mod send;
pub(super) use send::{SendOutcome, send_packet};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub(super) struct Packet {
    pub bytes: Bytes,
    _bytes: OwnedSemaphorePermit,
}

struct Partial {
    created: Instant,
    total: usize,
    bytes: usize,
    received: usize,
    parts: Vec<Option<Bytes>>,
    reservation: OwnedSemaphorePermit,
}

pub(super) struct Reassembly {
    packets: HashMap<(u32, u32), Partial>,
    reserved_bytes: usize,
    max_bytes: usize,
    next_expiry: Option<Instant>,
}

impl Default for Reassembly {
    fn default() -> Self {
        Self::new(1024 * 1024)
    }
}

impl Reassembly {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            packets: HashMap::new(),
            reserved_bytes: 0,
            max_bytes,
            next_expiry: None,
        }
    }

    pub fn remove_flow(&mut self, flow: u32) {
        let removed: usize = self
            .packets
            .iter()
            .filter(|((id, _), _)| *id == flow)
            .map(|(_, partial)| partial.total)
            .sum();
        self.packets.retain(|(id, _), _| *id != flow);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(removed);
        if self.packets.is_empty() {
            self.next_expiry = None;
        }
    }

    pub fn expire(&mut self, now: Instant) {
        if self.next_expiry.is_none_or(|deadline| now <= deadline) {
            return;
        }
        let mut released = 0usize;
        self.packets.retain(|_, packet| {
            let keep = now.saturating_duration_since(packet.created) <= Duration::from_secs(10);
            if !keep {
                released = released.saturating_add(packet.total);
            }
            keep
        });
        self.reserved_bytes = self.reserved_bytes.saturating_sub(released);
        self.next_expiry = self
            .packets
            .values()
            .filter_map(|packet| packet.created.checked_add(Duration::from_secs(10)))
            .min();
    }

    fn remove(&mut self, key: &(u32, u32)) -> Option<Partial> {
        let partial = self.packets.remove(key)?;
        self.reserved_bytes = self.reserved_bytes.saturating_sub(partial.total);
        if self.packets.is_empty() {
            self.next_expiry = None;
        }
        Some(partial)
    }

    pub fn receive(&mut self, frame: Bytes, budget: &Arc<Semaphore>) -> Option<Packet> {
        let word = u32::from_be_bytes(frame.get(..4)?.try_into().ok()?);
        let kind = word >> 30;
        let flow = word & 0x3fff_ffff;
        if flow == 0 {
            return None;
        }
        if kind == 0 {
            let payload = &frame[4..];
            if payload.len() > 65535 {
                return None;
            }
            let reservation = Arc::clone(budget)
                .try_acquire_many_owned(payload.len().max(1) as u32)
                .ok()?;
            return Some(Packet {
                bytes: frame.slice(4..),
                _bytes: reservation,
            });
        }
        if kind != 1 || frame.len() <= 12 {
            return None;
        }
        let id = u32::from_be_bytes(frame[4..8].try_into().ok()?);
        let index = frame[8] as usize;
        let count = frame[9] as usize;
        let total = u16::from_be_bytes(frame[10..12].try_into().ok()?) as usize;
        let payload = &frame[12..];
        if id == 0
            || count < 2
            || index >= count
            || total < count
            || payload.len() > total - (count - 1)
        {
            return None;
        }
        let key = (flow, id);
        let now = Instant::now();
        self.expire(now);
        if let Some(partial) = self.packets.get_mut(&key) {
            if partial.total != total || partial.parts.len() != count {
                self.remove(&key);
                return None;
            }
            if let Some(previous) = &partial.parts[index] {
                if previous.as_ref() != payload {
                    self.remove(&key);
                }
                return None;
            }
            let retained = partial.bytes.saturating_add(payload.len());
            if retained > total {
                self.remove(&key);
                return None;
            }
            partial.parts[index] = Some(frame.slice(12..));
            partial.received += 1;
            partial.bytes = retained;
            if partial.received < count {
                return None;
            }
            let partial = self.remove(&key)?;
            if partial.bytes != partial.total {
                return None;
            }
            let mut bytes = bytes::BytesMut::with_capacity(partial.total);
            for part in partial.parts {
                bytes.extend_from_slice(&part?);
            }
            return Some(Packet {
                bytes: bytes.freeze(),
                _bytes: partial.reservation,
            });
        }
        let oldest = if self.packets.len() >= 64 {
            self.packets
                .iter()
                .min_by_key(|(_, partial)| partial.created)
                .map(|(key, _)| *key)
        } else {
            None
        };
        let replaced = oldest
            .and_then(|key| self.packets.get(&key))
            .map_or(0, |partial| partial.total);
        if self
            .reserved_bytes
            .saturating_sub(replaced)
            .saturating_add(total)
            > self.max_bytes
        {
            return None;
        }
        let reservation = Arc::clone(budget)
            .try_acquire_many_owned(total as u32)
            .ok()?;
        if let Some(oldest) = oldest {
            self.remove(&oldest);
        }
        self.reserved_bytes += total;
        let expiry = now.checked_add(Duration::from_secs(10)).unwrap_or(now);
        self.next_expiry = Some(
            self.next_expiry
                .map_or(expiry, |current| current.min(expiry)),
        );
        let mut parts = vec![None; count];
        let retained = payload.len();
        parts[index] = Some(frame.slice(12..));
        self.packets.insert(
            key,
            Partial {
                created: now,
                total,
                bytes: retained,
                received: 1,
                parts,
                reservation,
            },
        );
        None
    }
}

pub(super) fn flow_id(raw_stream_id: u64) -> anyhow::Result<u32> {
    if raw_stream_id & 3 != 0 {
        anyhow::bail!("Nowhere requires client bidirectional streams");
    }
    let id = (raw_stream_id >> 2) + 1;
    if id > 0x3fff_ffff {
        anyhow::bail!("Nowhere flow ID exhausted");
    }
    Ok(id as u32)
}

pub(super) fn fragments(
    flow: u32,
    packet: u32,
    data: &[u8],
    mtu: usize,
) -> std::io::Result<Fragments<'_>> {
    use crate::proxy::PacketRejection;
    if data.len() > 65535 {
        return Err(PacketRejection::InvalidSize.into());
    }
    let (capacity, count) = if mtu >= 4 && data.len() <= mtu - 4 {
        (data.len(), 1)
    } else {
        let capacity = mtu
            .checked_sub(12)
            .filter(|capacity| *capacity != 0)
            .ok_or(PacketRejection::InvalidSize)?;
        let count = data.len().div_ceil(capacity);
        if !(2..=255).contains(&count) || packet == 0 {
            return Err(PacketRejection::InvalidSize.into());
        }
        (capacity, count as u8)
    };
    Ok(Fragments {
        flow,
        packet,
        data,
        capacity,
        count,
        next: 0,
    })
}

pub(super) struct Fragments<'a> {
    flow: u32,
    packet: u32,
    data: &'a [u8],
    capacity: usize,
    count: u8,
    next: u8,
}

impl Iterator for Fragments<'_> {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let index = self.next;
        self.next += 1;
        if self.count == 1 {
            let mut out = bytes::BytesMut::with_capacity(4 + self.data.len());
            out.extend_from_slice(&self.flow.to_be_bytes());
            out.extend_from_slice(self.data);
            return Some(out.freeze());
        }
        let start = index as usize * self.capacity;
        let end = self.data.len().min(start + self.capacity);
        let chunk = &self.data[start..end];
        let mut out = Vec::with_capacity(12 + chunk.len());
        out.extend_from_slice(&(self.flow | 0x4000_0000).to_be_bytes());
        out.extend_from_slice(&self.packet.to_be_bytes());
        out.extend_from_slice(&[index, self.count]);
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
        Some(out.into())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.next) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Fragments<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_datagrams_retain_payload_storage_and_release_budget() {
        let budget = Arc::new(Semaphore::new(10000));
        let mut assembly = Reassembly::default();
        let frame = Bytes::from(vec![0, 0, 0, 2, 1, 2, 3]);
        let payload_ptr = frame[4..].as_ptr();
        let packet = assembly.receive(frame, &budget).unwrap();
        assert_eq!(packet.bytes.as_ptr(), payload_ptr);
        assert_eq!(packet.bytes.as_ref(), [1, 2, 3]);
        assert_eq!(budget.available_permits(), 9997);
        drop(packet);
        assert_eq!(budget.available_permits(), 10000);

        let payload = vec![0x55; 3500];
        let mut frames = fragments(2, 1, &payload, 1200).unwrap();
        let frame = frames.next().unwrap();
        let payload_ptr = frame[12..].as_ptr();
        assert!(assembly.receive(frame, &budget).is_none());
        assert_eq!(
            assembly.packets[&(2, 1)].parts[0]
                .as_ref()
                .unwrap()
                .as_ptr(),
            payload_ptr
        );
        for frame in frames.by_ref().take(1) {
            assert!(assembly.receive(frame, &budget).is_none());
        }
        let packet = assembly.receive(frames.next().unwrap(), &budget).unwrap();
        assert_eq!(packet.bytes.as_ref(), payload);
        drop(packet);
        assert_eq!(budget.available_permits(), 10000);
    }
    fn tiny_fragment(flow: u32, index: u8) -> Bytes {
        let mut frame = Vec::from((flow | 0x4000_0000).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 1, index, 2, 0, 2, index + 1]);
        frame.into()
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_is_strict_and_data_does_not_sweep_pending_fragments() {
        let budget = Arc::new(Semaphore::new(10000));
        let mut assembly = Reassembly::default();
        let payload = [0x55; 2000];
        let frame = fragments(2, 1, &payload, 1200).unwrap().next().unwrap();
        assert!(assembly.receive(frame, &budget).is_none());
        tokio::time::advance(Duration::from_secs(10)).await;
        assembly.expire(Instant::now());
        assert_eq!(assembly.packets.len(), 1);
        tokio::time::advance(Duration::from_nanos(1)).await;
        let data = Bytes::from_static(&[0, 0, 0, 2, 1]);
        drop(assembly.receive(data, &budget).unwrap());
        assert_eq!(assembly.packets.len(), 1);
        assembly.expire(Instant::now());
        assert!(assembly.packets.is_empty());
        assert_eq!(budget.available_permits(), 10000);
    }

    #[tokio::test(start_paused = true)]
    async fn connection_slot_limit_evicts_oldest_across_flows_only_after_reservation() {
        let budget = Arc::new(Semaphore::new(128));
        let mut assembly = Reassembly::default();
        for flow in 1..=64 {
            let frame = tiny_fragment(flow, 0);
            assert!(assembly.receive(frame, &budget).is_none());
            tokio::time::advance(Duration::from_nanos(1)).await;
        }
        assert_eq!(assembly.packets.len(), 64);
        assert_eq!(budget.available_permits(), 0);
        let frame = tiny_fragment(65, 0);
        assert!(assembly.receive(frame.clone(), &budget).is_none());
        assert!(assembly.packets.contains_key(&(1, 1)));
        assert!(!assembly.packets.contains_key(&(65, 1)));
        budget.add_permits(2);
        assert!(assembly.receive(frame, &budget).is_none());
        assert_eq!(assembly.packets.len(), 64);
        assert!(!assembly.packets.contains_key(&(1, 1)));
        assert!(assembly.packets.contains_key(&(2, 1)));
        assert!(assembly.packets.contains_key(&(65, 1)));
        assert_eq!(assembly.reserved_bytes, 128);
        assert_eq!(budget.available_permits(), 2);
        assembly.remove_flow(2);
        assert_eq!(assembly.packets.len(), 63);
        assert_eq!(budget.available_permits(), 4);
        drop(assembly);
        assert_eq!(budget.available_permits(), 130);
    }

    #[test]
    fn partial_byte_limit_and_completion_capacity_are_separate_from_queued_bytes() {
        let budget = Arc::new(Semaphore::new(4 * 1024 * 1024));
        let mut assembly = Reassembly::default();
        let payload = [0x55; 65535];
        for flow in 1..=16 {
            let frame = fragments(flow, 1, &payload, 1200).unwrap().next().unwrap();
            assert!(assembly.receive(frame, &budget).is_none());
        }
        let frame = fragments(17, 1, &payload, 1200).unwrap().next().unwrap();
        assert!(assembly.receive(frame, &budget).is_none());
        assert_eq!(assembly.packets.len(), 16);
        assert_eq!(assembly.reserved_bytes, 16 * 65535);
        assert!(!assembly.packets.contains_key(&(17, 1)));
        drop(assembly);
        let mut custom = Reassembly::new(2);
        assert!(custom.receive(tiny_fragment(2, 0), &budget).is_none());
        let packet = custom.receive(tiny_fragment(2, 1), &budget).unwrap();
        assert!(custom.packets.is_empty());
        assert_eq!(custom.reserved_bytes, 0);
        assert_eq!(budget.available_permits(), 4 * 1024 * 1024 - 2);
        let frame = tiny_fragment(3, 0);
        assert!(custom.receive(frame, &budget).is_none());
        assert_eq!(custom.reserved_bytes, 2);
        assert_eq!(custom.packets.len(), 1);
        drop(packet);
        assert_eq!(budget.available_permits(), 4 * 1024 * 1024 - 2);
        drop(custom);
        assert_eq!(budget.available_permits(), 4 * 1024 * 1024);
    }
}
