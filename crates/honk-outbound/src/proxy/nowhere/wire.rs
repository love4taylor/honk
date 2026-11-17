use std::net::SocketAddr;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) const EXPORTER: &str = "EXPORTER-Nowhere-nw3-Auth";

pub(super) fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(super) fn auth_key(key: &str) -> [u8; 32] {
    let salt = Sha256::digest(b"nowhere/nw3/auth-root");
    let root = hmac(&salt, key.as_bytes());
    hmac(&root, b"vector-authentication\x01")
}

pub(super) fn auth(key: &[u8; 32], carrier: u8, exporter: &[u8; 32]) -> [u8; 16] {
    let mut input = [0; 33];
    input[0] = carrier;
    input[1..].copy_from_slice(exporter);
    hmac(key, &input)[..16].try_into().unwrap()
}

pub(super) struct Request {
    bytes: [u8; 258],
    len: usize,
}

impl std::ops::Deref for Request {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsRef<[u8]> for Request {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

pub(super) fn request(
    target: SocketAddr,
    domain: Option<&str>,
    udp: bool,
) -> anyhow::Result<Request> {
    if target.port() == 0 {
        anyhow::bail!("Nowhere target port must be nonzero");
    }
    if let Some(name) = domain
        && (name.is_empty()
            || name.len() > 253
            || !name.is_ascii()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
    {
        anyhow::bail!("invalid Nowhere target domain");
    }
    let mut request = Request {
        bytes: [0; 258],
        len: 0,
    };
    request.bytes[0] = u8::from(udp);
    let port_offset = if let Some(domain) = domain {
        request.bytes[1] = 3;
        request.bytes[2] = domain.len() as u8;
        request.bytes[3..3 + domain.len()].copy_from_slice(domain.as_bytes());
        3 + domain.len()
    } else {
        match target.ip() {
            std::net::IpAddr::V4(ip) => {
                request.bytes[1] = 1;
                request.bytes[2..6].copy_from_slice(&ip.octets());
                6
            }
            std::net::IpAddr::V6(ip) => {
                request.bytes[1] = 4;
                request.bytes[2..18].copy_from_slice(&ip.octets());
                18
            }
        }
    };
    request.bytes[port_offset..port_offset + 2].copy_from_slice(&target.port().to_be_bytes());
    request.len = port_offset + 2;
    Ok(request)
}

pub(super) async fn ready(reader: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<()> {
    let result = reader.read_u8().await?;
    match result {
        0 => Ok(()),
        2 => Err(super::super::PacketRejection::Capacity.into()),
        3 => Err(super::super::TargetFailure(anyhow::anyhow!("Nowhere target dial failed")).into()),
        1 | 4 => anyhow::bail!("Nowhere rejected flow setup ({result})"),
        _ => anyhow::bail!("invalid Nowhere setup result"),
    }
}
