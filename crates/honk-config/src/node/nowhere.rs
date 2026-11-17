use serde::{Deserialize, Serialize};

use super::TlsOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NowhereCarrier {
    #[default]
    Tcp,
    Udp,
}

impl NowhereCarrier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NowhereConfig {
    pub key: String,
    pub carrier: NowhereCarrier,
    pub morph: bool,
    pub tls: TlsOptions,
}

impl Default for NowhereConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            carrier: NowhereCarrier::Tcp,
            morph: true,
            tls: TlsOptions {
                enabled: true,
                alpn: vec!["nw3".into()],
                ..Default::default()
            },
        }
    }
}

impl NowhereConfig {
    pub(crate) fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        if self.key.len() != 32
            || !self
                .key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err((
                "nowhere_key",
                "Nowhere key must contain exactly 32 lowercase hexadecimal characters",
            ));
        }
        if !self.tls.enabled || self.tls.alpn != ["nw3"] {
            return Err(("tls_alpn", "Nowhere requires TLS with exactly nw3 ALPN"));
        }
        if self.tls.skip_cert_verify
            || self.tls.ech_enabled
            || self.tls.ech_config.is_some()
            || self.tls.ech_config_path.is_some()
            || self.tls.reality_public_key.is_some()
            || self.tls.reality_short_id.is_some()
            || self.tls.reality_spider_x.is_some()
        {
            return Err((
                "tls",
                "Nowhere requires CA/hostname verification or an exact certificate pin",
            ));
        }
        if let Some(pin) = &self.tls.pin_sha256
            && (pin.len() != 64
                || !pin
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return Err((
                "tls_pin_sha256",
                "Nowhere pin must contain 64 lowercase hexadecimal characters",
            ));
        }
        if let Some(sni) = &self.tls.sni
            && !valid_domain(sni)
        {
            return Err(("sni", "Nowhere SNI must be an ASCII DNS name"));
        }
        Ok(())
    }
}

pub(crate) fn valid_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
