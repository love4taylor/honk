use crate::diagnostic::SourceRef;
use crate::error::DetailedConfigError;
use crate::node::{Node, NowhereCarrier, NowhereConfig, OutboundConfig};

fn decode(value: &str, source: &SourceRef) -> Result<String, DetailedConfigError> {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(super::invalid_link(source));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    String::from_utf8(super::percent_decode_bytes(value)).map_err(|_| super::invalid_link(source))
}

pub(super) fn parse(
    raw: &str,
    url: &url::Url,
    source: &SourceRef,
) -> Result<Node, DetailedConfigError> {
    let invalid = || super::invalid_link(source);
    // Inspect the original suffix: URL normalization removes dot segments.
    let authority = raw.split_once("://").ok_or_else(invalid)?.1;
    let endpoint = authority.split(['?', '#']).next().ok_or_else(invalid)?;
    if endpoint.contains('/')
        || endpoint.contains('\\')
        || raw.chars().any(char::is_whitespace)
        || url.password().is_some()
        || !url.path().is_empty()
    {
        return Err(invalid());
    }
    let host = url
        .host_str()
        .ok_or_else(invalid)?
        .trim_matches(['[', ']'])
        .to_owned();
    let host = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        match url::Host::parse(&host).map_err(|_| invalid())? {
            url::Host::Domain(name) if crate::node::valid_nowhere_domain(&name) => name,
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
            _ => return Err(invalid()),
        }
    };
    let port = url.port().filter(|port| *port != 0).ok_or_else(invalid)?;
    let mut config = NowhereConfig {
        key: decode(url.username(), source)?,
        ..Default::default()
    };
    let mut seen = std::collections::HashSet::new();
    for pair in url.query().unwrap_or("").split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Ok(name) = decode(name, source) else {
            continue;
        };
        if !matches!(name.as_str(), "net" | "morph" | "sni" | "pin") || !seen.insert(name.clone()) {
            continue;
        }
        let value = decode(value, source)?;
        match name.as_str() {
            "net" => {
                config.carrier = match value.as_str() {
                    "tcp" => NowhereCarrier::Tcp,
                    "udp" => NowhereCarrier::Udp,
                    _ => return Err(invalid()),
                }
            }
            "morph" => {
                config.morph = match value.as_str() {
                    "0" => false,
                    "1" => true,
                    _ => return Err(invalid()),
                }
            }
            "sni" if !value.is_empty() && value != "none" => config.tls.sni = Some(value),
            "pin" if !value.is_empty() && value != "none" => config.tls.pin_sha256 = Some(value),
            _ => {}
        }
    }
    let name = url
        .fragment()
        .map(|s| decode(s, source))
        .transpose()?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("nowhere-{host}"));
    Ok(Node {
        name,
        address: if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        },
        host,
        port,
        outbound: OutboundConfig::Nowhere(config),
        ..Default::default()
    })
}
