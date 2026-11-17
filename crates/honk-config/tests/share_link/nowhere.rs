use honk_config::node::{Node, NowhereCarrier};

const KEY: &str = "0123456789abcdef0123456789abcdef";

fn parse(suffix: &str) -> Node {
    Node::from_share_link(&format!("nowhere://{KEY}@relay.example:2000{suffix}")).unwrap()
}

#[test]
fn official_nowhere_links_defaults_duplicates_and_ipv6() {
    let implicit = parse("");
    let explicit = parse("?net=tcp&morph=1#Name%20one");
    assert_eq!(implicit.id, explicit.id);
    assert_eq!(explicit.name, "Name one");
    let config = implicit.nowhere().unwrap();
    assert_eq!(config.key, KEY);
    assert_eq!(config.carrier, NowhereCarrier::Tcp);
    assert!(config.morph);
    assert_eq!(
        parse("?net=udp&net=invalid&morph=0&morph=invalid")
            .nowhere()
            .unwrap()
            .carrier,
        NowhereCarrier::Udp
    );
    let ipv6 = Node::from_share_link(&format!("nowhere://{KEY}@[::1]:2000?morph=0")).unwrap();
    assert_eq!(ipv6.host(), "::1");
    assert_eq!(ipv6.address, "[::1]:2000");
    let encoded =
        Node::from_share_link(&format!("nowhere://%30{}@relay.example:2000", &KEY[1..])).unwrap();
    assert_eq!(encoded.id, implicit.id);
}

#[test]
fn nowhere_refuses_malformed_links_and_security_assertions() {
    for link in [
        format!("nowhere://{KEY}@relay.example:0"),
        format!("nowhere://{KEY}@relay.example"),
        format!("nowhere://{KEY}:password@relay.example:2000"),
        format!("nowhere://{KEY}@relay.example:2000/"),
        format!("nowhere://{KEY}@relay.example:2000/a/.."),
        format!("nowhere://{KEY}@*:2000"),
        format!("nowhere://{KEY}@*.example:2000"),
        format!("nowhere://{KEY}@bad_.example:2000"),
        format!("nowhere://{KEY}@bad..example:2000"),
        format!("nowhere://{KEY}@relay.example:2000?net=quic"),
        format!("nowhere://{KEY}@relay.example:2000?morph=true"),
        format!("nowhere://{KEY}@relay.example:2000?net=bad&net=tcp"),
        format!("nowhere://{KEY}@relay.example:2000?pin={}", "f".repeat(63)),
        format!("nowhere://{KEY}@relay.example:2000?sni=bad_name"),
        format!("nowhere://{KEY}@relay.example:2000?morph=%31%"),
        format!("nowhere://{KEY}@relay.example:2000?morph=%2531"),
        format!("nowhere://{KEY}@relay.example:2000#%FF"),
        "nowhere://0123456789ABCDEF0123456789abcdef@relay.example:2000".into(),
        "nowhere://%zz@relay.example:2000".into(),
    ] {
        assert!(Node::from_share_link(&link).is_err(), "accepted {link}");
    }
}

#[test]
fn nowhere_identity_covers_credentials_carrier_morph_sni_and_pin() {
    let base = parse("");
    for node in [
        parse("?net=udp"),
        parse("?morph=0"),
        parse("?sni=cert.example"),
        parse(&format!("?pin={}", "a".repeat(64))),
        Node::from_share_link("nowhere://1123456789abcdef0123456789abcdef@relay.example:2000")
            .unwrap(),
    ] {
        assert_ne!(node.id, base.id);
    }
    assert_eq!(parse("?sni=none&pin=none").id, base.id);
}

#[test]
fn nowhere_round_trips_all_flat_storage_formats() {
    let node = parse(&format!(
        "?net=udp&morph=0&sni=cert.example&pin={}#Test",
        "a".repeat(64)
    ));
    let json = serde_json::to_string(&node).unwrap();
    let yaml = serde_yaml::to_string(&node).unwrap();
    let toml = toml::to_string(&node).unwrap();
    for restored in [
        serde_json::from_str::<Node>(&json).unwrap(),
        serde_yaml::from_str(&yaml).unwrap(),
        toml::from_str(&toml).unwrap(),
    ] {
        assert_eq!(restored.outbound, node.outbound);
        assert_eq!(restored.id, node.id);
    }
    for (field, value) in [
        ("skip_cert_verify", serde_json::json!(true)),
        ("tls_alpn", serde_json::json!(["h2"])),
        ("nowhere_key", serde_json::json!("bad")),
    ] {
        let mut json = serde_json::to_value(&node).unwrap();
        json[field] = value;
        assert!(serde_json::from_value::<Node>(json).is_err());
    }
}

#[test]
fn nowhere_dae_declaration_uses_share_links_and_explicit_tags() {
    let source = format!(
        "node {{\n    edge: 'nowhere://{KEY}@relay.example:2000?net=udp&morph=0#fragment'\n}}\nrouting {{ fallback: direct }}"
    );
    let mut diagnostics = Vec::new();
    let config =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics)
            .unwrap();
    assert!(diagnostics.is_empty());
    assert_eq!(config.nodes.len(), 1);
    assert_eq!(config.nodes[0].name, "edge");
    assert_eq!(
        config.nodes[0].nowhere().unwrap().carrier,
        NowhereCarrier::Udp
    );
}
