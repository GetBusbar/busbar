// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST-STORE MIGRATION (`busbar --migrate-config`): plugin TLS settings move into the one
//! core trust store (`advanced.tls`), and settings that would reach a destination without
//! encryption are rewritten or reported.
//!
//! * A plugin `ca_cert_pem` (auth-ldap `url`, auth-github `api_base`/`authorize_base`/
//!   `token_base`, auth-oidc `issuer`/`jwks_url`, secret-vault `addr`) and plane-mcp
//!   `tools.<s>.tls.ca_cert_pem` (`url`) become an exact-host `advanced.tls.destinations` entry
//!   per host the plugin dials, merged into an existing entry with the same match (BUSBAR-3415).
//!   A value held in a secret reference is not copied (a CA cannot come from a secret store): a
//!   TODO names it. A literal certificate that is not a CA is reported (BUSBAR-3418). auth-oidc's
//!   discovered hosts cannot be known offline: a TODO (BUSBAR-3416).
//! * auth-ldap `allow_insecure_transport` is removed with a TODO: credentials never cross in
//!   clear (BUSBAR-3417).
//! * A literal postgres store URL with `sslmode=prefer`/`allow` or no sslmode becomes
//!   `sslmode=require` (BUSBAR-3412). A literal valkey store URL loses `#insecure` (BUSBAR-3413).
//!   A literal postgres URL reaching a non-loopback host in clear (`sslmode=disable`) gains a
//!   `{match: <host>, plaintext: true}` entry (BUSBAR-3414); a valkey `redis://` URL to one gets a
//!   TODO (the valkey store accepts plaintext only to loopback). Ref-held URLs get a TODO.
//!
//! Idempotent: a second run finds nothing to move.

use serde_yaml::{Mapping, Value};

use super::migrate_plugins::Ledger;

/// The plugin modules whose `ca_cert_pem` moves, and the settings naming the hosts they dial.
const CA_PLUGINS: &[(&str, &[&str])] = &[
    ("ldap", &["url"]),
    ("auth-ldap", &["url"]),
    ("github", &["api_base", "authorize_base", "token_base"]),
    ("auth-github", &["api_base", "authorize_base", "token_base"]),
    ("oidc", &["issuer", "jwks_url"]),
    ("auth-oidc", &["issuer", "jwks_url"]),
    ("vault", &["addr"]),
    ("secret-vault", &["addr"]),
];

/// The default hosts a plugin dials when its URL setting is omitted.
fn default_hosts(module: &str) -> &'static [&'static str] {
    match module {
        "github" | "auth-github" => &["api.github.com", "github.com"],
        _ => &[],
    }
}

fn key(k: &str) -> Value {
    Value::String(k.to_owned())
}

/// Apply every trust-store rewrite to `root`.
pub(super) fn apply(root: &mut Mapping, ledger: &mut Ledger<'_>) {
    let mut entries: Vec<(String, Value, String)> = Vec::new();
    let mut plaintext: Vec<(String, String)> = Vec::new();
    for section in ["identity-providers", "identity_providers", "secrets"] {
        let Some(Value::Mapping(named)) = root.get_mut(key(section)) else {
            continue;
        };
        for (name, block) in named.iter_mut() {
            let name = name.as_str().unwrap_or_default().to_owned();
            let at = format!("{section}.{name}");
            plugin_block(&at, block, &mut entries, ledger);
        }
    }
    if let Some(block) = root.get_mut(key("store")) {
        store_block(block, &mut plaintext, ledger);
    }
    if let Some(Value::Mapping(tools)) = root.get_mut(key("tools")) {
        for (name, tool) in tools.iter_mut() {
            let name = name.as_str().unwrap_or_default().to_owned();
            mcp_tool(&format!("tools.{name}"), tool, &mut entries, ledger);
        }
    }
    if entries.is_empty() && plaintext.is_empty() {
        return;
    }
    let destinations = destinations(root);
    for (host, anchor, from) in entries {
        merge_anchor(destinations, &host, anchor, &from, ledger);
    }
    for (host, from) in plaintext {
        if !destinations.iter().any(|d| {
            d.get(key("match")).and_then(Value::as_str) == Some(host.as_str())
                && d.get(key("plaintext")).and_then(Value::as_bool) == Some(true)
        }) {
            let mut e = Mapping::new();
            e.insert(key("match"), Value::String(host.clone()));
            e.insert(key("plaintext"), Value::Bool(true));
            destinations.push(Value::Mapping(e));
            ledger.changes.push(format!(
                "BUSBAR-3414: advanced.tls.destinations: added {{match: {host}, plaintext: true}}: \
                 {from} reaches {host} without TLS, which busbar 1.6 admits only to loopback or an \
                 exact plaintext entry. Credentials are still never sent in clear to it; prefer \
                 TLS and remove the entry"
            ));
        }
    }
}

/// The `advanced.tls.destinations` list, created when absent.
fn destinations(root: &mut Mapping) -> &mut Vec<Value> {
    let advanced = root
        .entry(key("advanced"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if !advanced.is_mapping() {
        *advanced = Value::Mapping(Mapping::new());
    }
    let tls = advanced
        .as_mapping_mut()
        .expect("mapping")
        .entry(key("tls"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if !tls.is_mapping() {
        *tls = Value::Mapping(Mapping::new());
    }
    let list = tls
        .as_mapping_mut()
        .expect("mapping")
        .entry(key("destinations"))
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if !list.is_sequence() {
        *list = Value::Sequence(Vec::new());
    }
    list.as_sequence_mut().expect("sequence")
}

fn merge_anchor(
    destinations: &mut Vec<Value>,
    host: &str,
    anchor: Value,
    from: &str,
    ledger: &mut Ledger<'_>,
) {
    let existing = destinations.iter_mut().find(|d| {
        d.get(key("match")).and_then(Value::as_str) == Some(host)
            && d.get(key("plaintext")).and_then(Value::as_bool) != Some(true)
    });
    let entry = match existing {
        Some(e) => e,
        None => {
            let mut e = Mapping::new();
            e.insert(key("match"), Value::String(host.to_owned()));
            destinations.push(Value::Mapping(e));
            destinations.last_mut().expect("pushed")
        }
    };
    let map = entry.as_mapping_mut().expect("an entry is a mapping");
    let anchors = map
        .entry(key("trust_anchors"))
        .or_insert_with(|| Value::Sequence(Vec::new()));
    if !anchors.is_sequence() {
        *anchors = Value::Sequence(Vec::new());
    }
    let list = anchors.as_sequence_mut().expect("sequence");
    let fingerprint = fingerprint(&anchor);
    if !list.contains(&anchor) {
        list.push(anchor);
    }
    ledger.changes.push(format!(
        "BUSBAR-3415: advanced.tls.destinations: {from}.ca_cert_pem moved to an entry for \
         {host}{}; its anchors replace the public roots for that host (move it to \
         advanced.tls.trust_anchors instead if it is a corporate root for many hosts)",
        fingerprint.map_or_else(String::new, |f| format!(" (sha256 {f})"))
    ));
}

fn fingerprint(anchor: &Value) -> Option<String> {
    let pem = anchor.as_str()?;
    let der = first_der(pem)?;
    use sha2::Digest as _;
    Some(hex::encode(sha2::Sha256::digest(&der)))
}

fn first_der(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let body = &pem[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = body.find("-----END CERTIFICATE-----")?;
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Whether a literal PEM's first certificate says `basicConstraints CA:TRUE` (`None` when it
/// cannot be read).
fn is_ca(pem: &str) -> Option<bool> {
    let der = first_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(
        cert.basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|bc| bc.value.ca),
    )
}

/// The settings of a plugin block: its `settings` mapping, or the block itself (flat form).
fn settings_of(block: &mut Value) -> Option<&mut Mapping> {
    let map = block.as_mapping_mut()?;
    if map.get(key("settings")).is_some_and(Value::is_mapping) {
        return map.get_mut(key("settings")).and_then(Value::as_mapping_mut);
    }
    Some(map)
}

fn module_of(block: &Value) -> String {
    block
        .get(key("module"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// The host of a literal URL (`scheme://[user@]host[:port]/...`), lowercased; `None` for a
/// reference or anything that is not a URL.
fn url_host(v: &Value) -> Option<String> {
    let url = v.as_str()?;
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split_once(']')?.0
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    (!host.is_empty()).then(|| host.trim_end_matches('.').to_ascii_lowercase())
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn plugin_block(
    at: &str,
    block: &mut Value,
    entries: &mut Vec<(String, Value, String)>,
    ledger: &mut Ledger<'_>,
) {
    let module = module_of(block);
    let Some((_, url_keys)) = CA_PLUGINS.iter().find(|(m, _)| *m == module) else {
        return;
    };
    let Some(settings) = settings_of(block) else {
        return;
    };
    if module.ends_with("ldap") && settings.remove(key("allow_insecure_transport")).is_some() {
        ledger.todos.push(format!(
            "BUSBAR-3417: {at}.allow_insecure_transport was removed: busbar 1.6 never sends a bind \
             password in clear to a host that is not loopback. Use ldaps:// or start_tls: true, and \
             list the directory's CA under advanced.tls.destinations if it is not publicly trusted"
        ));
    }
    let Some(ca) = settings.remove(key("ca_cert_pem")) else {
        return;
    };
    if ca.is_null() || ca.as_str().is_some_and(|s| s.trim().is_empty()) {
        return;
    }
    let mut hosts: Vec<String> = url_keys
        .iter()
        .filter_map(|k| settings.get(key(k)).and_then(url_host))
        .collect();
    if hosts.is_empty() {
        hosts = default_hosts(&module).iter().map(|h| (*h).to_owned()).collect();
    }
    hosts.dedup();
    if !ca.is_string() {
        ledger.todos.push(format!(
            "BUSBAR-3415: {at}.ca_cert_pem was removed: it is a reference, and the trust store \
             takes a CA only from a file, an environment variable or inline PEM (a CA cannot come \
             from a secret store). Add advanced.tls.destinations: [{{match: {}, trust_anchors: \
             [{{file: <the CA's PEM file>}}]}}]",
            hosts.first().map_or("<the plugin's host>", String::as_str)
        ));
        return;
    }
    if hosts.is_empty() {
        ledger.todos.push(format!(
            "BUSBAR-3415: {at}.ca_cert_pem was removed but the host it applies to is not a literal \
             URL: add an advanced.tls.destinations entry for that host listing the CA"
        ));
        return;
    }
    if is_ca(ca.as_str().unwrap_or_default()) == Some(false) {
        ledger.todos.push(format!(
            "BUSBAR-3418: {at}.ca_cert_pem is a server certificate (no basicConstraints CA:TRUE), \
             which busbar 1.6 refuses as a trust anchor (BUSBAR-3137). List the CA that issued it, \
             or re-issue the server's certificate from a CA you control and list that CA"
        ));
    }
    if module.ends_with("oidc") {
        ledger.todos.push(format!(
            "BUSBAR-3416: {at}: the issuer's discovery document may name other hosts (jwks_uri, \
             token_endpoint) that need the same CA; add advanced.tls.destinations entries for them, \
             or move the CA to advanced.tls.trust_anchors if it is a corporate root"
        ));
    }
    for host in hosts {
        entries.push((host, ca.clone(), at.to_owned()));
    }
}

fn mcp_tool(
    at: &str,
    tool: &mut Value,
    entries: &mut Vec<(String, Value, String)>,
    ledger: &mut Ledger<'_>,
) {
    let Some(map) = tool.as_mapping_mut() else {
        return;
    };
    let host = map.get(key("url")).and_then(url_host);
    let Some(Value::Mapping(tls)) = map.get_mut(key("tls")) else {
        return;
    };
    let Some(ca) = tls.remove(key("ca_cert_pem")) else {
        return;
    };
    let empty = tls.is_empty();
    if empty {
        map.remove(key("tls"));
    }
    match (host, ca.is_string()) {
        (Some(h), true) => entries.push((h, ca, format!("{at}.tls"))),
        (h, _) => ledger.todos.push(format!(
            "BUSBAR-3415: {at}.tls.ca_cert_pem was removed: add advanced.tls.destinations: \
             [{{match: {}, trust_anchors: [{{file: <the CA's PEM file>}}]}}]",
            h.as_deref().unwrap_or("<the tool's host>")
        )),
    }
}

fn store_block(block: &mut Value, plaintext: &mut Vec<(String, String)>, ledger: &mut Ledger<'_>) {
    let module = module_of(block);
    let Some(settings) = settings_of(block) else {
        return;
    };
    let Some(url) = settings.get_mut(key("url")) else {
        return;
    };
    match module.as_str() {
        "postgres" | "store-postgres" => postgres_url(url, plaintext, ledger),
        "valkey" | "redis" | "store-valkey" => valkey_url(url, ledger),
        _ => {}
    }
}

fn postgres_url(url: &mut Value, plaintext: &mut Vec<(String, String)>, ledger: &mut Ledger<'_>) {
    let Some(text) = url.as_str().map(str::to_owned) else {
        ledger.todos.push(
            "BUSBAR-3412: store.settings.url is a reference: make sure it sets sslmode=require \
             (or verify-ca/verify-full); sslmode=prefer, sslmode=allow and a missing sslmode are \
             refused (BUSBAR-3142)"
                .into(),
        );
        return;
    };
    if !text.contains("://") {
        return;
    }
    let host = url_host(url).unwrap_or_default();
    let (base, query) = text.split_once('?').map_or((text.as_str(), ""), |(b, q)| (b, q));
    let mut params: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.split_once('=')
                .map_or((p.to_owned(), String::new()), |(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    let mode = params
        .iter()
        .find(|(k, _)| k == "sslmode")
        .map(|(_, v)| v.to_ascii_lowercase());
    let socket = host.is_empty() || host.starts_with('/') || host.starts_with("%2f");
    match mode.as_deref() {
        None | Some("prefer" | "allow") if !socket => {
            params.retain(|(k, _)| k != "sslmode");
            params.push(("sslmode".into(), "require".into()));
            let q: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
            *url = Value::String(format!("{base}?{}", q.join("&")));
            ledger.changes.push(format!(
                "BUSBAR-3412: store.settings.url: sslmode {} rewritten to require for {host}: \
                 busbar 1.6 has no opportunistic TLS. The database must offer TLS; list its CA \
                 under advanced.tls.destinations if it is not publicly trusted",
                mode.as_deref().unwrap_or("(unset)")
            ));
        }
        Some("disable") if !socket && !is_loopback(&host) => {
            plaintext.push((host, "the postgres store (sslmode=disable)".into()));
        }
        _ => {}
    }
}

fn valkey_url(url: &mut Value, ledger: &mut Ledger<'_>) {
    let Some(text) = url.as_str().map(str::to_owned) else {
        ledger.todos.push(
            "BUSBAR-3413: store.settings.url is a reference: make sure it carries no #insecure \
             fragment (refused, BUSBAR-3143) and list the server's CA under \
             advanced.tls.destinations"
                .into(),
        );
        return;
    };
    let host = url_host(url).unwrap_or_default();
    if let Some(stripped) = text.strip_suffix("#insecure") {
        *url = Value::String(stripped.to_owned());
        ledger.changes.push(format!(
            "BUSBAR-3413: store.settings.url: #insecure removed for {host}: the connection is now \
             verified. List the server's CA under advanced.tls.destinations (match: {host}) if it \
             is not publicly trusted"
        ));
    }
    let lower = text.to_ascii_lowercase();
    if (lower.starts_with("redis://") || lower.starts_with("valkey://"))
        && !host.is_empty()
        && !is_loopback(&host)
    {
        let credentialed = lower
            .split_once("://")
            .and_then(|(_, r)| r.split(['/', '?', '#']).next())
            .is_some_and(|a| a.contains('@'));
        if credentialed {
            ledger.todos.push(format!(
                "BUSBAR-3146: store.settings.url sends a password in clear to {host} (redis://):                  busbar 1.6 never sends credentials in clear to a host that is not loopback. Use                  rediss:// and list the server's CA under advanced.tls.destinations"
            ));
        } else {
            ledger.todos.push(format!(
                "BUSBAR-3141: store.settings.url reaches {host} with redis:// (no TLS): the valkey \
                 store accepts plaintext only to loopback. Use rediss:// and list the server's CA \
                 under advanced.tls.destinations"
            ));
        }
    }
}

#[cfg(test)]
#[path = "tests/migrate_tls_tests.rs"]
mod tests;
