// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::allow_dest` (IF §12.10 item 3, "allow-if-private", moved from the retired plugin
//! handover): 1.5.5 dialled a private or loopback provider upstream with no allowlist, and 1.6.0
//! refuses one unless `advanced.allow_destinations` names it. The hosts are core's own providers'
//! `base_url` and `token_url`; no plugin supplies one and no plugin's bag is read.
//!
//! The candidates are 1.5.5's `reachable` rule: every provider a `models.<m>` entry names plus every
//! provider the deployment's own `providers:` section authors (a catalog-only entry no model names
//! is never dialled and adds nothing). Each candidate's resolved entry is the authored one over the
//! catalog's, key by key. [`run`] decides each host once, as the destination guard would: an entry
//! already listed is left as it is, a cloud-metadata name or alternate IPv4 spelling is never added,
//! an address literal or a `localhost` name is judged directly, any other name is resolved once, and
//! the host is added only when every answer is private or loopback and none is cloud metadata. One
//! report line per decision.

use std::net::{IpAddr, ToSocketAddrs};

use busbar_contract::net::{
    embedded_ipv4, host_ip, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
    is_link_local_v6, judged_host, url_host, METADATA_HOSTS,
};
use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

/// How a host name is resolved at migrate time: its addresses, or why it did not resolve.
pub type Resolve = fn(&str) -> Result<Vec<IpAddr>, String>;

/// The system resolver, once, at migrate time.
///
/// # Errors
/// The resolver's own text.
pub fn system_resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    (host, 0u16)
        .to_socket_addrs()
        .map(|answers| answers.map(|answer| answer.ip()).collect())
        .map_err(|error| error.to_string())
}

const KEYS: [&str; 2] = ["base_url", "token_url"];

/// The hosts of core's candidate providers, deduplicated, in document order: `resolved` is the
/// interpolated document, `catalog` the providers catalog 1.5.5 read.
pub(crate) fn candidates(resolved: &Value, catalog: Option<&Value>) -> Vec<String> {
    let mut names: Vec<&str> = Vec::new();
    if let Some(Value::Map(models)) = resolved.get("models") {
        for (_, model) in models {
            if let Some(provider) = model.get("provider").and_then(Value::as_str) {
                names.push(provider);
            }
        }
    }
    let authored = resolved.get("providers");
    if let Some(Value::Map(entries)) = authored {
        names.extend(entries.keys().filter_map(Value::as_str));
    }
    let mut hosts: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for name in names {
        if seen.contains(&name) {
            continue;
        }
        seen.push(name);
        let from = |side: Option<&Value>, key: &str| {
            side.and_then(|side| side.get(name))
                .and_then(|entry| entry.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        for key in KEYS {
            let url = from(authored, key).or_else(|| from(catalog, key));
            if let Some(host) = url.as_deref().and_then(url_host) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
    }
    hosts
}

/// 1d's allow-if-private over `root` (the document being converted): decide every candidate host
/// of `resolved` and `catalog`, adding the ones the rule admits to `advanced.allow_destinations`.
pub(crate) fn run(
    root: &mut Pairs,
    resolved: &Value,
    catalog: Option<&Value>,
    resolve: Resolve,
    report: &mut Vec<String>,
) {
    for host in candidates(resolved, catalog) {
        decide(root, &host, resolve, report);
    }
}

fn already_listed(root: &Pairs, name: &str) -> bool {
    let Some(Value::Array(list)) = root
        .get_key("advanced")
        .and_then(|advanced| advanced.get("allow_destinations"))
    else {
        return false;
    };
    list.iter().filter_map(Value::as_str).any(|entry| {
        let entry = entry.trim().trim_start_matches('[').trim_end_matches(']');
        entry
            .strip_suffix('.')
            .unwrap_or(entry)
            .eq_ignore_ascii_case(name)
    })
}

fn decide(root: &mut Pairs, raised: &str, resolve: Resolve, report: &mut Vec<String>) {
    let line = |text: String| format!("advanced.allow_destinations: {text}");
    let never = "cloud metadata is refused for every outbound connection and no configuration \
                 admits it";
    let name = match judged_host(raised) {
        Ok(name) if !name.is_empty() => name,
        _ => {
            report.push(line(format!(
                "not added '{raised}': not a host the destination guard can judge; write the plain \
                 host name or address"
            )));
            return;
        }
    };
    if already_listed(root, &name) {
        report.push(line(format!(
            "'{name}' is already listed, so it was left as it is (not resolved)"
        )));
        return;
    }
    if METADATA_HOSTS.contains(&name.as_str()) {
        report.push(line(format!(
            "not added '{name}': a cloud metadata name, not resolved, and {never}"
        )));
        return;
    }
    if is_alternate_ipv4_encoding(&name) {
        report.push(line(format!(
            "not added '{name}': an alternate IPv4 spelling the guard refuses whatever the \
             allowlist says; write the address in dotted-quad form"
        )));
        return;
    }
    let (answers, resolved) = if let Some(ip) = host_ip(&name) {
        (vec![ip], format!("{ip} (an address literal)"))
    } else if name == "localhost" || name.ends_with(".localhost") {
        (Vec::new(), "loopback (a `localhost` name)".to_owned())
    } else {
        match resolve(&name) {
            Ok(answers) if !answers.is_empty() => {
                let shown: Vec<String> = answers.iter().map(ToString::to_string).collect();
                let shown = format!("{} (this machine's DNS)", shown.join(", "));
                (answers, shown)
            }
            Ok(_) => {
                report.push(line(format!(
                    "not added '{name}': it answered no address at migrate time; if it is private \
                     where busbar runs, add it by hand"
                )));
                return;
            }
            Err(why) => {
                report.push(line(format!(
                    "not added '{name}': it did not resolve at migrate time ({why}); if it is \
                     private where busbar runs, add it by hand"
                )));
                return;
            }
        }
    };
    let link_local = |ip: &IpAddr| matches!(ip, IpAddr::V6(v6) if embedded_ipv4(v6).is_none() && is_link_local_v6(v6));
    if let Some(ip) = answers
        .iter()
        .find(|ip| ip_is_cloud_metadata(ip) || link_local(ip))
    {
        report.push(line(format!(
            "not added '{name}': resolved to {resolved}, and {ip} is cloud metadata or IPv6 \
             link-local, so {never}"
        )));
        return;
    }
    let public = answers.iter().filter(|ip| !ip_is_internal(ip)).count();
    if public > 0 && public == answers.len() {
        report.push(line(format!(
            "not added '{name}': resolved to {resolved}, every answer public, so it needs no entry"
        )));
        return;
    }
    if public > 0 {
        report.push(line(format!(
            "not added '{name}': resolved to {resolved}, some answers private and some public; \
             1.6.0 refuses such an answer unless the host is allowed, so add it by hand if every \
             address it answers is yours"
        )));
        return;
    }
    let advanced = root.entry_or_insert_with("advanced", || Value::Map(Pairs::new()));
    let Value::Map(advanced) = advanced else {
        report.push(line(format!(
            "not added '{name}': `advanced` is not a mapping; add it by hand"
        )));
        return;
    };
    let Value::Array(list) =
        advanced.entry_or_insert_with("allow_destinations", || Value::Array(Vec::new()))
    else {
        report.push(line(format!(
            "not added '{name}': `advanced.allow_destinations` is not a list; add it by hand"
        )));
        return;
    };
    list.push(Value::from(name.as_str()));
    report.push(line(format!(
        "added '{name}': resolved to {resolved}, every answer private or loopback and none cloud \
         metadata (1.6.0 refuses a private or loopback destination unless it is allowed; only this \
         host is allowed, not every private address)"
    )));
}

#[cfg(test)]
#[path = "tests/allow_dest_tests.rs"]
mod tests;
