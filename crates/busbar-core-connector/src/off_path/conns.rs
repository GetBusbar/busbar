// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connection table's off-path code (`crate::conns`, with its `listen` binding): what a need's
//! declaration, a registration's seal, a listener's bind and an instance's retirement build or let
//! go of, once per configuration or lifecycle, never per request. Beside it, the crate's test kit,
//! which no request ever runs.

use std::collections::BTreeMap;
use std::hash::Hash;
use std::sync::Arc;

use busbar_contract::conn::{ConnError, InstanceId, NeedId};
use foldhash::HashMap;

use crate::conns::framer::FramerDoor;
use crate::conns::hostio::{Admission, HostIo};
use crate::conns::program::{Declaration, Member, Members};

/// The test kit (a private test CA, the adoption observer) for this crate's tests and, behind
/// the `test-support` feature, for plugin repos' dev-dependencies.
#[cfg(any(test, feature = "test-support"))]
#[path = "../test_support.rs"]
pub mod test_support;

/// Hold `value` for `member` among a need's `members`: a member already held keeps its name and
/// takes the new value (the old one is answered); a new member's name is kept once, as it is first
/// sealed.
pub(crate) fn hold_member<V>(
    members: &mut HashMap<String, V>,
    member: &str,
    value: V,
) -> Option<V> {
    if let Some(held) = members.get_mut(member) {
        return Some(std::mem::replace(held, value));
    }
    members.insert(member.to_owned(), value)
}

/// Record `member`'s seal at its registration's destination, once, at declaration.
pub(crate) fn seal_registration<V>(members: &mut BTreeMap<String, V>, member: &str, sealed: V) {
    members.insert(member.to_owned(), sealed);
}

/// A need's declaration (or a listener's bind) keeps its own copy of the entry's protocol list.
pub(crate) fn declared_alpn(alpn: &[Vec<u8>]) -> Vec<Vec<u8>> {
    alpn.to_vec()
}

/// A member-program need's members, declared once: a member whose program is unchanged from
/// `before` is kept (its environment reloaded), every other is declared afresh over `door`.
pub(crate) fn declare_members(
    programs: &[(String, busbar_contract::conn::Program)],
    before: Option<&Members>,
    scope: &busbar_contract::config_time::ConfigScope,
    secrets: Option<crate::conns::spawn_env::SpawnSecretFn>,
    (door, io): (&Arc<dyn FramerDoor>, &Arc<HostIo>),
    alpn: &[Vec<u8>],
) -> Result<Members, ConnError> {
    programs
        .iter()
        .map(|(name, p)| {
            let kept = before
                .and_then(|b| b.get(name))
                .filter(|m| m.program() == p)
                .cloned();

            if let Some(kept) = &kept {
                kept.env().reload(scope);
            }
            let member = match kept {
                Some(kept) => kept,
                None => Arc::new(Declaration::new(Member::new(
                    p.clone(),
                    crate::conns::spawn_env::HeldEnv::load(&p.env_refs, secrets, scope),
                    crate::conns::compose::Via {
                        door: Arc::clone(door),
                        io: Arc::clone(io),
                    },
                    alpn.to_vec(),
                )?)),
            };
            Ok((name.clone(), member))
        })
        .collect::<Result<_, ConnError>>()
}

/// `target` without its userinfo: the authority's text up to and including its last `@` left out,
/// cleared once, at declaration.
pub(crate) fn without_userinfo(target: &str) -> Option<String> {
    let parts = busbar_contract::net::url_authority(target);
    parts.userinfo?;
    Some(format!(
        "{}{}{}{}",
        parts.scheme.unwrap_or_default(),
        if parts.scheme.is_some() { "://" } else { "" },
        parts.host_port,
        parts.tail
    ))
}

/// The client TLS a need declared with the operator CA `pem` (`trust_from`, deprecated) dials
/// with: its anchors logged, its configuration built, or the refusal's text kept for the need.
pub(crate) fn operator_anchors(
    owner: InstanceId,
    need: NeedId,
    trust_from: &str,
    pem: &str,
) -> Result<
    Option<(
        Arc<rustls::ClientConfig>,
        busbar_contract::transport::trust::EgressTrust,
    )>,
    String,
> {
    crate::conns::tls::client::operator_ca_anchors(pem.as_bytes()).and_then(|roots| {
        log_operator_anchors(owner, need, trust_from, &roots);
        let policy = busbar_contract::transport::trust::EgressTrust {
            extra_anchors: roots,
            ..Default::default()
        };
        crate::conns::tls::client::build_client_config(&policy)
            .map(|config| Some((Arc::new(config), policy)))
            .map_err(|e| e.to_string())
    })
}

/// CA via `trust_from` (deprecated, refused from 1.7.0 once the core trust store exists): one info
/// line naming the SHA-256 of each operator anchor a need was declared with. No operator warning:
/// there is nothing the operator can move it to yet.
fn log_operator_anchors(owner: InstanceId, need: NeedId, trust_from: &str, roots: &[Vec<u8>]) {
    for der in roots {
        let sha256 =
            busbar_contract::abi::sdk::digest::lower_hex(&busbar_contract::crypto::sha256(der));
        tracing::info!(
            instance = owner.0,
            need = need.0,
            trust_from,
            sha256 = %sha256,
            "an outbound need trusts an operator CA from its plugin settings (deprecated: the core \
             trust store replaces it)"
        );
    }
}

/// Bind `member`'s auth `binding` for `origin`, once, keeping its names.
pub(crate) fn bind_auth(
    auths: &mut crate::conns::Auths,
    (owner, need): (InstanceId, NeedId),
    member: &str,
    origin: &str,
    binding: busbar_contract::conn::ConnAuth,
) {
    auths
        .entry(owner)
        .or_default()
        .entry(need)
        .or_default()
        .entry(member.to_string())
        .or_default()
        .insert(origin.to_string(), binding);
}

/// A listener's admission: exactly its bind, admitted once, as it is bound.
pub(crate) fn bind_admission(bind: &str) -> Admission {
    Admission::Bind(bind.to_owned())
}

/// Take every entry of `map` whose key `owned` names out, as an instance retires.
pub(crate) fn take_owned<K: Copy + Eq + Hash, V>(
    map: &mut HashMap<K, V>,
    owned: impl Fn(&K) -> bool,
) -> Vec<V> {
    let keys: Vec<K> = map.keys().filter(|k| owned(*k)).copied().collect();
    keys.iter().filter_map(|k| map.remove(k)).collect()
}

/// Every need `owner` declared in `over`, as it retires.
pub(crate) fn needs_of<V>(
    over: &HashMap<(InstanceId, NeedId), V>,
    owner: InstanceId,
) -> Vec<NeedId> {
    over.keys()
        .filter(|(o, _)| *o == owner)
        .map(|(_, n)| *n)
        .collect()
}

/// Let go of every entry of `map` whose key `owned` names, as an instance retires.
pub(crate) fn forget_owned<K: Eq + Hash, V>(map: &mut HashMap<K, V>, owned: impl Fn(&K) -> bool) {
    map.retain(|k, _| !owned(k));
}

/// An owned copy of `text`, kept by a dialled connection's own record (its target, authority,
/// member or located place), once, as the connection is dialled.
pub(crate) fn owned(text: &str) -> String {
    text.to_owned()
}

/// An owned copy of an optional name, as [`owned`].
pub(crate) fn owned_name(name: Option<&str>) -> Option<String> {
    name.map(str::to_owned)
}

/// `text` lower-cased, the key a dialled connection is pooled and anchored under.
pub(crate) fn lowered(text: &str) -> String {
    text.to_ascii_lowercase()
}

/// An owned copy of `items`, kept by a dialled connection's own record (its head words, its
/// protocol offer, the head defaults), once, as the connection is dialled.
pub(crate) fn copied<T: Clone>(items: &[T]) -> Vec<T> {
    items.to_vec()
}

/// The head an opener lent, copied into the dial's own owned fields once, as the connection is
/// dialled.
pub(crate) fn copied_fields(fields: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    fields
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
        .collect()
}

/// An owned copy of `bytes` (a dial's method or head target words), once, as the connection is
/// dialled or opened.
pub(crate) fn owned_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}
