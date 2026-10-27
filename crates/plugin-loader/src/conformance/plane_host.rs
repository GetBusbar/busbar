// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE SCRIPT'S HOST (`conformance.json`'s `plane.host`): the kernel services a plane asks
//! on its crossings, served the way the kernel serves them (THE DESIGN §11.12), with the kernel's
//! answers and refusals, from what the plugin's inputs and its own Statement state. A door that runs
//! in production on a service runs on it here, linked and dropped in alike (THE DESIGN §2).
//!
//! * `entitlement.check` answers ENTITLED when the crossing serves a unit and a grant names the
//!   target (`"<scope kind>:<name>"`), for every unit or for the units it lists; a crossing that
//!   serves no unit is entitled to nothing (`KernelServices::entitled`'s rule).
//! * `trust.serves` answers the verdict a row states for `(counterparty, item)`; a row whose item is
//!   `null` states the counterparty's own verdict, the one an item-less ask is answered. An item no
//!   row names is `DISTRUST_UNKNOWN_ITEM`; an item-less ask of a counterparty no row names is
//!   `DISTRUST_UNKNOWN`, a counterparty the instance does not declare.
//! * `clock.now` reads `0`, so what a plane stamps with the host's clock folds the same on both legs.
//! * `random.fill` writes the bytes asked for, fresh at every call, from a deterministic stream that
//!   starts over on each leg, so what a plane mints from it folds the same on both; a fill of no
//!   bytes or above `MAX_RANDOM_FILL` is refused in the kernel's words.
//! * `dest.judge` is the deployment's destination guard at the owner default
//!   (`advanced.block_private_addresses: true`, nothing allowlisted, no metadata carve-out): the
//!   scheme arm of the egress class, then the name arm (cloud-metadata names, alternate IPv4
//!   spellings, an IP literal judged as its own answer, the `localhost` family), and asked to
//!   resolve, the answer `plane.host.resolve` states for the name, every address judged and, admitted,
//!   written one span each; a name it states no answer for is `DEST_UNRESOLVABLE`. A resolution asked
//!   outside a ticketed op is refused, as the kernel refuses it.
//! * `records.get` / `records.list` / `records.claim` are the instance's own records, of the record
//!   kinds its Statement declares (the instance is admitted once it is loaded, [`Host::admit`]): the
//!   record writes its answers carry are kept ([`Host::keep`]) and read back (read-your-writes), a
//!   chained kind's write appended to its chain and read whole through `records.list`, and a claim
//!   won once per key. An instance never admitted, a kind it did not declare and a claim with no
//!   time to live are refused in the kernel's words. Every answer is ready at once (a may-pend
//!   service that answers at once is within its contract).
//! * Every other service is refused UNSERVED, as a host that serves none of it.
//!
//! ```json
//! "host": {
//!   "entitled": [ { "target": "<scope kind>:<name>", "units": [<unit>, ...] }, ... ],  // units optional
//!   "trusted":  [ ["<counterparty>", "<item>" | null, "none" | "not_approved" | ...], ... ],
//!   "resolve":  { "<name>": ["<address>", ...], ... },                                 // optional
//!   "records":  [ { "kind": "<kind>", "key": "<key>", "value": "<text>" | <JSON> }, ... ] } // optional
//! ```
//!
//! `records` are what the instance's store already holds when it is loaded (an instance opened again
//! over records an earlier one wrote, as the kernel's store keeps them across opens): each row is
//! read back by `records.get` / `records.list` exactly as a kept write is, a JSON value as its
//! serialized bytes. A row of a kind the Statement does not declare is never read, as the kernel
//! refuses the kind.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::{
    ItemSpan, ABSENT, CLAIM_TAKEN, CLAIM_WON, DEST_ALLOWED, DEST_EXPLAIN, DEST_INTERNAL,
    DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST, DEST_OBFUSCATED, DEST_PLAINTEXT,
    DEST_REFUSE_PRIVATE, DEST_RESOLVE, DEST_SCHEME, DEST_UNRESOLVABLE, DISTRUST_CHANGED,
    DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_QUARANTINED, DISTRUST_UNKNOWN,
    DISTRUST_UNKNOWN_ITEM, DISTRUST_UNSIGHTED, ENTITLED, FOUND, MAX_RANDOM_FILL, MAX_SPANS,
    NOT_ENTITLED,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::net::{
    extract_normalized_host, host_ip, ip_is_cloud_metadata, ip_is_internal,
    is_alternate_ipv4_encoding, judged_host, parse_url, METADATA_HOSTS,
};
use busbar_contract::plane_calls::InstanceDecl;
use busbar_contract::services::{
    chain_key, chain_key_parts, merge_list, Caller, DiskDest, HookAsk, NestAsk, RecordsList,
    Snapshot, UNSERVED,
};
use serde_json::Value;

use crate::dispatch::services::{FILL_OUT_OF_RANGE, NO_TTL, UNTICKETED};
use crate::dispatch::{HostServices, Ran, Reading, Stored};
use crate::stand_in::FramedFacts;

/// The completion a pending service answer is handed (the services' own callback type): never
/// called here, every service this host serves answers at once.
type Pended = Box<dyn FnOnce(Stored) + Send>;

/// The kernel's refusal of a caller-scoped service from an instance it never admitted.
const NOT_ADMITTED: &str = "the instance is not admitted";
/// The kernel's refusal of a record kind the caller did not declare.
const NOT_A_KIND: &str = "not a record kind the instance declared";
/// The kernel's refusal of `records.get` on a chained record kind.
const CHAIN_READ_WHOLE: &str = "a chained record kind is read whole, through records.list";

/// The egress classes a private address is refused in at the owner default
/// (`block_private_addresses: true`): the default class, the provider class and open web.
const PRIVATE_REFUSED_IN: &[u32] = &[EGRESS_DEFAULT, EGRESS_PROVIDER, EGRESS_OPEN_WEB];

/// One grant: its target, and the units it holds for (`None` = every unit).
struct Grant {
    target: String,
    units: Option<Vec<u64>>,
}

/// The admitted instance: its label, its declared record kinds, and which of them are chained.
struct Admitted {
    instance: Arc<str>,
    kinds: Vec<(String, bool)>,
}

/// What the instance's record writes and claims left.
#[derive(Default)]
struct Kept {
    admitted: Option<Admitted>,
    /// `(kind, key)` → value; an empty value is a tombstone. A chained kind's records are kept
    /// under their listed key (`chain_key(scope, seq)`).
    rows: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    /// `(kind, scope)` → the last sequence appended to that chain.
    chains: BTreeMap<(String, Vec<u8>), u64>,
    /// `(kind, key)` claimed. The host's clock reads `0`, so no claim lapses within a fold.
    claims: HashSet<(String, Vec<u8>)>,
}

/// The host the inputs state.
pub(super) struct Host {
    entitled: Vec<Grant>,
    trusted: Vec<(String, Option<String>, u64)>,
    resolve: BTreeMap<String, Vec<IpAddr>>,
    /// The URL scheme of a secured destination, as the stand-in transport's facts state it.
    secure_scheme: String,
    /// The fills drawn so far.
    drawn: AtomicU64,
    kept: Mutex<Kept>,
}

/// A `trust.serves` verdict by its name.
fn verdict(name: &str) -> u64 {
    match name {
        "none" => DISTRUST_NONE,
        "unknown" => DISTRUST_UNKNOWN,
        "unsighted" => DISTRUST_UNSIGHTED,
        "quarantined" => DISTRUST_QUARANTINED,
        "not_approved" => DISTRUST_NOT_APPROVED,
        "changed" => DISTRUST_CHANGED,
        "unknown_item" => DISTRUST_UNKNOWN_ITEM,
        other => panic!("conformance.json: plane.host.trusted names no verdict `{other}`"),
    }
}

impl Host {
    /// The host `v` (`plane.host`) states; `None` when the inputs state none.
    pub(super) fn of(v: &Value) -> Option<Self> {
        if v.is_null() {
            return None;
        }
        let entitled = v["entitled"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|g| Grant {
                target: g["target"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("conformance.json: plane.host.entitled[].target must be a string")
                    })
                    .to_string(),
                units: g["units"].as_array().map(|u| {
                    u.iter()
                        .map(|n| {
                            n.as_u64().unwrap_or_else(|| {
                                panic!("conformance.json: plane.host.entitled[].units holds a non-number")
                            })
                        })
                        .collect()
                }),
            })
            .collect();
        let trusted = v["trusted"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| match row.as_array().map(Vec::as_slice) {
                Some([Value::String(c), Value::String(i), Value::String(v)]) => {
                    (c.clone(), Some(i.clone()), verdict(v))
                }
                Some([Value::String(c), Value::Null, Value::String(v)]) => {
                    (c.clone(), None, verdict(v))
                }
                _ => panic!(
                    "conformance.json: plane.host.trusted rows are [\"<counterparty>\", \"<item>\" | null, \"<verdict>\"]"
                ),
            })
            .collect();
        let resolve = v["resolve"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, addrs)| {
                let addrs: Vec<IpAddr> = addrs
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|a| {
                        a.as_str().and_then(|a| a.parse().ok()).unwrap_or_else(|| {
                            panic!(
                                "conformance.json: plane.host.resolve.{name} holds a non-address"
                            )
                        })
                    })
                    .collect();
                // A stated name no mapping reads is never asked: the name arm refuses it first.
                (norm(name).unwrap_or_else(|| name.to_string()), addrs)
            })
            .collect();
        let rows = v["records"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                let field = |name: &str| {
                    r[name].as_str().unwrap_or_else(|| {
                        panic!("conformance.json: plane.host.records[].{name} must be a string")
                    })
                };
                let value = match &r["value"] {
                    Value::String(text) => text.as_bytes().to_vec(),
                    Value::Null => {
                        panic!("conformance.json: plane.host.records[].value is required")
                    }
                    json => serde_json::to_vec(json).expect("a JSON value serializes"),
                };
                (
                    (field("kind").to_string(), field("key").as_bytes().to_vec()),
                    value,
                )
            })
            .collect();
        Some(Self {
            entitled,
            trusted,
            resolve,
            secure_scheme: FramedFacts::stand_in().secure_scheme,
            drawn: AtomicU64::new(0),
            kept: Mutex::new(Kept {
                rows,
                ..Kept::default()
            }),
        })
    }

    fn kept(&self) -> MutexGuard<'_, Kept> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// ADMIT the loaded instance on what its Statement declares, as the kernel admits it at bind:
    /// its label, its record kinds and which of them are chained.
    pub(super) fn admit(&self, d: &InstanceDecl) {
        let kinds = d
            .record_kinds
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let chained = d.record_chains.iter().any(|c| c.kind as usize == i);
                ((*k).to_string(), chained)
            })
            .collect();
        self.kept().admitted = Some(Admitted {
            instance: Arc::clone(&d.label),
            kinds,
        });
    }

    /// KEEP one `RECORD_PUT` an answer carried, of the record kind at `kind` of the Statement's
    /// list, as the kernel's flush writes it: an empty value is a tombstone; a chained kind's write
    /// is appended to the chain its key names (an empty one drops the chain). A write the kernel
    /// would refuse (no admitted instance, no such kind, a chained key that is no scope) is not kept.
    pub(super) fn keep(&self, kind: u32, key: &[u8], value: &[u8]) {
        let mut kept = self.kept();
        let Some((kind, chained)) = kept
            .admitted
            .as_ref()
            .and_then(|a| a.kinds.get(kind as usize).cloned())
        else {
            return;
        };
        if !chained {
            kept.rows.insert((kind, key.to_vec()), value.to_vec());
            return;
        }
        let scope_fit =
            std::str::from_utf8(key).is_ok_and(|s| !s.is_empty()) && chain_key_parts(key).is_none();
        if !scope_fit {
            return;
        }
        if value.is_empty() {
            kept.rows.retain(|(k, row), _| {
                *k != kind || chain_key_parts(row).is_none_or(|(scope, _)| scope != key)
            });
            kept.chains.remove(&(kind, key.to_vec()));
            return;
        }
        let seq = {
            let last = kept.chains.entry((kind.clone(), key.to_vec())).or_insert(0);
            *last += 1;
            *last
        };
        let at = chain_key(key, seq);
        kept.rows.insert((kind, at), value.to_vec());
    }

    /// The caller's record kind `kind`, whether it is chained; or the kernel's refusal.
    fn scope(kept: &Kept, caller: &Caller, kind: &str) -> Result<bool, Stored> {
        let admitted = kept
            .admitted
            .as_ref()
            .filter(|a| a.instance == caller.instance)
            .ok_or_else(|| Stored::refused(NOT_ADMITTED))?;
        admitted
            .kinds
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, chained)| *chained)
            .ok_or_else(|| Stored::refused(NOT_A_KIND))
    }

    /// `len` bytes of the fill stream, fresh at every call.
    fn draw(&self, len: usize) -> Vec<u8> {
        let call = self.drawn.fetch_add(1, Ordering::Relaxed);
        let mut state = call.wrapping_add(1).wrapping_mul(0xD1B5_4A32_D192_ED03);
        let mut bytes = Vec::with_capacity(len + 8);
        while bytes.len() < len {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            bytes.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
        }
        bytes.truncate(len);
        bytes
    }

    /// THE ONE JUDGEMENT asked to resolve: the addresses judged (the literal, or the stated answer
    /// for the name), or the refusal with what decided it.
    fn resolved(
        &self,
        (host, https, literal): (String, bool, Option<IpAddr>),
        class: u32,
        strict: bool,
    ) -> Result<Vec<IpAddr>, (u64, Option<String>)> {
        if let Some(ip) = literal {
            return Ok(vec![ip]);
        }
        let Some(addrs) = norm(&host).and_then(|name| self.resolve.get(&name)) else {
            return Err((
                DEST_UNRESOLVABLE,
                Some(format!("the host's resolver answers no `{host}`")),
            ));
        };
        if addrs.is_empty() {
            return Err((DEST_NO_ADDRESSES, None));
        }
        for a in addrs {
            judge_address(*a, class, strict).map_err(|v| (v, Some(a.to_string())))?;
        }
        plaintext_to_loopback(class, https, &host).map_err(|v| (v, None))?;
        Ok(addrs.clone())
    }
}

/// A target name as the guard compares it, through the guard's own mapping
/// (`busbar_contract::net::judged_host`: UTS #46 to-ASCII, held to `url`'s IPv4 reading); `None`, a
/// host the guard refuses as unjudgeable (`DEST_NO_HOST`).
fn norm(host: &str) -> Option<String> {
    judged_host(host).ok()
}

/// Loopback as the guard reads it: IPv4 `127.0.0.0/8`, IPv6 `::1`, and the IPv4-mapped and
/// -compatible spellings of a `127.0.0.0/8` address.
fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// A host WRITTEN as loopback: a loopback literal in any spelling, or the `localhost` family.
fn names_loopback(host: &str) -> bool {
    let Some(name) = norm(host) else {
        return false;
    };
    match host_ip(&name) {
        Some(ip) => is_loopback(ip),
        None => name == "localhost" || name.ends_with(".localhost"),
    }
}

/// The loopback-allowed class's scheme rule: plaintext only to a host written as loopback.
fn plaintext_to_loopback(class: u32, https: bool, host: &str) -> Result<(), u64> {
    if class == EGRESS_LOOPBACK_ALLOWED && !https && !names_loopback(host) {
        return Err(DEST_PLAINTEXT);
    }
    Ok(())
}

/// Whether a private address is refused under `class` (`strict`: `DEST_REFUSE_PRIVATE`).
fn refuses_private(class: u32, strict: bool) -> bool {
    strict || PRIVATE_REFUSED_IN.contains(&class)
}

/// One address the destination stands for: cloud metadata refused in every class, an internal
/// address where the class (or the caller) refuses private reach, and in the loopback-allowed
/// class every internal address but loopback.
fn judge_address(addr: IpAddr, class: u32, strict: bool) -> Result<(), u64> {
    if ip_is_cloud_metadata(&addr) {
        return Err(DEST_METADATA);
    }
    let off_loopback = class == EGRESS_LOOPBACK_ALLOWED && !is_loopback(addr);
    if (refuses_private(class, strict) || off_loopback) && ip_is_internal(&addr) {
        return Err(DEST_INTERNAL);
    }
    Ok(())
}

/// The name arm, before any resolution: `Some(ip)` for an IP literal (judged as its own answer),
/// `None` for a name to resolve.
fn judge_name(host: &str, class: u32, strict: bool) -> Result<Option<IpAddr>, u64> {
    let name = norm(host).ok_or(DEST_NO_HOST)?;
    if METADATA_HOSTS.iter().any(|h| name == *h) {
        return Err(DEST_METADATA);
    }
    if is_alternate_ipv4_encoding(&name)
        && !(class == EGRESS_LOOPBACK_ALLOWED && host_ip(&name).is_some())
    {
        return Err(DEST_OBFUSCATED);
    }
    if let Some(ip) = host_ip(&name) {
        judge_address(ip, class, strict)?;
        return Ok(Some(ip));
    }
    let loopback_name = name == "localhost" || name.ends_with(".localhost");
    if loopback_name && refuses_private(class, strict) {
        return Err(DEST_INTERNAL);
    }
    Ok(None)
}

/// A destination as `(host, secure)`: a URL of one of the two web schemes the shared host reader
/// takes (`extract_normalized_host`; the scheme read without case, any other scheme refused, a
/// userinfo refused), secure when its scheme is `secure_scheme`; or a bare `host[:port]` authority
/// (secure). The scheme's name is data (`stand_in.json`), never this source's.
fn split(dest: &str, secure_scheme: &str) -> Result<(String, bool), u64> {
    if let Some((scheme, rest)) = dest.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if extract_normalized_host(&format!("{scheme}://host")).is_none() {
            return Err(DEST_SCHEME);
        }
        let https = scheme == secure_scheme;
        let lowered = format!("{scheme}://{rest}");
        let parts = parse_url(&lowered).map_err(|_| DEST_NO_HOST)?;
        if parts.userinfo {
            return Err(DEST_NO_HOST);
        }
        return Ok((parts.host, https));
    }
    if dest.is_empty() || dest.contains('@') {
        return Err(DEST_NO_HOST);
    }
    let (host, port) = match dest.strip_prefix('[') {
        Some(inner) => {
            let (host, tail) = inner.split_once(']').ok_or(DEST_NO_HOST)?;
            (host, tail.strip_prefix(':'))
        }
        None => match dest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            _ => (dest, None),
        },
    };
    if let Some(p) = port {
        p.parse::<u16>().map_err(|_| DEST_NO_HOST)?;
    }
    if host.is_empty() {
        return Err(DEST_NO_HOST);
    }
    Ok((host.to_owned(), true))
}

/// The scheme and name arms under egress class `class`: the host, whether it is secure, and the
/// literal when it is one.
fn named(
    dest: &str,
    class: u32,
    strict: bool,
    secure_scheme: &str,
) -> Result<(String, bool, Option<IpAddr>), u64> {
    // The classes a need may declare are 0..=4; a destination under any other names none.
    if class > EGRESS_LOOPBACK_ALLOWED {
        return Err(DEST_NO_HOST);
    }
    let (host, https) = split(dest, secure_scheme)?;
    if !https && class == EGRESS_OPEN_WEB {
        return Err(DEST_PLAINTEXT);
    }
    let literal = judge_name(&host, class, strict)?;
    if literal.is_some() {
        plaintext_to_loopback(class, https, &host)?;
    }
    Ok((host, https, literal))
}

const fn absent() -> Span {
    Span {
        offset: SPAN_ABSENT,
        len: 0,
    }
}

fn span(at: usize, len: usize) -> Span {
    let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
    Span {
        offset: n(at),
        len: n(len),
    }
}

/// One span per key, value absent (the judged addresses, or what decided a refusal).
fn keyed(mut s: Stored, keys: impl IntoIterator<Item = String>) -> Stored {
    for key in keys {
        let at = s.bytes.len();
        s.bytes.extend_from_slice(key.as_bytes());
        s.spans.push(ItemSpan {
            key: span(at, key.len()),
            value: absent(),
        });
    }
    s
}

/// The rows, one span each over its key and its value.
fn rows_of(rows: Vec<(Vec<u8>, Vec<u8>)>) -> Stored {
    let mut s = Stored::ready(0);
    for (k, v) in rows {
        let key_at = s.bytes.len();
        s.bytes.extend_from_slice(&k);
        let value_at = s.bytes.len();
        s.bytes.extend_from_slice(&v);
        s.spans.push(ItemSpan {
            key: span(key_at, k.len()),
            value: span(value_at, v.len()),
        });
    }
    s
}

impl HostServices for Host {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: 0,
        }
    }

    fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
        let entitled = unit.is_some_and(|u| {
            self.entitled.iter().any(|g| {
                g.target == target && g.units.as_ref().is_none_or(|units| units.contains(&u))
            })
        });
        Stored::ready(if entitled { ENTITLED } else { NOT_ENTITLED })
    }

    fn trust_serves(
        &self,
        _: &Caller,
        counterparty: &str,
        item: Option<&str>,
        _: Option<&str>,
    ) -> Stored {
        let found = self
            .trusted
            .iter()
            .find(|(c, i, _)| c == counterparty && i.as_deref() == item);
        let unnamed = if item.is_some() {
            DISTRUST_UNKNOWN_ITEM
        } else {
            DISTRUST_UNKNOWN
        };
        Stored::ready(found.map_or(unnamed, |(_, _, v)| *v))
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Pended>) -> Ran {
        let strict = flags & DEST_REFUSE_PRIVATE != 0;
        // The name and scheme arms first, at once: a refusal never waits on a resolution.
        let named = match named(dest, class, strict, &self.secure_scheme) {
            Err(v) => return Ran::Now(Stored::ready(v)),
            Ok(_) if flags & DEST_RESOLVE == 0 => return Ran::Now(Stored::ready(DEST_ALLOWED)),
            Ok(n) => n,
        };
        if later.is_none() {
            return Ran::Now(Stored::refused(UNTICKETED));
        }
        Ran::Now(match self.resolved(named, class, strict) {
            Ok(addrs) => keyed(
                Stored::ready(DEST_ALLOWED),
                addrs.iter().map(ToString::to_string),
            ),
            Err((verdict, detail)) => keyed(
                Stored::ready(verdict),
                detail.filter(|_| flags & DEST_EXPLAIN != 0),
            ),
        })
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], _: Pended) -> Ran {
        let kept = self.kept();
        Ran::Now(match Self::scope(&kept, caller, kind) {
            Err(refused) => refused,
            Ok(true) => Stored::refused(CHAIN_READ_WHOLE),
            Ok(false) => match kept.rows.get(&(kind.to_string(), key.to_vec())) {
                Some(v) if !v.is_empty() => {
                    let mut s = Stored::ready(FOUND);
                    s.bytes.clone_from(v);
                    s.spans.push(ItemSpan {
                        key: absent(),
                        value: span(0, v.len()),
                    });
                    s
                }
                _ => Stored::ready(ABSENT),
            },
        })
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, _: Pended) -> Ran {
        let kept = self.kept();
        if let Err(refused) = Self::scope(&kept, caller, &list.kind) {
            return Ran::Now(refused);
        }
        let cap = usize::try_from(MAX_SPANS).unwrap_or(usize::MAX);
        let limit = match list.limit {
            0 => cap,
            n => (n as usize).min(cap),
        };
        let rows = kept
            .rows
            .iter()
            .filter(|((k, key), _)| *k == list.kind && key.starts_with(&list.prefix))
            .map(|((_, key), v)| (key.clone(), v.clone()))
            .collect();
        Ran::Now(rows_of(merge_list(
            rows,
            Vec::new(),
            list.after.as_deref(),
            limit,
        )))
    }

    fn records_claim(&self, caller: &Caller, kind: &str, key: &[u8], ttl: u64, _: Pended) -> Ran {
        let mut kept = self.kept();
        if let Err(refused) = Self::scope(&kept, caller, kind) {
            return Ran::Now(refused);
        }
        if ttl == 0 {
            return Ran::Now(Stored::refused(NO_TTL));
        }
        let won = kept.claims.insert((kind.to_string(), key.to_vec()));
        Ran::Now(Stored::ready(if won { CLAIM_WON } else { CLAIM_TAKEN }))
    }

    fn random_fill(&self, len: u64) -> Stored {
        if len == 0 || len > MAX_RANDOM_FILL {
            return Stored::refused(FILL_OUT_OF_RANGE);
        }
        Stored {
            bytes: self.draw(len as usize),
            ..Stored::ready(0)
        }
    }

    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn records_secret(&self, _: &str, _: &str, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn hook_call(&self, _: &Caller, _: Option<u64>, _: HookAsk, _: Pended) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn snapshot_read(&self, _: &Caller, _: u32) -> Snapshot {
        Snapshot::Refused(UNSERVED)
    }
}
