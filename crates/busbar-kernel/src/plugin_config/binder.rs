// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Binder`]: core's [`ConfigBinder`] (IF §12.7). Cold code: it runs once per instance load (boot, reload,
//! admin install, `--validate`), and the lookups the hot paths make (`secret`, `trust`, `dest`, `unix_path`)
//! take one read lock and index a vector.
//!
//! Handle order (the suites bind pointers in this order, T1 `FakeNeeds`): secrets are numbered from 1 in the
//! order of the declared D_SECRET_PATH pointers, a `*` pointer in ascending array index, then (`bind_any` only)
//! every other reference in document order; trust and dest handles likewise in their own declared order.

use busbar_ports::binder::RefSource;
use busbar_ports::binder::{NetworkEndpoint, NetworkLease, NetworkPermit};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use busbar_contract::json::SchemaCheck;
use busbar_contract::secret_ref::{context, SecretRef, Sugars};
use busbar_contract::secure::SecureVec;
use serde_json::{Map, Value};

use super::{pem, pointer, BindError, BoxFut, ConfigBinder, DestDef, TrustAnchor};

/// The most secret plus trust handles one instance binds (IF §12.7 C-REF-PATH); it also bounds the instance's
/// scrub set (§12.16). More is [`BindError::TooMany`].
pub const MAX_BINDINGS: usize = 1_024;
/// host_disk.rs `MAX_KEEP`: the most rotated files a file-sink destination keeps.
const MAX_KEEP: u32 = crate::host_disk::MAX_KEEP;
const DEFAULT_ROTATE_MB: u64 = 64;
const DEFAULT_KEEP: u32 = 9;
const SECRET: &str = "$secret";
const TRUST: &str = "$trust";
const DEST: &str = "$dest";

/// A generation's complete config binder; every instance opened in that generation binds through it.
pub struct Binder {
    sugars: Arc<Sugars>,
    schemas: HashMap<Arc<str>, Option<SchemaCheck>>,
    instances: RwLock<HashMap<u64, Arc<Entry>>>,
}

/// One instance's bindings (the frozen [`super::Bindings`] fields, trust shared as `Arc`) and the operator's
/// original text of each, for `unbind_refs`.
struct Entry {
    network_lease: NetworkLease,
    network: OnceLock<Box<[NetworkEndpoint]>>,
    secrets: Vec<SecretRef>,
    secret_text: Vec<Value>,
    trust: Vec<Arc<TrustAnchor>>,
    trust_text: Vec<Value>,
    dests: Vec<Arc<DestDef>>,
    dest_text: Vec<Value>,
    refs: Vec<RefEntry>,
    /// The D_REF_PATH patterns of the describe the instance was bound under.
    ref_paths: Vec<Box<str>>,
}

/// One `Bindings.refs` entry.
struct RefEntry {
    pointer: Box<str>,
    reference: SecretRef,
    text: Value,
    /// SHA-256 of the value `resolve_refs` wrote (the value itself is never kept here).
    resolved: Mutex<Option<[u8; 32]>>,
}

impl Binder {
    #[must_use]
    pub fn new(sugars: Arc<Sugars>, schemas: Vec<(Arc<str>, Box<str>)>) -> Self {
        let schemas = schemas
            .into_iter()
            .map(|(name, schema)| (name, SchemaCheck::new(schema.as_bytes()).ok()))
            .collect();
        Self {
            sugars,
            schemas,
            instances: RwLock::new(HashMap::new()),
        }
    }

    fn entry(&self, instance: u64) -> Option<Arc<Entry>> {
        self.instances
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&instance)
            .cloned()
    }

    fn bind_mode(
        &self,
        instance: u64,
        config: &[u8],
        paths: Paths<'_>,
        any: bool,
    ) -> Result<Vec<u8>, BindError> {
        let sugars = Arc::clone(&self.sugars);
        let mut doc: Value = crate::json::parse(config)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;

        let secret_at = concrete(&doc, paths.secret);
        let trust_at = concrete(&doc, paths.trust);
        let dest_at = concrete(&doc, paths.dest);
        let ref_at = concrete(&doc, paths.reference);

        // Stray references and markers, on the operator's text, outside every declared position. In
        // `bind_any` a reference there is bound instead (collected in document order).
        let mut declared: Vec<&str> = Vec::new();
        for at in secret_at
            .iter()
            .chain(&trust_at)
            .chain(&dest_at)
            .chain(&ref_at)
        {
            declared.push(at.as_str());
        }
        let mut anywhere = Vec::new();
        let mut at = String::new();
        scan(&doc, &mut at, &declared, &sugars, any, &mut anywhere)?;

        let mut entry = Entry {
            network_lease: NetworkLease::new(instance),
            network: OnceLock::new(),
            secrets: Vec::new(),
            secret_text: Vec::new(),
            trust: Vec::new(),
            trust_text: Vec::new(),
            dests: Vec::new(),
            dest_text: Vec::new(),
            refs: Vec::new(),
            ref_paths: paths.reference.iter().map(|p| Box::from(*p)).collect(),
        };

        for at in &secret_at {
            let Some(node) = doc.pointer(at) else {
                continue;
            };
            match node {
                Value::Null => continue,
                // Round 31: a 1.x literal at a declared secret position, for CORE_CFG(LIFT).
                Value::String(_) if any => continue,
                _ => {}
            }
            let node = node.clone();
            let reference =
                parse_reference(&node, &sugars).ok_or_else(|| BindError::NotAReference {
                    pointer: at.as_str().into(),
                })?;
            self.check_ref_schema(at, &node, &reference, &sugars)?;
            let handle = push_secret(&mut entry, reference, node)?;
            replace(&mut doc, at, SECRET, handle);
        }
        for at in &anywhere {
            let Some(node) = doc.pointer(at).cloned() else {
                continue;
            };
            let Some(reference) = parse_reference(&node, &sugars) else {
                continue;
            };
            self.check_ref_schema(at, &node, &reference, &sugars)?;
            let handle = push_secret(&mut entry, reference, node)?;
            replace(&mut doc, at, SECRET, handle);
        }
        for at in &trust_at {
            let Some(node) = doc.pointer(at) else {
                continue;
            };
            if node.is_null() {
                continue;
            }
            let anchor =
                node.as_str()
                    .and_then(pem::trust_anchor)
                    .ok_or_else(|| BindError::BadPem {
                        pointer: at.as_str().into(),
                    })?;
            entry.trust_text.push(node.clone());
            entry.trust.push(Arc::new(anchor));
            if entry.secrets.len() + entry.trust.len() > MAX_BINDINGS {
                return Err(BindError::TooMany);
            }
            let handle = entry.trust.len();
            replace(&mut doc, at, TRUST, handle);
        }
        for at in &ref_at {
            let Some(node) = doc.pointer(at) else {
                continue;
            };
            if node.is_null() || node.is_string() {
                continue;
            }
            let node = node.clone();
            let reference =
                parse_reference(&node, &sugars).ok_or_else(|| BindError::NotAReference {
                    pointer: at.as_str().into(),
                })?;
            self.check_ref_schema(at, &node, &reference, &sugars)?;
            entry.refs.push(RefEntry {
                pointer: at.as_str().into(),
                reference,
                text: node,
                resolved: Mutex::new(None),
            });
        }
        // Last: a dest at `""` is the whole bag.
        for at in &dest_at {
            let Some(node) = doc.pointer(at) else {
                continue;
            };
            if node.is_null() {
                continue;
            }
            let dest = dest_def(node).ok_or_else(|| BindError::BadDest {
                pointer: at.as_str().into(),
            })?;
            entry.dest_text.push(node.clone());
            entry.dests.push(Arc::new(dest));
            if entry.dests.len() > usize::from(u16::MAX) {
                return Err(BindError::TooMany);
            }
            let handle = entry.dests.len();
            replace(&mut doc, at, DEST, handle);
        }

        let bound = serde_json::to_vec(&doc)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
        let mut instances = self
            .instances
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if instances.contains_key(&instance) {
            return Err(BindError::BadNetwork);
        }
        instances.insert(instance, Arc::new(entry));
        Ok(bound)
    }

    /// Round 8: a Source reference's `settings` against the D_REF_SCHEMA of the secret instance it routes to.
    /// A template reference routes to its fill source and carries no settings of its own.
    fn check_ref_schema(
        &self,
        at: &str,
        node: &Value,
        reference: &SecretRef,
        sugars: &Sugars,
    ) -> Result<(), BindError> {
        if !matches!(reference, SecretRef::Source(_)) {
            return Ok(());
        }
        let Value::Object(map) = node else {
            return Ok(());
        };
        let (key, settings, names) = if let Some(Value::String(module)) = map.get("module") {
            let settings = map
                .get("settings")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            (module.as_str(), settings, None)
        } else if let Some((word, value)) = map.iter().next().filter(|_| map.len() == 1) {
            let Some(sugar) = sugars.get(word) else {
                return Ok(());
            };
            let mut settings = Map::new();
            settings.insert(sugar.setting.clone(), value.clone());
            (
                word.as_str(),
                Value::Object(settings),
                Some(sugar.names.as_str()),
            )
        } else {
            return Ok(());
        };
        let Some(check) = self.schemas.get(key) else {
            return Ok(());
        };
        let valid = match check {
            Some(check) => serde_json::to_vec(&settings)
                .map(|bytes| check.is_valid(&bytes))
                .unwrap_or(false),
            None => false,
        };
        if valid {
            return Ok(());
        }
        let mut text = String::new();
        {
            use std::fmt::Write as _;
            let _ = write!(
                text,
                "the secret reference at {} does not match the reference settings secret instance '{}' accepts",
                display_pointer(at),
                key
            );
            if let Some(names) = names {
                let _ = write!(text, " (the value names {names})");
            }
        }
        Err(BindError::BadReference {
            pointer: at.into(),
            text: text.into(),
        })
    }
}

/// The four declared path sets of one bind.
#[derive(Clone, Copy)]
struct Paths<'a> {
    secret: &'a [&'a str],
    trust: &'a [&'a str],
    dest: &'a [&'a str],
    reference: &'a [&'a str],
}

fn concrete(doc: &Value, patterns: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for p in patterns {
        let mark = out.len();
        pointer::expand(doc, p, &mut out);
        // A pattern repeated in the describe binds its node once.
        let mut i = mark;
        while i < out.len() {
            if out[..mark].contains(&out[i]) {
                out.remove(i);
            } else {
                i += 1;
            }
        }
    }
    out
}

fn display_pointer(at: &str) -> &str {
    if at.is_empty() {
        "the top of the config"
    } else {
        at
    }
}

/// A node as a reference under the installed shorthand table; None = it is not one.
fn parse_reference(node: &Value, sugars: &Sugars) -> Option<SecretRef> {
    context::deserialize::<SecretRef, _>(node.clone(), sugars).ok()
}

/// Whether an object node reads as a reference: a canonical `{module, settings?}`, a `{template: ..}`, or a
/// declared shorthand `{<word>: X}`.
fn is_reference_object(map: &Map<String, Value>, sugars: &Sugars) -> bool {
    let candidate = map.contains_key("module")
        || map.contains_key("template")
        || (map.len() == 1 && map.keys().next().is_some_and(|w| sugars.get(w).is_some()));
    candidate && parse_reference(&Value::Object(map.clone()), sugars).is_some()
}

fn is_marker(map: &Map<String, Value>) -> bool {
    map.contains_key(SECRET) || map.contains_key(TRUST) || map.contains_key(DEST)
}

fn scan(
    node: &Value,
    at: &mut String,
    declared: &[&str],
    sugars: &Sugars,
    any: bool,
    anywhere: &mut Vec<String>,
) -> Result<(), BindError> {
    if declared.iter().any(|d| pointer::within(d, at)) {
        return Ok(());
    }
    let mark = at.len();
    match node {
        Value::Object(map) => {
            if is_marker(map) {
                return Err(BindError::StraySecret {
                    pointer: at.as_str().into(),
                });
            }
            if is_reference_object(map, sugars) {
                if any {
                    anywhere.push(at.clone());
                    return Ok(());
                }
                return Err(BindError::StraySecret {
                    pointer: at.as_str().into(),
                });
            }
            for (key, child) in map {
                at.push('/');
                pointer::escape_into(at, key);
                scan(child, at, declared, sugars, any, anywhere)?;
                at.truncate(mark);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                use std::fmt::Write as _;
                let _ = write!(at, "/{i}");
                scan(child, at, declared, sugars, any, anywhere)?;
                at.truncate(mark);
            }
        }
        _ => {}
    }
    Ok(())
}

fn push_secret(entry: &mut Entry, reference: SecretRef, text: Value) -> Result<usize, BindError> {
    entry.secrets.push(reference);
    entry.secret_text.push(text);
    if entry.secrets.len() + entry.trust.len() > MAX_BINDINGS {
        return Err(BindError::TooMany);
    }
    Ok(entry.secrets.len())
}

fn marker(key: &str, handle: usize) -> Value {
    let mut map = Map::new();
    map.insert(
        key.into(),
        Value::from(u64::try_from(handle).unwrap_or(u64::MAX)),
    );
    Value::Object(map)
}

fn replace(doc: &mut Value, at: &str, key: &str, handle: usize) {
    if let Some(slot) = doc.pointer_mut(at) {
        *slot = marker(key, handle);
    }
}

/// `{"$secret": n}` (or `$trust`/`$dest`) as the binder writes it: one key, a positive integer.
fn read_marker(map: &Map<String, Value>) -> Option<(&'static str, usize)> {
    if map.len() != 1 {
        return None;
    }
    let (key, value) = map.iter().next()?;
    let key = match key.as_str() {
        SECRET => SECRET,
        TRUST => TRUST,
        DEST => DEST,
        _ => return None,
    };
    let n = usize::try_from(value.as_u64()?).ok()?;
    Some((key, n))
}

/// Round 7: `{path, rotate_mb?, keep?}`; `path` passes today's destination admission (a non-empty path with no
/// NUL and no `..` segment) and `keep` ≤ `MAX_KEEP`.
fn dest_def(node: &Value) -> Option<DestDef> {
    let map = node.as_object()?;
    if map
        .keys()
        .any(|k| !matches!(k.as_str(), "path" | "rotate_mb" | "keep"))
    {
        return None;
    }
    let path = map.get("path")?.as_str()?;
    if path.trim().is_empty() || path.contains('\0') || path.split('/').any(|seg| seg == "..") {
        return None;
    }
    let rotate_mb = match map.get("rotate_mb") {
        None => DEFAULT_ROTATE_MB,
        Some(v) => v.as_u64()?,
    };
    let keep = match map.get("keep") {
        None => DEFAULT_KEEP,
        Some(v) => u32::try_from(v.as_u64()?).ok()?,
    };
    if keep > MAX_KEEP {
        return None;
    }
    Some(DestDef {
        path: path.into(),
        rotate_mb,
        keep,
    })
}

/// Every marker back to its original text, and every resolved D_REF_PATH value back to its reference.
fn restore(node: &mut Value, at: &mut String, entry: &Entry) -> Result<(), BindError> {
    let mark = at.len();
    match node {
        Value::Object(map) => {
            if let Some((key, n)) = read_marker(map) {
                let texts = match key {
                    SECRET => &entry.secret_text,
                    TRUST => &entry.trust_text,
                    _ => &entry.dest_text,
                };
                let text = n.checked_sub(1).and_then(|i| texts.get(i)).ok_or_else(|| {
                    BindError::NotAReference {
                        pointer: at.as_str().into(),
                    }
                })?;
                *node = text.clone();
                return Ok(());
            }
            if is_marker(map) {
                return Err(BindError::NotAReference {
                    pointer: at.as_str().into(),
                });
            }
            for (key, child) in map.iter_mut() {
                at.push('/');
                pointer::escape_into(at, key);
                restore(child, at, entry)?;
                at.truncate(mark);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter_mut().enumerate() {
                use std::fmt::Write as _;
                let _ = write!(at, "/{i}");
                restore(child, at, entry)?;
                at.truncate(mark);
            }
        }
        Value::String(s) => {
            if entry.refs.is_empty() {
                return Ok(());
            }
            let digest = busbar_contract::crypto::sha256(s.as_bytes());
            let mut equal = entry.refs.iter().filter(|r| {
                *r.resolved
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    == Some(digest)
            });
            let Some(first) = equal.next() else {
                return Ok(());
            };
            let here = std::iter::once(first)
                .chain(equal)
                .find(|r| &*r.pointer == at.as_str());
            let movable = entry
                .ref_paths
                .iter()
                .any(|p| pointer::matches(p, at.as_str()));
            let chosen = match (here, movable) {
                (Some(r), _) => r,
                (None, true) => first,
                // A resolved plain value is never written back.
                (None, false) => {
                    return Err(BindError::NotAReference {
                        pointer: at.as_str().into(),
                    })
                }
            };
            *node = chosen.text.clone();
        }
        _ => {}
    }
    Ok(())
}

impl ConfigBinder for Binder {
    fn freeze_network(
        &self,
        instance: u64,
        endpoints: &[NetworkEndpoint],
    ) -> Result<(), BindError> {
        let bad = || BindError::BadNetwork;
        let entry = self.entry(instance).ok_or_else(bad)?;
        if endpoints.len() > 16 {
            return Err(BindError::TooMany);
        }
        let frozen = NetworkEndpoint::canonical_set(endpoints).ok_or_else(bad)?;
        entry.network.set(frozen).map_err(|_| bad())
    }

    fn admit_network(&self, instance: u64, endpoint: &NetworkEndpoint) -> Option<NetworkPermit> {
        use busbar_plugin_abi::need::egress;
        let entry = self.entry(instance)?;
        if !entry.network_lease.live() {
            return None;
        }
        let frozen = entry.network.get()?;
        let canonical = NetworkEndpoint::new(endpoint.op, endpoint.flags, &endpoint.dest)?;
        let class = canonical.flags >> 16;
        if matches!(
            class,
            egress::OPERATOR_INFRASTRUCTURE | egress::LOOPBACK_ALLOWED
        ) {
            let (index, checked) = frozen.iter().enumerate().find(|(_, e)| **e == canonical)?;
            Some(NetworkPermit {
                lease: entry.network_lease.clone(),
                instance,
                registration: u32::try_from(index + 1).ok()?,
                endpoint: checked.clone(),
            })
        } else {
            Some(NetworkPermit {
                lease: entry.network_lease.clone(),
                instance,
                registration: 0,
                endpoint: canonical,
            })
        }
    }
    fn bind(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        let paths = Paths {
            secret: secret_paths,
            trust: trust_paths,
            dest: dest_paths,
            reference: ref_paths,
        };
        self.bind_mode(instance, config, paths, false)
    }

    fn resolve_refs<'a>(
        &'a self,
        instance: u64,
        slot: u32,
        bound: Vec<u8>,
        source: &'a dyn RefSource,
    ) -> BoxFut<'a, Result<SecureVec, BindError>> {
        Box::pin(async move {
            let Some(entry) = self.entry(instance).filter(|e| !e.refs.is_empty()) else {
                return Ok(SecureVec::from(bound));
            };
            let mut doc: Value = crate::json::parse(&bound)
                .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
            let mut written: Vec<&str> = Vec::with_capacity(entry.refs.len());
            let mut result = Ok(());
            for (binding, r) in entry.refs.iter().enumerate() {
                let refused = |why: &str| {
                    let mut text = String::new();
                    {
                        use std::fmt::Write as _;
                        let _ = write!(
                            text,
                            "the secret reference at {} {why}",
                            display_pointer(&r.pointer)
                        );
                    }
                    BindError::BadReference {
                        pointer: r.pointer.clone(),
                        text: text.into(),
                    }
                };
                let Ok(binding) = u32::try_from(binding) else {
                    result = Err(BindError::TooMany);
                    break;
                };
                let Some(value) = source.resolve(instance, slot, binding, &r.reference).await
                else {
                    result = Err(refused("could not be resolved"));
                    break;
                };
                let Ok(text) = std::str::from_utf8(value.as_slice()) else {
                    result = Err(refused("resolved to a value that is not UTF-8 text"));
                    break;
                };
                *r.resolved
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(busbar_contract::crypto::sha256(text.as_bytes()));
                if let Some(slot) = doc.pointer_mut(&r.pointer) {
                    *slot = Value::String(text.into());
                    written.push(&r.pointer);
                }
            }
            let out = match result {
                Ok(()) => serde_json::to_vec(&doc)
                    .map(SecureVec::from)
                    .map_err(|_| BindError::NotAReference { pointer: "".into() }),
                Err(refused) => Err(refused),
            };
            // The plain values leave only in the returned buffer.
            for at in written {
                if let Some(Value::String(s)) = doc.pointer_mut(at) {
                    zeroize::Zeroize::zeroize(s);
                }
            }
            out
        })
    }

    fn unbind(&self, instance: u64) {
        if let Some(entry) = self
            .instances
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&instance)
        {
            entry.network_lease.retire();
        }
    }

    fn bind_any(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        let paths = Paths {
            secret: secret_paths,
            trust: trust_paths,
            dest: dest_paths,
            reference: ref_paths,
        };
        self.bind_mode(instance, config, paths, true)
    }

    fn unbind_refs(&self, instance: u64, bound: &[u8]) -> Result<Vec<u8>, BindError> {
        let entry = self
            .entry(instance)
            .ok_or_else(|| BindError::NotAReference { pointer: "".into() })?;
        let mut doc: Value = crate::json::parse(bound)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
        let mut at = String::new();
        restore(&mut doc, &mut at, &entry)?;
        serde_json::to_vec(&doc).map_err(|_| BindError::NotAReference { pointer: "".into() })
    }

    fn secret(&self, instance: u64, handle: u32) -> Option<SecretRef> {
        let entry = self.entry(instance)?;
        let i = usize::try_from(handle).ok()?.checked_sub(1)?;
        entry.secrets.get(i).cloned()
    }

    fn trust(&self, instance: u64, handle: u32) -> Option<Arc<TrustAnchor>> {
        let entry = self.entry(instance)?;
        let i = usize::try_from(handle).ok()?.checked_sub(1)?;
        entry.trust.get(i).cloned()
    }

    fn dest(&self, instance: u64, handle: u32) -> Option<Arc<DestDef>> {
        let entry = self.entry(instance)?;
        let i = usize::try_from(handle).ok()?.checked_sub(1)?;
        entry.dests.get(i).cloned()
    }
}
