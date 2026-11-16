// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared suite harness (IF §14, MIN3 SDK suites). It admits a plugin image into a
//! `Registry<FakeNeeds>` over the real `HOST` static and a [`MemBinder`], opens instances with given
//! settings, hands back the kind's port to drive, and collects what the plugin did: the records it wrote
//! (RECORD), the OPEN/FETCH needs it made, the log lines it emitted and every refusal an open answered.
//!
//! The registry arms (C-ALIAS, C-BLIND, C-ERRORS, C-ADMIT-UNLOAD) admit more than one image into one registry
//! ([`Harness::admit_all`]) and open any of them by its `module:` word
//! ([`Harness::spec_for`]); an image the caller admitted itself (a dropped-in one, through the loader's `admit`)
//! comes in through [`Harness::admit_admitted`].
//!
//! The plugin runs in-process on the SDK safe test host; nothing here is `unsafe`.
//!
//! One caveat the registry owns: the entry fault sink and the log sink are process-wide and attach to the
//! first `Registry` built in a process (`install_sinks`). Log capture is therefore exact when each suite runs
//! in its own process (nextest's default); a second harness in the same process sees its calls but may miss its
//! log lines.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::json::{
    self as facade, JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value,
};
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, InstanceLimits};
use busbar_plugin_abi::host_side::HOST;
use busbar_plugin_abi::need::need_flag;
use busbar_plugin_abi::plugin::__rt::LinkedPlugin;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::admit::{admit_header, admit_linked, Admitted};
use busbar_plugin_loader::instance::{
    Ceilings, DeclaredEndpoint, ImagesBuilder, InstanceSpec, OpenError, OpenedPort, PluginCode,
    Registry, Settled, SlotTable,
};
use busbar_plugin_loader::refusal::{Refusal, RefusalCode};
use busbar_ports::auth::AuthPort;
use busbar_ports::binder::{BindError, ConfigBinder, DestDef, TrustAnchor};
use busbar_ports::export::ExportPort;
use busbar_ports::hook::HookPort;
use busbar_ports::plane::PlanePort;
use busbar_ports::secret::SecretPort;
use busbar_ports::store::StoreHandle;
use busbar_ports::transport::TransportPort;
use tracing::field::{Field, Visit};
use tracing::{span, Event, Metadata, Subscriber};

use crate::fake_needs::{FakeNeeds, Seen};

// ---------------------------------------------------------------------------------------------------------
// MemBinder
// ---------------------------------------------------------------------------------------------------------

const SECRET: &str = "$secret";
const TRUST: &str = "$trust";
const DEST: &str = "$dest";

/// What one instance's `bind` replaced, in handle order (handle `n` is element `n - 1`).
#[derive(Default)]
struct Bound {
    secrets: Vec<Value>,
    trust: Vec<Value>,
    dests: Vec<Value>,
    /// The D_REF_PATH references `bind` found, in pointer order, left in place until `resolve_refs`.
    refs: Vec<Ref>,
    /// The D_REF_PATH patterns the instance was bound under.
    ref_paths: Vec<String>,
}

/// One D_REF_PATH reference of a bound config.
struct Ref {
    /// Its concrete pointer.
    pointer: String,
    /// The operator's original node.
    text: Value,
    /// The value `resolve_refs` wrote in its place.
    resolved: Option<String>,
}

/// The suites' in-memory `ConfigBinder`. `bind` and `bind_any` replace the node at every declared
/// D_SECRET_PATH, D_TRUST_PATH and D_DEST_PATH pointer (a `*` segment matches every array element or object
/// member, in order; `""` is the whole document) with `{"$secret": n}`, `{"$trust": n}` or `{"$dest": n}`,
/// numbering each family from 1 in pointer order, so the plugin only ever sees handles. Values come from
/// `FakeNeeds::secret` in the same order. At a D_SECRET_PATH, as core's binder does: null is left as is, an object
/// is a reference, and a string is a 1.x literal that `bind_any` leaves in place and `bind` refuses
/// (`NotAReference`, `""` included), as it refuses any other node. Unlike core's `bind_any` it binds no
/// reference off a declared path (it cannot tell one without the grammar).
///
/// At a D_REF_PATH pointer, as core's binder does: a plain string or null is left as is, an object is a reference
/// recorded with its concrete pointer and left in place, anything else is `NotAReference`. `resolve_refs` writes
/// at each reference, as a JSON string, the value `FakeNeeds::secret` scripts for that concrete pointer; a pointer
/// with no scripted value, or a value that is not UTF-8, is `BadReference` (core's text). `unbind_refs` writes the
/// operator's original node back for every handle, and for every resolved value at its pointer or at any
/// D_REF_PATH pointer; a resolved value anywhere else is `NotAReference`. It parses no reference grammar (that is
/// core's binder, covered by its own tests): `secret`, `trust`, `dest` answer None and `unix_path` is false.
#[derive(Default)]
pub struct MemBinder {
    bound: Mutex<HashMap<u64, Bound>>,
    /// Where `resolve_refs` reads reference values; None resolves none.
    needs: Option<Arc<FakeNeeds>>,
}

impl MemBinder {
    /// A binder with no scripted values: every D_REF_PATH reference is unresolvable.
    pub fn new() -> Self {
        Self::default()
    }

    /// A binder that resolves D_REF_PATH references to the values `needs` scripts (`FakeNeeds::secret`).
    pub fn over(needs: Arc<FakeNeeds>) -> Self {
        Self {
            needs: Some(needs),
            ..Self::default()
        }
    }

    fn table(&self) -> MutexGuard<'_, HashMap<u64, Bound>> {
        self.bound.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// The segments of a pointer pattern, still escaped (`""` is the whole document: no segment).
fn segments(pattern: &str) -> Vec<&str> {
    pattern.split('/').skip(1).collect()
}

/// Hand `f` every node the pointer pattern `segs` names in `node`, with its concrete pointer (`at` is the pointer
/// of `node`; `*` is every element of an array, or of an object in key order; a missing path names nothing).
fn walk(node: &mut Value, segs: &[&str], at: &mut String, f: &mut dyn FnMut(&str, &mut Value)) {
    let Some((seg, rest)) = segs.split_first() else {
        f(at, node);
        return;
    };
    let mark = at.len();
    if *seg == "*" {
        if let Some(items) = node.as_array_mut() {
            for (i, item) in items.iter_mut().enumerate() {
                at.push('/');
                at.push_str(&i.to_string());
                walk(item, rest, at, f);
                at.truncate(mark);
            }
        } else if let Some(members) = node.as_object_mut() {
            let mut keys: Vec<String> = members.iter().map(|(k, _)| k.to_owned()).collect();
            keys.sort();
            for key in keys {
                if let Some(child) = node.get_mut(key.as_str()) {
                    at.push('/');
                    at.push_str(&escape(&key));
                    walk(child, rest, at, f);
                    at.truncate(mark);
                }
            }
        }
        return;
    }
    let key = seg.replace("~1", "/").replace("~0", "~");
    let child = if node.is_array() {
        key.parse::<usize>().ok().and_then(|i| node.get_mut(i))
    } else {
        node.get_mut(key.as_str())
    };
    if let Some(child) = child {
        at.push('/');
        at.push_str(seg);
        walk(child, rest, at, f);
        at.truncate(mark);
    }
}

/// Whether the concrete pointer `at` is named by `pattern` (`*` matching any array index), as core's binder
/// matches a field the conversion moved.
fn names(pattern: &str, at: &str) -> bool {
    let (p, a) = (segments(pattern), segments(at));
    p.len() == a.len()
        && p.iter().zip(&a).all(|(p, a)| {
            p == a || (*p == "*" && !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Record every reference the D_REF_PATH `paths` name in `doc` (each concrete pointer once), as core's binder
/// does: a plain string or null is left as is, an object is a reference, anything else is `NotAReference`.
fn record_refs(doc: &mut Value, paths: &[&str], refs: &mut Vec<Ref>) -> Result<(), BindError> {
    let mut refused = None;
    for pattern in paths {
        walk(
            doc,
            &segments(pattern),
            &mut String::new(),
            &mut |at, node| {
                if refused.is_some()
                    || node.is_null()
                    || node.as_str().is_some()
                    || refs.iter().any(|r| r.pointer == at)
                {
                    return;
                }
                if node.is_object() {
                    refs.push(Ref {
                        pointer: at.to_owned(),
                        text: node.clone(),
                        resolved: None,
                    });
                } else {
                    refused = Some(BindError::NotAReference { pointer: at.into() });
                }
            },
        );
        if let Some(refused) = refused {
            return Err(refused);
        }
    }
    Ok(())
}

/// Core's text for a reference `resolve_refs` could not write.
fn bad_reference(pointer: &str, why: &str) -> BindError {
    let at = if pointer.is_empty() {
        "the top of the config"
    } else {
        pointer
    };
    BindError::BadReference {
        pointer: pointer.into(),
        text: format!("the secret reference at {at} {why}").into(),
    }
}

/// The operator's original node for the resolved value `s` found at `at`: the reference recorded at `at`, else
/// (a field the conversion moved) the first reference resolved to `s` when a D_REF_PATH pattern names `at`. None
/// when `s` is no resolved value; a resolved value anywhere else is `NotAReference` (never written back).
fn ref_text(s: &str, at: &str, bound: &Bound) -> Result<Option<Value>, BindError> {
    let mut equal = bound
        .refs
        .iter()
        .filter(|r| r.resolved.as_deref() == Some(s));
    let Some(first) = equal.next() else {
        return Ok(None);
    };
    let here = std::iter::once(first)
        .chain(equal)
        .find(|r| r.pointer == at);
    let movable = bound.ref_paths.iter().any(|p| names(p, at));
    match (here, movable) {
        (Some(r), _) => Ok(Some(r.text.clone())),
        (None, true) => Ok(Some(first.text.clone())),
        (None, false) => Err(BindError::NotAReference { pointer: at.into() }),
    }
}

/// A JSON non-negative integer, whether the tree holds it typed or as its exact lexeme.
fn count(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_raw_number()
            .and_then(|n| n.as_str().parse::<u64>().ok())
    })
}

/// The handle object `{marker: n}`.
fn handle(marker: &str, n: usize) -> Value {
    facade::parse_typed(format!("{{\"{marker}\":{n}}}").as_bytes()).expect("a handle is JSON")
}

/// What a family does with the node at one declared concrete pointer: `Ok(true)` binds it to a handle,
/// `Ok(false)` leaves it in place.
type Admit<'a> = &'a dyn Fn(&str, &Value) -> Result<bool, BindError>;

/// Replace every node the `paths` name (each concrete pointer once; `""` is the whole document, as in core's
/// binder) that `admit` binds with `{marker: n}`, keeping the original in `saved`.
fn replace(
    doc: &mut Value,
    paths: &[&str],
    marker: &str,
    saved: &mut Vec<Value>,
    admit: Admit<'_>,
) -> Result<(), BindError> {
    let mut seen: Vec<String> = Vec::new();
    let mut refused = None;
    for pattern in paths {
        walk(
            doc,
            &segments(pattern),
            &mut String::new(),
            &mut |at, node| {
                if refused.is_some() || seen.iter().any(|s| s == at) {
                    return;
                }
                seen.push(at.to_owned());
                match admit(at, node) {
                    Ok(true) => {
                        saved.push(node.take());
                        *node = handle(marker, saved.len());
                    }
                    Ok(false) => {}
                    Err(e) => refused = Some(e),
                }
            },
        );
        if let Some(refused) = refused {
            return Err(refused);
        }
    }
    Ok(())
}

/// A D_SECRET_PATH node, as core's binder takes it: null is left as is; under `bind_any` a string is a 1.x
/// literal left in place (for CORE_CFG(LIFT)); an object is a reference; anything else (a literal under `bind`,
/// `""` included) is `NotAReference`.
fn secret_node(at: &str, node: &Value, any: bool) -> Result<bool, BindError> {
    if node.is_null() || (any && node.as_str().is_some()) {
        return Ok(false);
    }
    if node.is_object() {
        return Ok(true);
    }
    Err(BindError::NotAReference { pointer: at.into() })
}

/// A D_TRUST_PATH or D_DEST_PATH node: everything but null binds (this binder parses no PEM and no DestDef).
fn present(_at: &str, node: &Value) -> Result<bool, BindError> {
    Ok(!node.is_null())
}

/// The pointer of the first object that already looks like a bound handle.
fn stray(node: &Value, at: &str) -> Option<String> {
    if let Some(members) = node.as_object() {
        if [SECRET, TRUST, DEST]
            .iter()
            .any(|marker| node.get(*marker).is_some())
        {
            return Some(at.to_owned());
        }
        return members
            .iter()
            .find_map(|(k, v)| stray(v, &format!("{at}/{}", escape(k))));
    }
    node.as_array().and_then(|items| {
        items
            .iter()
            .enumerate()
            .find_map(|(i, v)| stray(v, &format!("{at}/{i}")))
    })
}

/// The original node for a handle object, or None when `node` is not one.
fn original(node: &Value, bound: &Bound, at: &str) -> Result<Option<Value>, BindError> {
    let Some(members) = node.as_object() else {
        return Ok(None);
    };
    if members.len() != 1 {
        return Ok(None);
    }
    for (marker, list) in [
        (SECRET, &bound.secrets),
        (TRUST, &bound.trust),
        (DEST, &bound.dests),
    ] {
        if let Some(n) = node.get(marker).and_then(count) {
            let found = usize::try_from(n)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| list.get(i));
            return match found {
                Some(value) => Ok(Some(value.clone())),
                None => Err(BindError::NotAReference { pointer: at.into() }),
            };
        }
    }
    Ok(None)
}

fn restore(node: &mut Value, at: &str, bound: &Bound) -> Result<(), BindError> {
    if let Some(value) = original(node, bound, at)? {
        *node = value;
        return Ok(());
    }
    if let Some(members) = node.as_object_mut() {
        for (k, v) in members.iter_mut() {
            restore(v, &format!("{at}/{}", escape(k)), bound)?;
        }
    } else if let Some(items) = node.as_array_mut() {
        for (i, v) in items.iter_mut().enumerate() {
            restore(v, &format!("{at}/{i}"), bound)?;
        }
    } else if let Some(s) = node.as_str() {
        if let Some(text) = ref_text(s, at, bound)? {
            *node = text;
        }
    }
    Ok(())
}

impl MemBinder {
    /// `paths` is D_SECRET_PATH, D_TRUST_PATH, D_DEST_PATH, D_REF_PATH; `any` is `bind_any`.
    fn bind_with(
        &self,
        instance: u64,
        config: &[u8],
        paths: [&[&str]; 4],
        any: bool,
    ) -> Result<Vec<u8>, BindError> {
        let mut doc: Value = facade::parse_value(config)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
        if !any {
            if let Some(pointer) = stray(&doc, "") {
                return Err(BindError::StraySecret {
                    pointer: pointer.into(),
                });
            }
        }
        let mut bound = Bound::default();
        replace(
            &mut doc,
            paths[0],
            SECRET,
            &mut bound.secrets,
            &|at, node| secret_node(at, node, any),
        )?;
        replace(&mut doc, paths[1], TRUST, &mut bound.trust, &present)?;
        record_refs(&mut doc, paths[3], &mut bound.refs)?;
        bound.ref_paths = paths[3].iter().map(|p| (*p).to_owned()).collect();
        #[cfg(feature = "target-sockets")]
        let socket_doc = doc.clone();
        // Last, as in core's binder: a dest at `""` is the whole bag.
        replace(&mut doc, paths[2], DEST, &mut bound.dests, &present)?;
        let out = facade::to_vec(&doc).map_err(|_| BindError::TooMany)?;
        #[cfg(feature = "target-sockets")]
        if let Some(needs) = &self.needs {
            if let Some(host) = needs.socket_report() {
                let mut values = crate::sockets::Bindings {
                    trusts: Vec::new(),
                    clients: Vec::new(),
                };
                collect_socket_bindings(&socket_doc, "", &bound, needs, host, &mut values)?;
                needs
                    .bind_sockets(instance, values)
                    .map_err(|_| bad_reference("", "socket trust binding refused"))?;
            }
        }
        self.table().insert(instance, bound);
        Ok(out)
    }

    /// `resolve_refs`, synchronously: every recorded reference's scripted value, as a JSON string, at its pointer.
    fn resolve_now(&self, instance: u64, bound: Vec<u8>) -> Result<SecureVec, BindError> {
        let mut table = self.table();
        let Some(entry) = table
            .get_mut(&instance)
            .filter(|entry| !entry.refs.is_empty())
        else {
            return Ok(SecureVec::from(bound));
        };
        let mut doc: Value = facade::parse_value(&bound)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
        for r in &mut entry.refs {
            let value = self
                .needs
                .as_ref()
                .and_then(|needs| needs.secret_at(&r.pointer))
                .ok_or_else(|| bad_reference(&r.pointer, "could not be resolved"))?;
            let text = String::from_utf8(value).map_err(|_| {
                bad_reference(&r.pointer, "resolved to a value that is not UTF-8 text")
            })?;
            if let Some(slot) = facade::pointer_mut(&mut doc, &r.pointer) {
                *slot = Value::from(text.as_str());
            }
            r.resolved = Some(text);
        }
        facade::to_vec(&doc)
            .map(SecureVec::from)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })
    }
}

impl ConfigBinder for MemBinder {
    fn bind(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        self.bind_with(
            instance,
            config,
            [secret_paths, trust_paths, dest_paths, ref_paths],
            false,
        )
    }

    fn resolve_refs<'a>(
        &'a self,
        instance: u64,
        bound: Vec<u8>,
    ) -> BoxFut<'a, Result<SecureVec, BindError>> {
        Box::pin(std::future::ready(self.resolve_now(instance, bound)))
    }

    fn unbind(&self, instance: u64) {
        #[cfg(feature = "target-sockets")]
        if let Some(needs) = &self.needs {
            needs.unbind_sockets(instance);
        }
        self.table().remove(&instance);
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
        self.bind_with(
            instance,
            config,
            [secret_paths, trust_paths, dest_paths, ref_paths],
            true,
        )
    }

    fn unbind_refs(&self, instance: u64, bound: &[u8]) -> Result<Vec<u8>, BindError> {
        let mut doc: Value = facade::parse_value(bound)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
        {
            let table = self.table();
            let empty = Bound::default();
            restore(&mut doc, "", table.get(&instance).unwrap_or(&empty))?;
        }
        facade::to_vec(&doc).map_err(|_| BindError::TooMany)
    }

    fn secret(
        &self,
        _instance: u64,
        _handle: u32,
    ) -> Option<busbar_contract::secret_ref::SecretRef> {
        None
    }

    fn trust(&self, _instance: u64, _handle: u32) -> Option<Arc<TrustAnchor>> {
        None
    }

    fn unix_path(&self, _instance: u64, _path: &str) -> bool {
        false
    }

    fn dest(&self, _instance: u64, _handle: u32) -> Option<Arc<DestDef>> {
        None
    }
}

// ---------------------------------------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------------------------------------

/// One line a plugin logged (`host.log`), as the registry's log sink attributed and scrubbed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    /// 1 error, 2 warn, 3 info, 4 debug, 5 trace.
    pub level: u32,
    /// The instance's kind code (`KindCode as u32`).
    pub kind: u32,
    /// The configured instance name.
    pub instance: String,
    /// The resolved `BUSBAR-<plugin>-<nnnn>` code, empty when the line named none.
    pub code: String,
    /// The line, after scrubbing every value the instance's scrub set holds (I14).
    pub message: String,
}

/// The shared sink the capture subscriber writes to.
#[derive(Default)]
struct LogBook {
    lines: Mutex<Vec<LogLine>>,
    /// The numbers of the registry's "plugin error number not declared" WARNs (`ErrorBook::resolve`), in order.
    undeclared: Mutex<Vec<u64>>,
    next_span: AtomicU64,
}

/// The message of the registry's one WARN for an error number an image did not declare (PLUGIN-ERROR-CODES §2.5).
const UNDECLARED: &str = "plugin error number not declared";

#[derive(Default)]
struct Fields {
    kind: Option<u64>,
    instance: Option<String>,
    number: Option<u64>,
    code: String,
    message: String,
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "kind" => self.kind = Some(value),
            "number" => self.number = Some(value),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "instance" => self.instance = Some(value.to_owned()),
            "code" => value.clone_into(&mut self.code),
            "message" => value.clone_into(&mut self.message),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

/// The subscriber: it keeps the events the registry's log sink emits (they carry `kind` and `instance`) and the
/// number of each "not declared" WARN the registry writes for an undeclared error number.
struct Tap(Arc<LogBook>);

impl Subscriber for Tap {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(self.0.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let (Some(kind), Some(instance)) = (fields.kind, fields.instance) else {
            if let (Some(number), true) = (fields.number, fields.message == UNDECLARED) {
                self.0
                    .undeclared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(number);
            }
            return;
        };
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => 1,
            tracing::Level::WARN => 2,
            tracing::Level::INFO => 3,
            tracing::Level::DEBUG => 4,
            _ => 5,
        };
        self.0
            .lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(LogLine {
                level,
                kind: u32::try_from(kind).unwrap_or(u32::MAX),
                instance,
                code: fields.code,
                message: fields.message,
            });
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

// ---------------------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------------------

/// One record the plugin holds (RECORD, IF §12.5), in the namespace core gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// The verified plugin identity.
    pub plugin: String,
    /// The configured instance name.
    pub instance: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A plugin image admitted into a test registry, with the runtime that drives its ports.
///
/// Drop order matters and is the field order: the registry and its instances go first, then the runtime, then
/// the log tap.
pub struct Harness {
    registry: Registry<FakeNeeds>,
    needs: Arc<FakeNeeds>,
    binder: Arc<MemBinder>,
    identity: String,
    kind: KindCode,
    refusals: Mutex<Vec<String>>,
    /// Every ENDPOINT a successful `check` declared, in order (the generic match reads them).
    declared: Mutex<Vec<DeclaredEndpoint>>,
    rt: crate::test_rt::TestRuntime,
    logs: Arc<LogBook>,
    _tap: tracing::subscriber::DefaultGuard,
}

impl Harness {
    /// Admit `plugin` (the `&'static Plugin` a plugin crate's `PLUGIN.plugin()` hands the frozen suite
    /// signatures; `LinkedPlugin::plugin`) into a fresh registry over `needs`, the real `HOST` static and a
    /// `MemBinder`, with `Ceilings::DEFAULT`. Admission runs every step `admit_linked` runs (null and stamp
    /// checks, compatibility) and `ImagesBuilder::admit` (describe, name conflicts, error book): a refusal comes back
    /// as it is. Capture of log lines starts here.
    pub fn admit(plugin: &'static Plugin, needs: FakeNeeds) -> Result<Harness, Refusal> {
        Self::start(|| admit_header(plugin).map(|image| vec![image]), needs)
    }

    /// [`Harness::admit`] for a caller that holds the `LinkedPlugin` static itself.
    pub fn admit_linked(
        linked: &'static LinkedPlugin,
        needs: FakeNeeds,
    ) -> Result<Harness, Refusal> {
        Self::start(|| admit_linked(linked).map(|image| vec![image]), needs)
    }

    /// Every image of `plugins` admitted into one registry, in order, as [`Harness::admit`] then
    /// image admission for each further one: the first refusal comes back as it is. [`Harness::identity`] and
    /// [`Harness::kind`] stay the first image's; open another by its word with [`Harness::spec_for`].
    pub fn admit_all(plugins: &[&'static Plugin], needs: FakeNeeds) -> Result<Harness, Refusal> {
        Self::start(
            || plugins.iter().map(|plugin| admit_header(plugin)).collect(),
            needs,
        )
    }

    /// A harness over an image the caller admitted itself (a dropped-in image through the loader's `admit`, or
    /// `busbar_plugin_loader::test_host::admit_bytes`): `ImagesBuilder::admit` and everything [`Harness::admit`] does
    /// after admission.
    pub fn admit_admitted(admitted: Admitted, needs: FakeNeeds) -> Result<Harness, Refusal> {
        Self::start(move || Ok(vec![admitted]), needs)
    }

    fn start(
        admit: impl FnOnce() -> Result<Vec<Admitted>, Refusal>,
        needs: FakeNeeds,
    ) -> Result<Harness, Refusal> {
        let logs = Arc::new(LogBook::default());
        let tap = tracing::subscriber::set_default(Tap(Arc::clone(&logs)));
        let rt = crate::test_rt::TestRuntime::new().map_err(|e| {
            Refusal::new(
                RefusalCode::Integrity,
                "runtime",
                e.to_string(),
                "a test runtime",
            )
        })?;
        let needs = Arc::new(needs);
        let binder = Arc::new(MemBinder::over(Arc::clone(&needs)));
        let admitted = admit()?;
        let first = admitted.first().ok_or_else(|| {
            Refusal::new(
                RefusalCode::Integrity,
                "images",
                "no image",
                "at least one image",
            )
        })?;
        let (identity, kind) = (first.identity().to_owned(), first.kind());
        let slots = Arc::new(SlotTable::new());
        busbar_plugin_loader::instance::install_sinks(&slots);
        let mut images = ImagesBuilder::new(&HOST, slots, Ceilings::DEFAULT);
        for image in admitted {
            images.admit(image)?;
        }
        let registry = Registry::new(
            images.finish(),
            Arc::clone(&needs),
            Arc::clone(&binder) as Arc<dyn ConfigBinder>,
        );

        Ok(Harness {
            registry,
            needs,
            binder,
            identity,
            kind,
            refusals: Mutex::new(Vec::new()),
            declared: Mutex::new(Vec::new()),
            rt,
            logs,
            _tap: tap,
        })
    }

    /// The verified stamp name of the admitted image (what `InstanceSpec::identity` takes).
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The kind the verified stamp names.
    pub fn kind(&self) -> KindCode {
        self.kind
    }

    /// The registry, for what the harness does not wrap (`set_store_seal`, `set_auth_core`, `described`,
    /// `take_settled`, `boot_plan`, `reconfigure`).
    pub fn registry(&self) -> &Registry<FakeNeeds> {
        &self.registry
    }

    /// The `FakeNeeds` the registry runs the plugin under (what it was handed, scripted answers included).
    pub fn needs(&self) -> &FakeNeeds {
        &self.needs
    }

    /// The binder the registry binds every config through.
    pub fn binder(&self) -> &MemBinder {
        &self.binder
    }

    /// Drive any future (a port call) to completion on the harness runtime, on the calling thread.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.rt.block_on(future)
    }

    /// The spec for instance `name` of the admitted image, opened with `config` (operator form, secret
    /// references included) and no limits, no `public_url`, no caller upstreams.
    pub fn spec<'a>(&'a self, name: &'a str, config: &'a [u8]) -> InstanceSpec<'a> {
        self.spec_for(&self.identity, name, config)
    }

    /// [`Harness::spec`] for the image the operator's `module` word names: an admitted identity or one of its
    /// `former_names` words (the registry resolves it), or a word nothing answers to (the open refuses it).
    pub fn spec_for<'a>(
        &'a self,
        module: &'a str,
        name: &'a str,
        config: &'a [u8],
    ) -> InstanceSpec<'a> {
        InstanceSpec {
            purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
            identity: module,
            name,
            config_json: config,
            limits: InstanceLimits::default(),
            public_url: None,
            caller_upstreams: &[],
        }
    }

    fn noted<T>(&self, answer: Result<T, OpenError>) -> Result<T, OpenError> {
        if let Err(e) = &answer {
            self.refusals
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(format!("{e:?}"));
        }
        answer
    }

    /// DRY_RUN open (`--validate`): bind, `check`, no instance kept. The ENDPOINTs the answer declared are kept
    /// for the generic match ([`Harness::undeclared`]).
    pub fn check(&self, name: &str, config: &[u8]) -> Result<(), OpenError> {
        let spec = self.spec(name, config);
        self.check_spec(&spec)
    }

    /// The typed store facade supplies limits without bypassing endpoint or refusal observations.
    pub(crate) fn check_spec(&self, spec: &InstanceSpec<'_>) -> Result<(), OpenError> {
        let declared = self.noted(self.block_on(self.registry.check_endpoints(spec)))?;
        self.declared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(declared);
        Ok(())
    }

    /// Every ENDPOINT a successful [`Harness::check`] declared so far, in order.
    pub fn declared(&self) -> Vec<DeclaredEndpoint> {
        self.declared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The generic ENDPOINT match (TRANSPORT-SECURITY-POLICY §2): every OPEN or FETCH the plugin made whose
    /// (host, TLS) is not among the ENDPOINTs its successful checks declared.
    pub fn undeclared(&self) -> Vec<Seen> {
        let declared = self.declared.lock().unwrap_or_else(PoisonError::into_inner);
        self.needs.undeclared(&endpoint_pairs(&declared))
    }

    /// Panics, naming `suite`, when [`Harness::undeclared`] is not empty: every Need a suite drove must match an
    /// ENDPOINT the plugin's `check` declared for the same config.
    pub fn assert_needs_declared(&self, suite: &str) {
        let undeclared = self.undeclared();
        assert!(
            undeclared.is_empty(),
            "{suite} suite: needs the plugin's check did not declare as an ENDPOINT (TRANSPORT-SECURITY-POLICY §2): {undeclared:?}; declared: {:?}",
            self.declared()
        );
    }

    /// Open the instance as its kind and return the typed port.
    pub fn open(&self, name: &str, config: &[u8]) -> Result<OpenedPort, OpenError> {
        match self.kind {
            KindCode::Store => self.open_store(name, config).map(OpenedPort::Store),
            KindCode::Secret => self.open_secret(name, config).map(OpenedPort::Secret),
            KindCode::Auth => self.open_auth(name, config).map(OpenedPort::Auth),
            KindCode::Hook => self.open_hook(name, config).map(OpenedPort::Hook),
            KindCode::Export => self.open_export(name, config).map(OpenedPort::Export),
            KindCode::Plane => self.open_plane(name, config).map(OpenedPort::Plane),
            KindCode::Transport => self.open_transport(name, config).map(OpenedPort::Transport),
        }
    }

    /// Open an unstamped legacy bag; CONFIG is required even when its contents are unchanged.
    pub fn open_converting(&self, name: &str, config: &[u8]) -> Result<OpenedPort, OpenError> {
        let mut spec = self.spec(name, config);
        spec.purpose = busbar_plugin_loader::instance::OpenPurpose::ConvertUnstamped;
        self.noted(self.block_on(async {
            match self.kind {
                KindCode::Store => self.registry.open_store(&spec).await.map(OpenedPort::Store),
                KindCode::Secret => self
                    .registry
                    .open_secret(&spec)
                    .await
                    .map(OpenedPort::Secret),
                KindCode::Auth => self.registry.open_auth(&spec).await.map(OpenedPort::Auth),
                KindCode::Hook => self.registry.open_hook(&spec).await.map(OpenedPort::Hook),
                KindCode::Export => self
                    .registry
                    .open_export(&spec)
                    .await
                    .map(OpenedPort::Export),
                KindCode::Plane => self.registry.open_plane(&spec).await.map(OpenedPort::Plane),
                KindCode::Transport => self
                    .registry
                    .open_transport(&spec)
                    .await
                    .map(OpenedPort::Transport),
            }
        }))
    }

    /// A store needs `registry().set_store_seal(..)` first (the kernel's seal factory).
    pub fn open_store(&self, name: &str, config: &[u8]) -> Result<StoreHandle, OpenError> {
        let spec = self.spec(name, config);
        self.open_store_spec(&spec)
    }

    /// Open with an explicit spec through the same refusal recorder as the ordinary harness.
    pub(crate) fn open_store_spec(
        &self,
        spec: &InstanceSpec<'_>,
    ) -> Result<StoreHandle, OpenError> {
        self.noted(self.block_on(self.registry.open_store(spec)))
    }

    pub fn open_secret(&self, name: &str, config: &[u8]) -> Result<Arc<dyn SecretPort>, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_secret(&spec)))
    }

    /// An auth instance needs `registry().set_auth_core(..)` first.
    pub fn open_auth(&self, name: &str, config: &[u8]) -> Result<Arc<dyn AuthPort>, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_auth(&spec)))
    }

    pub fn open_hook(&self, name: &str, config: &[u8]) -> Result<Arc<dyn HookPort>, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_hook(&spec)))
    }

    pub fn open_export(&self, name: &str, config: &[u8]) -> Result<Arc<dyn ExportPort>, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_export(&spec)))
    }

    pub fn open_plane(&self, name: &str, config: &[u8]) -> Result<Arc<dyn PlanePort>, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_plane(&spec)))
    }

    pub fn open_transport(
        &self,
        name: &str,
        config: &[u8],
    ) -> Result<Arc<dyn TransportPort>, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_transport(&spec)))
    }

    /// The settled answer of instance `name`'s last `open`, once (`Registry::take_settled`).
    pub fn settled(&self, name: &str) -> Option<Settled> {
        self.registry.take_settled(name)
    }

    /// Every line the plugin logged since the harness was built, in order.
    pub fn logs(&self) -> Vec<LogLine> {
        self.logs
            .lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The log lines, emptied.
    pub fn take_logs(&self) -> Vec<LogLine> {
        std::mem::take(
            &mut *self
                .logs
                .lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Every error number the registry found undeclared since the harness was built (an ERROR record or a `log`
    /// number the image's D_ERRORS does not hold, or one over 9999), once per instance, in order: the number of
    /// each "plugin error number not declared" WARN.
    pub fn undeclared(&self) -> Vec<u64> {
        self.logs
            .undeclared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every record the plugin holds through RECORD, in key order.
    pub fn records(&self) -> Vec<StoredRecord> {
        self.needs
            .records()
            .into_iter()
            .map(|(plugin, instance, key, value)| StoredRecord {
                plugin,
                instance,
                key,
                value,
            })
            .collect()
    }

    /// Every OPEN and FETCH the plugin made, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.needs.seen()
    }

    /// Every open or check that failed, as its `Debug` text, in order (the refusals a suite asserted on or
    /// must account for).
    pub fn refusals(&self) -> Vec<String> {
        self.refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Each declared ENDPOINT as the (dest, TLS) pair `FakeNeeds::undeclared` matches on: TLS when its `NeedRec.flags`
/// TLS bits ask for any TLS mode (TLS_INBAND included: the conn is upgraded in band) or its dest is an `https:` URL.
fn endpoint_pairs(declared: &[DeclaredEndpoint]) -> Vec<(&str, bool)> {
    declared
        .iter()
        .map(|ep| {
            let tls = (ep.flags & need_flag::TLS_MASK) != need_flag::TLS_NONE
                || ep.dest.starts_with("https://");
            (&*ep.dest, tls)
        })
        .collect()
}

/// The core refusal an open answered, when core (not the plugin) refused.
pub fn core_refusal(error: &OpenError) -> Option<&Refusal> {
    match error {
        OpenError::Refused { refusal, .. } => Some(refusal),
        _ => None,
    }
}

/// The status code a plugin's `open` answered: the REFUSED code of `Refused`'s plugin form is
/// [`plugin_code`]; `Config` and `Failed` carry the numeric code here.
pub fn status_code(error: &OpenError) -> Option<u32> {
    match error {
        OpenError::Config { code, .. } | OpenError::Failed { code, .. } => Some(*code),
        _ => None,
    }
}

/// The resolved `BUSBAR-<plugin>-<nnnn>` code of the plugin's ERROR record, when it named a declared one.
pub fn plugin_code(error: &OpenError) -> Option<PluginCode> {
    match error {
        OpenError::Refused { error, .. }
        | OpenError::Config { error, .. }
        | OpenError::Failed { error, .. } => *error,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_are_matched_against_the_endpoints_check_declared() {
        use busbar_plugin_abi::need::{need_flag, op};
        use busbar_plugin_loader::instance::DeclaredEndpoint;
        let declared = [
            DeclaredEndpoint {
                op: op::OPEN,
                flags: need_flag::TLS_REQUIRED,
                dest: "db.test:5432".into(),
            },
            DeclaredEndpoint {
                op: op::OPEN,
                flags: need_flag::TLS_INBAND,
                dest: "pg.test:5432".into(),
            },
            DeclaredEndpoint {
                op: op::FETCH,
                flags: need_flag::TLS_NONE,
                dest: "https://api.test/v1".into(),
            },
            DeclaredEndpoint {
                op: op::OPEN,
                flags: need_flag::TLS_NONE,
                dest: "cache.test:6379".into(),
            },
        ];
        assert_eq!(
            endpoint_pairs(&declared),
            [
                ("db.test:5432", true),
                ("pg.test:5432", true),
                ("https://api.test/v1", true),
                ("cache.test:6379", false),
            ]
        );
        let needs = FakeNeeds::default();
        assert!(
            needs.undeclared(&endpoint_pairs(&declared)).is_empty(),
            "no Need was made, so none is undeclared"
        );
    }

    #[test]
    fn bind_numbers_handles_from_one_in_pointer_order_and_unbind_restores() {
        let binder = MemBinder::new();
        let config = br#"{"a":{"k":{"env":"s1"}},"list":[{"v":{"env":"s2"}},{"v":{"env":"s3"}}],"keep":"x"}"#;
        let bound = binder
            .bind(7, config, &["/a/k", "/list/*/v"], &[], &[], &[])
            .unwrap();
        let doc: Value = facade::parse_value(&bound).unwrap();
        let handle_of = |path: &[&str]| {
            let mut node = &doc;
            for seg in path {
                node = match seg.parse::<usize>() {
                    Ok(i) => node.get(i),
                    Err(_) => node.get(*seg),
                }
                .unwrap();
            }
            count(node)
        };
        assert_eq!(handle_of(&["a", "k", "$secret"]), Some(1));
        assert_eq!(handle_of(&["list", "0", "v", "$secret"]), Some(2));
        assert_eq!(handle_of(&["list", "1", "v", "$secret"]), Some(3));
        assert_eq!(doc.get("keep").and_then(|v| v.as_str()), Some("x"));
        let back = binder.unbind_refs(7, &bound).unwrap();
        // Unbinding restores every value where it was (a re-serialised tree need not keep the member order).
        let restored: Value = facade::parse_value(&back).unwrap();
        let text = |path: &[&str]| {
            let mut node = &restored;
            for seg in path {
                node = match seg.parse::<usize>() {
                    Ok(i) => node.get(i),
                    Err(_) => node.get(*seg),
                }
                .unwrap();
            }
            node.as_str().map(str::to_owned)
        };
        assert_eq!(text(&["a", "k", "env"]).as_deref(), Some("s1"));
        assert_eq!(text(&["list", "0", "v", "env"]).as_deref(), Some("s2"));
        assert_eq!(text(&["list", "1", "v", "env"]).as_deref(), Some("s3"));
        assert_eq!(text(&["keep"]).as_deref(), Some("x"));
        assert_eq!(restored.as_object().map(|o| o.len()), Some(3));
    }

    /// `resolve_refs` on the harness runtime, as the registry drives it before `check` and `open`.
    fn resolved(binder: &MemBinder, instance: u64, bound: Vec<u8>) -> Result<Vec<u8>, BindError> {
        let rt = crate::test_rt::TestRuntime::new().unwrap();
        rt.block_on(binder.resolve_refs(instance, bound))
            .map(SecureVec::into_vec)
    }

    fn text_at(doc: &Value, at: &str) -> Option<String> {
        facade::pointer(doc, at)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    }

    #[test]
    fn resolve_refs_writes_the_scripted_value_at_each_ref_path_and_unbind_restores() {
        let mut needs = FakeNeeds::new();
        needs.secret("/token", b"the-token");
        needs.secret("/list/1/v", b"second");
        let binder = MemBinder::over(Arc::new(needs));
        let config =
            br#"{"token":{"env":"T"},"list":[{"v":"plain"},{"v":{"env":"V"}}],"keep":"x"}"#;
        let bound = binder
            .bind(3, config, &[], &[], &[], &["/token", "/list/*/v"])
            .unwrap();
        // `bind` leaves a reference in place until `resolve_refs`.
        let doc: Value = facade::parse_value(&bound).unwrap();
        assert_eq!(text_at(&doc, "/token/env").as_deref(), Some("T"));
        let resolved = resolved(&binder, 3, bound).unwrap();
        let doc: Value = facade::parse_value(&resolved).unwrap();
        assert_eq!(text_at(&doc, "/token").as_deref(), Some("the-token"));
        assert_eq!(text_at(&doc, "/list/0/v").as_deref(), Some("plain"));
        assert_eq!(text_at(&doc, "/list/1/v").as_deref(), Some("second"));
        assert_eq!(text_at(&doc, "/keep").as_deref(), Some("x"));
        let back = binder.unbind_refs(3, &resolved).unwrap();
        let restored: Value = facade::parse_value(&back).unwrap();
        assert_eq!(text_at(&restored, "/token/env").as_deref(), Some("T"));
        assert_eq!(text_at(&restored, "/list/0/v").as_deref(), Some("plain"));
        assert_eq!(text_at(&restored, "/list/1/v/env").as_deref(), Some("V"));
        assert_eq!(text_at(&restored, "/keep").as_deref(), Some("x"));
        // A resolved value anywhere no ref path names is never written back.
        let err = binder
            .unbind_refs(3, br#"{"elsewhere":"the-token"}"#)
            .unwrap_err();
        assert!(matches!(err, BindError::NotAReference { .. }));
    }

    #[test]
    fn a_ref_with_no_scripted_value_is_refused_as_a_bad_reference() {
        let binder = MemBinder::new();
        let bound = binder
            .bind(4, br#"{"token":{"env":"T"}}"#, &[], &[], &[], &["/token"])
            .unwrap();
        let err = resolved(&binder, 4, bound).unwrap_err();
        assert!(
            matches!(&err, BindError::BadReference { pointer, .. } if &**pointer == "/token"),
            "{err:?}"
        );
        // A plain string at a ref path is left as is; a node that is neither is not a reference.
        let bound = binder
            .bind(5, br#"{"token":"plain"}"#, &[], &[], &[], &["/token"])
            .unwrap();
        let doc: Value = facade::parse_value(&resolved(&binder, 5, bound).unwrap()).unwrap();
        assert_eq!(text_at(&doc, "/token").as_deref(), Some("plain"));
        let err = binder
            .bind(6, br#"{"token":7}"#, &[], &[], &[], &["/token"])
            .unwrap_err();
        assert!(matches!(err, BindError::NotAReference { .. }));
    }

    #[test]
    fn an_empty_pointer_binds_the_whole_document() {
        let binder = MemBinder::new();
        let config = br#"{"path":"/var/log/busbar.jsonl","keep":3}"#;
        let bound = binder.bind(8, config, &[], &[], &[""], &[]).unwrap();
        let doc: Value = facade::parse_value(&bound).unwrap();
        assert_eq!(doc.get(DEST).and_then(count), Some(1));
        assert_eq!(doc.as_object().map(|o| o.len()), Some(1));
        let back = binder.unbind_refs(8, &bound).unwrap();
        let restored: Value = facade::parse_value(&back).unwrap();
        assert_eq!(
            text_at(&restored, "/path").as_deref(),
            Some("/var/log/busbar.jsonl")
        );
        assert_eq!(restored.get("keep").and_then(count), Some(3));
    }

    #[test]
    fn a_handle_shaped_node_off_a_declared_path_is_a_stray_secret() {
        let binder = MemBinder::new();
        let err = binder
            .bind(1, br#"{"x":{"$secret":1}}"#, &["/y"], &[], &[], &[])
            .unwrap_err();
        assert!(matches!(err, BindError::StraySecret { .. }));
    }

    #[test]
    fn a_handle_the_instance_never_bound_is_not_a_reference() {
        let binder = MemBinder::new();
        binder
            .bind(1, br#"{"a":{"env":"s"}}"#, &["/a"], &[], &[], &[])
            .unwrap();
        let err = binder
            .unbind_refs(1, br#"{"a":{"$secret":9}}"#)
            .unwrap_err();
        assert!(matches!(err, BindError::NotAReference { .. }));
    }

    #[test]
    fn a_literal_at_a_secret_path_is_refused_by_bind_and_left_in_place_by_bind_any() {
        let binder = MemBinder::new();
        for config in [&br#"{"token":"1x-literal"}"#[..], br#"{"token":""}"#] {
            let err = binder
                .bind(9, config, &["/token"], &[], &[], &[])
                .unwrap_err();
            assert!(
                matches!(&err, BindError::NotAReference { pointer } if &**pointer == "/token"),
                "{err:?}"
            );
        }
        let config = br#"{"token":"","old":"1x-literal","new":{"env":"K"}}"#;
        let bound = binder
            .bind_any(10, config, &["/token", "/old", "/new"], &[], &[], &[])
            .unwrap();
        let doc: Value = facade::parse_value(&bound).unwrap();
        assert_eq!(text_at(&doc, "/token").as_deref(), Some(""));
        assert_eq!(text_at(&doc, "/old").as_deref(), Some("1x-literal"));
        assert_eq!(
            doc.get("new").and_then(|v| v.get(SECRET)).and_then(count),
            Some(1)
        );
        let err = binder
            .bind(11, br#"{"token":7}"#, &["/token"], &[], &[], &[])
            .unwrap_err();
        assert!(matches!(err, BindError::NotAReference { .. }));
    }
}

#[cfg(feature = "target-sockets")]
fn collect_socket_bindings(
    node: &Value,
    at: &str,
    bound: &Bound,
    needs: &FakeNeeds,
    host: &crate::sockets::SocketTargets,
    out: &mut crate::sockets::Bindings,
) -> Result<(), BindError> {
    if let Some(handle) = node.get(TRUST).and_then(count) {
        if host.wants_trust(at) {
            let index = usize::try_from(handle)
                .ok()
                .and_then(|h| h.checked_sub(1))
                .ok_or(BindError::TooMany)?;
            let pem = bound
                .trust
                .get(index)
                .and_then(JsonValueTrait::as_str)
                .ok_or_else(|| bad_reference(at, "socket trust must be PEM text"))?;
            out.trusts.push((
                at.to_owned(),
                u32::try_from(handle).map_err(|_| BindError::TooMany)?,
                pem.to_owned(),
            ));
        }
        return Ok(());
    }
    if let Some(handle) = node.get(SECRET).and_then(count) {
        if host.wants_client(at) {
            let pem = needs
                .secret_at(at)
                .ok_or_else(|| bad_reference(at, "socket client identity is not scripted"))?;
            out.clients.push((
                at.to_owned(),
                u32::try_from(handle).map_err(|_| BindError::TooMany)?,
                SecureVec::from(pem),
            ));
        }
        return Ok(());
    }
    if let Some(members) = node.as_object() {
        for (key, value) in members.iter() {
            collect_socket_bindings(
                value,
                &format!("{at}/{}", escape(key)),
                bound,
                needs,
                host,
                out,
            )?;
        }
    } else if let Some(items) = node.as_array() {
        for (index, value) in items.iter().enumerate() {
            collect_socket_bindings(value, &format!("{at}/{index}"), bound, needs, host, out)?;
        }
    }
    Ok(())
}
