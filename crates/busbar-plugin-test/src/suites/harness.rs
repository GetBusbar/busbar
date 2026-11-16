// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared suite harness (IF §14, MIN3 SDK suites). It admits a plugin image into a
//! `Registry<FakeNeeds>` over the real `HOST` static and a [`MemBinder`], opens instances with given
//! settings, hands back the kind's port to drive, and collects what the plugin did: the records it wrote
//! (RECORD), the OPEN/FETCH needs it made, the log lines it emitted and every refusal an open answered.
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
use busbar_plugin_abi::plugin::__rt::LinkedPlugin;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::admit::{admit_header, admit_linked, Admitted};
use busbar_plugin_loader::binder::{BindError, ConfigBinder, DestDef, TrustAnchor};
use busbar_plugin_loader::instance::{
    Ceilings, InstanceSpec, OpenError, OpenedPort, PluginCode, Registry, Settled,
};
use busbar_plugin_loader::ports::auth::AuthPort;
use busbar_plugin_loader::ports::export::ExportPort;
use busbar_plugin_loader::ports::hook::HookPort;
use busbar_plugin_loader::ports::plane::PlanePort;
use busbar_plugin_loader::ports::secret::SecretPort;
use busbar_plugin_loader::ports::store::StoreHandle;
use busbar_plugin_loader::ports::transport::TransportPort;
use busbar_plugin_loader::refusal::{Refusal, RefusalCode};
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
}

/// The suites' in-memory `ConfigBinder`. `bind` and `bind_any` replace the node at every declared
/// D_SECRET_PATH, D_TRUST_PATH and D_DEST_PATH pointer (a `*` segment matches every array element or object
/// member, in order) with `{"$secret": n}`, `{"$trust": n}` or `{"$dest": n}`, numbering each family from 1 in
/// pointer order, so the plugin only ever sees handles. Values come from `FakeNeeds::secret` in the same order.
/// `unbind_refs` writes the operator's original node back. It parses no reference grammar (that is core's
/// binder, covered by its own tests): `secret`, `trust`, `dest` answer None and `unix_path` is false.
#[derive(Default)]
pub struct MemBinder {
    bound: Mutex<HashMap<u64, Bound>>,
}

impl MemBinder {
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self) -> MutexGuard<'_, HashMap<u64, Bound>> {
        self.bound.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Hand `f` every node the pointer pattern `segs` names in `node` (`*` is every element of an array, or of an
/// object in key order; a missing path names nothing).
fn walk(node: &mut Value, segs: &[&str], f: &mut dyn FnMut(&mut Value)) {
    let Some((seg, rest)) = segs.split_first() else {
        f(node);
        return;
    };
    if *seg == "*" {
        if let Some(items) = node.as_array_mut() {
            for item in items.iter_mut() {
                walk(item, rest, f);
            }
        } else if let Some(members) = node.as_object_mut() {
            let mut keys: Vec<String> = members.iter().map(|(k, _)| k.to_owned()).collect();
            keys.sort();
            for key in keys {
                if let Some(child) = node.get_mut(key.as_str()) {
                    walk(child, rest, f);
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
        walk(child, rest, f);
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

/// Replace every node the `paths` name with `{marker: n}`, keeping the original in `saved`.
fn replace(doc: &mut Value, paths: &[&str], marker: &str, saved: &mut Vec<Value>) {
    for pattern in paths {
        if pattern.is_empty() {
            continue;
        }
        let segs: Vec<&str> = pattern.split('/').skip(1).collect();
        walk(doc, &segs, &mut |node| {
            if node.is_null() {
                return;
            }
            saved.push(node.take());
            *node = handle(marker, saved.len());
        });
    }
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
    }
    Ok(())
}

impl MemBinder {
    fn bind_with(
        &self,
        instance: u64,
        config: &[u8],
        paths: [&[&str]; 3],
        strict: bool,
    ) -> Result<Vec<u8>, BindError> {
        let mut doc: Value = facade::parse_value(config)
            .map_err(|_| BindError::NotAReference { pointer: "".into() })?;
        if strict {
            if let Some(pointer) = stray(&doc, "") {
                return Err(BindError::StraySecret {
                    pointer: pointer.into(),
                });
            }
        }
        let mut bound = Bound::default();
        replace(&mut doc, paths[0], SECRET, &mut bound.secrets);
        replace(&mut doc, paths[1], TRUST, &mut bound.trust);
        replace(&mut doc, paths[2], DEST, &mut bound.dests);
        let out = facade::to_vec(&doc).map_err(|_| BindError::TooMany)?;
        self.table().insert(instance, bound);
        Ok(out)
    }
}

impl ConfigBinder for MemBinder {
    fn set_sugars(&self, _sugars: Arc<busbar_contract::secret_ref::Sugars>) {}

    fn set_ref_schemas(&self, _schemas: Vec<(Arc<str>, Box<str>)>) {}

    fn bind(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        _ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        self.bind_with(
            instance,
            config,
            [secret_paths, trust_paths, dest_paths],
            true,
        )
    }

    fn resolve_refs<'a>(
        &'a self,
        _instance: u64,
        bound: Vec<u8>,
    ) -> BoxFut<'a, Result<SecureVec, BindError>> {
        Box::pin(std::future::ready(Ok(SecureVec::from(bound))))
    }

    fn unbind(&self, instance: u64) {
        self.table().remove(&instance);
    }

    fn bind_any(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        _ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError> {
        self.bind_with(
            instance,
            config,
            [secret_paths, trust_paths, dest_paths],
            false,
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
    next_span: AtomicU64,
}

#[derive(Default)]
struct Fields {
    kind: Option<u64>,
    instance: Option<String>,
    code: String,
    message: String,
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "kind" {
            self.kind = Some(value);
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

/// The subscriber: it keeps only the events the registry's log sink emits (they carry `kind` and `instance`).
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
    rt: crate::test_rt::TestRuntime,
    logs: Arc<LogBook>,
    _tap: tracing::subscriber::DefaultGuard,
}

impl Harness {
    /// Admit `plugin` (the `&'static Plugin` a plugin crate's `PLUGIN.plugin()` hands the frozen suite
    /// signatures; `LinkedPlugin::plugin`) into a fresh registry over `needs`, the real `HOST` static and a
    /// `MemBinder`, with `Ceilings::DEFAULT`. Admission runs every step `admit_linked` runs (null and stamp
    /// checks, compatibility) and `Registry::add` (describe, name conflicts, error book): a refusal comes back
    /// as it is. Capture of log lines starts here.
    pub fn admit(plugin: &'static Plugin, needs: FakeNeeds) -> Result<Harness, Refusal> {
        Self::start(|| admit_header(plugin), needs)
    }

    /// [`Harness::admit`] for a caller that holds the `LinkedPlugin` static itself.
    pub fn admit_linked(
        linked: &'static LinkedPlugin,
        needs: FakeNeeds,
    ) -> Result<Harness, Refusal> {
        Self::start(|| admit_linked(linked), needs)
    }

    fn start(
        admit: impl FnOnce() -> Result<Admitted, Refusal>,
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
        let binder = Arc::new(MemBinder::new());
        let mut registry = Registry::new(
            &HOST,
            Arc::clone(&needs),
            Arc::clone(&binder) as Arc<dyn ConfigBinder>,
            Ceilings::DEFAULT,
        );
        let admitted = admit()?;
        let (identity, kind) = (admitted.identity().to_owned(), admitted.kind());
        registry.add(admitted)?;
        Ok(Harness {
            registry,
            needs,
            binder,
            identity,
            kind,
            refusals: Mutex::new(Vec::new()),
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
        InstanceSpec {
            identity: &self.identity,
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

    /// DRY_RUN open (`--validate`): bind, `check`, no instance kept.
    pub fn check(&self, name: &str, config: &[u8]) -> Result<(), OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.check(&spec)))
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

    /// A store needs `registry().set_store_seal(..)` first (the kernel's seal factory).
    pub fn open_store(&self, name: &str, config: &[u8]) -> Result<StoreHandle, OpenError> {
        let spec = self.spec(name, config);
        self.noted(self.block_on(self.registry.open_store(&spec)))
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
        let config = br#"{"a":{"k":"s1"},"list":[{"v":"s2"},{"v":"s3"}],"keep":"x"}"#;
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
        assert_eq!(text(&["a", "k"]).as_deref(), Some("s1"));
        assert_eq!(text(&["list", "0", "v"]).as_deref(), Some("s2"));
        assert_eq!(text(&["list", "1", "v"]).as_deref(), Some("s3"));
        assert_eq!(text(&["keep"]).as_deref(), Some("x"));
        assert_eq!(restored.as_object().map(|o| o.len()), Some(3));
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
            .bind(1, br#"{"a":"s"}"#, &["/a"], &[], &[], &[])
            .unwrap();
        let err = binder
            .unbind_refs(1, br#"{"a":{"$secret":9}}"#)
            .unwrap_err();
        assert!(matches!(err, BindError::NotAReference { .. }));
    }
}
