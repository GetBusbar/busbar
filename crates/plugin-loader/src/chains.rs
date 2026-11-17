// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry's chains (IF §11.2): the describe decode `add` runs, the generic `open` and DRY_RUN chains every
//! `open_<kind>` and `check_endpoints` share, the boot order `boot_plan` computes and the config merge
//! `reconfigure` applies. W1-L2. The kind-specific part of an open (its port) stays in `instance.rs`.
//!
//! Every plugin entry here runs inline under `entry::guard` (describe) or through the driver (every open step,
//! which takes the same guard per step), on the thread that polls the future (I10, §10.7).

use core::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::json::{
    self, JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait as _,
};
use busbar_contract::secure::SecureVec;
use busbar_ffi::image::Admitted as Header;
use busbar_ffi::Kind;
use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::{Answer, OwnedAnswer};
use busbar_plugin_abi::host_side::caller::{CallStack, Caller};
use busbar_plugin_abi::host_side::driver::{
    Driver, Finished, Image, Instance, InstanceParts, NeedRow,
};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::needs::{
    ConnId, DirNeed, FetchNeed, NeedErr, NeedOut, OpenNeed, RecordNeed, TlsMode,
};

/// DRY_RUN never receives a serving capability or performs I/O.
pub(crate) struct DeniedNeeds;
pub(crate) struct DeniedRefs;
impl busbar_ports::binder::RefSource for DeniedRefs {
    fn resolve<'a>(
        &'a self,
        _: u64,
        _: u32,
        _: u32,
        _: &'a busbar_contract::secret_ref::SecretRef,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Option<SecureVec>> {
        Box::pin(async { None })
    }
}
impl Needs for DeniedNeeds {
    async fn open(
        &self,
        _cx: &Caller<'_>,
        _n: OpenNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn starttls(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _tls: TlsMode<'_>,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn write(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _bytes: &[u8],
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn read(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _max: u32,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn close(&self, _cx: &Caller<'_>, _c: ConnId, _reusable: bool) {}
    async fn fetch(
        &self,
        _cx: &Caller<'_>,
        _n: FetchNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn secret(
        &self,
        _cx: &Caller<'_>,
        _handle: u32,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn record(
        &self,
        _cx: &Caller<'_>,
        _n: RecordNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    async fn directory(
        &self,
        _cx: &Caller<'_>,
        _n: DirNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        Err(NeedErr::Denied)
    }
    fn release(&self, _cx: &Caller<'_>) {}
}

use busbar_plugin_abi::host_side::pool::Pool;
use busbar_plugin_abi::host_side::watch::ENTRY_OPEN;
use busbar_plugin_abi::records::{
    tag, CoreCfgRec, MaskRec, MetricDecl, Rec, RecErr, Records, Reply, U64Rec, Writer,
};
use busbar_plugin_abi::types::{KindCode, Status};

use crate::answer::{open_error, port_error};
use crate::instance::{
    BootPhase, CoreCfg, Described, ErrorBook, InstanceSpec, MetricInfo, OpenError, OpenPurpose,
    Registry, Settled, SlotLease,
};
use crate::refusal::{Refusal, RefusalCode};
use busbar_ports::binder::{BindError, ConfigBinder, RefSource};
use busbar_ports::codec::settled::{for_purpose, settled_limits};

/// An `open` chain may run this long end to end (its NEEDs included): the first poll is bounded by the §10.6
/// ceiling, the rest by the Need handlers' own timeouts and the step cap.
const OPEN_DEADLINE: Duration = Duration::from_secs(3_600);
/// The smallest out buffer an instance may be given (a FAIL record always fits, §3.2).
const MAX_OUT_FLOOR: usize = 4_096;

/// The kind's method mask and its REQUIRED methods.
fn kind_masks(kind: KindCode) -> (u64, u64) {
    use busbar_plugin_abi::kinds as k;
    match kind {
        KindCode::Store => (k::store::store::ALL, k::store::store::REQUIRED),
        KindCode::Secret => (k::secret::secret::ALL, k::secret::secret::REQUIRED),
        KindCode::Auth => (k::auth::auth::ALL, k::auth::auth::REQUIRED),
        KindCode::Hook => (k::hook::hook::ALL, k::hook::hook::REQUIRED),
        KindCode::Export => (k::export::export::ALL, k::export::export::REQUIRED),
        KindCode::Plane => (k::plane::plane::ALL, k::plane::plane::REQUIRED),
        KindCode::Transport => (
            k::transport::transport::ALL,
            k::transport::transport::REQUIRED,
        ),
    }
}

fn invalid(field: &'static str, have: impl Into<String>, want: &str) -> Refusal {
    Refusal::new(RefusalCode::DescribeInvalid, field, have, want)
}

/// `[a-z_][a-z0-9_]{0,63}`.
fn metric_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn decode_metric(rec: &Rec<'_>, seen: &[MetricInfo]) -> Result<MetricInfo, Refusal> {
    let bad = |have: &str| {
        invalid(
            "describe.metric",
            have,
            "MX_COUNTER, MX_GAUGE or MX_SUMMARY, a name [a-z_][a-z0-9_]{0,63}, help, at most 8 label keys",
        )
    };
    let (head, tail) = rec
        .pod_tail::<MetricDecl>()
        .map_err(|_| bad("short record"))?;
    if !(1..=3).contains(&head.kind) || seen.iter().any(|m| m.id == head.id) {
        return Err(bad("kind or id"));
    }
    let mut texts = Records::new(tail);
    let mut next = || -> Result<&str, Refusal> {
        match texts.next() {
            Some(Ok(r)) if r.tag == tag::TEXT => r.text().map_err(|_| bad("text")),
            _ => Err(bad("tail")),
        }
    };
    let name = next()?;
    let help = next()?;
    if !metric_name_ok(name) {
        return Err(bad("name"));
    }
    let mut label_keys: Vec<Box<str>> = Vec::new();
    for rec in texts {
        let rec = rec.map_err(|_| bad("tail"))?;
        if rec.tag != tag::TEXT || label_keys.len() == 8 {
            return Err(bad("label keys"));
        }
        label_keys.push(rec.text().map_err(|_| bad("label key"))?.into());
    }
    Ok(MetricInfo {
        id: head.id,
        kind: head.kind,
        name: name.into(),
        help: help.into(),
        label_keys,
    })
}

/// §8 / §11.2 `add`: the describe answer's items as `Described`, checked against the kind the stamp names. The
/// generic items (D_METHODS, D_FACTS, D_SCHEMA, D_METRIC) are decoded; every item is also kept in `items`, in
/// answer order, for the kind decoders and the path lists. A missing or oversized method mask, a method bit the
/// kind does not have (CapUnknown) and a missing REQUIRED method are refused here; D_ERRORS and D_CEILING are
/// judged by `admit_described`.
pub(crate) fn decode_described(
    kind: KindCode,
    describe: Records<'_>,
) -> Result<Described, Refusal> {
    let (all, required) = kind_masks(kind);
    let (mut methods, mut facts, mut schema) = (None, None, None);
    let mut metrics: Vec<MetricInfo> = Vec::new();
    let mut items = Vec::new();
    for rec in describe {
        let rec =
            rec.map_err(|_| invalid("describe", "a malformed record", "a well-formed frame"))?;
        match rec.tag {
            tag::D_METHODS | tag::D_FACTS => {
                let mask = rec
                    .pod::<MaskRec>()
                    .map_err(|_| invalid("describe.methods", "a short mask", "one MaskRec"))?
                    .mask;
                let slot = if rec.tag == tag::D_METHODS {
                    &mut methods
                } else {
                    &mut facts
                };
                if slot.replace(mask).is_some() {
                    return Err(invalid("describe.methods", "a second mask", "at most one"));
                }
            }
            tag::D_SCHEMA => {
                // IF r29 l.2764: core's D_SCHEMA validator holds the schema to the authoritative-schema rules.
                let text = crate::settings_schema::authoritative_schema(rec.body, "D_SCHEMA")
                    .map_err(|why| {
                        invalid(
                            "describe.schema",
                            why,
                            "a JSON Schema object or boolean of at most 262144 bytes",
                        )
                    })?;
                if schema.replace(Box::<str>::from(text)).is_some() {
                    return Err(invalid("describe.schema", "a second schema", "at most one"));
                }
            }
            tag::D_METRIC => {
                let metric = decode_metric(&rec, &metrics)?;
                metrics.push(metric);
            }
            _ => {}
        }
        items.push((rec.tag, rec.body.to_vec()));
    }
    let methods = methods.ok_or_else(|| {
        invalid(
            "describe.methods",
            "absent",
            "a D_METHODS item naming the kind's REQUIRED methods",
        )
    })?;
    if methods & !all != 0 {
        return Err(Refusal::new(
            RefusalCode::CapUnknown,
            "describe.methods",
            format!("{:#x}", methods & !all),
            "method bits the kind declares",
        ));
    }
    if methods & required != required {
        return Err(invalid(
            "describe.methods",
            format!("{:#x}", required & !methods),
            "every REQUIRED method of the kind",
        ));
    }
    crate::upstream_paths::validate(kind, &items)?;
    Ok(Described {
        kind,
        methods,
        facts: facts.unwrap_or(0),
        items,
        schema,
        metrics,
        error_codes_refused: None,
    })
}

/// A describe frame rebuilt from `items` (answer order), for the kind decoders that read a `Records`.
pub(crate) fn frame(items: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Reply::new();
    for (tag, body) in items {
        // An item came out of one frame, so it fits one again.
        let _ = out.put(*tag, body);
    }
    out.as_bytes().to_vec()
}

fn merge(base: &mut json::Value, patch: &json::Value) {
    match patch.as_object() {
        Some(fields) => {
            if !base.is_object() {
                *base = json::Value::from(json::Map::new());
            }
            if let Some(target) = base.as_object_mut() {
                for (key, value) in fields {
                    if value.is_null() {
                        target.remove(&key);
                    } else {
                        merge(target.entry(&key).or_insert(json::Value::new()), value);
                    }
                }
            }
        }
        None => *base = patch.clone(),
    }
}

/// RFC 7386 merge of `patch` (a JSON object) into `base` (the stored config of an instance): absent fields keep
/// their values, a `null` removes one, objects merge recursively. A patch that is not an object is refused.
pub(crate) fn merge_patch(base: &[u8], patch: &[u8]) -> Result<Vec<u8>, String> {
    let mut config: json::Value =
        json::parse_value(base).map_err(|e| format!("the stored config is not JSON: {e}"))?;
    let patch: json::Value =
        json::parse_value(patch).map_err(|e| format!("the pushed patch is not JSON: {e}"))?;
    if !patch.is_object() {
        return Err("the pushed patch is not a JSON object".to_owned());
    }
    merge(&mut config, &patch);
    json::to_vec(&config).map_err(|e| e.to_string())
}

/// The depth of the secret-instance chain a store's open may need (r6 §3 step 2a).
const MAX_SECRET_DEPTH: usize = 4;

fn plan_error(text: String) -> OpenError {
    OpenError::Config {
        code: R_CONFIG,
        text,
        error: None,
    }
}

fn visit(
    at: usize,
    kinds: &[KindCode],
    deps: &mut dyn FnMut(usize) -> Result<Vec<usize>, OpenError>,
    path: &mut Vec<usize>,
    placed: &mut [bool],
    plan: &mut Vec<(u32, BootPhase)>,
) -> Result<(), OpenError> {
    if kinds.get(at) != Some(&KindCode::Secret) || placed[at] {
        return Ok(());
    }
    if let Some(from) = path.iter().position(|i| *i == at) {
        let cycle: Vec<String> = path[from..].iter().map(usize::to_string).collect();
        return Err(plan_error(format!(
            "secret instances {} reference each other (instance {at} again)",
            cycle.join(", ")
        )));
    }
    if path.len() == MAX_SECRET_DEPTH {
        let chain: Vec<String> = path.iter().chain([&at]).map(usize::to_string).collect();
        return Err(plan_error(format!(
            "the store's secret instances chain deeper than {MAX_SECRET_DEPTH}: {}",
            chain.join(" -> ")
        )));
    }
    path.push(at);
    for dep in deps(at)? {
        visit(dep, kinds, deps, path, placed, plan)?;
    }
    path.pop();
    placed[at] = true;
    plan.push((at as u32, BootPhase::StoreSecrets));
    Ok(())
}

/// The r6 §3 step 2 order over configured kinds. `deps(i)` = the secret instances instance `i`'s bag references
/// (indices into `kinds`). `roots` = the secret instances core's own sections reference (indices into
/// `kinds`; ignored without a store, where there is no 2a). 2a = the store's secret instances and, transitively, theirs (depth at most 4, a cycle
/// is refused), dependencies first; 2b = the store; 2c = every remaining instance kind by kind (secret, auth,
/// hook, export, plane, transport), config order within a kind.
pub(crate) fn plan_order(
    kinds: &[KindCode],
    roots: &[usize],
    deps: &mut dyn FnMut(usize) -> Result<Vec<usize>, OpenError>,
) -> Result<Vec<(u32, BootPhase)>, OpenError> {
    let mut plan = Vec::new();
    let mut placed = vec![false; kinds.len()];
    if let Some(store) = kinds.iter().position(|k| *k == KindCode::Store) {
        let mut path = Vec::new();
        for dep in deps(store)? {
            visit(dep, kinds, deps, &mut path, &mut placed, &mut plan)?;
        }
        // Core's own sections the store boot needs (admin token, signing key): the secret instances
        // they name open in 2a too, after the store's own, each with its own dependencies first. A root that is
        // not a secret instance, or is already placed, is skipped by `visit`.
        for &root in roots {
            visit(root, kinds, deps, &mut path, &mut placed, &mut plan)?;
        }
        placed[store] = true;
        plan.push((store as u32, BootPhase::Store));
    }
    for kind in [
        KindCode::Store,
        KindCode::Secret,
        KindCode::Auth,
        KindCode::Hook,
        KindCode::Export,
        KindCode::Plane,
        KindCode::Transport,
    ] {
        for (i, k) in kinds.iter().enumerate() {
            if *k == kind && !placed[i] {
                placed[i] = true;
                plan.push((i as u32, BootPhase::Rest));
            }
        }
    }
    Ok(plan)
}

/// An `InstanceSpec` the future owns: the open methods return `BoxFut<'_>` tied to the registry only, so the
/// borrowed spec is copied once, synchronously, before the future is built.
pub(crate) struct OwnedSpec {
    purpose: OpenPurpose,
    identity: String,
    name: String,
    config_json: SecureVec,
    limits: busbar_plugin_abi::host_side::caller::InstanceLimits,
    public_url: Option<String>,
    caller_upstreams: Vec<Box<str>>,
}

impl OwnedSpec {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }
    pub(crate) fn new(s: &InstanceSpec<'_>) -> Self {
        OwnedSpec {
            purpose: s.purpose,
            identity: s.identity.to_owned(),
            name: s.name.to_owned(),
            config_json: SecureVec::from(s.config_json),
            limits: s.limits,
            public_url: s.public_url.map(str::to_owned),
            caller_upstreams: s.caller_upstreams.to_vec(),
        }
    }

    pub(crate) fn spec(&self) -> InstanceSpec<'_> {
        InstanceSpec {
            purpose: self.purpose,
            identity: &self.identity,
            name: &self.name,
            config_json: &self.config_json,
            limits: self.limits,
            public_url: self.public_url.as_deref(),
            caller_upstreams: &self.caller_upstreams,
        }
    }
}

/// `binder.unbind(id)` when dropped: any failure after bind, and the instance's own end.
pub(crate) struct Unbind {
    binder: Arc<dyn ConfigBinder>,
    id: u64,
}

impl Unbind {
    pub(crate) fn new(binder: Arc<dyn ConfigBinder>, id: u64) -> Self {
        Unbind { binder, id }
    }
}

impl Drop for Unbind {
    fn drop(&mut self) {
        self.binder.unbind(self.id);
    }
}

/// What an `Instance` keeps alive for its life (`InstanceParts::tether`): its binding first, its slot lease last.
struct Tether {
    _unbind: Unbind,
    _lease: SlotLease,
}

fn bind_error(name: &str, e: BindError) -> OpenError {
    let text = match e {
        BindError::NotAReference { pointer } => {
            format!("{name}: {pointer} is not a secret reference")
        }
        BindError::StraySecret { pointer } => {
            format!("{name}: a secret reference at {pointer}, which the plugin does not declare")
        }
        BindError::BadPem { pointer } => format!("{name}: {pointer} is not PEM certificates"),
        BindError::BadDest { pointer } => {
            format!("{name}: {pointer} is not an admitted destination")
        }
        BindError::BadReference { pointer, text } => format!("{name}: {pointer}: {text}"),
        BindError::TooMany => format!("{name}: too many unix socket paths"),
    };
    plan_error(text)
}

/// RFC 6901 `pointer` into `v`: the parent object and the last token.
fn set_at(
    v: &mut json::Value,
    pointer: &str,
    value: json::Value,
    name: &str,
) -> Result<(), OpenError> {
    let refuse = |why: &str| plan_error(format!("{name}: core cannot write {pointer}: {why}"));
    let (parent, key) = pointer
        .rsplit_once('/')
        .ok_or_else(|| refuse("not a JSON pointer"))?;
    let key = key.replace("~1", "/").replace("~0", "~");
    let parent = json::pointer_mut(v, parent).ok_or_else(|| refuse("no such parent"))?;
    let object = parent
        .as_object_mut()
        .ok_or_else(|| refuse("the parent is not an object"))?;
    if object.get(&key).is_some_and(|held| !held.is_null()) {
        return Err(refuse("the operator's config already holds that position"));
    }
    object.insert(&key, value);
    Ok(())
}

/// How many `{"$dest": n}` handles the bound config holds.
fn count_dests(v: &json::Value) -> u32 {
    match v.get_type() {
        json::JsonType::Object => match v.as_object() {
            Some(map) if map.contains_key(&"$dest") => 1,
            Some(map) => map.iter().map(|(_, v)| count_dests(v)).sum(),
            None => 0,
        },
        json::JsonType::Array => v
            .as_array()
            .map_or(0, |items| items.iter().map(count_dests).sum()),
        _ => 0,
    }
}

/// An image and the config bound for one instance-to-be, before any plugin entry of that instance runs.
pub(crate) struct Prepared {
    id: u64,
    header: Header,
    image: Arc<Image>,
    identity: Arc<str>,
    errors: &'static ErrorBook,
    ceilings: [u32; 64],
    described: Described,
    bound: SecureVec,
    dests: u32,
    unbind: Unbind,
}

/// A finished open: the instance, its answer and what its kind's port needs from the image.
pub(crate) struct Opened {
    pub instance: Arc<Instance>,
    pub answer: OwnedAnswer,
    pub described: Described,
    pub errors: &'static ErrorBook,
    pub dests: u32,
}

impl Registry {
    /// Cold: the admitted image `s.identity` names, the config bound and its references resolved (§11.2 `open`:
    /// `bind`, `resolve_refs`, the core values at D_PUBLIC_URL_PATH and D_CALLER_UPSTREAMS_PATH). The D_SCHEMA
    /// check is the plugin's own `open`/`check` (the engine graph carries no JSON Schema validator).
    async fn prepare_with_id(
        &self,
        s: &InstanceSpec<'_>,
        kind: KindCode,
        id: u64,
        slot: u32,
        refs: &dyn RefSource,
    ) -> Result<Prepared, OpenError> {
        let entry = self.entry_of(s.identity).ok_or_else(|| {
            OpenError::Unknown(format!(
                "{}: no admitted plugin answers to module {}",
                s.name, s.identity
            ))
        })?;
        if entry.described.kind != kind {
            return Err(plan_error(format!(
                "{}: module {} is a {:?} plugin, not a {:?}",
                s.name, s.identity, entry.described.kind, kind
            )));
        }
        let (Some(header), Some(image)) = (entry.header, entry.image.as_ref()) else {
            return Err(OpenError::Unknown(format!(
                "{}: module {} has no loaded image",
                s.name, s.identity
            )));
        };
        let paths = |wanted: u16| -> Vec<&str> {
            entry
                .described
                .items
                .iter()
                .filter(|(t, _)| *t == wanted)
                .filter_map(|(_, b)| core::str::from_utf8(b).ok())
                .collect()
        };
        let bind = match s.purpose {
            OpenPurpose::Canonical => ConfigBinder::bind,
            OpenPurpose::ConvertUnstamped => ConfigBinder::bind_any,
        };
        let bound = bind(
            &*self.binder,
            id,
            s.config_json,
            &paths(tag::D_SECRET_PATH),
            &paths(tag::D_TRUST_PATH),
            &paths(tag::D_DEST_PATH),
            &paths(tag::D_REF_PATH),
        )
        .map_err(|e| bind_error(s.name, e))?;
        let unbind = Unbind {
            binder: Arc::clone(&self.binder),
            id,
        };
        let resolved = self
            .binder
            .resolve_refs(id, slot, bound, refs)
            .await
            .map_err(|e| bind_error(s.name, e))?;
        let (urls, ups) = (
            paths(tag::D_PUBLIC_URL_PATH),
            paths(tag::D_CALLER_UPSTREAMS_PATH),
        );
        let dest_paths = paths(tag::D_DEST_PATH);
        let write_urls = s.public_url.is_some() && !urls.is_empty();
        let (bound, dests) = if write_urls || !ups.is_empty() || !dest_paths.is_empty() {
            let mut v: json::Value = json::parse_value(resolved.as_slice()).map_err(|e| {
                plan_error(format!("{}: the bound config is not JSON: {e}", s.name))
            })?;
            if let Some(url) = s.public_url {
                for p in &urls {
                    set_at(&mut v, p, json::Value::from(url), s.name)?;
                }
            }
            for p in &ups {
                let names = s
                    .caller_upstreams
                    .iter()
                    .map(|n| json::Value::from(n.to_string().as_str()))
                    .collect::<Vec<json::Value>>();
                set_at(&mut v, p, json::Value::from(names), s.name)?;
            }
            let dests = count_dests(&v);
            if write_urls || !ups.is_empty() {
                (SecureVec::from(json::to_vec(&v).unwrap_or_default()), dests)
            } else {
                (resolved, dests)
            }
        } else {
            (resolved, 0)
        };
        Ok(Prepared {
            id,
            header,
            image: Arc::clone(image),
            identity: Arc::from(entry.identity.as_ref()),
            errors: entry.errors,
            ceilings: entry.ceilings,
            described: entry.described.clone(),
            bound,
            dests,
            unbind,
        })
    }

    /// The instance's `max_out` (D_MAX_OUT, clamped by core's own ceiling for the kind).
    fn max_out_of(&self, d: &Described) -> usize {
        let core = if d.kind == KindCode::Store {
            self.ceilings.max_out_store
        } else {
            self.ceilings.max_out
        };
        let declared = d
            .items
            .iter()
            .filter(|(t, _)| *t == tag::D_MAX_OUT)
            .find_map(|(t, b)| Rec { tag: *t, body: b }.pod::<U64Rec>().ok())
            .map_or(core, |rec| usize::try_from(rec.value).unwrap_or(core));
        declared.min(core).max(MAX_OUT_FLOOR)
    }

    /// One `open` entry chain of kind `K` (flags: 0, or DRY_RUN) through the driver, Image-owned.
    async fn run_open<K: Kind, N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        p: &Prepared,
        lease: &SlotLease,
        flags: u32,
        needs: &N,
    ) -> Result<busbar_plugin_abi::host_side::driver::Finished<K>, OpenError> {
        let max_out = self.max_out_of(&p.described);
        let host = self.host;
        let header = p.header;
        let caller = Caller {
            plugin: &p.identity,
            kind: K::CODE,
            name: s.name,
            instance: p.id,
            slot: lease.slot(),
            chain: 0,
            deadline: Instant::now() + OPEN_DEADLINE,
            stack: CallStack::default(),
            out_of_process: false,
            limits: s.limits,
        };
        let mut drv = Driver::new(needs, caller)
            .for_open()
            .with_max_steps(self.ceilings.max_steps);
        if K::CODE == KindCode::Store
            && p.described.facts & busbar_plugin_abi::store::F_BLOCKING_FILE != 0
        {
            drv = drv.with_row(NeedRow::EMPTY);
        }
        let req = Pool::global()
            .acquire_with(max_out, p.bound.as_slice())
            .map_err(|_| {
                plan_error(format!(
                    "{}: the bound config is larger than the plugin's max_out ({max_out})",
                    s.name
                ))
            })?;
        drv.run::<K, _>(ENTRY_OPEN, max_out, req, move |req, out| {
            header
                .open::<K>(host, req.bytes().to_vec(), flags, out)
                .into()
        })
        .await
        .map_err(OpenError::Call)
    }

    /// The generic open (§11.2): prepare, run the `open` chain under a leased slot, and on OK + INSTANCE build the
    /// `Instance` in the same poll (§10.4), keep the settled answer for the write-back (round 31) and tether the
    /// binding and the lease to the instance. A REFUSED or FAILED answer is the open's error.
    pub(crate) async fn open_reserved_instance<K: Kind, N: Needs>(
        &self,
        reserved: crate::instance::PreparedInstance,
        needs: &Arc<N>,
        refs: &dyn RefSource,
    ) -> Result<Opened, OpenError> {
        let crate::instance::PreparedInstance {
            owner,
            spec: owned,
            id,
            kind,
            lease,
        } = reserved;
        let s = &owned.spec();
        if kind != K::CODE {
            return Err(plan_error("reserved instance has another kind".into()));
        }
        if !Arc::ptr_eq(&owner, &self.reservation_owner) || !Arc::ptr_eq(lease.table(), &self.slots)
        {
            return Err(plan_error(
                "reserved instance belongs to another process".into(),
            ));
        }
        let p = self
            .prepare_with_id(s, kind, id, lease.slot(), refs)
            .await?;
        let finished = self.run_open::<K, N>(s, &p, &lease, 0, &**needs).await?;
        let Finished { answer, instance } = finished;
        let (status, scrub, errors) = (
            answer.answer().status,
            Arc::clone(&lease.record().scrub),
            p.errors,
        );
        let Some(live) = instance else {
            if status == Status::OK {
                return Err(OpenError::Call(CallError::Fault(FaultReason::BadRecords(
                    RecErr::Size,
                ))));
            }
            let latch = AtomicBool::new(false);
            return Err(match port_error(&scrub, errors, &latch, &answer.answer()) {
                Some(e) => open_error(e),
                None => OpenError::Call(CallError::Fault(FaultReason::BadStatus(status.0))),
            });
        };
        let quarantined = !lease.is_live();
        let Prepared {
            id,
            image,
            identity,
            described,
            dests,
            unbind,
            ..
        } = p;
        let limits = settled_limits(s.limits, &answer.answer());
        let parts = InstanceParts {
            image,
            identity,
            name: Arc::from(s.name),
            id,
            slot: lease.slot(),
            cell: Arc::clone(lease.cell()),
            epoch: lease.epoch(),
            limits,
            max_out: self.max_out_of(&described),
            methods: described.methods,
            facts: described.facts,
            scrub: Arc::clone(&scrub),
            tether: Box::new(Tether {
                _unbind: unbind,
                _lease: lease,
            }),
        };
        let instance = Instance::new::<K>(parts, live);
        if quarantined {
            return Err(OpenError::Call(CallError::Quarantined));
        }
        self.settle(s, id, &answer.answer())?;
        Ok(Opened {
            instance,
            answer,
            described,
            errors,
            dests,
        })
    }

    /// Round 31: CONFIG and CORE_CFG* of an OK open answer mapped back through the binder's reference map and
    /// kept for `take_settled`. A refused inverse mapping is CONFIG and the instance never serves.
    fn settle(&self, s: &InstanceSpec<'_>, id: u64, answer: &Answer<'_>) -> Result<(), OpenError> {
        let fault = |e: RecErr| OpenError::Call(CallError::Fault(FaultReason::BadRecords(e)));
        let Some(out) = for_purpose(answer.records(), s.purpose == OpenPurpose::ConvertUnstamped)
            .map_err(|_| {
            plan_error(format!(
                "{}: open CONFIG or CORE_CFG violates its purpose",
                s.name
            ))
        })?
        else {
            return Ok(());
        };
        let config_json = SecureVec::from(
            self.binder
                .unbind_refs(id, out.config)
                .map_err(|e| bind_error(s.name, e))?,
        );
        json::parse_value(config_json.as_slice())
            .map_err(|_| plan_error(format!("{}: open CONFIG is not valid JSON", s.name)))?;
        let mut core_cfg = Vec::new();
        for rec in out.core_cfg {
            let rec = rec.map_err(fault)?;
            let (head, tail) = rec.pod_tail::<CoreCfgRec>().map_err(fault)?;
            let name_len = usize::try_from(head.name_len).map_err(|_| fault(RecErr::Size))?;
            let (name, value) = tail
                .split_at_checked(name_len)
                .ok_or_else(|| fault(RecErr::Size))?;
            match self.binder.unbind_refs(id, value) {
                Ok(value_json) => core_cfg.push(CoreCfg {
                    section: head.section,
                    name: String::from_utf8_lossy(name).into(),
                    value_json: SecureVec::from(value_json),
                }),
                Err(e) => {
                    return Err(bind_error(s.name, e));
                }
            }
        }
        self.keep_settled(
            s.name,
            Settled {
                config_json,
                core_cfg,
            },
        );
        Ok(())
    }

    /// The DRY_RUN chain (§11.2 `check`): the same bind, an `open` entry with `OPEN_DRY_RUN`, never an instance.
    /// The ENDPOINT records of its OK answer are judged by `judge_check_answer`.
    pub(crate) async fn dry_run<K: Kind>(
        &self,
        s: &InstanceSpec<'_>,
        refs: &dyn RefSource,
    ) -> Result<Vec<crate::instance::DeclaredEndpoint>, OpenError> {
        let kind = K::CODE;
        let reserved = self.reserve(s)?;
        let lease = reserved.lease;
        let p = self
            .prepare_with_id(s, kind, reserved.id, lease.slot(), refs)
            .await?;
        let finished = self
            .run_open::<K, DeniedNeeds>(
                s,
                &p,
                &lease,
                busbar_plugin_abi::plugin::OPEN_DRY_RUN,
                &DeniedNeeds,
            )
            .await?;
        if !lease.is_live() {
            return Err(OpenError::Call(CallError::Quarantined));
        }
        let answer = finished.answer.answer();
        if answer.status == Status::OK {
            return self.judge_check_answer(s, answer.records().rest());
        }
        let latch = AtomicBool::new(false);
        Err(
            match port_error(&lease.record().scrub, p.errors, &latch, &answer) {
                Some(e) => open_error(e),
                None => OpenError::Call(CallError::Fault(FaultReason::BadStatus(answer.status.0))),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::fail::refused::R_CONFIG;
    use busbar_plugin_abi::kinds::store::store as st;
    use busbar_plugin_abi::records::{tag, MaskRec, MetricDecl, Reply, Writer};

    use crate::refusal::RefusalCode;

    fn mask(r: &mut Reply, t: u16, mask: u64) {
        r.put_pod(t, &MaskRec { mask }).unwrap();
    }

    fn describe(methods: u64) -> Reply {
        let mut r = Reply::new();
        mask(&mut r, tag::D_METHODS, methods);
        mask(&mut r, tag::D_FACTS, 0b101);
        r.put_text(tag::D_SCHEMA, r#"{"type":"object"}"#).unwrap();
        let mut tail = Reply::new();
        tail.put_text(tag::TEXT, "reads").unwrap();
        tail.put_text(tag::TEXT, "Reads served").unwrap();
        tail.put_text(tag::TEXT, "op").unwrap();
        r.put_pod_tail(
            tag::D_METRIC,
            &MetricDecl { id: 7, kind: 1 },
            tail.as_bytes(),
        )
        .unwrap();
        r
    }

    #[test]
    fn a_describe_frame_decodes_into_its_facts() {
        let r = describe(st::REQUIRED);
        let d = decode_described(KindCode::Store, Records::new(r.as_bytes())).unwrap();
        assert_eq!(d.kind, KindCode::Store);
        assert_eq!(d.methods, st::REQUIRED);
        assert_eq!(d.facts, 0b101);
        assert_eq!(d.schema.as_deref(), Some(r#"{"type":"object"}"#));
        assert_eq!(d.items.len(), 4);
        let [m] = &d.metrics[..] else {
            panic!("one metric")
        };
        assert_eq!(
            (m.id, m.kind, &*m.name, &*m.help),
            (7, 1, "reads", "Reads served")
        );
        assert_eq!(
            m.label_keys.iter().map(|k| &**k).collect::<Vec<_>>(),
            ["op"]
        );
    }

    /// IF r29 l.2764 ("core's D_SCHEMA validator"): the describe's D_SCHEMA meets the authoritative-schema rules
    /// a Statement settings_schema met (public JSON within 262144 bytes, an object or boolean), so a pathological
    /// schema is DescribeInvalid at admission, naming D_SCHEMA and the parser's reason.
    #[test]
    fn a_pathological_or_non_schema_d_schema_is_describe_invalid() {
        let schema = |text: &str| {
            let mut r = Reply::new();
            mask(&mut r, tag::D_METHODS, st::REQUIRED);
            r.put_text(tag::D_SCHEMA, text).unwrap();
            decode_described(KindCode::Store, Records::new(r.as_bytes()))
        };
        let bomb = format!("{}true{}", "{\"allOf\":[".repeat(500), "]}".repeat(500));
        let e = schema(&bomb).err().expect("a recursion bomb is refused");
        assert_eq!(e.code, RefusalCode::DescribeInvalid);
        assert_eq!(e.field, "describe.schema");
        assert!(
            e.have.contains("D_SCHEMA") && e.have.contains("recursion limit exceeded"),
            "{e:?}"
        );
        let e = schema("[1]").err().expect("an array is not a schema");
        assert_eq!(e.code, RefusalCode::DescribeInvalid);
        let e = schema("{").err().expect("not JSON");
        assert_eq!(e.code, RefusalCode::DescribeInvalid);
        let big = format!("{{\"description\":\"{}\"}}", "x".repeat(256 * 1024));
        let e = schema(&big).err().expect("over the cap");
        assert_eq!(e.code, RefusalCode::DescribeInvalid);
        assert!(schema("true").is_ok() && schema(r#"{"type":"object"}"#).is_ok());
    }

    #[test]
    fn a_method_the_kind_lacks_is_cap_unknown_and_a_missing_required_one_is_invalid() {
        let r = describe(st::REQUIRED | st::ALL + 1);
        let e = decode_described(KindCode::Store, Records::new(r.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(e.code, RefusalCode::CapUnknown);
        let r = describe(st::REQUIRED & !1);
        let e = decode_described(KindCode::Store, Records::new(r.as_bytes()))
            .err()
            .unwrap();
        assert_eq!(e.code, RefusalCode::DescribeInvalid);
        let e = decode_described(KindCode::Store, Records::new(&[]))
            .err()
            .unwrap();
        assert_eq!(
            (e.code, e.field),
            (RefusalCode::DescribeInvalid, "describe.methods")
        );
    }

    fn json(bytes: &[u8]) -> busbar_contract::json::Value {
        busbar_contract::json::parse_value(bytes).unwrap()
    }

    #[test]
    fn a_patch_keeps_absent_fields_merges_objects_and_null_removes() {
        let out = merge_patch(
            br#"{"a":1,"b":{"c":2,"e":5},"f":[1]}"#,
            br#"{"a":null,"b":{"c":3,"d":4},"f":[2]}"#,
        )
        .unwrap();
        assert_eq!(json(&out), json(br#"{"b":{"c":3,"d":4,"e":5},"f":[2]}"#));
        assert!(merge_patch(b"{}", b"[1]").is_err());
        assert!(merge_patch(b"{}", b"nope").is_err());
        assert!(merge_patch(b"nope", b"{}").is_err());
    }

    use BootPhase::{Rest, Store, StoreSecrets};
    use KindCode as K;

    #[test]
    fn the_plan_runs_store_secrets_then_the_store_then_every_other_kind_in_order() {
        // 0 plane, 1 store, 2 secret, 3 secret (the store's), 4 auth, 5 hook, 6 secret
        let kinds = [
            K::Plane,
            K::Store,
            K::Secret,
            K::Secret,
            K::Auth,
            K::Hook,
            K::Secret,
        ];
        let mut deps = |i: usize| {
            Ok(match i {
                1 => vec![3],
                3 => vec![2],
                _ => vec![],
            })
        };
        let plan = plan_order(&kinds, &[], &mut deps).unwrap();
        assert_eq!(
            plan,
            [
                (2, StoreSecrets),
                (3, StoreSecrets),
                (1, Store),
                (6, Rest),
                (4, Rest),
                (5, Rest),
                (0, Rest)
            ]
        );
    }

    #[test]
    fn a_secret_cycle_and_a_chain_deeper_than_four_are_refused_naming_the_instances() {
        let kinds = [K::Store, K::Secret, K::Secret];
        let mut cycle = |i: usize| {
            Ok(match i {
                0 => vec![1],
                1 => vec![2],
                2 => vec![1],
                _ => vec![],
            })
        };
        let Err(OpenError::Config { code, text, .. }) = plan_order(&kinds, &[], &mut cycle) else {
            panic!("a cycle is refused")
        };
        assert_eq!(code, R_CONFIG);
        assert!(text.contains('1') && text.contains('2'), "{text}");
        let kinds = [
            K::Store,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
        ];
        let mut deep = |i: usize| Ok(if i < 6 { vec![i + 1] } else { vec![] });
        assert!(matches!(
            plan_order(&kinds, &[], &mut deep),
            Err(OpenError::Config { .. })
        ));
        let mut shallow = |i: usize| Ok(if i < 4 { vec![i + 1] } else { vec![] });
        assert!(plan_order(&kinds[..5], &[], &mut shallow).is_ok());
    }

    #[test]
    fn core_roots_open_in_2a_after_the_stores_own_secrets_and_with_theirs_first() {
        // 0 plane, 1 store (needs 3), 2 secret (core's root, needs 4), 3 secret, 4 secret, 5 secret (unreferenced)
        let kinds = [
            K::Plane,
            K::Store,
            K::Secret,
            K::Secret,
            K::Secret,
            K::Secret,
        ];
        let mut deps = |i: usize| {
            Ok(match i {
                1 => vec![3],
                2 => vec![4],
                _ => vec![],
            })
        };
        let plan = plan_order(&kinds, &[2], &mut deps).unwrap();
        assert_eq!(
            plan,
            [
                (3, StoreSecrets),
                (4, StoreSecrets),
                (2, StoreSecrets),
                (1, Store),
                (5, Rest),
                (0, Rest)
            ]
        );
        // A root the store already pulled in is placed once; a root that is not a secret is ignored.
        let plan = plan_order(&kinds, &[3, 0, 3], &mut deps).unwrap();
        assert_eq!(plan[0], (3, StoreSecrets));
        assert_eq!(plan.iter().filter(|(i, _)| *i == 3).count(), 1);
    }

    #[test]
    fn core_roots_with_no_store_stay_in_2c() {
        let kinds = [K::Auth, K::Secret];
        let plan = plan_order(&kinds, &[1], &mut |_| Ok(vec![])).unwrap();
        assert_eq!(plan, [(1, Rest), (0, Rest)]);
    }

    #[test]
    fn a_core_root_cycle_is_refused() {
        let kinds = [K::Store, K::Secret, K::Secret];
        let mut cycle = |i: usize| {
            Ok(if i == 1 {
                vec![2]
            } else if i == 2 {
                vec![1]
            } else {
                vec![]
            })
        };
        assert!(matches!(
            plan_order(&kinds, &[1], &mut cycle),
            Err(OpenError::Config { .. })
        ));
    }

    #[test]
    fn no_store_means_no_store_phase() {
        let kinds = [K::Auth, K::Secret];
        let plan = plan_order(&kinds, &[], &mut |_| Ok(vec![])).unwrap();
        assert_eq!(plan, [(1, Rest), (0, Rest)]);
    }
}
