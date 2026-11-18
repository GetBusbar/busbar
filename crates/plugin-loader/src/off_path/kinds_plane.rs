// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane kind's code that runs once per load, bind or configuration, never per request
//! (lint ruling Q4, LINT-BOUNDARY.md "L5 loader split"): moved from `dispatch::kinds::plane` with
//! its behaviour unchanged; that module re-exports the paths its callers use.
//!
//! Every caller, at the move:
//! - the Statement read ([`tail_facts`] and the tail readers [`kept_blob`],
//!   [`kept_mechanisms`], [`listed`], [`dialect_flags`]): `Kind::context` and
//!   `Kind::optional_by_statement` of `Plane`, which the loader calls once per load and bind
//!   (`dispatch::load`), and `cold::dispatch::kinds` (`plane_declared`, `plane_served`), called
//!   from [`tail_facts`] only;
//! - [`stated_facts`], [`stated_registration`], [`registration`], [`linked_probe`] (test
//!   support): the root's linked-plane boot (`root/linked.rs`) and tests; the registration's
//!   `validate` and `face` closures run once per (changed) plane configuration, from the root's
//!   configuration validation;
//! - [`linked_cli_help`], [`rendered_cli_help`]: the CLI's help text, before any serving;
//! - [`provider_facts`] and [`provider`]: [`facing`] and the root's plane open
//!   (`root/off_path/serve.rs`), once per plane open;
//! - [`refresh_door_on`], [`retire_door`]: the root's configuration worker
//!   (`root/off_path/serve.rs`), once per configuration change; [`open_door`] and
//!   [`refresh_door`] are test support;
//! - [`owned_str`], [`owned_blob`]: `cold::dispatch::kinds::plane_snapshot`, called from
//!   `dispatch::kinds::plane::copy_snapshot` once per OPEN or REFRESH.
//!
//! It holds no `unsafe`: the plugin memory it reads (the tail, its lists, texts and blobs, the
//! Statement's extensions, a snapshot's texts) is read through the safe primitives
//! `dispatch::kinds::plane` keeps beside its other unsafe code (`plane_tail`, `tail_slice`,
//! `tail_blob`, `kept`, `statement_blob`, `metric_lanes_checked`, `fee_units_checked`,
//! `snapshot_text_of`, `snapshot_bytes_of`), so the unsafe register (unsafe.yaml) keeps its
//! per-file counts.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, RefreshIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::{
    check_billable_classes, check_pin_mechanisms, check_record_chains, check_record_retentions,
    check_refusal_statuses, check_route_cost, check_sections, check_tail, check_trust_keys, Bounds,
};
use busbar_contract::abi::plane::{
    self, BillableClass, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneTail,
};
use busbar_contract::plane::PinMechanismDecl;
use busbar_contract::plane_calls::InstanceDecl;
use busbar_contract::secure::SecureVec;

use crate::dispatch::kinds::plane::{
    check_tail_text, copy_snapshot, fee_units_checked, kept, metric_lanes_checked, plane_tail,
    snapshot_bytes_of, snapshot_text_of, statement_blob, tail_blob, tail_slice, OwnedSnapshot,
    Plane, PlaneFacts, ProbeBind, ServedFacts,
};
use crate::dispatch::lifecycle;
use crate::dispatch::{in_head, out_head, Frame};

pub(crate) fn tail_facts(st: &Statement) -> Result<PlaneFacts, String> {
    OVER_CAP.with(|c| c.set(false));
    let facts = tail_facts_read(st);
    if OVER_CAP.with(|c| c.replace(false)) {
        return Err(crate::cold::dispatch::kinds::refusal(
            "the plane tail states a list or string longer than its cap",
        ));
    }
    facts
}

/// The load-time refusal naming the rule and field a plane tail breaks.
fn broke(f: Fault) -> String {
    crate::cold::dispatch::kinds::tail_fault("plane", f)
}

std::thread_local! {
    /// A tail read ([`kept`], [`kept_blob`], [`listed`]) met a length over its cap, or a list or
    /// string NULL with a count: nothing was formed over it, and [`tail_facts`] refuses the plane
    /// (THE DESIGN §11.13 M1, "Every slice built from a plugin-reported length is capped and
    /// validated before it is formed").
    static OVER_CAP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn over_cap() {
    OVER_CAP.with(|c| c.set(true));
}

pub(crate) fn stated_collections(
    blob: Blob,
    extensions: &[u8],
    kinds: u64,
) -> Result<Vec<plane::RecordCollection>, String> {
    let rows = plane::collections::from_extensions(extensions, kinds)
        .map_err(|_| "invalid plane record collection declaration")?;
    if busbar_contract::abi::mechanism::extensions::get(
        extensions,
        plane::collections::EXT_RECORD_COLLECTIONS,
    )
    .is_some()
        && (blob.fmt != busbar_contract::abi::mechanism::call::BLOB_OCTETS || blob.flags != 0)
    {
        return Err("invalid plane record collection declaration blob".into());
    }
    Ok(rows)
}

fn tail_facts_read(st: &Statement) -> Result<PlaneFacts, String> {
    let tail = plane_tail(st)?;
    check_tail(&tail).map_err(broke)?;
    refuse_retired_trust_roles(&tail)?;
    check_tail_trust_keys(&tail).map_err(broke)?;
    check_tail_fee_units(&tail).map_err(broke)?;
    let admin_routes = listed(tail.admin_routes, tail.admin_routes_len);
    plane::check::check_admin_routes(&admin_routes).map_err(broke)?;

    check_record_chains(
        &listed(tail.record_chains, tail.record_chains_len),
        tail.record_kinds_len as u64,
    )
    .map_err(broke)?;

    check_record_retentions(
        &listed(tail.record_retentions, tail.record_retentions_len),
        tail.record_kinds_len as u64,
    )
    .map_err(broke)?;
    check_route_cost(
        &listed(tail.route_cost, tail.route_cost_len),
        tail.billable_classes_len as u64,
    )
    .map_err(broke)?;
    let streaming_content_types = listed(
        tail.streaming_content_types,
        tail.streaming_content_types_len,
    );
    for media in &streaming_content_types {
        check_tail_text(*media, "tail.streaming_content_types").map_err(broke)?;
    }
    let metric_lanes = listed(tail.metric_lanes, tail.metric_lanes_len);
    for lane in &metric_lanes {
        check_tail_text(*lane, "tail.metric_lanes").map_err(broke)?;
    }
    metric_lanes_checked(&metric_lanes).map_err(broke)?;

    let sections = listed(st.sections, st.sections_len);
    check_sections(&sections).map_err(crate::cold::dispatch::kinds::plane_sections_fault)?;
    let refusal_statuses = listed(tail.refusal_statuses, tail.refusal_statuses_len);
    check_refusal_statuses(&refusal_statuses, tail.dialects_len as u64).map_err(broke)?;

    busbar_contract::abi::plane::check::check_dialect_auth(
        &listed(tail.dialect_auth, tail.dialect_auth_len),
        tail.dialects_len as u64,
    )
    .map_err(broke)?;
    let mut decl = crate::cold::dispatch::kinds::plane_declared(&tail);
    decl.ticket_prefix = ticket_prefix(st)?;

    let extensions = if st.extensions.len
        > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize
        || (st.extensions.len != 0 && st.extensions.ptr.is_null())
    {
        &[][..]
    } else {
        // The raw length is bounded above.
        statement_blob(st.extensions).ok_or("invalid plane Statement extensions")?
    };
    decl.record_collections =
        stated_collections(st.extensions, extensions, tail.record_kinds_len as u64)?;
    use busbar_contract::abi::sdk::plane::conditional;
    if conditional::present(extensions) {
        if st.extensions.fmt != busbar_contract::abi::mechanism::call::BLOB_OCTETS
            || st.extensions.flags != 0
        {
            return Err("invalid conditional record capability blob".into());
        }
        decl.conditional_records = match conditional::entry(extensions, conditional::CAPABILITY)? {
            Some(b"1") => true,
            _ => return Err("invalid conditional record capability".into()),
        };
        decl.conditional_record_kinds = conditional::required_kinds(extensions)?;
        decl.conditional_records_optional = conditional::optional(extensions)?;
        if decl
            .conditional_record_kinds
            .iter()
            .any(|&k| k as usize >= decl.record_kinds.len())
        {
            return Err("conditional record kind is not declared".into());
        }
    }
    // The served facts are copied out once, at bind, out of line; the provider keys last, as the
    // tail's other lists are read first.
    let mut served = crate::cold::dispatch::kinds::plane_served(st, &tail);
    served.provider_keys = stated_provider_keys(st.extensions)?;
    Ok(PlaneFacts {
        bounds: Bounds::of(&tail),
        refusal_statuses,
        declared: decl,
        served,
    })
}

pub(crate) fn stated_provider_keys(
    ext: Blob,
) -> Result<Option<busbar_contract::provider_keys::ProviderKeys>, String> {
    if ext.ptr.is_null() || ext.len == 0 {
        return Ok(None);
    }
    if ext.len > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err("the Statement's extensions are longer than any blob may be".into());
    }
    // Its length capped first; the descriptor is decoded into owned values before this returns.
    let bytes =
        statement_blob(ext).ok_or("the Statement's extensions are longer than any blob may be")?;
    busbar_contract::provider_keys::stated(bytes)
        .map_err(crate::cold::dispatch::kinds::plane_provider_keys)
}

pub(crate) fn dialect_flags(tail: &busbar_contract::abi::plane::PlaneTail) -> Vec<u32> {
    let mut flags = vec![0; listed(tail.dialects, tail.dialects_len).len()];
    for d in listed(tail.dialect_auth, tail.dialect_auth_len) {
        if let Some(f) = flags.get_mut(d.dialect as usize) {
            *f |= d.flags;
        }
    }
    flags
}

pub(crate) fn kept_blob(b: Blob) -> &'static [u8] {
    let Some(bytes) = tail_blob(b) else {
        return &[];
    };
    static BLOBS: std::sync::OnceLock<std::sync::Mutex<foldhash::HashSet<&'static [u8]>>> =
        std::sync::OnceLock::new();
    let mut blobs = BLOBS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(kept) = blobs.get(bytes) {
        return kept;
    }
    crate::cold::dispatch::kinds::first_blob(&mut blobs, bytes)
}

pub(crate) fn kept_mechanisms(mechanisms: Vec<PinMechanismDecl>) -> &'static [PinMechanismDecl] {
    if mechanisms.is_empty() {
        return &[];
    }
    static MECHANISMS: std::sync::OnceLock<std::sync::Mutex<Vec<&'static [PinMechanismDecl]>>> =
        std::sync::OnceLock::new();
    let mut kept = MECHANISMS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = kept.iter().find(|m| **m == mechanisms.as_slice()) {
        return existing;
    }
    let mechanisms: &'static [PinMechanismDecl] = mechanisms.leak();
    kept.push(mechanisms);
    mechanisms
}

pub(crate) fn listed<T: Copy>(p: *const T, n: usize) -> Vec<T> {
    tail_slice(p, n).map_or_else(Vec::new, |list| {
        crate::cold::dispatch::kinds::statement_list(list)
    })
}

fn ticket_prefix(st: &Statement) -> Result<Option<&'static str>, String> {
    use busbar_contract::abi::mechanism::door::MARK_WORD_ISSUED_ID_PREFIX;
    let mut found = None;
    for w in listed(st.mark_words, st.mark_words_len) {
        if w.class != MARK_WORD_ISSUED_ID_PREFIX {
            continue;
        }
        let word = kept(w.word);
        if word.is_empty() {
            return Err(crate::cold::dispatch::kinds::refusal(
                "the plane declares an empty issued-id prefix",
            ));
        }
        if found.replace(word).is_some() {
            return Err(crate::cold::dispatch::kinds::refusal(
                "the plane declares two issued-id prefixes",
            ));
        }
    }
    Ok(found)
}

#[cfg(any(test, feature = "test-support"))]
pub fn linked_probe(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    instance: &str,
    callers: Arc<dyn busbar_contract::services::CallerBinding>,
) -> ProbeBind {
    use crate::cold::dispatch::kinds as cold;
    let dispatcher = Arc::new(crate::dispatch::Dispatcher::new(
        crate::dispatch::DispatchConfig::default(),
        callers,
    ));
    let instance = cold::shared_name(instance);
    Arc::new(move || {
        let row = crate::dispatch::LinkedRow::of(door).map_err(cold::load_refusal)?;
        crate::dispatch::load_linked::<Plane>(
            &row,
            crate::dispatch::Bind {
                accept: Default::default(),
                instance: Arc::clone(&instance),
                max_inflight_cap: 64,
                sink: Arc::new(crate::dispatch::NoSink),
                dispatcher: dispatcher.adopter(),
                conns: crate::dispatch::ConnTable::Probe,
            },
        )
        .map_err(cold::load_refusal)
    })
}

pub fn linked_cli_help(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<Option<&'static str>, String> {
    use crate::cold::dispatch::kinds as cold;
    let (door, _) = crate::dispatch::load::read_door(
        crate::dispatch::load::enter_door(crate::dispatch::load::raw(door)),
        Some(KindCode::Plane),
    )
    .map_err(cold::load_refusal)?;
    let st = crate::dispatch::load::statement(&door).map_err(cold::load_refusal)?;
    let tail = plane_tail(&st)?;
    check_tail(&tail).map_err(broke)?;
    check_tail_text(tail.cli_help, "tail.cli_help").map_err(broke)?;
    let help = kept(tail.cli_help);
    Ok((!help.is_empty()).then_some(help))
}

pub fn rendered_cli_help(rendering: &[u8]) -> Result<Option<String>, String> {
    use crate::cold::dispatch::kinds as cold;
    use busbar_contract::abi::mechanism::rendering::{read, read_plane_cli_help};
    let r = read(rendering).map_err(|e| cold::unreadable("the plane Statement", &e))?;
    if r.kind != KindCode::Plane as u32 {
        return Err(cold::rendering_kind(r.kind, "plane"));
    }
    if r.kind_tail_size == 0 {
        return Err(cold::refusal("a plane states no kind tail"));
    }
    let help =
        read_plane_cli_help(&r.kind_tail).map_err(|e| cold::unreadable("the plane tail's", &e))?;
    Ok((!help.is_empty()).then_some(help))
}

pub fn stated_facts(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<(String, PlaneFacts), String> {
    stated_facts_raw(crate::dispatch::load::raw(door))
}

fn stated_facts_raw(
    door: busbar_contract::abi::sdk::door::RawDoorFn,
) -> Result<(String, PlaneFacts), String> {
    use crate::cold::dispatch::kinds as cold;
    let v = crate::dispatch::load::validate::<Plane>(door).map_err(cold::load_refusal)?;
    let name = crate::dispatch::plugin::str_bytes(v.statement.name)
        .map(cold::lossy_name)
        .ok_or("the plane's Statement name is NULL or over-long")?;
    Ok((name, tail_facts(&v.statement)?))
}

pub fn stated_registration(
    candidate: &crate::boot::Candidate,
    bind: ProbeBind,
) -> Result<busbar_contract::plane_calls::PlaneRegistration, String> {
    match &candidate.origin {
        crate::boot::Origin::Linked(row) => {
            let (name, facts) = stated_facts_raw(row.door)?;
            Ok(registered(
                &name,
                &facts.served,
                &facts.declared,
                None,
                bind,
            ))
        }
        crate::boot::Origin::Dropped { .. } => registration(bind),
    }
}

pub fn registration(
    bind: ProbeBind,
) -> Result<busbar_contract::plane_calls::PlaneRegistration, String> {
    let plugin = Arc::new(bind()?);
    let declared = plugin.declared();
    Ok(registered(
        plugin.name(),
        &plugin.served(),
        &declared,
        Some(Arc::clone(&plugin)),
        bind,
    ))
}

type Judge = std::sync::OnceLock<Arc<crate::dispatch::Plugin<Plane>>>;

fn judge_of(
    judge: &Judge,
    bind: &ProbeBind,
) -> Result<Arc<crate::dispatch::Plugin<Plane>>, String> {
    if let Some(plugin) = judge.get() {
        return Ok(Arc::clone(plugin));
    }
    let plugin = Arc::new(bind()?);
    Ok(Arc::clone(judge.get_or_init(|| plugin)))
}

fn registered(
    name: &str,
    served: &ServedFacts,
    declared: &InstanceDecl,
    bound: Option<Arc<crate::dispatch::Plugin<Plane>>>,
    bind: ProbeBind,
) -> busbar_contract::plane_calls::PlaneRegistration {
    use crate::cold::dispatch::kinds as cold;
    let key = crate::intern_name(name);
    let judge: Judge = std::sync::OnceLock::new();
    if let Some(plugin) = bound {
        let _ = judge.set(plugin);
    }
    let judge_bind = Arc::clone(&bind);
    let dialects = cold::statement_list(&served.dialects);
    let probe: std::sync::Mutex<Option<Probe>> = std::sync::Mutex::new(None);
    let validate: busbar_contract::plane_calls::SectionJudge =
        Arc::new(move |settings: &[u8]| {
            let plugin = judge_of(&judge, &judge_bind)?;
            lifecycle::validate_json(&plugin, settings)
        });
    let face: busbar_contract::plane_calls::FacingProbe = Arc::new(
        move |settings: &[u8],
              owned: &[u8],
              public_url: Option<&str>,
              facts: &[busbar_contract::plane_calls::DialectFacts]| {
            let url = public_url.unwrap_or_default();
            let same = |p: &Probe| p.url == url && p.owned == owned && p.facts == facts;
            let lock = || {
                probe
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            };
            let taken = { lock().take() };
            let mut probe = match taken {
                Some(probe) if same(&probe) => probe,
                other => {
                    drop(other);
                    // A facing probe is bound once per changed plane settings.
                    let (probe_url, probe_owned, probe_facts) = cold::probe_key(url, owned, facts);
                    Probe {
                        url: probe_url,
                        owned: probe_owned,
                        facts: probe_facts,
                        plugin: bind()?,
                        generation: 0,
                    }
                }
            };
            let faced = facing(
                &probe.plugin,
                &dialects,
                &mut probe.generation,
                settings,
                owned,
                public_url,
                facts,
            );
            let spare = if faced.is_ok() && !probe.plugin.is_faulted() {
                lock().replace(probe)
            } else {
                Some(probe)
            };
            drop(spare);
            faced
        },
    );
    cold::plane_registration(key, served, declared, validate, face)
}

struct Probe {
    url: String,
    owned: Vec<u8>,
    facts: Vec<busbar_contract::plane_calls::DialectFacts>,
    plugin: crate::dispatch::Plugin<Plane>,

    generation: u64,
}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.plugin.is_open() {
            let called = self
                .plugin
                .call(life::CLOSE, &mut Frame::new(in_head(), out_head()));
            if called.outcome != Outcome::Ready {
                tracing::warn!(
                    plane = self.plugin.name(),
                    outcome = ?called.outcome,
                    "plane probe did not close"
                );
            }
        }
    }
}

/// The provider facts a plane's open is lent, one per dialect, borrowing `dialects`; built once
/// per plane open.
#[must_use]
pub fn provider_facts(
    dialects: &[busbar_contract::plane_calls::DialectFacts],
) -> Vec<busbar_contract::abi::plane::ProviderFacts> {
    crate::cold::dispatch::kinds::plane_provider_facts(dialects)
}

/// One dialect's provider facts, borrowing `d`.
pub(crate) fn provider(
    d: &busbar_contract::plane_calls::DialectFacts,
) -> busbar_contract::abi::plane::ProviderFacts {
    use busbar_contract::abi::mechanism::call::{BLOB_ABSENT, BLOB_JSON};
    let text = |s: &str| AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    };
    busbar_contract::abi::plane::ProviderFacts {
        name: text(&d.name),
        protocol: text(&d.protocol),
        error_map: match &d.error_map {
            Some(json) => Blob {
                ptr: json.as_ptr(),
                len: json.len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
            None => Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: BLOB_ABSENT,
                flags: 0,
            },
        },
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn open_door(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    owned: &[u8],
    public_url: Option<&str>,
) -> Result<OwnedSnapshot, String> {
    checked(plugin, opened(plugin, settings, owned, public_url, &[])?)
}

fn opened(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    owned: &[u8],
    public_url: Option<&str>,
    providers: &[busbar_contract::abi::plane::ProviderFacts],
) -> Result<Option<OwnedSnapshot>, String> {
    use busbar_contract::abi::mechanism::call::BLOB_JSON;
    let blob = |bytes: &[u8]| lifecycle::blob(bytes, BLOB_JSON, 0);
    let mut frame = Frame::new(
        PlaneOpenIn {
            open: lifecycle::open_in(blob(settings)),
            public_url: lifecycle::lend_or_null(public_url.unwrap_or_default()),
            owned: blob(owned),
            providers: if providers.is_empty() {
                std::ptr::null()
            } else {
                providers.as_ptr()
            },
            providers_len: providers.len(),
        },
        PlaneOpenOut {
            open: lifecycle::open_out(),
            snapshot: std::ptr::null(),
        },
    );
    let (called, snapshot) = plugin.open(&mut frame);
    if called.outcome != Outcome::Ready {
        return Err(called.open_failure(plugin.name()));
    }
    Ok(snapshot)
}

fn checked(
    plugin: &crate::dispatch::Plugin<Plane>,
    snapshot: Option<OwnedSnapshot>,
) -> Result<OwnedSnapshot, String> {
    snapshot.ok_or_else(|| crate::cold::dispatch::kinds::plane_snapshot_refused(plugin.name()))
}

#[cfg(any(test, feature = "test-support"))]
pub fn refresh_door(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    owned: &[u8],
    next: u64,
) -> Result<OwnedSnapshot, String> {
    checked(plugin, refreshed(plugin, settings, owned, next)?)
}

/// Refresh a served plane through its dispatcher. Contention with an ordinary crossing is
/// queued on the existing binding admission wake, not mistaken for a plugin refusal. The
/// config worker waits for the lifecycle result; request threads never wait here.
pub fn refresh_door_on(
    plugin: &crate::dispatch::Plugin<Plane>,
    dispatcher: &Arc<crate::dispatch::Dispatcher>,
    settings: &[u8],
    owned: &[u8],
    next: u64,
) -> Result<OwnedSnapshot, String> {
    use crate::dispatch::call::Ticketed;
    use busbar_contract::abi::mechanism::call::{DeadlineClass, BLOB_JSON, BLOB_OCTETS};

    // A queued or watchdog-detached crossing must never retain a loan into this caller's
    // stack. The dispatch job owns both byte buffers until it releases the input frame.
    let settings = SecureVec::from(settings);
    let extensions = SecureVec::from(if owned.is_empty() {
        Vec::new()
    } else {
        busbar_contract::abi::mechanism::extensions::encode(&[(plane::EXT_OWNED, owned)])
    });
    let inputs = Arc::new((settings, extensions));
    let mut call = (0..dispatcher.workers().max(1))
        .find_map(|worker| Ticketed::mint(dispatcher, worker))
        .ok_or_else(|| {
            crate::cold::dispatch::kinds::refusal("no ticket could be minted for a plane refresh")
        })?;
    let mut head = in_head();
    head.extensions = lifecycle::blob(&inputs.1, BLOB_OCTETS, 0);
    let frame = Frame::new(
        RefreshIn {
            head,
            generation: next,
            settings: lifecycle::blob(&inputs.0, BLOB_JSON, 0),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: std::ptr::null(),
        },
    );
    let deadline = crate::dispatch::now_ns().saturating_add(
        u64::try_from(dispatcher.budgets().lifecycle.as_nanos()).unwrap_or(u64::MAX),
    );
    call.submit(
        plugin,
        life::REFRESH,
        frame,
        DeadlineClass::Call,
        deadline,
        inputs,
    );
    // The dispatcher expires an unadmitted job at its deadline. Once a crossing starts,
    // retain its result custody until it returns or its own watchdog faults it: dropping
    // an active answer at the queue deadline could miss a legitimate late publication.
    let done = futures::executor::block_on(&mut call);
    let _lease = lifecycle::AnswerLease::new(plugin, done.lease);
    if done.outcome != Outcome::Ready {
        return Err(refresh_failure(
            plugin.name(),
            done.outcome,
            done.error.as_deref(),
        ));
    }
    // Copy before dropping the lifecycle ticket/answer lease. The caller serializes config
    // refreshes and owns this generation until its later RETIRE.
    checked(
        plugin,
        done.frame
            .and_then(|frame| copy_snapshot(frame.out.snapshot, plugin.dialects())),
    )
}

/// A refresh that did not come back READY, with the plugin's own error text when it gave one.
pub(crate) fn refresh_failure(name: &str, outcome: Outcome, error: Option<&[u8]>) -> String {
    crate::cold::dispatch::kinds::plane_refresh_failure(name, outcome, error)
}

fn refreshed(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    owned: &[u8],
    next: u64,
) -> Result<Option<OwnedSnapshot>, String> {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS};
    let blob = lifecycle::blob(settings, BLOB_JSON, 0);

    let extensions = if owned.is_empty() {
        Vec::new()
    } else {
        busbar_contract::abi::mechanism::extensions::encode(&[(
            busbar_contract::abi::plane::EXT_OWNED,
            owned,
        )])
    };
    let mut head = in_head();
    if !extensions.is_empty() {
        head.extensions = Blob {
            ptr: extensions.as_ptr(),
            len: extensions.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
    }
    let mut frame = Frame::new(
        RefreshIn {
            head,
            generation: next,
            settings: blob,
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: std::ptr::null(),
        },
    );
    let (called, snapshot) = plugin.refresh(&mut frame);
    if called.outcome != Outcome::Ready {
        return Err(refresh_failure(
            plugin.name(),
            called.outcome,
            called.error.as_deref(),
        ));
    }
    Ok(snapshot)
}

pub fn retire_door(plugin: &crate::dispatch::Plugin<Plane>, generation: u64) {
    use busbar_contract::abi::mechanism::lifecycle::GenIn;
    let mut retire = Frame::new(
        GenIn {
            head: in_head(),
            generation,
        },
        out_head(),
    );
    let called = plugin.call(life::RETIRE, &mut retire);
    if called.outcome != Outcome::Ready {
        tracing::warn!(
            plane = plugin.name(),
            generation,
            outcome = ?called.outcome,
            "plane generation did not retire"
        );
    }
}

fn facing(
    plugin: &crate::dispatch::Plugin<Plane>,
    dialects: &[&'static str],
    current: &mut u64,
    settings: &[u8],
    owned: &[u8],
    public_url: Option<&str>,
    facts: &[busbar_contract::plane_calls::DialectFacts],
) -> Result<busbar_contract::plane_calls::DoorFacing, String> {
    let snapshot = if *current == 0 {
        let providers = provider_facts(facts);
        let snapshot = opened(plugin, settings, owned, public_url, &providers)?;
        *current = 1;
        snapshot
    } else {
        let next = *current + 1;
        let snapshot = refreshed(plugin, settings, owned, next)?;
        retire_door(plugin, *current);
        *current = next;
        snapshot
    };
    let snapshot = checked(plugin, snapshot)?;
    Ok(crate::cold::dispatch::kinds::plane_facing(
        snapshot, dialects,
    ))
}

fn check_tail_fee_units(tail: &PlaneTail) -> Result<(), Fault> {
    let classes: Vec<BillableClass> = listed(tail.billable_classes, tail.billable_classes_len);
    for class in &classes {
        check_tail_text(class.class, "billable_class.class")?;
        check_tail_text(class.family, "billable_class.family")?;
    }
    check_billable_classes(&classes)?;
    let fee_units: Vec<AbiStr> = listed(tail.fee_units, tail.fee_units_len);
    for fee in &fee_units {
        check_tail_text(*fee, "tail.fee_units")?;
    }
    fee_units_checked(&fee_units, &classes, || {
        listed(tail.class_parents, tail.class_parents_len)
    })
}

/// BUSBAR-6017 (`PLUGIN_DECLARES_RETIRED_ABI_VALUE`): a plane declaring the retired trust role
/// `TRUST_PRIVATE_REACH` (4) is refused, naming the key and the role, before any other trust-key
/// rule reads it.
fn refuse_retired_trust_roles(tail: &PlaneTail) -> Result<(), String> {
    const CODE: busbar_contract::diagnostic::Banner = busbar_contract::diagnostic::Banner(6017);
    for key in listed(tail.trust_keys, tail.trust_keys_len) {
        if key.role == plane::TRUST_PRIVATE_REACH {
            return Err(crate::cold::dispatch::kinds::retired_trust_role(
                CODE,
                kept(key.key),
            ));
        }
    }
    Ok(())
}

fn check_tail_trust_keys(tail: &PlaneTail) -> Result<(), Fault> {
    let keys = listed(tail.trust_keys, tail.trust_keys_len);
    check_trust_keys(&keys)?;
    for key in keys {
        let mechanisms = listed(key.mechanisms, key.mechanisms_len);
        check_pin_mechanisms(&mechanisms)?;
    }
    Ok(())
}

pub(crate) fn owned_str(
    s: busbar_contract::abi::mechanism::call::AbiStr,
) -> Option<Option<String>> {
    snapshot_text_of(s).map(|t| t.map(crate::cold::dispatch::kinds::snapshot_text))
}

pub(crate) fn owned_blob(b: Blob) -> Option<Option<Vec<u8>>> {
    snapshot_bytes_of(b).map(|bytes| bytes.map(crate::cold::dispatch::kinds::snapshot_bytes))
}
