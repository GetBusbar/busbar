// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::check::{fault, reported, Fault, Rule};
use busbar_contract::abi::mechanism::door::{
    Statement, SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, DriveIn, OpenIn, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::{
    check_arrive, check_billable_classes, check_cancel, check_cancel_records, check_drive,
    check_fee_units, check_metric_lanes, check_on_piece, check_pin_mechanisms, check_project,
    check_record_chains, check_record_retentions, check_refusal, check_refusal_statuses,
    check_route_cost, check_sections, check_serve, check_snapshot, check_tail, check_trust_keys,
    Bounds, Caps, ProjectHost, MAX_SESSIONS,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, BillableClass, OnPieceIn, OnPieceOut, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RecordWrite, RefusalIn, RefusalOut, RefusalStatus, ServeIn, ServeOut,
};
use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::InstanceDecl;

use crate::dispatch::lifecycle;
use crate::dispatch::{
    in_head, lifecycle_name, out_head, stamp_drive, Answer, CancelFrame, Context, DriveFrame,
    Frame, InFrame, Kind, OutFrame,
};

const PLANE_TAIL_FROZEN: usize = std::mem::offset_of!(PlaneTail, stream_ceiling_secs);

/// The plane kind.
#[derive(Debug, Clone, Copy)]
pub struct Plane;

// SAFETY: `#[repr(C)]` in `abi/plane/`, each leading with its head (`PlaneOpenIn` with an
// `OpenIn`, `PlaneOpenOut` with an `OpenOut`, each of which leads with its head); their pointers
// are host buffers, host-borrowed inputs, or the plugin's generation snapshot, valid until
// `retire` of its generation.
unsafe impl InFrame for PlaneOpenIn {}
unsafe impl InFrame for PlaneDriveIn {}
unsafe impl InFrame for plane::PlaneCancelIn {}
unsafe impl InFrame for ArriveIn {}
unsafe impl InFrame for OnPieceIn {}
unsafe impl InFrame for RefusalIn {}
unsafe impl InFrame for ServeIn {}
unsafe impl InFrame for ProjectIn {}
unsafe impl InFrame for plane::CatalogIn {}
unsafe impl OutFrame for PlaneOpenOut {}
unsafe impl OutFrame for PlaneRefreshOut {}
unsafe impl OutFrame for PlaneDriveOut {}
unsafe impl OutFrame for plane::PlaneCancelOut {}
unsafe impl OutFrame for ArriveOut {}
unsafe impl OutFrame for OnPieceOut {}
unsafe impl OutFrame for RefusalOut {}
unsafe impl OutFrame for ServeOut {}
unsafe impl OutFrame for ProjectOut {}
unsafe impl OutFrame for plane::CatalogOut {}

/// What the instance's tail states that the host keeps: the list bounds every answer's indices are
/// judged against, and the refusal statuses the kernel chooses from. Read once at bind.
#[derive(Debug, Clone)]
pub struct PlaneFacts {
    /// The tail's list lengths.
    pub bounds: Bounds,
    /// The tail's refusal statuses, each judged by `check_refusal_statuses` at bind.
    pub refusal_statuses: Vec<RefusalStatus>,
    /// What the tail declares for the instance's admission (its label is the bind's).
    pub declared: InstanceDecl,
    /// What the composition root serves the instance by.
    pub served: ServedFacts,
}

/// WHAT THE COMPOSITION ROOT SERVES A PLANE INSTANCE BY, kept from its Statement at bind: the
/// section it declares (the configuration it opens with), its operation classes in tail order (what
/// `arrive`'s `op_class` indexes) and the `audit_kind` its admin rows are written under.
#[derive(Debug, Clone, Default)]
pub struct ServedFacts {
    /// The key of the one section the Statement declares.
    pub section: &'static str,
    /// The keys of the sections the Statement reads beside it (`SECTION_CONSUMED`), in its order:
    /// the plane opens with all of them, one `{section: value}` object (spec Part 1 §4).
    pub consumed: Vec<&'static str>,
    /// The keys of the other sections it owns (neither declaring nor consumed): what it opens
    /// with beside its settings (`PlaneOpenIn::owned`).
    pub owns: Vec<&'static str>,
    /// The keys of the sections it consumes (`SECTION_CONSUMED`), in Statement order.
    pub consumes: Vec<&'static str>,
    /// The keys of the sections it marks required (`SECTION_REQUIRED`), in Statement order: a
    /// document must carry each while the plane is linked (CONFIG-REQ).
    pub requires: Vec<&'static str>,
    /// The Statement's secret-reference paths (`Statement::secret_refs`), in order.
    pub secret_refs: Vec<&'static str>,
    /// The admin routes the tail states, in order.
    pub admin_routes: Vec<busbar_contract::plane_calls::StatedAdminRoute>,
    /// Their OpenAPI fragment, as the tail states it (kept for the process).
    pub admin_openapi: Option<&'static [u8]>,
    /// The tail's operation classes, in order.
    pub op_classes: Vec<&'static str>,
    /// The tail's `audit_kind`.
    pub audit_kind: &'static str,
    /// The tail's billable classes, in order: a unit count's `class` indexes them (the money
    /// steps ledger each count under its class name, THE DESIGN §7).
    pub billable_classes: Vec<&'static str>,
    /// The validated routing-cost terms: billable-class index and default expected units.
    pub route_cost: Vec<(u32, f64)>,
    /// The tail's fee units, each also one of [`Self::billable_classes`]: the plane's report of
    /// whether a unit incurred its fee (THE DESIGN §7, "the plane reports ... whether a fee unit was
    /// incurred").
    pub fee_units: Vec<&'static str>,
    /// The tail's counter lane words (`PlaneTail::metric_lanes`): the words beside the operator's
    /// entry names a stated attempt `lane` label may carry.
    pub metric_lanes: Vec<&'static str>,
    /// Declared response media types requiring streamed delivery.
    pub streaming_content_types: Vec<&'static str>,
    /// Each need's response-head rule, in Statement need order (`Need::keep_mode`, its kept and
    /// denied names): what of a far end's head the host hands the plane on that need.
    pub keeps: Vec<NeedKeep>,
    /// Each need's direction and auth element, in Statement need order (`Need::direction`,
    /// `Need::auth`): what a member's resolved style is matched against at config load.
    pub need_auths: Vec<(u32, &'static str)>,
    /// Each need's `target_from`, in Statement need order: a member-target path
    /// (`busbar_contract::section::member_target`) names where each registration's member is
    /// reached.
    pub need_targets: Vec<&'static str>,
    /// Each need's `trust_from`, in Statement need order: on a member-target need, a member path
    /// (`settings.*.<key>`) names, per registration, the object holding busbar's client identity
    /// for it, `{cert, key}` as secret references.
    pub need_trust: Vec<&'static str>,
    /// The tail's kernel-owned trust keys: a registration whose pin names a mechanism that pins the
    /// far end's key (`PinMechanismDecl::peer_key`) has that key sealed into its member route.
    pub trust_keys: Vec<TrustKeyDecl>,
    /// Each need's transport, in the same order (`Need::transport`): a member binds at most one
    /// need per (transport, auth).
    pub need_transports: Vec<&'static str>,
    /// The tail's dialects, in order.
    pub dialects: Vec<&'static str>,
    /// The tail's `dialect_auth`: each dialect's default outbound style, by its dialect index
    /// (THE DESIGN §6 step 2: a provider entry's `auth:`, else this), and the style's parameters
    /// for it, a JSON object's text (empty: none).
    pub dialect_auth: Vec<(u32, &'static str, &'static [u8])>,
    /// Each dialect's `DIALECT_*` flags off its `dialect_auth` line, parallel to
    /// [`Self::dialects`] (`0` for a dialect with no line): whether a provider may name it
    ///.
    pub dialect_flags: Vec<u32>,
    /// The tail's `label`, `subject_noun` and `admin_noun` (what the kernel's registry entry names
    /// the plane and one registration by).
    pub nouns: (&'static str, &'static str, &'static str),
    /// The tail's billable classes' unit families, parallel to [`Self::billable_classes`].
    pub billable_families: Vec<&'static str>,
    /// Whether the tail states `TAIL_PROBES`: the plane answers the kernel's health probe unit.
    pub probes: bool,
    /// Whether the tail states `TAIL_FALLBACK`: the plane is the catch-all.
    pub fallback: bool,
    /// The tail's `caller_credential_refusal`; `""` = it states none.
    pub caller_credential_refusal: &'static str,
    /// The tail's `TAIL_*` flags (the fallback catch-all, probes, the gate-first hook order).
    pub tail_flags: u32,
    /// The tail's `stream_ceiling_secs`: how long a unit whose `arrive` states `ROUTE_STREAM` may
    /// run once its route is known; `0` = no ceiling.
    pub stream_ceiling_secs: u64,
    /// The provider-key descriptor the Statement's extensions state
    /// (`busbar_contract::provider_keys::EXT_PROVIDER_KEYS`), judged in the neutral shape
    /// vocabulary at bind; `None` = it states none.
    pub provider_keys: Option<busbar_contract::provider_keys::ProviderKeys>,
}

/// ONE NEED'S RESPONSE-HEAD RULE, as its Statement declares it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeedKeep {
    /// `KEEP_NAMED` or `KEEP_ALL_EXCEPT_DENIED`.
    pub mode: u32,
    /// `keep_response_headers`.
    pub kept: Vec<&'static str>,
    /// `deny_response_headers`.
    pub denied: Vec<&'static str>,
}

fn bounds<'a>(a: &Answer<'a>) -> Result<&'a Bounds, Fault> {
    a.context::<PlaneFacts>()
        .map(|f| &f.bounds)
        .ok_or(fault(Rule::Missing, "plane.tail"))
}

fn tail_facts(st: &Statement) -> Result<PlaneFacts, String> {
    OVER_CAP.with(|c| c.set(false));
    let facts = tail_facts_read(st);
    if OVER_CAP.with(|c| c.replace(false)) {
        return Err("the plane tail states a list or string longer than its cap".to_string());
    }
    facts
}

std::thread_local! {
    /// A tail read ([`kept`], [`kept_blob`], [`listed`]) met a length over its cap, or a list or
    /// string NULL with a count: nothing was formed over it, and [`tail_facts`] refuses the plane
    /// (THE DESIGN §11.13 M1, "Every slice built from a plugin-reported length is capped and
    /// validated before it is formed").
    static OVER_CAP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn over_cap() {
    OVER_CAP.with(|c| c.set(true));
}

fn tail_facts_read(st: &Statement) -> Result<PlaneFacts, String> {
    // SAFETY: `PlaneTail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid); a
    // non-NULL kind tail is `'static` plugin data of its stated size.
    let tail: PlaneTail =
        unsafe { crate::dispatch::plugin::kind_tail(st, "a plane", PLANE_TAIL_FROZEN) }?;
    check_tail(&tail).map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_trust_keys(&tail)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_fee_units(&tail)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;

    check_record_chains(
        &listed(tail.record_chains, tail.record_chains_len),
        tail.record_kinds_len as u64,
    )
    .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;

    check_record_retentions(
        &listed(tail.record_retentions, tail.record_retentions_len),
        tail.record_kinds_len as u64,
    )
    .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_route_cost(
        &listed(tail.route_cost, tail.route_cost_len),
        tail.billable_classes_len as u64,
    )
    .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    let streaming_content_types = listed(
        tail.streaming_content_types,
        tail.streaming_content_types_len,
    );
    for media in &streaming_content_types {
        check_tail_text(*media, "tail.streaming_content_types")
            .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    }
    let metric_lanes = listed(tail.metric_lanes, tail.metric_lanes_len);
    for lane in &metric_lanes {
        check_tail_text(*lane, "tail.metric_lanes")
            .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    }
    // SAFETY: the bound Statement owns these static lane bytes for the loaded plugin lifetime.
    unsafe { check_metric_lanes(&metric_lanes) }
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;

    let sections = listed(st.sections, st.sections_len);
    check_sections(&sections)
        .map_err(|f| format!("the plane's sections break {:?} at {}", f.rule, f.field))?;
    let refusal_statuses = listed(tail.refusal_statuses, tail.refusal_statuses_len);
    check_refusal_statuses(&refusal_statuses, tail.dialects_len as u64)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;

    busbar_contract::abi::plane::check::check_dialect_auth(
        &listed(tail.dialect_auth, tail.dialect_auth_len),
        tail.dialects_len as u64,
    )
    .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    let mut decl = declared(&tail);
    decl.ticket_prefix = ticket_prefix(st)?;

    let extensions = if st.extensions.len
        > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize
        || (st.extensions.len != 0 && st.extensions.ptr.is_null())
    {
        &[][..]
    } else {
        // SAFETY: the raw length is bounded above; Statement bytes live for the loaded instance.
        unsafe { crate::dispatch::validate::lent(st.extensions.ptr, st.extensions.len) }
            .ok_or("invalid plane Statement extensions")?
    };
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
        if decl
            .conditional_record_kinds
            .iter()
            .any(|&k| k as usize >= decl.record_kinds.len())
        {
            return Err("conditional record kind is not declared".into());
        }
    }
    Ok(PlaneFacts {
        bounds: Bounds::of(&tail),
        refusal_statuses,
        declared: decl,
        served: ServedFacts {
            section: sections
                .iter()
                .find(|s| s.flags & SECTION_DECLARING != 0)
                .map_or("", |s| kept(s.name)),
            consumed: sections
                .iter()
                .filter(|s| s.flags & SECTION_CONSUMED != 0)
                .map(|s| kept(s.name))
                .collect(),
            owns: sections
                .iter()
                .filter(|s| s.flags & (SECTION_DECLARING | SECTION_CONSUMED) == 0)
                .map(|s| kept(s.name))
                .collect(),
            consumes: sections
                .iter()
                .filter(|s| s.flags & SECTION_CONSUMED != 0)
                .map(|s| kept(s.name))
                .collect(),
            requires: sections
                .iter()
                .filter(|s| s.flags & SECTION_REQUIRED != 0)
                .map(|s| kept(s.name))
                .collect(),
            secret_refs: listed(st.secret_refs, st.secret_refs_len)
                .into_iter()
                .map(kept)
                .collect(),
            admin_routes: listed(tail.admin_routes, tail.admin_routes_len)
                .into_iter()
                .map(|r| busbar_contract::plane_calls::StatedAdminRoute {
                    verb: kept(r.verb),
                    target: kept(r.target),
                    flags: r.flags,
                    audit_verb: kept(r.audit_verb),
                })
                .collect(),
            admin_openapi: (!tail.admin_openapi.ptr.is_null())
                .then(|| kept_blob(tail.admin_openapi)),
            op_classes: listed(tail.op_classes, tail.op_classes_len)
                .into_iter()
                .map(|c| kept(c.op))
                .collect(),
            audit_kind: kept(tail.audit_kind),
            billable_classes: listed(tail.billable_classes, tail.billable_classes_len)
                .into_iter()
                .map(|c| kept(c.class))
                .collect(),
            route_cost: listed(tail.route_cost, tail.route_cost_len)
                .into_iter()
                .map(|term| (term.class, term.weight))
                .collect(),
            fee_units: listed(tail.fee_units, tail.fee_units_len)
                .into_iter()
                .map(kept)
                .collect(),
            streaming_content_types: streaming_content_types.into_iter().map(kept).collect(),
            metric_lanes: listed(tail.metric_lanes, tail.metric_lanes_len)
                .into_iter()
                .map(kept)
                .collect(),
            keeps: listed(st.needs, st.needs_len)
                .into_iter()
                .map(|n| NeedKeep {
                    mode: n.keep_mode,
                    kept: listed(n.keep_response_headers, n.keep_response_headers_len)
                        .into_iter()
                        .map(kept)
                        .collect(),
                    denied: listed(n.deny_response_headers, n.deny_response_headers_len)
                        .into_iter()
                        .map(kept)
                        .collect(),
                })
                .collect(),
            need_auths: listed(st.needs, st.needs_len)
                .into_iter()
                .map(|n| (n.direction, kept(n.auth)))
                .collect(),
            need_targets: listed(st.needs, st.needs_len)
                .into_iter()
                .map(|n| kept(n.target_from))
                .collect(),
            need_trust: listed(st.needs, st.needs_len)
                .into_iter()
                .map(|n| kept(n.trust_from))
                .collect(),
            trust_keys: declared(&tail).trust_keys,
            need_transports: listed(st.needs, st.needs_len)
                .into_iter()
                .map(|n| kept(n.transport))
                .collect(),
            dialects: listed(tail.dialects, tail.dialects_len)
                .into_iter()
                .map(kept)
                .collect(),
            dialect_auth: listed(tail.dialect_auth, tail.dialect_auth_len)
                .into_iter()
                .map(|d| (d.dialect, kept(d.style), kept_blob(d.params)))
                .collect(),
            dialect_flags: dialect_flags(&tail),
            nouns: (
                kept(tail.label),
                kept(tail.subject_noun),
                kept(tail.admin_noun),
            ),
            billable_families: listed(tail.billable_classes, tail.billable_classes_len)
                .into_iter()
                .map(|c| kept(c.family))
                .collect(),
            probes: tail.flags & busbar_contract::abi::plane::TAIL_PROBES != 0,
            fallback: tail.flags & busbar_contract::abi::plane::TAIL_FALLBACK != 0,
            caller_credential_refusal: kept(tail.caller_credential_refusal),
            tail_flags: tail.flags,
            stream_ceiling_secs: tail.stream_ceiling_secs,
            provider_keys: stated_provider_keys(st.extensions)?,
        },
    })
}

fn stated_provider_keys(
    ext: Blob,
) -> Result<Option<busbar_contract::provider_keys::ProviderKeys>, String> {
    if ext.ptr.is_null() || ext.len == 0 {
        return Ok(None);
    }
    if ext.len > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err("the Statement's extensions are longer than any blob may be".into());
    }
    // SAFETY: a non-NULL Statement blob is `len` bytes of `'static` plugin data, read here while the
    // plugin is loaded, its length capped before the slice is formed; the descriptor is decoded
    // into owned values before this returns.
    let bytes = unsafe { crate::dispatch::validate::lent(ext.ptr, ext.len) }
        .ok_or("the Statement's extensions are longer than any blob may be")?;
    busbar_contract::provider_keys::stated(bytes)
        .map_err(|e| format!("the plane's provider keys are refused: {e}"))
}

fn dialect_flags(tail: &busbar_contract::abi::plane::PlaneTail) -> Vec<u32> {
    let mut flags = vec![0; listed(tail.dialects, tail.dialects_len).len()];
    for d in listed(tail.dialect_auth, tail.dialect_auth_len) {
        if let Some(f) = flags.get_mut(d.dialect as usize) {
            *f |= d.flags;
        }
    }
    flags
}

fn kept(s: AbiStr) -> &'static str {
    if check_tail_text(s, "plane.tail.text").is_err() {
        over_cap();
        return "";
    }
    if s.len == 0 {
        return "";
    }
    // SAFETY: `check_tail` judged every tail string: a non-NULL span of `len` bytes of `'static`
    // plugin data, read here while the plugin is loaded and copied; its length capped first.
    let Some(bytes) = (unsafe { crate::dispatch::validate::lent_str(s) }) else {
        over_cap();
        return "";
    };
    crate::intern_name(&String::from_utf8_lossy(bytes))
}

fn kept_blob(b: Blob) -> &'static [u8] {
    if busbar_contract::abi::mechanism::check::blob(&b, "plane.tail.blob", "plane.tail.blob")
        .is_err()
    {
        over_cap();
        return &[];
    }
    if b.len == 0 {
        return &[];
    }
    // SAFETY: `check_dialect_auth` judged the blob (`tail_facts`): a non-NULL span of `len` bytes of
    // `'static` plugin data, read here while the plugin is loaded and copied; its length capped
    // first.
    let Some(bytes) = (unsafe { crate::dispatch::validate::lent(b.ptr, b.len) }) else {
        over_cap();
        return &[];
    };

    static BLOBS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<&'static [u8]>>> =
        std::sync::OnceLock::new();
    let mut blobs = BLOBS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(kept) = blobs.get(bytes) {
        return kept;
    }
    let kept: &'static [u8] = bytes.to_vec().leak();
    blobs.insert(kept);
    kept
}

fn kept_mechanisms(mechanisms: Vec<PinMechanismDecl>) -> &'static [PinMechanismDecl] {
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

fn listed<T: Copy>(p: *const T, n: usize) -> Vec<T> {
    if busbar_contract::abi::mechanism::check::bounded(p, n, "plane.tail.list").is_err() {
        over_cap();
        return Vec::new();
    }
    // SAFETY: `check_tail` refused a NULL list counted non-zero; the list is `'static` plugin data
    // of `n` entries, its length capped before the slice is formed.
    let Some(list) = (unsafe { crate::dispatch::validate::lent(p, n) }) else {
        over_cap();
        return Vec::new();
    };
    list.to_vec()
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
            return Err("the plane declares an empty issued-id prefix".to_string());
        }
        if found.replace(word).is_some() {
            return Err("the plane declares two issued-id prefixes".to_string());
        }
    }
    Ok(found)
}

fn declared(t: &PlaneTail) -> InstanceDecl {
    let words = |p: *const AbiStr, n: usize| -> Vec<&'static str> {
        listed(p, n).into_iter().map(kept).collect()
    };
    let (domain, prefix) = (kept(t.signing_domain), kept(t.signing_kid_prefix));
    let trust_keys = listed(t.trust_keys, t.trust_keys_len)
        .into_iter()
        .map(|k| TrustKeyDecl {
            key: kept(k.key),
            role: match k.role {
                plane::TRUST_PIN => TrustRole::Pin,
                plane::TRUST_REVERIFY_TTL => TrustRole::ReverifyTtl,
                plane::TRUST_PRIVATE_REACH => TrustRole::PrivateReach,
                plane::TRUST_ITEM_APPROVALS => TrustRole::ItemApprovals,
                _ => TrustRole::RecoveryBackoff,
            },
            fingerprint: k.flags & plane::PIN_FINGERPRINT != 0,
            default: Some(kept(k.default)).filter(|d| !d.is_empty()),
            mechanisms: kept_mechanisms(
                listed(k.mechanisms, k.mechanisms_len)
                    .into_iter()
                    .map(|m| PinMechanismDecl {
                        token: kept(m.token),
                        root: m.flags & plane::MECHANISM_ROOT != 0,
                        peer_key: m.flags & plane::MECHANISM_PEER_KEY != 0,
                    })
                    .collect::<Vec<_>>(),
            ),
        })
        .collect();
    InstanceDecl {
        conditional_records: false,
        conditional_record_kinds: Vec::new(),
        label: Arc::from(""),
        record_kinds: words(t.record_kinds, t.record_kinds_len),
        signing: (!domain.is_empty() && !prefix.is_empty()).then_some((domain, prefix)),
        scope_kinds: words(t.scope_kinds, t.scope_kinds_len),
        trust_keys,
        record_chains: listed(t.record_chains, t.record_chains_len),
        record_retentions: listed(t.record_retentions, t.record_retentions_len),
        ticket_prefix: None,
    }
}

impl crate::dispatch::Plugin<Plane> {
    pub fn declared(&self) -> InstanceDecl {
        let mut d = self
            .inner
            .context::<PlaneFacts>()
            .map(|f| f.declared.clone())
            .unwrap_or_default();
        if let Some(c) = self.inner.wake.caller.get() {
            d.label = Arc::clone(&c.instance);
        }
        d
    }

    pub fn served(&self) -> ServedFacts {
        self.inner
            .context::<PlaneFacts>()
            .map(|f| f.served.clone())
            .unwrap_or_default()
    }

    pub fn refusal_statuses(&self) -> &[RefusalStatus] {
        self.inner
            .context::<PlaneFacts>()
            .map_or(&[], |f| f.refusal_statuses.as_slice())
    }

    fn dialects(&self) -> u64 {
        self.inner
            .context::<PlaneFacts>()
            .map_or(0, |f| f.bounds.dialects)
    }
}

pub type ProbeBind = Arc<dyn Fn() -> Result<crate::dispatch::Plugin<Plane>, String> + Send + Sync>;

pub fn linked_probe(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    instance: &str,
) -> ProbeBind {
    static PROBE: std::sync::OnceLock<crate::dispatch::Dispatcher> = std::sync::OnceLock::new();
    let instance: Arc<str> = Arc::from(instance);
    Arc::new(move || {
        let dispatcher = PROBE.get_or_init(|| {
            crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default())
        });
        let row = crate::dispatch::LinkedRow::of(door).map_err(|e| format!("{e:?}"))?;
        crate::dispatch::load_linked::<Plane>(
            &row,
            crate::dispatch::Bind {
                instance: Arc::clone(&instance),
                max_inflight_cap: 64,
                sink: Arc::new(crate::dispatch::NoSink),
                dispatcher: dispatcher.adopter(),
                conns: crate::dispatch::ConnTable::Probe,
            },
        )
        .map_err(|e| format!("{e:?}"))
    })
}

pub fn linked_cli_help(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<Option<&'static str>, String> {
    let (door, _) = crate::dispatch::load::read_door(
        crate::dispatch::load::enter_door(crate::dispatch::load::raw(door)),
        Some(KindCode::Plane),
    )
    .map_err(|e| format!("{e:?}"))?;
    let st = crate::dispatch::load::statement(&door).map_err(|e| format!("{e:?}"))?;
    // SAFETY: `PlaneTail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid); a
    // non-NULL kind tail is `'static` plugin data of its stated size.
    let tail: PlaneTail =
        unsafe { crate::dispatch::plugin::kind_tail(&st, "a plane", PLANE_TAIL_FROZEN) }?;
    check_tail(&tail).map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_text(tail.cli_help, "tail.cli_help")
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    let help = kept(tail.cli_help);
    Ok((!help.is_empty()).then_some(help))
}

pub fn rendered_cli_help(rendering: &[u8]) -> Result<Option<String>, String> {
    use busbar_contract::abi::mechanism::rendering::{read, read_plane_cli_help};
    let r = read(rendering).map_err(|e| {
        format!(
            "the plane Statement rendering does not read back: byte {} is not {}",
            e.at, e.what
        )
    })?;
    if r.kind != KindCode::Plane as u32 {
        return Err(format!(
            "the Statement rendering states kind {}, not plane",
            r.kind
        ));
    }
    if r.kind_tail_size == 0 {
        return Err("a plane states no kind tail".to_string());
    }
    let help = read_plane_cli_help(&r.kind_tail).map_err(|e| {
        format!(
            "the plane tail's rendering does not read back: byte {} is not {}",
            e.at, e.what
        )
    })?;
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
    let v = crate::dispatch::load::validate::<Plane>(door).map_err(|e| e.to_string())?;
    let name = crate::dispatch::plugin::str_bytes(v.statement.name)
        .map(|n| String::from_utf8_lossy(n).into_owned())
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
    let name = plugin.name().to_string();
    Ok(registered(
        &name,
        &plugin.served(),
        &declared,
        Some(plugin),
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
    let (label, subject_noun, admin_noun) = served.nouns;
    let key = crate::intern_name(name);
    let refusal = served.caller_credential_refusal;
    let judge: Judge = std::sync::OnceLock::new();
    if let Some(plugin) = bound {
        let _ = judge.set(plugin);
    }
    let judge_bind = Arc::clone(&bind);
    let dialects = served.dialects.clone();
    let probe: std::sync::Mutex<Option<Probe>> = std::sync::Mutex::new(None);
    busbar_contract::plane_calls::PlaneRegistration {
        key,
        section: served.section,
        owns: served.owns.clone(),
        consumes: served.consumes.clone(),
        requires: served.requires.clone(),
        secret_refs: served.secret_refs.clone(),
        admin_routes: served.admin_routes.clone(),
        admin_openapi: served.admin_openapi,
        streaming_content_types: served.streaming_content_types.clone(),
        label,
        subject_noun,
        admin_noun,
        audit_kind: served.audit_kind,
        signing: declared.signing,
        dialects: served.dialects.clone(),
        dialect_flags: served.dialect_flags.clone(),
        scope_kinds: declared.scope_kinds.clone(),
        billable_classes: served
            .billable_classes
            .iter()
            .copied()
            .zip(served.billable_families.iter().copied())
            .collect(),
        fee_units: served.fee_units.clone(),
        record_kinds: declared.record_kinds.clone(),
        trust_keys: declared.trust_keys.clone(),
        caller_credential_refusal: (!refusal.is_empty()).then_some(refusal),
        fallback: served.fallback,
        provider_keys: served.provider_keys.clone(),
        validate: Arc::new(move |settings: &[u8]| {
            let plugin = judge_of(&judge, &judge_bind)?;
            lifecycle::validate_json(&plugin, settings)
        }),
        facing: Arc::new(
            move |settings: &[u8],
                  owned: &[u8],
                  public_url: Option<&str>,
                  facts: &[busbar_contract::plane_calls::DialectFacts]| {
                let url = public_url.unwrap_or_default().to_string();
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
                        Probe {
                            url: url.clone(),
                            owned: owned.to_vec(),
                            facts: facts.to_vec(),
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
        ),
    }
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

#[must_use]
pub fn provider_facts(
    dialects: &[busbar_contract::plane_calls::DialectFacts],
) -> Vec<busbar_contract::abi::plane::ProviderFacts> {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON};
    let text = |s: &str| AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    };
    dialects
        .iter()
        .map(|d| busbar_contract::abi::plane::ProviderFacts {
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
        })
        .collect()
}

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
    snapshot.ok_or_else(|| {
        format!(
            "plane `{}`'s snapshot did not pass the host's checks",
            plugin.name()
        )
    })
}

pub fn refresh_door(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    owned: &[u8],
    next: u64,
) -> Result<OwnedSnapshot, String> {
    checked(plugin, refreshed(plugin, settings, owned, next)?)
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
        return Err(format!(
            "plane `{}` did not refresh: {:?}",
            plugin.name(),
            called.outcome
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
        let snapshot = refreshed(plugin, settings, &[], next)?;
        retire_door(plugin, *current);
        *current = next;
        snapshot
    };
    let snapshot = checked(plugin, snapshot)?;
    Ok(busbar_contract::plane_calls::DoorFacing {
        claims: snapshot
            .claims
            .iter()
            .map(|c| {
                let dialect = dialects
                    .get(usize::from(c.refusal_dialect))
                    .copied()
                    .unwrap_or_default();
                (c.target.clone(), dialect)
            })
            .collect(),
        admission: snapshot.audience.zip(snapshot.resource_metadata),
        listed: snapshot.listed,
    })
}

fn check_tail_fee_units(tail: &PlaneTail) -> Result<(), Fault> {
    let classes: Vec<BillableClass> = listed(tail.billable_classes, tail.billable_classes_len);
    for class in &classes {
        check_tail_text(class.class, "billable_class.class")?;
    }
    check_billable_classes(&classes)?;
    let fee_units: Vec<AbiStr> = listed(tail.fee_units, tail.fee_units_len);
    for fee in &fee_units {
        check_tail_text(*fee, "tail.fee_units")?;
    }
    // SAFETY: the bound Statement owns the static fee/class bytes for the loaded plugin lifetime.
    unsafe { check_fee_units(&fee_units, &classes) }
}

fn check_tail_text(text: AbiStr, field: &'static str) -> Result<(), Fault> {
    busbar_contract::abi::mechanism::check::text(text, field)?;
    if text.len as u64 > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES {
        return Err(fault(Rule::OverMax, field));
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

impl Kind for Plane {
    const CODE: KindCode = KindCode::Plane;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(tail_facts(st)?)))
    }
    type Ops = plane::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn optional_slot(s: u32) -> bool {
        s == slot::CATALOG
    }

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::ARRIVE => "arrive",
            slot::ON_PIECE => "on_piece",
            slot::REFUSAL => "refusal",
            slot::SERVE => "serve",
            slot::HYDRATE => "hydrate",
            slot::START => "start",
            slot::PROJECT => "project",
            slot::CATALOG => "catalog",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::ARRIVE => arrive(a),
            slot::ON_PIECE => on_piece(a),
            slot::REFUSAL => {
                let i = a.input::<RefusalIn>()?;
                let o = a.out::<RefusalOut>()?;
                // SAFETY: `fields_buf` is the host's own buffer of `fields_cap` `OutField`s,
                // named by this op's `in`.
                let fields = unsafe {
                    reported(
                        i.fields_buf.cast_const(),
                        u64::from(o.fields_written),
                        i.fields_cap as u64,
                        "refusal.fields",
                    )
                }?;
                let caps = Caps {
                    reply: i.reply_cap as u64,
                    fields: i.fields_cap as u64,
                    arena: i.arena_cap as u64,
                    records: i.records_cap as u64,
                    ..Caps::default()
                };
                // SAFETY: `records_buf` is the host's own buffer of `records_cap` `RecordWrite`s,
                // named by this op's `in` (NULL with `0` from a host that lends none).
                let records = unsafe {
                    reported(
                        i.records_buf.cast_const(),
                        u64::from(o.records_written),
                        i.records_cap as u64,
                        "refusal.records",
                    )
                }?;

                let b = if o.records_written == 0 {
                    Bounds::default()
                } else {
                    *bounds(a)?
                };
                check_refusal(a.outcome, o, fields, records, &caps, &b)
            }
            slot::SERVE => {
                let i = a.input::<ServeIn>()?;
                let o = a.out::<ServeOut>()?;
                // SAFETY: as `refusal`: the host's `fields_buf` of `fields_cap` elements.
                let fields = unsafe {
                    reported(
                        i.fields_buf.cast_const(),
                        u64::from(o.fields_written),
                        i.fields_cap as u64,
                        "serve.fields",
                    )
                }?;
                let caps = Caps {
                    reply: i.reply_cap as u64,
                    fields: i.fields_cap as u64,
                    arena: i.arena_cap as u64,
                    records: i.records_cap as u64,
                    ..Caps::default()
                };
                // SAFETY: as `refusal`: the host's `records_buf` of `records_cap` elements.
                let records = unsafe {
                    reported(
                        i.records_buf.cast_const(),
                        u64::from(o.records_written),
                        i.records_cap as u64,
                        "serve.records",
                    )
                }?;
                let b = if o.records_written == 0 {
                    Bounds::default()
                } else {
                    *bounds(a)?
                };
                check_serve(a.outcome, o, fields, records, &caps, &b)
            }
            slot::PROJECT => project(a),
            slot::CATALOG => {
                let i = a.input::<plane::CatalogIn>()?;
                let o = a.out::<plane::CatalogOut>()?;
                // SAFETY: as `refusal`: the host's `fields_buf` of `fields_cap` elements.
                let fields = unsafe {
                    reported(
                        i.fields_buf.cast_const(),
                        u64::from(o.fields_written),
                        i.fields_cap as u64,
                        "catalog.fields",
                    )
                }?;
                let caps = Caps {
                    reply: i.reply_cap as u64,
                    fields: i.fields_cap as u64,
                    arena: i.arena_cap as u64,
                    ..Caps::default()
                };
                plane::check::check_catalog(a.outcome, o, fields, &caps)
            }
            life::OPEN if a.outcome == Outcome::Ready => {
                let generation = a.input::<OpenIn>()?.generation;
                snapshot(
                    a.out::<PlaneOpenOut>()?.snapshot,
                    generation,
                    "open.snapshot",
                )
            }
            life::REFRESH if a.outcome == Outcome::Ready => {
                let generation = a.input::<RefreshIn>()?.generation;
                snapshot(
                    a.out::<PlaneRefreshOut>()?.snapshot,
                    generation,
                    "refresh.snapshot",
                )
            }
            life::CANCEL => {
                let i = a.input::<plane::PlaneCancelIn>()?;
                let o = a.out::<plane::PlaneCancelOut>()?;
                check_cancel(a.outcome, o.cancel.disposition)?;
                // SAFETY: `records_buf` is the host's own buffer of `records_cap` `RecordWrite`s,
                // named by this op's `in` (NULL with `0` from a host that lends none).
                let records = unsafe {
                    reported(
                        i.records_buf.cast_const(),
                        u64::from(o.records_written),
                        i.records_cap as u64,
                        "cancel.records",
                    )
                }?;
                let b = if o.records_written == 0 {
                    Bounds::default()
                } else {
                    *bounds(a)?
                };
                let caps = (i.records_cap as u64, i.arena_cap as u64);
                check_cancel_records(a.outcome, o, records, caps, &b)
            }
            life::DRIVE => {
                let cap = a.input::<PlaneDriveIn>()?.sessions_cap as u64;
                check_drive(a.outcome, a.out::<PlaneDriveOut>()?, cap)
            }

            _ => Ok(()),
        }
    }

    fn drive_frame() -> Box<dyn DriveFrame> {
        Box::new(PlaneDrive::new())
    }

    fn cancel_frame() -> Box<dyn CancelFrame> {
        Box::new(PlaneCancel::new())
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn unit_of(s: u32, input: *const InHead, in_size: usize) -> Option<u64> {
        /// The host's `in` read as a `T`, when its frame holds a whole one.
        ///
        /// # Safety
        /// `input` is the host's own `in`, `in_size` bytes, live for the crossing.
        unsafe fn read<T: Copy>(input: *const InHead, in_size: usize) -> Option<T> {
            // SAFETY: the frame holds a whole `T` (the caller's contract).
            (in_size >= std::mem::size_of::<T>())
                .then(|| unsafe { input.cast::<T>().read_unaligned() })
        }
        // SAFETY: the dispatcher hands its own `in` and the size it wrote.
        let key = unsafe {
            match s {
                slot::ARRIVE => read::<ArriveIn>(input, in_size).map(|i| i.unit),
                slot::ON_PIECE => read::<OnPieceIn>(input, in_size).map(|i| i.unit),
                slot::PROJECT => read::<ProjectIn>(input, in_size).map(|i| i.unit),
                slot::REFUSAL => read::<RefusalIn>(input, in_size).map(|i| i.unit),
                _ => None,
            }
        };
        key.filter(|k| *k != 0)
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::ARRIVE => a.out::<ArriveOut>().is_ok_and(|o| o.units_needed != 0),
            slot::ON_PIECE => a.out::<OnPieceOut>().is_ok_and(|o| {
                o.units_needed != 0
                    || o.records_needed != 0
                    || o.fields_needed != 0
                    || o.arena_needed != 0
            }),
            slot::REFUSAL => a.out::<RefusalOut>().is_ok_and(|o| {
                o.reply_needed != 0
                    || o.fields_needed != 0
                    || o.arena_needed != 0
                    || o.records_needed != 0
            }),
            slot::SERVE => a.out::<ServeOut>().is_ok_and(|o| {
                o.reply_needed != 0
                    || o.fields_needed != 0
                    || o.arena_needed != 0
                    || o.records_needed != 0
            }),
            slot::PROJECT => a.out::<ProjectOut>().is_ok_and(|o| {
                o.signals_needed != 0 || o.messages_needed != 0 || o.arena_needed != 0
            }),
            slot::CATALOG => a
                .out::<plane::CatalogOut>()
                .is_ok_and(|o| o.reply_needed != 0 || o.fields_needed != 0 || o.arena_needed != 0),
            life::DRIVE => a
                .out::<PlaneDriveOut>()
                .is_ok_and(|o| o.sessions_needed != 0),
            _ => false,
        }
    }
}

pub const CANCEL_RECORDS: usize = 16;

pub const CANCEL_ARENA: usize = 4096;

pub struct PlaneCancel {
    frame: Frame<plane::PlaneCancelIn, plane::PlaneCancelOut>,
    records: Vec<RecordWrite>,
    arena: Vec<u8>,
}

impl Default for PlaneCancel {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaneCancel {
    #[must_use]
    pub fn new() -> Self {
        let none = RecordWrite {
            kind: 0,
            op: 0,
            key: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
            value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
        };
        let base = crate::dispatch::cancel_frame(Ticket::NONE);
        PlaneCancel {
            frame: Frame::new(
                plane::PlaneCancelIn {
                    cancel: base.input,
                    records_buf: std::ptr::null_mut(),
                    records_cap: 0,
                    arena_buf: std::ptr::null_mut(),
                    arena_cap: 0,
                    unit: 0,
                },
                plane::PlaneCancelOut {
                    cancel: base.out,
                    records_written: 0,
                    _reserved: 0,
                    arena_written: 0,
                },
            ),
            records: vec![none; CANCEL_RECORDS],
            arena: vec![0; CANCEL_ARENA],
        }
    }

    pub fn frame(&mut self) -> &mut Frame<plane::PlaneCancelIn, plane::PlaneCancelOut> {
        &mut self.frame
    }
}

impl CancelFrame for PlaneCancel {
    fn prepare(&mut self, ticket: Ticket, class: u8) -> (*mut InHead, *mut OutHead, u32) {
        let base = crate::dispatch::cancel_frame(ticket);
        let input = &mut self.frame.input;
        input.cancel = base.input;
        input.cancel.head.size = std::mem::size_of::<plane::PlaneCancelIn>() as u32;
        input.cancel.head.deadline_class = class;
        input.records_buf = self.records.as_mut_ptr();
        input.records_cap = self.records.len();
        input.arena_buf = self.arena.as_mut_ptr();
        input.arena_cap = self.arena.len();
        self.frame.out = plane::PlaneCancelOut {
            cancel: base.out,
            records_written: 0,
            _reserved: 0,
            arena_written: 0,
        };
        self.frame.heads()
    }

    fn disposition(&self) -> u32 {
        self.frame.out.cancel.disposition
    }

    fn name_unit(&mut self, unit: u64) {
        self.frame.input.unit = unit;
    }

    fn writes(&self) -> Vec<busbar_contract::plane_calls::CancelWrite> {
        let arena = (self.frame.out.arena_written as usize).min(self.arena.len());
        busbar_contract::plane_calls::CancelWrite::owned(
            &self.records,
            (self.frame.out.records_written as usize).min(self.records.len()),
            &self.arena[..arena],
        )
    }
}

struct PlaneDrive {
    frame: Frame<PlaneDriveIn, PlaneDriveOut>,
    sessions: Vec<u64>,
}

impl PlaneDrive {
    fn new() -> Self {
        PlaneDrive {
            frame: Frame::new(
                PlaneDriveIn {
                    drive: DriveIn {
                        head: in_head(),
                        driver: Ticket::NONE,
                    },
                    sessions_buf: std::ptr::null_mut(),
                    sessions_cap: 0,
                },
                PlaneDriveOut {
                    head: out_head(),
                    sessions_written: 0,
                    sessions_needed: 0,
                },
            ),
            sessions: vec![0; MAX_SESSIONS as usize],
        }
    }
}

impl DriveFrame for PlaneDrive {
    fn prepare(&mut self, driver: Ticket, flags: u32) -> (*mut InHead, *mut OutHead, u32) {
        let input = &mut self.frame.input;
        stamp_drive(
            &mut input.drive,
            driver,
            flags,
            std::mem::size_of::<PlaneDriveIn>(),
        );
        input.sessions_buf = self.sessions.as_mut_ptr();
        input.sessions_cap = self.sessions.len();
        self.frame.heads()
    }

    fn named(&self) -> &[u64] {
        let n = self.frame.out.sessions_written as usize;
        &self.sessions[..n.min(self.sessions.len())]
    }
}

fn arrive(a: &Answer) -> Result<(), Fault> {
    let i = a.input::<ArriveIn>()?;
    let o = a.out::<ArriveOut>()?;
    let cap = i.units_cap as u64;
    // SAFETY: `units_buf` is the host's own buffer of `units_cap` `UnitCount`s, named by this op's
    // `in`.
    let units = unsafe {
        reported(
            i.units_buf.cast_const(),
            u64::from(o.units_written),
            cap,
            "arrive.units",
        )
    }?;
    check_arrive(a.outcome, o, units, cap, bounds(a)?)
}

fn on_piece(a: &Answer) -> Result<(), Fault> {
    let i = a.input::<OnPieceIn>()?;
    let o = a.out::<OnPieceOut>()?;
    let caps = Caps {
        reply: i.reply_cap as u64,
        units: i.units_cap as u64,
        records: i.records_cap as u64,
        fields: i.fields_cap as u64,
        arena: i.arena_cap as u64,
    };
    // SAFETY: `units_buf`, `records_buf` and `fields_buf` are the host's own buffers of
    // `units_cap`, `records_cap` and `fields_cap` elements, named by this op's `in`.
    let (units, records, fields) = unsafe {
        (
            reported(
                i.units_buf.cast_const(),
                u64::from(o.units_written),
                caps.units,
                "on_piece.units",
            )?,
            reported(
                i.records_buf.cast_const(),
                u64::from(o.records_written),
                caps.records,
                "on_piece.records",
            )?,
            reported(
                i.fields_buf.cast_const(),
                u64::from(o.fields_written),
                caps.fields,
                "on_piece.fields",
            )?,
        )
    };
    check_on_piece(a.outcome, o, (units, records, fields), &caps, bounds(a)?)
}

fn project(a: &Answer) -> Result<(), Fault> {
    let i = a.input::<ProjectIn>()?;
    let o = a.out::<ProjectOut>()?;
    let cap = i.signals_cap as u64;
    // SAFETY: `signals_buf` is the host's own buffer of `signals_cap` `SignalEntry`s, named by
    // this op's `in`.
    let signals = unsafe {
        reported(
            i.signals_buf.cast_const(),
            o.view.signals_len as u64,
            cap,
            "project.signals",
        )
    }?;
    let messages_cap = i.messages_cap as u64;
    // SAFETY: `messages_buf` is the host's own buffer of `messages_cap` `MessageView`s, named
    // by this op's `in`.
    let messages = unsafe {
        reported(
            i.messages_buf.cast_const(),
            o.prompt.message_count,
            messages_cap,
            "project.messages",
        )
    }?;
    // SAFETY: the ABI requires each reported signal's tag to name its initialized union member;
    // the host owns these buffers until validation and delivery complete. This checks the answer's
    // values, not whether an untrusted native plugin obeyed Rust initialization requirements.
    unsafe {
        check_project(
            a.outcome,
            o,
            &ProjectHost {
                signals,
                signals_cap: cap,
                messages,
                messages_cap,
                arena: (i.arena_buf.cast_const(), i.arena_cap as u64),
                rewrite: i.rewrite.len != 0,
            },
        )
    }
}

fn snapshot(s: *const PlaneSnapshot, generation: u64, field: &'static str) -> Result<(), Fault> {
    if s.is_null() {
        return Err(fault(Rule::Missing, field));
    }
    check_snapshot(&as_written(s), generation)
}

fn as_written(p: *const PlaneSnapshot) -> PlaneSnapshot {
    // SAFETY: a non-NULL snapshot is the plugin's generation data, valid until `retire` of its
    // generation; its leading `size` is read alone first.
    let size = unsafe { p.cast::<u32>().read_unaligned() };
    let n =
        busbar_contract::abi::honoured_size(size, std::mem::size_of::<PlaneSnapshot>()) as usize;
    let mut s = std::mem::MaybeUninit::<PlaneSnapshot>::zeroed();
    // SAFETY: the plugin states `size` bytes of snapshot at `p`, and `n` is at most that and at
    // most the host's own struct, which `s` is; all-zero is a valid `PlaneSnapshot` (integers, raw
    // pointers, plain structs of both), so every byte the copy does not reach is a valid none.
    unsafe {
        std::ptr::copy_nonoverlapping(p.cast::<u8>(), s.as_mut_ptr().cast::<u8>(), n);
        s.assume_init()
    }
}

/// One claim of a snapshot, owned by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedClaim {
    /// The verb.
    pub verb: String,
    /// The target path.
    pub target: String,
    /// The transport claim it arrives over.
    pub carrier: String,
    /// `CLAIM_OPEN` | `CLAIM_EXACT` | `CLAIM_PATTERN`.
    pub flags: u32,
    /// The dialect a refusal on this route wears before `arrive` has read the arrival (an index
    /// into the tail's dialects, opaque to the host): the guest-list line's dialect.
    pub refusal_dialect: u16,
    /// The span an arrival on it opens (`PlaneSnapshot::arrival_spans`); empty = none.
    pub arrival_span: String,
}

/// One admin route of a snapshot, owned by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedAdminRoute {
    /// The verb.
    pub verb: String,
    /// The target path.
    pub target: String,
    /// `ROUTE_PUBLIC` or `0`.
    pub flags: u32,
    /// The word a served request is audited under; empty = never audited.
    pub audit_verb: String,
}

/// A GENERATION SNAPSHOT COPIED OUT OF THE PLUGIN at the crossing that published it, so nothing
/// the host keeps points into plugin memory after that generation's `retire` or the plugin's next
/// `refresh`. The host keeps it with the generation (claim targets, pattern segments, audience).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSnapshot {
    /// The generation it was published for.
    pub generation: u64,
    /// The paths it answers on.
    pub claims: Vec<OwnedClaim>,
    /// Its admin routes.
    pub admin_routes: Vec<OwnedAdminRoute>,
    /// Its OpenAPI contribution; `None` = none.
    pub openapi: Option<Vec<u8>>,
    /// The audience it binds; `None` = none.
    pub audience: Option<String>,
    /// Its resource metadata document; `None` = none.
    pub resource_metadata: Option<String>,
    /// Its protected-resource facts (JSON); `None` = none.
    pub resource_facts: Option<Vec<u8>>,
    /// The names it lists, in its order; empty = none (and none from a snapshot published before
    /// the list was appended).
    pub listed: Vec<String>,
}

impl crate::dispatch::Plugin<Plane> {
    pub fn open(
        &self,
        frame: &mut crate::dispatch::Frame<PlaneOpenIn, PlaneOpenOut>,
    ) -> (crate::dispatch::Called, Option<OwnedSnapshot>) {
        let called = self.call(life::OPEN, frame);
        let copy = (called.outcome == Outcome::Ready)
            .then(|| copy_snapshot(frame.out.snapshot, self.dialects()))
            .flatten();
        (called, copy)
    }

    pub fn refresh(
        &self,
        frame: &mut crate::dispatch::Frame<RefreshIn, PlaneRefreshOut>,
    ) -> (crate::dispatch::Called, Option<OwnedSnapshot>) {
        let called = self.call(life::REFRESH, frame);
        let copy = (called.outcome == Outcome::Ready)
            .then(|| copy_snapshot(frame.out.snapshot, self.dialects()))
            .flatten();
        (called, copy)
    }
}

fn owned_str(s: busbar_contract::abi::mechanism::call::AbiStr) -> Option<Option<String>> {
    if s.ptr.is_null() {
        return Some(None);
    }
    // SAFETY: the plugin's generation data, valid until `retire` of its generation, and read only
    // inside the READY crossing that published it; its length capped before the slice is formed.
    let bytes = unsafe { crate::dispatch::validate::lent_str(s) }?;
    std::str::from_utf8(bytes).ok().map(|t| Some(t.to_string()))
}

fn owned_blob(b: Blob) -> Option<Option<Vec<u8>>> {
    if b.ptr.is_null() {
        return Some(None);
    }
    // SAFETY: as `owned_str`.
    unsafe { crate::dispatch::validate::lent(b.ptr, b.len) }.map(|bytes| Some(bytes.to_vec()))
}

pub(crate) fn copy_snapshot(p: *const PlaneSnapshot, dialects: u64) -> Option<OwnedSnapshot> {
    use busbar_contract::abi::plane::check::{
        check_admin_routes, check_arrival_spans, check_claim_target, check_claims, check_listed,
    };
    if p.is_null() {
        return None;
    }

    let s = &as_written(p);
    // SAFETY: the check refused a list counted over a NULL pointer or over its cap; each names
    // `*_len` entries, bounded again before the slice is formed. A snapshot from before `listed`
    // was appended reads NULL with `0`.
    let (claims, routes, listed) = unsafe {
        use crate::dispatch::validate::lent;
        (
            lent(s.claims, s.claims_len)?,
            lent(s.admin_routes, s.admin_routes_len)?,
            lent(s.listed, s.listed_len)?,
        )
    };
    // SAFETY: as above; a snapshot from before the list was appended reads NULL with `0`, and the
    // check refused any length but `0` or one per claim.
    let spans = if s.arrival_spans_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(s.arrival_spans, s.arrival_spans_len) }
    };
    check_claims(claims, dialects).ok()?;
    check_admin_routes(routes).ok()?;
    check_listed(listed).ok()?;
    check_arrival_spans(spans).ok()?;

    let span_of = |i: usize| -> Option<String> {
        let name = spans.get(i).map_or(Some(String::new()), |n| {
            owned_str(*n).map(Option::unwrap_or_default)
        })?;
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            .then_some(name)
    };
    let text = |a| owned_str(a)?.or(Some(String::new()));
    Some(OwnedSnapshot {
        generation: s.generation,
        claims: claims
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let target = text(c.target)?;
                check_claim_target(&target, c.flags).ok()?;
                Some(OwnedClaim {
                    verb: text(c.verb)?,
                    target,
                    carrier: text(c.carrier)?,
                    flags: c.flags,
                    refusal_dialect: c.refusal_dialect,
                    arrival_span: span_of(i)?,
                })
            })
            .collect::<Option<_>>()?,
        admin_routes: routes
            .iter()
            .map(|r| {
                Some(OwnedAdminRoute {
                    verb: text(r.verb)?,
                    target: text(r.target)?,
                    flags: r.flags,
                    audit_verb: text(r.audit_verb)?,
                })
            })
            .collect::<Option<_>>()?,
        openapi: owned_blob(s.openapi)?,
        audience: owned_str(s.audience)?,
        resource_metadata: owned_str(s.resource_metadata)?,
        resource_facts: owned_blob(s.resource_facts)?,
        listed: listed
            .iter()
            .map(|n| owned_str(*n).flatten())
            .collect::<Option<_>>()?,
    })
}

#[cfg(test)]
#[path = "../../tests/plane_probe_tests.rs"]
mod probe_tests;

#[cfg(test)]
#[test]
fn conditional_statement_requires_its_own_format_and_preserves_unrelated_extensions() {
    use busbar_contract::abi::{
        mechanism::call::{BLOB_JSON, BLOB_OCTETS, BLOB_SECRET},
        sdk::plane::conditional,
    };
    // SAFETY: the fixture door's Statement is process-static, copied while its owner is live.
    let mut statement = unsafe { *crate::plane_door_plugin::door().parts().statement };
    let capability = conditional::statement(&[]).unwrap();
    statement.extensions = Blob {
        ptr: capability.as_ptr(),
        len: capability.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    assert!(tail_facts(&statement).unwrap().declared.conditional_records);
    statement.extensions.fmt = BLOB_JSON;
    assert!(tail_facts(&statement).is_err());
    statement.extensions.fmt = BLOB_OCTETS;
    statement.extensions.flags = BLOB_SECRET;
    assert!(tail_facts(&statement).is_err());
    let unrelated = busbar_contract::abi::mechanism::extensions::encode(&[("unrelated", b"kept")]);
    statement.extensions = Blob {
        ptr: unrelated.as_ptr(),
        len: unrelated.len(),
        fmt: BLOB_JSON,
        flags: BLOB_SECRET,
    };
    assert!(!tail_facts(&statement).unwrap().declared.conditional_records);
    statement.extensions = Blob {
        ptr: std::ptr::null(),
        len: 1,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    assert!(!tail_facts(&statement).unwrap().declared.conditional_records);
}

#[cfg(test)]
#[test]
fn provider_key_statement_bound_precedes_every_slice() {
    let oversized = Blob {
        ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(),
        len: busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize + 1,
        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
    assert!(stated_provider_keys(oversized).is_err());
}
