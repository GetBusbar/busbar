// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND: `abi/plane/`. Every answer is judged by its kind's own check:
//!
//! * `arrive` by `check_arrive`, its units over the host's `units_buf`/`units_cap`;
//! * `on_piece` by `check_on_piece`, its units, records and fields over the host's buffers, every
//!   cap from `OnPieceIn`;
//! * `refusal` by `check_refusal` and `serve` by `check_serve`, their fields over the host's
//!   `fields_buf`/`fields_cap`, every cap from the op's `in`;
//! * `project` by `check_project`, its view's signals over the host's `signals_buf`/`signals_cap`
//!   and its strings and body over the host's `arena_buf`/`arena_cap`, from `ProjectIn`;
//! * `open` and `refresh` by `check_snapshot` on the generation snapshot a READY answer carries,
//!   against the generation the `in` names;
//! * `cancel` by `check_cancel` on its disposition (answered on READY only);
//! * `drive` by `check_drive`, its ready sessions over the host's `sessions_cap` from
//!   `PlaneDriveIn`.
//!
//! Every outcome is judged; each check decides what an outcome carries. A snapshot is read only
//! from a READY `open`/`refresh`: on another outcome the plugin publishes none.
//!
//! `hydrate` and `start` answer a bare `OutHead`: no per-answer rule beyond the mechanism's. The
//! snapshot's claims and admin routes (`check_claims`, `check_admin_routes`) and the Statement tail
//! are generation and load data, judged where the kernel adopts them, not per answer.
//!
//! THE TAIL'S INDICES. A unit's billable class, a record's kind, `arrive`'s op class and dialect
//! index lists of the plane's Statement tail ([`PlaneTail`]). The tail is read once at bind: it
//! must be a whole `PlaneTail` that passes `check_tail`, or the load is refused. Its list lengths
//! are the instance's context ([`Bounds`]), and every answer's indices are judged against them at
//! the crossing: an index past its list is FAULT.
//!
//! SHORT ANSWERS: `arrive`, `on_piece`, `refusal`, `serve`, `project` and `drive` have the short
//! path; a FAILED answer of one of them with any `*_needed` non-zero is short.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::check::{fault, reported, Fault, Rule};
use busbar_contract::abi::mechanism::door::{Statement, SECTION_CONSUMED, SECTION_DECLARING};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, DriveIn, OpenIn, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::{
    check_arrive, check_billable_classes, check_cancel, check_cancel_records, check_drive,
    check_fee_units, check_on_piece, check_pin_mechanisms, check_project, check_refusal,
    check_refusal_records, check_refusal_statuses, check_sections, check_serve,
    check_serve_records, check_snapshot, check_tail, check_trust_keys, Bounds, Caps, ProjectHost,
    MAX_SESSIONS,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, BillableClass, OnPieceIn, OnPieceOut, PinMechanism,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    PlaneTail, ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut, RefusalStatus, ServeIn,
    ServeOut, TrustKey,
};
use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::InstanceDecl;

use crate::dispatch::{
    in_head, lifecycle_name, out_head, stamp_drive, Answer, CancelFrame, Context, DriveFrame,
    Frame, InFrame, Kind, OutFrame,
};

/// The plane tail's last frozen size: it has not grown, so it is this host's (THE KIND TAIL
/// GROWTH RULE, `abi::mechanism::door::tail_read_len`).
const PLANE_TAIL_FROZEN: usize = std::mem::size_of::<PlaneTail>();

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
unsafe impl OutFrame for PlaneOpenOut {}
unsafe impl OutFrame for PlaneRefreshOut {}
unsafe impl OutFrame for PlaneDriveOut {}
unsafe impl OutFrame for plane::PlaneCancelOut {}
unsafe impl OutFrame for ArriveOut {}
unsafe impl OutFrame for OnPieceOut {}
unsafe impl OutFrame for RefusalOut {}
unsafe impl OutFrame for ServeOut {}
unsafe impl OutFrame for ProjectOut {}

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
    /// The tail's fee units, each also one of [`Self::billable_classes`]: the plane's report of
    /// whether a unit incurred its fee (THE DESIGN §7, "the plane reports ... whether a fee unit was
    /// incurred").
    pub fee_units: Vec<&'static str>,
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
    /// for it, `{cert, key}` as secret references (the transport pin, ARCHITECT 2026-10-03).
    pub need_trust: Vec<&'static str>,
    /// The tail's kernel-owned trust keys: a registration whose pin names a mechanism that pins the
    /// far end's key (`PinMechanismDecl::peer_key`) has that key sealed into its member route.
    pub trust_keys: Vec<TrustKeyDecl>,
    /// Each need's transport, in the same order (`Need::transport`): a member binds at most one
    /// need per (transport, auth) (ARCHITECT Q-L5B-NEEDS).
    pub need_transports: Vec<&'static str>,
    /// The tail's dialects, in order.
    pub dialects: Vec<&'static str>,
    /// The tail's `dialect_auth`: each dialect's default outbound style, by its dialect index
    /// (THE DESIGN §6 step 2: a provider entry's `auth:`, else this), and the style's parameters
    /// for it, a JSON object's text (empty: none; ARCHITECT RULING 2026-10-03, Q-L6-AUTHPARAMS).
    pub dialect_auth: Vec<(u32, &'static str, &'static [u8])>,
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

/// The instance's tail bounds; an answer judged without them is FAULT (a plane instance always
/// binds with its tail).
fn bounds<'a>(a: &Answer<'a>) -> Result<&'a Bounds, Fault> {
    a.context::<PlaneFacts>()
        .map(|f| &f.bounds)
        .ok_or(fault(Rule::Missing, "plane.tail"))
}

/// The plane's tail, read from the Statement: a whole `PlaneTail` that passes `check_tail`, its
/// billable classes and fee units (`check_billable_classes`, `check_fee_units`: every fee unit is a
/// billable class, so the plane can report it), the Statement's sections, exactly one of them
/// declaring (`check_sections`), and refusal statuses that pass `check_refusal_statuses`.
fn tail_facts(st: &Statement) -> Result<PlaneFacts, String> {
    // SAFETY: `PlaneTail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid); a
    // non-NULL kind tail is `'static` plugin data of its stated size.
    let tail: PlaneTail =
        unsafe { crate::dispatch::plugin::kind_tail(st, "a plane", PLANE_TAIL_FROZEN) }?;
    check_tail(&tail).map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_trust_keys(&tail)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_fee_units(&tail)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    // A plane declares exactly one section: its verb. The loader's Statement check already
    // refused a NULL list with a count.
    let sections = if st.sections_len == 0 {
        &[][..]
    } else {
        // SAFETY: a non-NULL `sections` holds `sections_len` `'static` entries.
        unsafe { std::slice::from_raw_parts(st.sections, st.sections_len) }
    };
    check_sections(sections)
        .map_err(|f| format!("the plane's sections break {:?} at {}", f.rule, f.field))?;
    let refusal_statuses: Vec<RefusalStatus> = (0..tail.refusal_statuses_len)
        .map(|i| {
            // SAFETY: `check_tail` refused a count over a NULL list; the list is `'static` plugin
            // data of `refusal_statuses_len` entries.
            unsafe { tail.refusal_statuses.add(i).read_unaligned() }
        })
        .collect();
    check_refusal_statuses(&refusal_statuses, tail.dialects_len as u64)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    // Each dialect's default style and its parameters, judged before they are kept.
    busbar_contract::abi::plane::check::check_dialect_auth(
        &listed(tail.dialect_auth, tail.dialect_auth_len),
        tail.dialects_len as u64,
    )
    .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    Ok(PlaneFacts {
        bounds: Bounds::of(&tail),
        refusal_statuses,
        declared: declared(&tail),
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
            admin_openapi: (!tail.admin_openapi.ptr.is_null()).then(|| {
                // SAFETY: the tail check accepted the blob: `len` bytes of `'static` plugin data.
                let bytes = unsafe {
                    std::slice::from_raw_parts(tail.admin_openapi.ptr, tail.admin_openapi.len)
                };
                &*bytes.to_vec().leak()
            }),
            op_classes: listed(tail.op_classes, tail.op_classes_len)
                .into_iter()
                .map(|c| kept(c.op))
                .collect(),
            audit_kind: kept(tail.audit_kind),
            billable_classes: listed(tail.billable_classes, tail.billable_classes_len)
                .into_iter()
                .map(|c| kept(c.class))
                .collect(),
            fee_units: listed(tail.fee_units, tail.fee_units_len)
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
        },
    })
}

/// A tail string, kept for the process (`""` when absent).
fn kept(s: AbiStr) -> &'static str {
    if s.ptr.is_null() || s.len == 0 {
        return "";
    }
    // SAFETY: `check_tail` judged every tail string: a non-NULL span of `len` bytes of `'static`
    // plugin data, read here while the plugin is loaded and copied.
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    String::from_utf8_lossy(bytes).into_owned().leak()
}

/// A tail blob's bytes, kept for the process (empty when absent).
fn kept_blob(b: Blob) -> &'static [u8] {
    if b.ptr.is_null() || b.len == 0 {
        return &[];
    }
    // SAFETY: `check_dialect_auth` judged the blob (`tail_facts`): a non-NULL span of `len` bytes of
    // `'static` plugin data, read here while the plugin is loaded and copied.
    let bytes = unsafe { std::slice::from_raw_parts(b.ptr, b.len) };
    bytes.to_vec().leak()
}

/// A tail list of `n` `T`s at `p`, copied.
fn listed<T: Copy>(p: *const T, n: usize) -> Vec<T> {
    if p.is_null() || n == 0 {
        return Vec::new();
    }
    // SAFETY: `check_tail` refused a NULL list counted non-zero; the list is `'static` plugin data
    // of `n` entries.
    unsafe { std::slice::from_raw_parts(p, n) }.to_vec()
}

/// What the tail declares for the instance's admission: record kinds, signing, scope kinds and the
/// trust keys (each judged at bind by `check_tail_trust_keys`).
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
                _ => TrustRole::RecoveryBackoff,
            },
            fingerprint: k.flags & plane::PIN_FINGERPRINT != 0,
            default: Some(kept(k.default)).filter(|d| !d.is_empty()),
            mechanisms: listed(k.mechanisms, k.mechanisms_len)
                .into_iter()
                .map(|m| PinMechanismDecl {
                    token: kept(m.token),
                    root: m.flags & plane::MECHANISM_ROOT != 0,
                    peer_key: m.flags & plane::MECHANISM_PEER_KEY != 0,
                })
                .collect::<Vec<_>>()
                .leak(),
        })
        .collect();
    InstanceDecl {
        label: Arc::from(""),
        record_kinds: words(t.record_kinds, t.record_kinds_len),
        signing: (!domain.is_empty() && !prefix.is_empty()).then_some((domain, prefix)),
        scope_kinds: words(t.scope_kinds, t.scope_kinds_len),
        trust_keys,
        record_chains: listed(t.record_chains, t.record_chains_len),
    }
}

impl crate::dispatch::Plugin<Plane> {
    /// What the instance declares for its admission: its bind label and its tail's facts.
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

    /// What the composition root serves the instance by (empty with no tail facts).
    pub fn served(&self) -> ServedFacts {
        self.inner
            .context::<PlaneFacts>()
            .map(|f| f.served.clone())
            .unwrap_or_default()
    }

    /// The refusal statuses the plane's tail states, as judged at bind.
    pub fn refusal_statuses(&self) -> &[RefusalStatus] {
        self.inner
            .context::<PlaneFacts>()
            .map_or(&[], |f| f.refusal_statuses.as_slice())
    }

    /// The dialects the plane's tail declares (`0` with no tail facts).
    fn dialects(&self) -> u64 {
        self.inner
            .context::<PlaneFacts>()
            .map_or(0, |f| f.bounds.dialects)
    }
}

/// A probe instance of a door, bound afresh: the door's one load, on a dispatcher of the caller's.
pub type ProbeBind = Arc<dyn Fn() -> Result<crate::dispatch::Plugin<Plane>, String> + Send + Sync>;

/// A [`ProbeBind`] over a LINKED door: each bind loads `door` through the one load
/// ([`crate::dispatch::load_linked`]) as `instance`, on a probe dispatcher the process keeps for its
/// life (a probe it adopted is refreshed through it at every generation).
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

/// THE REGISTRY FACTS A DOOR STATES (ARCHITECT RULING 2026-10-03, Q-DEL-A2A-DECL): its Statement
/// name, its declaring section and its tail's words, read off the facts kept at its bind, and its
/// own `validate` (ticket-less; it never pends) over a whole section. `bind` binds a probe instance
/// of the door through the one load (a linked and a dropped door alike); one is bound here for the
/// facts and the section judge, and one more per public base URL its facing is asked for (a plane
/// states its audience and claims against the URL it was opened with).
///
/// # Errors
///
/// The door will not bind.
pub fn registration(
    bind: ProbeBind,
) -> Result<busbar_contract::plane_calls::PlaneRegistration, String> {
    let plugin = Arc::new(bind()?);
    let served = plugin.served();
    let declared = plugin.declared();
    let (label, subject_noun, admin_noun) = served.nouns;
    let key: &'static str = plugin.name().to_string().leak();
    let refusal = served.caller_credential_refusal;
    let judge = Arc::clone(&plugin);
    let dialects = served.dialects.clone();
    let probes: std::sync::Mutex<Vec<Probe>> = std::sync::Mutex::new(Vec::new());
    Ok(busbar_contract::plane_calls::PlaneRegistration {
        key,
        section: served.section,
        owns: served.owns.clone(),
        consumes: served.consumes.clone(),
        secret_refs: served.secret_refs.clone(),
        admin_routes: served.admin_routes.clone(),
        admin_openapi: served.admin_openapi,
        label,
        subject_noun,
        admin_noun,
        audit_kind: served.audit_kind,
        signing: declared.signing,
        dialects: served.dialects.clone(),
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
        validate: Arc::new(move |settings: &[u8]| validate(&judge, settings)),
        facing: Arc::new(
            move |settings: &[u8], owned: &[u8], public_url: Option<&str>| {
                let url = public_url.unwrap_or_default().to_string();
                let mut probes = probes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let at = match probes.iter().position(|p| p.url == url && p.owned == owned) {
                    Some(at) => at,
                    None => {
                        probes.push(Probe {
                            url: url.clone(),
                            owned: owned.to_vec(),
                            plugin: bind()?,
                            generation: 0,
                        });
                        probes.len() - 1
                    }
                };
                let probe = &mut probes[at];
                facing(
                    &probe.plugin,
                    &dialects,
                    &mut probe.generation,
                    settings,
                    owned,
                    public_url,
                )
            },
        ),
    })
}

/// One probe instance of a door, opened against one public base URL and one set of owned sections
/// (both are read at its open; a change of either is a restart).
struct Probe {
    url: String,
    owned: Vec<u8>,
    plugin: crate::dispatch::Plugin<Plane>,
    /// Its current generation; `0` = not opened yet.
    generation: u64,
}

/// OPEN `plugin` at generation 1 over `settings` (JSON; empty = absent), its `owned` sections (one
/// JSON object keyed by section name; empty = none) and `public_url`, as the composition root opens
/// a door plane: the first generation's snapshot, or why it did not open.
///
/// # Errors
///
/// The plane did not answer READY, or its snapshot did not pass the host's checks.
pub fn open_door(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    owned: &[u8],
    public_url: Option<&str>,
) -> Result<OwnedSnapshot, String> {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::OpenOut;
    let blob = |bytes: &[u8]| {
        if bytes.is_empty() {
            Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: BLOB_ABSENT,
                flags: 0,
            }
        } else {
            Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_JSON,
                flags: 0,
            }
        }
    };
    let url = public_url.unwrap_or_default();
    let mut frame = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: blob(settings),
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            public_url: AbiStr {
                ptr: if url.is_empty() {
                    std::ptr::null()
                } else {
                    url.as_ptr()
                },
                len: url.len(),
            },
            owned: blob(owned),
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
            snapshot: std::ptr::null(),
        },
    );
    let (called, snapshot) = plugin.open(&mut frame);
    if called.outcome != Outcome::Ready {
        return Err(called.open_failure(plugin.name()));
    }
    snapshot.ok_or_else(|| {
        format!(
            "plane `{}`'s snapshot did not pass the host's checks",
            plugin.name()
        )
    })
}

/// REFRESH `plugin` onto `next` over `settings` (JSON; empty = absent), as a config apply refreshes
/// a served door plane: the new generation's snapshot, or why it did not refresh. The previous
/// generation stays live for units still running on it; retire it with [`retire_door`].
///
/// # Errors
///
/// The plane did not answer READY, or its snapshot did not pass the host's checks.
pub fn refresh_door(
    plugin: &crate::dispatch::Plugin<Plane>,
    settings: &[u8],
    next: u64,
) -> Result<OwnedSnapshot, String> {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON};
    let blob = if settings.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        }
    } else {
        Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        }
    };
    let mut frame = Frame::new(
        RefreshIn {
            head: in_head(),
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
    snapshot.ok_or_else(|| {
        format!(
            "plane `{}`'s snapshot did not pass the host's checks",
            plugin.name()
        )
    })
}

/// RETIRE `generation` of `plugin`: no unit runs on it any more.
pub fn retire_door(plugin: &crate::dispatch::Plugin<Plane>, generation: u64) {
    use busbar_contract::abi::mechanism::lifecycle::GenIn;
    let mut retire = Frame::new(
        GenIn {
            head: in_head(),
            generation,
        },
        out_head(),
    );
    let _ = plugin.call(life::RETIRE, &mut retire);
}

/// What `plugin` faces the world with over `settings`, its `owned` sections and `public_url`, as a
/// snapshot it published: the probe instance is `open`ed on the first call (with `public_url` and
/// `owned`, which a plane states its audience against) and `refresh`ed onto a new generation on
/// each later one, the previous generation retired. The probe instance lives for the process beside
/// the one the composition root serves through; a public base URL and the owned sections are read
/// at its open (a change of either is a restart).
fn facing(
    plugin: &crate::dispatch::Plugin<Plane>,
    dialects: &[&'static str],
    current: &mut u64,
    settings: &[u8],
    owned: &[u8],
    public_url: Option<&str>,
) -> Result<busbar_contract::plane_calls::DoorFacing, String> {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::{GenIn, OpenOut, RefreshIn};
    let blob = if settings.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        }
    } else {
        Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        }
    };
    let snapshot = if *current == 0 {
        let url = public_url.unwrap_or_default();
        let mut frame = Frame::new(
            PlaneOpenIn {
                open: OpenIn {
                    head: in_head(),
                    host: std::ptr::null(),
                    settings: blob,
                    secrets: std::ptr::null(),
                    secrets_len: 0,
                    generation: 1,
                    err_buf: std::ptr::null_mut(),
                    err_cap: 0,
                },
                public_url: AbiStr {
                    ptr: if url.is_empty() {
                        std::ptr::null()
                    } else {
                        url.as_ptr()
                    },
                    len: url.len(),
                },
                owned: if owned.is_empty() {
                    Blob {
                        ptr: std::ptr::null(),
                        len: 0,
                        fmt: BLOB_ABSENT,
                        flags: 0,
                    }
                } else {
                    Blob {
                        ptr: owned.as_ptr(),
                        len: owned.len(),
                        fmt: BLOB_JSON,
                        flags: 0,
                    }
                },
            },
            PlaneOpenOut {
                open: OpenOut {
                    head: out_head(),
                    instance: std::ptr::null_mut(),
                    err_len: 0,
                },
                snapshot: std::ptr::null(),
            },
        );
        let (called, snapshot) = plugin.open(&mut frame);
        if called.outcome != Outcome::Ready {
            return Err(called.open_failure(plugin.name()));
        }
        *current = 1;
        snapshot
    } else {
        let next = *current + 1;
        let mut frame = Frame::new(
            RefreshIn {
                head: in_head(),
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
        let mut retire = Frame::new(
            GenIn {
                head: in_head(),
                generation: *current,
            },
            out_head(),
        );
        let _ = plugin.call(life::RETIRE, &mut retire);
        *current = next;
        snapshot
    };
    let snapshot = snapshot.ok_or_else(|| {
        format!(
            "plane `{}`'s snapshot did not pass the host's checks",
            plugin.name()
        )
    })?;
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
    })
}

/// `validate` `settings` on `plugin` (ticket-less; it never pends): `Ok` when READY, else the
/// plugin's words.
fn validate(plugin: &crate::dispatch::Plugin<Plane>, settings: &[u8]) -> Result<(), String> {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::ValidateIn;
    let blob = if settings.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        }
    } else {
        Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        }
    };
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: blob,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let c = plugin.call(life::VALIDATE, &mut f);
    match c.outcome {
        Outcome::Ready => Ok(()),
        o => Err(c
            .error
            .map(|e| String::from_utf8_lossy(&e).into_owned())
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| format!("{o:?}"))),
    }
}

/// The tail's billable classes and fee units, judged PER ELEMENT (ARCHITECT Q-L5-FEE (C)): each
/// class by `check_billable_classes`, then each fee unit by `check_fee_units`, which holds every fee
/// unit to one of the classes (the plane reports "a fee unit was incurred" as a count on it; a fee
/// unit no class lists could never be reported, and its fee would be refunded on every unit).
fn check_tail_fee_units(tail: &PlaneTail) -> Result<(), Fault> {
    let classes: Vec<BillableClass> = listed(tail.billable_classes, tail.billable_classes_len);
    check_billable_classes(&classes)?;
    let fee_units: Vec<AbiStr> = listed(tail.fee_units, tail.fee_units_len);
    check_fee_units(&fee_units, &classes)
}

/// The tail's kernel-owned trust keys, judged PER ELEMENT: each key by `check_trust_keys`, each
/// pin's mechanisms by `check_pin_mechanisms`. `check_tail` proved only that no list is counted over
/// a NULL pointer; the elements are read here, once, at bind.
fn check_tail_trust_keys(tail: &PlaneTail) -> Result<(), Fault> {
    let keys: &[TrustKey] = if tail.trust_keys_len == 0 {
        &[]
    } else {
        // SAFETY: `check_tail` refused a NULL `trust_keys` counted non-zero; the tail is `'static`
        // plugin data whose list is `trust_keys_len` `TrustKey`s.
        unsafe { std::slice::from_raw_parts(tail.trust_keys, tail.trust_keys_len) }
    };
    check_trust_keys(keys)?;
    for key in keys {
        let mechanisms: &[PinMechanism] = if key.mechanisms_len == 0 {
            &[]
        } else {
            // SAFETY: `check_trust_keys` refused a NULL `mechanisms` counted non-zero; the list is
            // `'static` plugin data of `mechanisms_len` `PinMechanism`s.
            unsafe { std::slice::from_raw_parts(key.mechanisms, key.mechanisms_len) }
        };
        check_pin_mechanisms(mechanisms)?;
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

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::ARRIVE => "arrive",
            slot::ON_PIECE => "on_piece",
            slot::REFUSAL => "refusal",
            slot::SERVE => "serve",
            slot::HYDRATE => "hydrate",
            slot::START => "start",
            slot::PROJECT => "project",
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
                    ..Caps::default()
                };
                check_refusal(a.outcome, o, fields, &caps)?;
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
                // A refusal that writes no record needs no tail to be judged against.
                let b = if o.records_written == 0 {
                    Bounds::default()
                } else {
                    *bounds(a)?
                };
                check_refusal_records(a.outcome, o, records, i.records_cap as u64, &b)
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
                    ..Caps::default()
                };
                check_serve(a.outcome, o, fields, &caps)?;
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
                check_serve_records(a.outcome, o, records, i.records_cap as u64, &b)
            }
            slot::PROJECT => project(a),
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
            // `hydrate`, `start` (a bare `OutHead`) and the other lifecycle answers: no
            // per-answer rule beyond the mechanism's.
            _ => Ok(()),
        }
    }

    /// The plane's `drive` frame: `PlaneDriveIn`/`PlaneDriveOut`, with a host buffer for the ready
    /// sessions at the kind's maximum, so a `drive` never answers short.
    fn drive_frame() -> Box<dyn DriveFrame> {
        Box::new(PlaneDrive::new())
    }

    /// The plane's `cancel` frame: `PlaneCancelIn`/`PlaneCancelOut`, lending record buffers so the
    /// cancelled unit writes its row (SEAM-L(r)).
    fn cancel_frame() -> Box<dyn CancelFrame> {
        Box::new(PlaneCancel::new())
    }

    /// THE REQUEST LOOKUP: the unit an `arrive`, an `on_piece` or a `refusal` serves, the kernel-
    /// minted key its `in` carries (`ArriveIn::unit`, `OnPieceIn::unit`, `RefusalIn::unit`), so a
    /// host service the plane calls inside the crossing (`entitlement.check`) answers for that
    /// unit's principal. `0` is no unit (a refusal before any unit arrived); every other op serves
    /// none.
    // The trait's own contract (`Kind::unit_of`): `input` is the dispatcher's own `in` of `in_size`
    // bytes, written by the host for this crossing; only the dispatcher calls it.
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
            slot::REFUSAL => a
                .out::<RefusalOut>()
                .is_ok_and(|o| o.reply_needed != 0 || o.fields_needed != 0 || o.arena_needed != 0),
            slot::SERVE => a
                .out::<ServeOut>()
                .is_ok_and(|o| o.reply_needed != 0 || o.fields_needed != 0 || o.arena_needed != 0),
            slot::PROJECT => a.out::<ProjectOut>().is_ok_and(|o| {
                o.signals_needed != 0 || o.messages_needed != 0 || o.arena_needed != 0
            }),
            life::DRIVE => a
                .out::<PlaneDriveOut>()
                .is_ok_and(|o| o.sessions_needed != 0),
            _ => false,
        }
    }
}

/// The record writes a plane's `cancel` may carry, and the arena their bytes go in: `cancel` is
/// never re-called, so a plane writes within these.
pub const CANCEL_RECORDS: usize = 16;
/// The arena bytes a plane's `cancel` is lent.
pub const CANCEL_ARENA: usize = 4096;

/// A plane's `cancel` frame and the host buffers its `in` names (SEAM-L(r)).
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
    /// A frame with [`CANCEL_RECORDS`] record slots and a [`CANCEL_ARENA`]-byte arena.
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

    /// The frame, for a ticketless `cancel` crossing through [`Plugin::call`].
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

    fn writes(&self) -> Vec<busbar_contract::plane_calls::CancelWrite> {
        let arena = (self.frame.out.arena_written as usize).min(self.arena.len());
        busbar_contract::plane_calls::CancelWrite::owned(
            &self.records,
            (self.frame.out.records_written as usize).min(self.records.len()),
            &self.arena[..arena],
        )
    }
}

/// A plane driver ticket's `drive` frame and the host buffer its `in` names.
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

/// `arrive`: the expected units over the host's `units_buf`, `units_cap` from `ArriveIn`.
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

/// `on_piece`: units, records and fields over the host's buffers, every cap from `OnPieceIn`.
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

/// `project`: the view's signals over the host's `signals_buf`, its prompt turns over the host's
/// `messages_buf`, its strings and bodies over the host's arena, every cap from `ProjectIn`.
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

/// A READY `open`'s or `refresh`'s generation snapshot: present, of this host's size, then
/// `check_snapshot` against the generation the `in` names. The size is read before the whole
/// struct, so a smaller foreign snapshot is never read past its end.
fn snapshot(s: *const PlaneSnapshot, generation: u64, field: &'static str) -> Result<(), Fault> {
    if s.is_null() {
        return Err(fault(Rule::Missing, field));
    }
    // SAFETY: a non-NULL snapshot is the plugin's generation data, valid until `retire` of its
    // generation; its leading `size` is read alone first.
    let size = unsafe { s.cast::<u32>().read_unaligned() };
    if size as usize != std::mem::size_of::<PlaneSnapshot>() {
        return Err(fault(Rule::Foreign, "snapshot.size"));
    }
    // SAFETY: as above; the snapshot states this host's full size.
    let snap = unsafe { s.read_unaligned() };
    check_snapshot(&snap, generation)
}

// ── the host's copy of a generation snapshot ─────────────────────────────────────────────────────

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
}

impl crate::dispatch::Plugin<Plane> {
    /// `open`, and the first generation's snapshot COPIED while the crossing that published it
    /// proves it live: `Some` exactly when the answer is READY and every claim, admin route and
    /// string of the snapshot passes the contract's checks and is UTF-8.
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

    /// `refresh`, and the new generation's snapshot copied as [`Self::open`] copies it.
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

/// A string of the plugin's generation data, owned; `None` when absent. Called only on data a READY
/// crossing's checks accepted (no string counted over a NULL pointer).
fn owned_str(s: busbar_contract::abi::mechanism::call::AbiStr) -> Option<Option<String>> {
    if s.ptr.is_null() {
        return Some(None);
    }
    // SAFETY: the plugin's generation data, valid until `retire` of its generation, and read only
    // inside the READY crossing that published it; the contract's checks refused a NULL with a count.
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    std::str::from_utf8(bytes).ok().map(|t| Some(t.to_string()))
}

/// Copy the snapshot a READY `open`/`refresh` published: the loader's own `check_snapshot` has
/// passed (its size, generation, lists and strings), and the claims and admin routes are judged
/// here by the contract's element checks before any element string is read: a claim's refusal
/// dialect against the `dialects` its tail declares.
fn copy_snapshot(p: *const PlaneSnapshot, dialects: u64) -> Option<OwnedSnapshot> {
    use busbar_contract::abi::plane::check::{check_admin_routes, check_claims};
    if p.is_null() {
        return None;
    }
    // SAFETY: a READY answer's snapshot, whose size and lists this crossing's check accepted;
    // valid until `retire` of its generation.
    let s = unsafe { &*p };
    // SAFETY: the check refused a list counted over a NULL pointer; each names `*_len` entries.
    let claims = if s.claims_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(s.claims, s.claims_len) }
    };
    // SAFETY: as above.
    let routes = if s.admin_routes_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(s.admin_routes, s.admin_routes_len) }
    };
    check_claims(claims, dialects).ok()?;
    check_admin_routes(routes).ok()?;
    let text = |a| owned_str(a)?.or(Some(String::new()));
    Some(OwnedSnapshot {
        generation: s.generation,
        claims: claims
            .iter()
            .map(|c| {
                Some(OwnedClaim {
                    verb: text(c.verb)?,
                    target: text(c.target)?,
                    carrier: text(c.carrier)?,
                    flags: c.flags,
                    refusal_dialect: c.refusal_dialect,
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
        openapi: (!s.openapi.ptr.is_null()).then(|| {
            // SAFETY: the check accepted the blob; it names `len` bytes of generation data.
            unsafe { std::slice::from_raw_parts(s.openapi.ptr, s.openapi.len) }.to_vec()
        }),
        audience: owned_str(s.audience)?,
        resource_metadata: owned_str(s.resource_metadata)?,
        resource_facts: (!s.resource_facts.ptr.is_null()).then(|| {
            // SAFETY: the check accepted the blob; it names `len` bytes of generation data.
            unsafe { std::slice::from_raw_parts(s.resource_facts.ptr, s.resource_facts.len) }
                .to_vec()
        }),
    })
}
