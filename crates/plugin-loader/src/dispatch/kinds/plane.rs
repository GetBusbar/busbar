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
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelOut, DriveIn, OpenIn, RefreshIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::{
    check_arrive, check_cancel, check_drive, check_on_piece, check_pin_mechanisms, check_project,
    check_refusal, check_refusal_statuses, check_sections, check_serve, check_snapshot, check_tail,
    check_trust_keys, Bounds, Caps, ProjectHost, MAX_SESSIONS,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, PinMechanism, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RefusalIn, RefusalOut, RefusalStatus, ServeIn, ServeOut, TrustKey,
};
use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::InstanceDecl;

use crate::dispatch::{
    in_head, lifecycle_name, out_head, stamp_drive, Answer, Context, DriveFrame, Frame, InFrame,
    Kind, OutFrame,
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
unsafe impl InFrame for ArriveIn {}
unsafe impl InFrame for OnPieceIn {}
unsafe impl InFrame for RefusalIn {}
unsafe impl InFrame for ServeIn {}
unsafe impl InFrame for ProjectIn {}
unsafe impl OutFrame for PlaneOpenOut {}
unsafe impl OutFrame for PlaneRefreshOut {}
unsafe impl OutFrame for PlaneDriveOut {}
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

/// The plane's tail, read from the Statement: a whole `PlaneTail` that passes `check_tail`, the
/// Statement's sections, exactly one of them declaring (`check_sections`), and refusal statuses
/// that pass `check_refusal_statuses`.
fn tail_facts(st: &Statement) -> Result<PlaneFacts, String> {
    // SAFETY: `PlaneTail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid); a
    // non-NULL kind tail is `'static` plugin data of its stated size.
    let tail: PlaneTail =
        unsafe { crate::dispatch::plugin::kind_tail(st, "a plane", PLANE_TAIL_FROZEN) }?;
    check_tail(&tail).map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_trust_keys(&tail)
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
                _ => TrustRole::RecoveryBackoff,
            },
            fingerprint: k.flags & plane::PIN_FINGERPRINT != 0,
            default: Some(kept(k.default)).filter(|d| !d.is_empty()),
            mechanisms: listed(k.mechanisms, k.mechanisms_len)
                .into_iter()
                .map(|m| PinMechanismDecl {
                    token: kept(m.token),
                    root: m.flags & plane::MECHANISM_ROOT != 0,
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

/// THE REGISTRY FACTS `plugin` STATES (ARCHITECT RULING 2026-10-03, Q-DEL-A2A-DECL): its Statement
/// name, its declaring section and its tail's words, read off the facts kept at bind, and its own
/// `validate` (ticket-less; it never pends) over a whole section. The same function for a linked and
/// a dropped door: both bound through the one load.
#[must_use]
pub fn registration(
    plugin: Arc<crate::dispatch::Plugin<Plane>>,
) -> busbar_contract::plane_calls::PlaneRegistration {
    let served = plugin.served();
    let declared = plugin.declared();
    let (label, subject_noun, admin_noun) = served.nouns;
    let key: &'static str = plugin.name().to_string().leak();
    busbar_contract::plane_calls::PlaneRegistration {
        key,
        section: served.section,
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
        fallback: served.fallback,
        validate: Arc::new(move |settings: &[u8]| validate(&plugin, settings)),
    }
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
                check_refusal(a.outcome, o, fields, &caps)
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
                check_serve(a.outcome, o, fields, &caps)
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
            life::CANCEL => check_cancel(a.outcome, a.out::<CancelOut>()?.disposition),
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
    })
}
