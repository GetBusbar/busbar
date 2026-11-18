// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome};
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::check::{fault, reported, Fault, Rule};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, DriveIn, OpenIn, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::{
    check_arrive, check_cancel, check_cancel_records, check_drive, check_fee_units,
    check_metric_lanes, check_on_piece, check_project, check_refusal, check_serve, check_snapshot,
    Bounds, Caps, ProjectHost, MAX_SESSIONS,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, BillableClass, OnPieceIn, OnPieceOut, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RecordWrite, RefusalIn, RefusalOut, RefusalStatus, ServeIn, ServeOut,
};
use busbar_contract::plane::TrustKeyDecl;
use busbar_contract::plane_calls::InstanceDecl;

use crate::dispatch::lifecycle;
use crate::dispatch::{
    in_head, lifecycle_name, out_head, stamp_drive, Answer, CancelFrame, Context, DriveFrame,
    Frame, InFrame, Kind, OutFrame,
};

// The plane's once-per-load and per-configuration code (the Statement's tail read at bind, the
// registration and its facing probe, the provider facts lent to OPEN, the config worker's refresh
// and retire) lives in `off_path::kinds_plane`, outside the request-path marker; the paths callers
// use stay here.
use crate::off_path::kinds_plane::tail_facts;
pub(crate) use crate::off_path::kinds_plane::{
    dialect_flags, kept_blob, kept_mechanisms, listed, owned_blob, owned_str, provider,
};
pub use crate::off_path::kinds_plane::{
    linked_cli_help, provider_facts, refresh_door_on, registration, rendered_cli_help, retire_door,
    stated_facts, stated_registration,
};
#[cfg(any(test, feature = "test-support"))]
pub use crate::off_path::kinds_plane::{linked_probe, open_door, refresh_door};
#[cfg(test)]
use crate::off_path::kinds_plane::{refresh_failure, stated_collections, stated_provider_keys};

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
unsafe impl InFrame for plane::AuthenticatedRouteIn {}
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
unsafe impl OutFrame for plane::AuthenticatedRouteOut {}
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
    /// Validated generic class parent edges, resolved to names.
    pub class_parents: Vec<busbar_contract::plane::ClassParent>,
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
    /// as its dialect.
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

const PLANE_TAIL_FROZEN: usize = std::mem::offset_of!(PlaneTail, stream_ceiling_secs);

// THE PLUGIN MEMORY THE PLANE'S OFF-PATH CODE READS (`off_path::kinds_plane`: the tail and its
// lists, texts and blobs at bind, a snapshot's texts at OPEN and REFRESH), read here beside the
// kind's other unsafe code: each primitive is one read, the checks before it and its SAFETY case.

/// The plane tail `st` states (THE KIND TAIL GROWTH RULE, `dispatch::plugin::kind_tail`).
pub(crate) fn plane_tail(st: &Statement) -> Result<PlaneTail, String> {
    // SAFETY: `PlaneTail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid); a
    // non-NULL kind tail is `'static` plugin data of its stated size.
    unsafe { crate::dispatch::plugin::kind_tail(st, "a plane", PLANE_TAIL_FROZEN) }
}

/// A Statement blob's bytes (its `extensions`), or `None` when [`lent`] refuses the span. Callers
/// pass only the bound Statement's own blobs, their length bounded above first.
///
/// [`lent`]: crate::dispatch::validate::lent
pub(crate) fn statement_blob(b: Blob) -> Option<&'static [u8]> {
    // SAFETY: a non-NULL Statement blob is `len` bytes of `'static` plugin data, read here while the
    // plugin is loaded; its length is capped and its span checked before the slice is formed.
    unsafe { crate::dispatch::validate::lent(b.ptr, b.len) }
}

/// A tail list of `n` entries at `p`, or `None` (and the read marked over its cap) when the list
/// is over its cap or NULL with a count. Callers pass only the bound tail's own lists.
pub(crate) fn tail_slice<'a, T: Copy>(p: *const T, n: usize) -> Option<&'a [T]> {
    if busbar_contract::abi::mechanism::check::bounded(p, n, "plane.tail.list").is_err() {
        crate::off_path::kinds_plane::over_cap();
        return None;
    }
    // SAFETY: `check_tail` refused a NULL list counted non-zero; the list is `'static` plugin data
    // of `n` entries, its length capped before the slice is formed.
    let Some(list) = (unsafe { crate::dispatch::validate::lent(p, n) }) else {
        crate::off_path::kinds_plane::over_cap();
        return None;
    };
    Some(list)
}

/// A tail string, interned; `""` (and the read marked over its cap) when it is over its cap, NULL
/// with a count or not UTF-8.
pub(crate) fn kept(s: AbiStr) -> &'static str {
    if check_tail_text(s, "plane.tail.text").is_err() {
        crate::off_path::kinds_plane::over_cap();
        return "";
    }
    if s.len == 0 {
        return "";
    }
    // SAFETY: `check_tail` judged every tail string: a non-NULL span of `len` bytes of `'static`
    // plugin data, read here while the plugin is loaded and copied; its length capped first.
    let Some(bytes) = (unsafe { crate::dispatch::validate::lent_str(s) }) else {
        crate::off_path::kinds_plane::over_cap();
        return "";
    };
    // Reject non-UTF-8 consistently with export and hook kinds, which refuse
    // lossy strings at load. A lossy U+FFFD repair would silently collapse
    // distinct invalid byte sequences into the same interned name.
    let Ok(text) = std::str::from_utf8(bytes) else {
        crate::off_path::kinds_plane::over_cap();
        return "";
    };
    crate::intern_name(text)
}

/// A tail blob's bytes; `None` when it is empty, or (the read marked over its cap) over its cap or
/// NULL with a count.
pub(crate) fn tail_blob(b: Blob) -> Option<&'static [u8]> {
    if busbar_contract::abi::mechanism::check::blob(&b, "plane.tail.blob", "plane.tail.blob")
        .is_err()
    {
        crate::off_path::kinds_plane::over_cap();
        return None;
    }
    if b.len == 0 {
        return None;
    }
    // SAFETY: `check_dialect_auth` judged the blob (`tail_facts`): a non-NULL span of `len` bytes of
    // `'static` plugin data, read here while the plugin is loaded and copied; its length capped
    // first.
    let Some(bytes) = (unsafe { crate::dispatch::validate::lent(b.ptr, b.len) }) else {
        crate::off_path::kinds_plane::over_cap();
        return None;
    };
    Some(bytes)
}

pub(crate) fn check_tail_text(text: AbiStr, field: &'static str) -> Result<(), Fault> {
    busbar_contract::abi::mechanism::check::text(text, field)?;
    if text.len as u64 > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES {
        return Err(fault(Rule::OverMax, field));
    }
    Ok(())
}

/// `check_metric_lanes` over the bound tail's lane words.
pub(crate) fn metric_lanes_checked(lanes: &[AbiStr]) -> Result<(), Fault> {
    // SAFETY: the bound Statement owns these static lane bytes for the loaded plugin lifetime.
    unsafe { check_metric_lanes(lanes) }
}

/// `check_fee_units`, then `check_class_parents` over the parents `parents` reads (read only once
/// the fee units pass), all of the bound tail.
pub(crate) fn fee_units_checked(
    fee_units: &[AbiStr],
    classes: &[BillableClass],
    parents: impl FnOnce() -> Vec<plane::ClassParent>,
) -> Result<(), Fault> {
    // SAFETY: the bound Statement owns the static fee/class bytes for the loaded plugin lifetime.
    unsafe {
        check_fee_units(fee_units, classes)?;
        busbar_contract::abi::plane::check::check_class_parents(&parents(), classes, fee_units)
    }
}

/// A snapshot text, borrowed: `Some(None)` for NULL, `None` when its span is refused or it is not
/// UTF-8. Read only inside the READY crossing that published the snapshot.
pub(crate) fn snapshot_text_of<'a>(s: AbiStr) -> Option<Option<&'a str>> {
    if s.ptr.is_null() {
        return Some(None);
    }
    // SAFETY: the plugin's generation data, valid until `retire` of its generation, and read only
    // inside the READY crossing that published it; its length capped before the slice is formed.
    let bytes = unsafe { crate::dispatch::validate::lent_str(s) }?;
    std::str::from_utf8(bytes).ok().map(Some)
}

/// A snapshot blob, borrowed: `Some(None)` for NULL, `None` when its span is refused. As
/// [`snapshot_text_of`].
pub(crate) fn snapshot_bytes_of<'a>(b: Blob) -> Option<Option<&'a [u8]>> {
    if b.ptr.is_null() {
        return Some(None);
    }
    // SAFETY: as `snapshot_text_of`.
    unsafe { crate::dispatch::validate::lent(b.ptr, b.len) }.map(Some)
}
impl crate::dispatch::Plugin<Plane> {
    pub fn declared(&self) -> InstanceDecl {
        let mut d = self
            .inner
            .context::<PlaneFacts>()
            .map(|f| f.declared.clone())
            .unwrap_or_default();
        if let Some(c) = self.inner.wake.caller.get() {
            d.label = Arc::clone(c.namespace());
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

    pub(crate) fn dialects(&self) -> u64 {
        self.inner
            .context::<PlaneFacts>()
            .map_or(0, |f| f.bounds.dialects)
    }
}

pub type ProbeBind = Arc<dyn Fn() -> Result<crate::dispatch::Plugin<Plane>, String> + Send + Sync>;

impl crate::dispatch::kind_seal::Validated for Plane {}

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

    fn optional_by_statement(s: u32, st: &Statement) -> bool {
        (s == slot::SERVE && tail_facts(st).is_ok_and(|facts| facts.served.admin_routes.is_empty()))
            || (s == slot::AUTHENTICATED_ROUTE
                && tail_facts(st).is_ok_and(|facts| !facts.declared.authenticated_route))
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
            slot::AUTHENTICATED_ROUTE => "authenticated_route",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::ARRIVE => arrive(a),
            slot::AUTHENTICATED_ROUTE => {
                let i = a.input::<plane::AuthenticatedRouteIn>()?;
                let o = a.out::<plane::AuthenticatedRouteOut>()?;
                if i.unit == 0
                    || i.head.ticket.is_none()
                    || i.caller_ref.len == 0
                    || !a
                        .context::<PlaneFacts>()
                        .is_some_and(|f| f.declared.authenticated_route)
                {
                    return Err(fault(Rule::Missing, "authenticated_route.authority"));
                }
                // SAFETY: these are the host's retained output bytes, bounded before reading.
                let entry = unsafe {
                    reported(
                        i.entry_buf.cast_const(),
                        u64::from(o.entry_written),
                        i.entry_cap as u64,
                        "authenticated_route.entry",
                    )
                }?;
                plane::check::check_authenticated_route(a.outcome, o, entry, i.entry_cap)
            }
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
                    a,
                    a.out::<PlaneOpenOut>()?.snapshot,
                    generation,
                    "open.snapshot",
                )
            }
            life::REFRESH if a.outcome == Outcome::Ready => {
                let generation = a.input::<RefreshIn>()?.generation;
                snapshot(
                    a,
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

    #[expect(
        clippy::not_unsafe_ptr_arg_deref,
        reason = "the dispatcher hands its own `in` and the size it wrote"
    )]
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
                slot::AUTHENTICATED_ROUTE => {
                    read::<plane::AuthenticatedRouteIn>(input, in_size).map(|i| i.unit)
                }
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
        // A malformed span refuses the whole answer: drop the writes rather than invent empty ones.
        .unwrap_or_default()
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
        // Reset the output so a READY or PENDING drive that does not rewrite
        // these fields does not republish the previous iteration's values.
        // PlaneCancel::prepare already does this; PlaneDrive must match.
        self.frame.out = PlaneDriveOut {
            head: out_head(),
            sessions_written: 0,
            sessions_needed: 0,
        };
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
    check_arrive(a.outcome, o, units, cap, bounds(a)?)?;
    if o.route == plane::ROUTE_AUTHENTICATED
        && (!a.has_operation(slot::AUTHENTICATED_ROUTE)
            || !a
                .context::<PlaneFacts>()
                .is_some_and(|f| f.declared.authenticated_route))
    {
        return Err(fault(Rule::Missing, "arrive.authenticated_route"));
    }
    Ok(())
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

fn snapshot(
    answer: &Answer<'_>,
    s: *const PlaneSnapshot,
    generation: u64,
    field: &'static str,
) -> Result<(), Fault> {
    if s.is_null() {
        return Err(fault(Rule::Missing, field));
    }
    let snapshot = as_written(s);
    check_snapshot(&snapshot, generation)?;
    // SAFETY: the snapshot's checked lists are generation-owned plugin memory, live
    // throughout this crossing. `lent` also checks their alignment and byte bounds.
    let (claims, routes) = unsafe {
        use crate::dispatch::validate::lent;
        (
            lent(snapshot.claims, snapshot.claims_len)
                .ok_or(fault(Rule::Foreign, "snapshot.claims"))?,
            lent(snapshot.admin_routes, snapshot.admin_routes_len)
                .ok_or(fault(Rule::Foreign, "snapshot.admin_routes"))?,
        )
    };
    if claims
        .iter()
        .any(|claim| claim.flags & plane::CLAIM_CATALOG != 0)
        && !answer.has_operation(slot::CATALOG)
    {
        return Err(fault(Rule::Missing, "snapshot.catalog.operation"));
    }
    if routes.is_empty() {
        return Ok(());
    }
    if !answer.has_operation(slot::SERVE) {
        return Err(fault(Rule::Missing, "snapshot.admin_routes.operation"));
    }
    plane::check::check_admin_routes(routes)?;
    let facts = answer
        .context::<PlaneFacts>()
        .ok_or(fault(Rule::Missing, "plane.tail"))?;
    for route in routes {
        // Compared in place: the answer's admin routes are read, not copied, by this check.
        let text = |value| {
            snapshot_text_of(value)
                .map(Option::unwrap_or_default)
                .ok_or(fault(Rule::Foreign, "snapshot.admin_routes"))
        };
        let verb = text(route.verb)?;
        let target = text(route.target)?;
        let audit_verb = text(route.audit_verb)?;
        if !facts.served.admin_routes.iter().any(|declared| {
            declared.verb == verb
                && declared.target == target
                && declared.flags == route.flags
                && declared.audit_verb == audit_verb
        }) {
            return Err(fault(
                Rule::Contradiction,
                "snapshot.admin_routes.declaration",
            ));
        }
    }
    Ok(())
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
    test_support_pub! {
        fn open(
            &self,
            frame: &mut crate::dispatch::Frame<PlaneOpenIn, PlaneOpenOut>,
        ) -> (crate::dispatch::Called, Option<OwnedSnapshot>) {
            let called = self.call(life::OPEN, frame);
            let copy = (called.outcome == Outcome::Ready)
                .then(|| copy_snapshot(frame.out.snapshot, self.dialects()))
                .flatten();
            (called, copy)
        }
    }

    /// OPEN, its snapshot copied while the answer's lease is held, then the lease released: the
    /// public plane open, which leaves the caller nothing to hand back.
    pub fn answer_open(
        &self,
        frame: &mut crate::dispatch::Frame<PlaneOpenIn, PlaneOpenOut>,
    ) -> (crate::dispatch::Answered, Option<OwnedSnapshot>) {
        let (called, copy) = self.open(frame);
        lifecycle::release(self, called.lease);
        (called.into(), copy)
    }

    test_support_pub! {
        fn refresh(
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
}

pub(crate) fn copy_snapshot(p: *const PlaneSnapshot, dialects: u64) -> Option<OwnedSnapshot> {
    use busbar_contract::abi::plane::check::{
        check_admin_routes, check_arrival_spans, check_claims, check_listed,
    };
    if p.is_null() {
        return None;
    }

    let s = &as_written(p);
    // SAFETY: the check refused a list counted over a NULL pointer or over its cap; each names
    // `*_len` live entries, with byte bounds and alignment checked by `lent` before any slice is
    // formed. A snapshot from before `listed` or `arrival_spans` was appended reads NULL with `0`.
    let (claims, routes, listed, spans) = unsafe {
        use crate::dispatch::validate::lent;
        (
            lent(s.claims, s.claims_len)?,
            lent(s.admin_routes, s.admin_routes_len)?,
            lent(s.listed, s.listed_len)?,
            lent(s.arrival_spans, s.arrival_spans_len)?,
        )
    };
    check_claims(claims, dialects).ok()?;
    check_admin_routes(routes).ok()?;
    check_listed(listed).ok()?;
    check_arrival_spans(spans).ok()?;
    // The snapshot is copied out once per open or refresh, out of line.
    crate::cold::dispatch::kinds::plane_snapshot(s, claims, routes, listed, spans)
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
fn conditional_optional_statement_keeps_capability_and_rejects_orphan_marker() {
    use busbar_contract::abi::{mechanism::call::BLOB_OCTETS, sdk::plane::conditional};
    // SAFETY: fixture Statement remains process-static for this copy and call.
    let mut statement = unsafe { *crate::plane_door_plugin::door().parts().statement };
    let encoded = conditional::optional_statement(&[]).unwrap();
    statement.extensions = Blob {
        ptr: encoded.as_ptr(),
        len: encoded.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let facts = tail_facts(&statement).unwrap();
    assert!(facts.declared.conditional_records);
    assert!(facts.declared.conditional_records_optional);
    let orphan =
        busbar_contract::abi::mechanism::extensions::encode(&[(conditional::OPTIONAL, b"1")]);
    statement.extensions.ptr = orphan.as_ptr();
    statement.extensions.len = orphan.len();
    assert!(tail_facts(&statement).is_err());
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

#[cfg(test)]
#[test]
fn collection_statement_admits_only_supported_complete_descriptor() {
    use busbar_contract::abi::mechanism::{call::BLOB_OCTETS, extensions};
    use plane::collections::{self, CollectionMode, RecordCollection};
    let rows = [
        RecordCollection {
            kind: 0,
            mode: CollectionMode::Upsert,
            parent: None,
        },
        RecordCollection {
            kind: 1,
            mode: CollectionMode::Append,
            parent: Some(0),
        },
    ];
    let valid = collections::encode(&rows, 2).unwrap();
    for invalid in [false, true] {
        let mut value = valid.clone();
        if invalid {
            value[..4].copy_from_slice(&2u32.to_le_bytes());
        }
        let bytes = extensions::encode(&[(collections::EXT_RECORD_COLLECTIONS, &value)]);
        let blob = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        let result = stated_collections(blob, &bytes, 2);
        if invalid {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), rows);
            let mut wrong = blob;
            wrong.fmt = busbar_contract::abi::mechanism::call::BLOB_JSON;
            assert!(stated_collections(wrong, &bytes, 2).is_err());
            wrong = blob;
            wrong.flags = busbar_contract::abi::mechanism::call::BLOB_SECRET;
            assert!(stated_collections(wrong, &bytes, 2).is_err());
        }
    }
}
