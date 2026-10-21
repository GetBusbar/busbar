// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST SUPPORT: what a plugin's own tests need to drive its door and read its
//! Statement WITHOUT writing `unsafe` (BUSBAR-1.6.0.md l.272-274: a transport, store or export keeps
//! `unsafe` only in its reviewed `mod door`, and a plane, hook, auth or secret crate forbids it).
//! The one `unsafe` read of each kind lives here, once, reviewed, instead of once per plugin test.
//!
//! Four parts:
//!
//! * [`zeroed`] and `Default`: the all-zero value of a REVIEWED ABI struct (every slot `in`/`out`
//!   the contract states, and the row structs a test lays out beside them). [`AllZero`] is sealed,
//!   so the constructor cannot be called on any type this module has not reviewed.
//! * [`DoorView`]: a door's Statement, its claims, declared answers, kind tail, claim rows and their
//!   facts, a plane tail's texts and counted lists, and its ops table, as Rust values.
//! * [`written`] / [`written_text`]: what a plugin wrote into a buffer the test lent it, bounded by
//!   the length its `out` states and the capacity the test lent.
//! * [`fake`]: a fake host whose services a test writes as safe Rust, the `in` read and the
//!   `ServiceOut` written for it.
//!
//! DEV-ONLY: the module is compiled for this crate's own tests and behind the dev-only `test-seal`
//! feature a plugin's `[dev-dependencies]` edge enables (`tests/test_seal_is_dev_only.rs` refuses
//! any other edge), so no shipped image carries it. It adds no `#[repr(C)]` type and changes no
//! layout.

use core::mem::size_of;

use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::door::{Door, DoorFn, Statement};
use crate::abi::mechanism::{KindCode, DOOR_MAGIC};
use crate::abi::sdk::door::{AbiIn, AbiOut, KindOps};

mod sealed {
    /// Only this module implements it: the reviewed all-zero structs.
    pub trait Sealed {}
    /// Only this module implements it: the reviewed kind tails.
    pub trait SealedTail {}
    /// Only this module implements it: the plane tail's counted row lists.
    pub trait PlaneRow: Sized + 'static {
        /// The list in `tail`: its pointer, its count and its field name.
        fn of(tail: &crate::abi::plane::PlaneTail) -> (*const Self, usize, &'static str);
    }
}

pub mod fake;

// ── THE ALL-ZERO VALUE ──────────────────────────────────────────────────────────────────────────

/// A REVIEWED ABI struct whose all-zero bit pattern is a valid value. Sealed: the implementors are
/// exactly the structs listed in this module, each under the SAFETY argument beside its list, and
/// arrays of them.
pub trait AllZero: sealed::Sealed + Copy + 'static {}

/// The all-zero `T`: every integer `0`, every raw pointer NULL, every `Option<fn>` `None`. A test
/// fills the fields its call states, as the host does.
///
/// ```ignore
/// use busbar_contract::abi::sdk::test_support::zeroed;
/// use busbar_contract::abi::transport::{FramePiece, IngestIn};
///
/// let mut i: IngestIn = zeroed();
/// let pieces: Vec<FramePiece> = vec![zeroed(); 8];
/// ```
#[must_use]
pub fn zeroed<T: AllZero>() -> T {
    // SAFETY: `AllZero` is sealed. Its implementors are the structs `all_zero!` lists below, each
    // reviewed under the SAFETY argument of its list (all-zero is a valid value of every field),
    // and arrays of them (an array of valid values is valid).
    unsafe { core::mem::zeroed() }
}

impl<T: AllZero, const N: usize> sealed::Sealed for [T; N] {}
impl<T: AllZero, const N: usize> AllZero for [T; N] {}

/// Compiles only for an [`AbiIn`]: the list of slot `in`s below rides that trait's promise.
const fn slot_in<T: AbiIn>() {}
/// Compiles only for an [`AbiOut`]: the list of slot `out`s below rides that trait's promise.
const fn slot_out<T: AbiOut>() {}
/// Compiles for any plain `Copy` row; the review is the SAFETY argument over its list.
const fn row<T: Copy + 'static>() {}

/// `all_zero!(witness: T, ...)`: each `T` is [`AllZero`], its `Default` is [`zeroed`], and
/// `witness::<T>()` must compile.
macro_rules! all_zero {
    ($witness:ident: $($t:ty),+ $(,)?) => {$(
        const _: () = $witness::<$t>();
        impl sealed::Sealed for $t {}
        impl AllZero for $t {}
        impl Default for $t {
            fn default() -> Self {
                zeroed()
            }
        }
    )+};
}

// SAFETY (every slot `in` below): each is an `AbiIn` (checked at compile time by `slot_in`), whose
// unsafe contract states that EVERY initialized bit pattern, all-zero included, is a valid value:
// integers, raw pointers, `Option<fn>` and `#[repr(transparent)]` bytes only.
all_zero!(slot_in:
    crate::abi::mechanism::call::InHead,
    crate::abi::mechanism::lifecycle::ValidateIn,
    crate::abi::mechanism::lifecycle::OpenIn,
    crate::abi::mechanism::lifecycle::GenIn,
    crate::abi::mechanism::lifecycle::RefreshIn,
    crate::abi::mechanism::lifecycle::TickIn,
    crate::abi::mechanism::lifecycle::DriveIn,
    crate::abi::mechanism::lifecycle::CancelIn,
    crate::abi::mechanism::lifecycle::ReleaseIn,
    crate::abi::mechanism::lifecycle::ReadyIn,
    crate::abi::auth::VerifyIn,
    crate::abi::auth::BeginLoginIn,
    crate::abi::auth::CompleteLoginIn,
    crate::abi::auth::OpenOutboundIn,
    crate::abi::auth::OutboundReadyIn,
    crate::abi::auth::FieldsIn,
    crate::abi::auth::TargetIn,
    crate::abi::export::DeliverIn,
    crate::abi::export::ScrapeIn,
    crate::abi::export::CheckIn,
    crate::abi::export::ServeIn,
    crate::abi::hook::DecideIn,
    crate::abi::hook::NotifyIn,
    crate::abi::hook::ConfigureIn,
    crate::abi::hook::ServeIn,
    crate::abi::plane::PlaneOpenIn,
    crate::abi::plane::PlaneDriveIn,
    crate::abi::plane::PlaneCancelIn,
    crate::abi::plane::ArriveIn,
    crate::abi::plane::OnPieceIn,
    crate::abi::plane::RefusalIn,
    crate::abi::plane::ServeIn,
    crate::abi::plane::ProjectIn,
    crate::abi::plane::CatalogIn,
    crate::abi::secret::CheckIn,
    crate::abi::secret::ResolveIn,
    crate::abi::store::AddUsageBatchIn,
    crate::abi::store::AddUsageIn,
    crate::abi::store::AppendBatchIn,
    crate::abi::store::AppendPlaneRecordIn,
    crate::abi::store::BlobIn,
    crate::abi::store::GetPlaneRecordIn,
    crate::abi::store::IdIn,
    crate::abi::store::IdReasonIn,
    crate::abi::store::KeyWithCredentialIn,
    crate::abi::store::KindBeforeIn,
    crate::abi::store::KindIdIn,
    crate::abi::store::ListPlaneRecordsIn,
    crate::abi::store::OpBlobIn,
    crate::abi::store::OpBlobsIn,
    crate::abi::store::PutUsageIn,
    crate::abi::store::RecordGetIn,
    crate::abi::store::RecordPutIn,
    crate::abi::store::RecordScanIn,
    crate::abi::store::ReserveIn,
    crate::abi::store::SessionPutIn,
    crate::abi::store::SessionsForIn,
    crate::abi::store::SliceReleaseIn,
    crate::abi::store::TokenIn,
    crate::abi::store::U64In,
    crate::abi::store::UpsertPlaneRecordIn,
    crate::abi::store::WindowCapsIn,
    crate::abi::store::WindowIn,
    crate::abi::transport::ListenIn,
    crate::abi::transport::AcceptIn,
    crate::abi::transport::DialIn,
    crate::abi::transport::ReadIn,
    crate::abi::transport::WriteIn,
    crate::abi::transport::ConnIn,
    crate::abi::transport::ShutIn,
    crate::abi::transport::ArrivalIn,
    crate::abi::transport::LocateIn,
    crate::abi::transport::BeginIn,
    crate::abi::transport::IngestIn,
    crate::abi::transport::EmitIn,
    crate::abi::transport::EncodeIn,
    crate::abi::transport::RefuseIn,
    crate::abi::transport::FinishIn,
    crate::abi::transport::FramingIn,
    crate::abi::transport::AdoptIn,
);

// SAFETY (every slot `out` below): each is an `AbiOut` (checked at compile time by `slot_out`), whose
// unsafe contract states that every initialized bit pattern, all-zero included, is a valid value.
all_zero!(slot_out:
    crate::abi::mechanism::call::OutHead,
    crate::abi::mechanism::lifecycle::OpenOut,
    crate::abi::mechanism::lifecycle::TickOut,
    crate::abi::mechanism::lifecycle::CancelOut,
    crate::abi::auth::IdentifyOut,
    crate::abi::auth::BeginLoginOut,
    crate::abi::auth::OpenOutboundOut,
    crate::abi::auth::OutboundReadyOut,
    crate::abi::auth::FieldsOut,
    crate::abi::auth::TargetOut,
    crate::abi::export::ScrapeOut,
    crate::abi::export::StatusOut,
    crate::abi::export::CheckOut,
    crate::abi::export::ServeOut,
    crate::abi::hook::ConfigureOut,
    crate::abi::hook::DecideOut,
    crate::abi::hook::DescribeOut,
    crate::abi::hook::ServeOut,
    crate::abi::hook::StatusOut,
    crate::abi::hook::TransformOut,
    crate::abi::plane::PlaneOpenOut,
    crate::abi::plane::PlaneRefreshOut,
    crate::abi::plane::PlaneDriveOut,
    crate::abi::plane::PlaneCancelOut,
    crate::abi::plane::ArriveOut,
    crate::abi::plane::OnPieceOut,
    crate::abi::plane::RefusalOut,
    crate::abi::plane::ServeOut,
    crate::abi::plane::ProjectOut,
    crate::abi::plane::CatalogOut,
    crate::abi::secret::ResolveOut,
    crate::abi::store::CountOut,
    crate::abi::store::HeadOut,
    crate::abi::store::HeadsOut,
    crate::abi::store::HostBytesOut,
    crate::abi::store::HostListOut,
    crate::abi::store::LeasedBlobOut,
    crate::abi::store::LeasedListOut,
    crate::abi::store::LeasedStrListOut,
    crate::abi::store::ReserveOut,
    crate::abi::store::SliceReleaseOut,
    crate::abi::store::VerdictOut,
    crate::abi::transport::ListenOut,
    crate::abi::transport::AcceptOut,
    crate::abi::transport::ConnOut,
    crate::abi::transport::IoOut,
    crate::abi::transport::ArrivalOut,
    crate::abi::transport::LocateOut,
    crate::abi::transport::FramerOut,
);

// SAFETY (every row below, reviewed field by field): each is `#[repr(C)]` plain data whose fields
// are integers, raw pointers, `Option<extern "C" fn>` (`None` is the all-zero niche), or another
// struct of this list (`AbiStr`, `Span`, `Field`). `SignalEntry`'s `value` is a `#[repr(C)]` union
// of integers, an `f64` and an `AbiStr`, every one valid at all-zero. No `bool`, enum, reference,
// `NonNull` or non-`Option` function pointer appears in any of them.
all_zero!(row:
    crate::abi::mechanism::call::AbiStr,
    crate::abi::mechanism::call::Blob,
    crate::abi::mechanism::call::Span,
    crate::abi::mechanism::call::Field,
    crate::abi::host::service::HostSlots,
    crate::abi::auth::StripName,
    crate::abi::auth::FieldSpan,
    crate::abi::hook::SignalEntry,
    crate::abi::hook::MessageView,
    crate::abi::plane::OutField,
    crate::abi::plane::RecordWrite,
    crate::abi::plane::UnitCount,
    crate::abi::transport::FramePiece,
    crate::abi::transport::FramerSink,
    crate::abi::transport::ConnFacts,
    crate::abi::transport::Destination,
    crate::abi::host::service::ServiceOut,
    crate::abi::host::service::ItemSpan,
    crate::abi::host::service::ClockReading,
    crate::abi::host::io::IoSlots,
    crate::abi::host::conn::connector::ConnectorSlots,
);

// ── THE STATEMENT, READ ─────────────────────────────────────────────────────────────────────────

/// A kind's Statement tail [`DoorView::kind_tail`] reads. Sealed: the six kind tails below.
pub trait KindTail: sealed::SealedTail + Copy + 'static {
    /// The kind whose Statement carries this tail.
    const KIND: KindCode;
}

/// `kind_tail!(Kind => Tail, ...)`.
macro_rules! kind_tail {
    ($($kind:ident => $t:ty),+ $(,)?) => {$(
        impl sealed::SealedTail for $t {}
        impl KindTail for $t {
            const KIND: KindCode = KindCode::$kind;
        }
    )+};
}

// Each is the `#[repr(C)]` tail its kind's `abi/<kind>/` module states, leading with
// `head: KindTailHead`; secret states none.
kind_tail!(
    Store => crate::abi::store::StoreTail,
    Auth => crate::abi::auth::AuthTail,
    Hook => crate::abi::hook::Tail,
    Export => crate::abi::export::Tail,
    Plane => crate::abi::plane::PlaneTail,
    Transport => crate::abi::transport::TransportTail,
);

/// One transport claim's row, read: the Statement's `claim_rows[i]`, describing `claims()[i]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRow {
    /// Its selector forms, one code byte each.
    pub selector_forms: &'static [u8],
    /// Its outbound selector forms, one code byte each.
    pub egress_selector_forms: &'static [u8],
    /// Its transport fact keys, in stated order.
    pub facts: Vec<&'static str>,
    /// Its status numbering (empty = none).
    pub status_namespace: &'static str,
    /// `1` = it carries sessions.
    pub session: u8,
    /// `1` = a session on it caches its principal.
    pub session_bound: u8,
    /// What opens a session's first unit (`UNIT0_*`).
    pub unit0_trigger: u8,
    /// Which frame carries its status (`STATUS_AT_*`).
    pub status_at: u8,
}

/// A plugin's door, read as the host reads it, through the plugin's own door function
/// (`plugin_door!`'s `door`, or the function `export_door!` forwards to).
///
/// TRUST: a [`DoorFn`] answers a `'static` door whose Statement lists point at their stated counts
/// of live `'static` entries. That is the one-door contract every plugin states and the host's
/// loader reads under; this reader relies on exactly it, and checks what can be checked (the magic,
/// NULL lists with a count, alignment, the kind of a tail or table) before every read, panicking
/// with the field it refused.
#[derive(Debug, Clone, Copy)]
pub struct DoorView {
    door: &'static Door,
    statement: &'static Statement,
}

impl DoorView {
    /// The door `door` answers.
    ///
    /// # Panics
    ///
    /// The function answers NULL or a misaligned pointer, a door without [`DOOR_MAGIC`], or a door
    /// with no Statement.
    #[must_use]
    pub fn of(door: DoorFn) -> Self {
        let d = door();
        assert!(!d.is_null(), "the door function answered NULL");
        assert!(
            d.is_aligned(),
            "the door function answered a misaligned door"
        );
        // SAFETY: a non-NULL, aligned door a `DoorFn` answered: `'static` by the door contract.
        let door: &'static Door = unsafe { &*d };
        assert_eq!(
            door.magic, DOOR_MAGIC,
            "not a busbar door: its magic is wrong"
        );
        let st = door.statement;
        assert!(!st.is_null(), "the door states no Statement");
        assert!(st.is_aligned(), "the door's Statement is misaligned");
        // SAFETY: a non-NULL, aligned Statement of a `'static` door: `'static` by the door contract.
        let statement: &'static Statement = unsafe { &*st };
        Self { door, statement }
    }

    /// The door itself.
    #[must_use]
    pub fn door(&self) -> &'static Door {
        self.door
    }

    /// The Statement itself (its scalar fields; read its lists through the methods below).
    #[must_use]
    pub fn statement(&self) -> &'static Statement {
        self.statement
    }

    /// The kind the door states, or `None` for a number no kind has.
    #[must_use]
    pub fn kind(&self) -> Option<KindCode> {
        KindCode::from_raw(self.door.kind)
    }

    /// The plugin's name.
    ///
    /// # Panics
    ///
    /// The name is not UTF-8, or is NULL with a length.
    #[must_use]
    pub fn name(&self) -> &'static str {
        text(self.statement.name, "statement.name")
    }

    /// The URL schemes the Statement claims (a transport's), in stated order.
    ///
    /// # Panics
    ///
    /// The list or a name breaks the door contract (NULL with a count, misaligned, not UTF-8).
    #[must_use]
    pub fn claims(&self) -> Vec<&'static str> {
        let st = self.statement;
        list(st.claims, st.claims_len, "statement.claims")
            .iter()
            .map(|s| text(*s, "statement.claim"))
            .collect()
    }

    /// The structured answers the Statement declares (`answers`), in stated order.
    ///
    /// # Panics
    ///
    /// As [`DoorView::claims`].
    #[must_use]
    pub fn declares(&self) -> Vec<&'static str> {
        let st = self.statement;
        list(st.answers, st.answers_len, "statement.answers")
            .iter()
            .map(|s| text(*s, "statement.answer"))
            .collect()
    }

    /// The Statement's kind tail, as the kind's `T`.
    ///
    /// # Panics
    ///
    /// The door is not of `T`'s kind, states no tail, or states one misaligned or shorter than `T`
    /// (a plugin built against an older contract than this test).
    #[must_use]
    pub fn kind_tail<T: KindTail>(&self) -> &'static T {
        assert_eq!(
            self.door.kind,
            T::KIND as u32,
            "the door is not of the kind whose tail was asked for ({:?})",
            T::KIND
        );
        let head = self.statement.kind_tail;
        assert!(!head.is_null(), "the Statement states no kind tail");
        let tail = head.cast::<T>();
        assert!(tail.is_aligned(), "the Statement's kind tail is misaligned");
        // SAFETY: a non-NULL, aligned tail of a `'static` Statement leads with its head (the kind
        // tail rule, `KindTailHead`): `'static` by the door contract.
        let stated = unsafe { (*head).size } as usize;
        assert!(
            stated >= size_of::<T>(),
            "the Statement's kind tail states {stated} bytes, fewer than the {} this contract reads",
            size_of::<T>()
        );
        // SAFETY: the door is of `T`'s kind, so its tail is the `#[repr(C)]` `T` that kind states
        // (the sealed `KindTail` list), and its head says the plugin wrote all of it.
        unsafe { &*tail }
    }

    /// The door's ops table, as the kind's `T`.
    ///
    /// # Panics
    ///
    /// The door is not of `T`'s kind, or its table is NULL, misaligned or shorter than `T`.
    #[must_use]
    pub fn ops<T: KindOps>(&self) -> &'static T {
        assert_eq!(
            self.door.kind,
            T::KIND as u32,
            "the door is not of the kind whose table was asked for ({:?})",
            T::KIND
        );
        let head = self.door.ops;
        assert!(!head.is_null(), "the door states no ops table");
        let table = head.cast::<T>();
        assert!(table.is_aligned(), "the door's ops table is misaligned");
        // SAFETY: a non-NULL, aligned table of a `'static` door leads with its `OpsHead` (the
        // `KindOps` layout): `'static` by the door contract.
        let stated = unsafe { (*head).size } as usize;
        assert!(
            stated >= size_of::<T>(),
            "the door's ops table states {stated} bytes, fewer than the {} this contract reads",
            size_of::<T>()
        );
        // SAFETY: the door is of `T`'s kind, so its table is that kind's `#[repr(C)]` `T` (the
        // `KindOps` contract), and its head says the plugin wrote all of it.
        unsafe { &*table }
    }

    /// A transport's claim rows, row `i` describing [`DoorView::claims`]`[i]`.
    ///
    /// # Panics
    ///
    /// As [`DoorView::kind_tail`] for a transport tail, or a row's list or text breaks the door
    /// contract.
    #[must_use]
    pub fn claim_rows(&self) -> Vec<ClaimRow> {
        let tail = self.kind_tail::<crate::abi::transport::TransportTail>();
        list(tail.claim_rows, tail.claim_rows_len, "transport.claim_rows")
            .iter()
            .map(|c| ClaimRow {
                selector_forms: bytes(c.selector_forms, "claim.selector_forms"),
                egress_selector_forms: bytes(
                    c.egress_selector_forms,
                    "claim.egress_selector_forms",
                ),
                facts: list(c.facts, c.facts_len, "claim.facts")
                    .iter()
                    .map(|f| text(*f, "claim.fact"))
                    .collect(),
                status_namespace: text(c.status_namespace, "claim.status_namespace"),
                session: c.session,
                session_bound: c.session_bound,
                unit0_trigger: c.unit0_trigger,
                status_at: c.status_at,
            })
            .collect()
    }
}

// ── A PLANE'S TAIL, READ ────────────────────────────────────────────────────────────────────────

/// One text the plane tail states, for [`DoorView::plane_text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneText {
    /// `scope`.
    Scope,
    /// `label`.
    Label,
    /// `subject_noun`.
    SubjectNoun,
    /// `admin_noun`.
    AdminNoun,
    /// `audit_kind`.
    AuditKind,
    /// `signing_domain`.
    SigningDomain,
    /// `signing_kid_prefix`.
    SigningKidPrefix,
    /// `cli_help`.
    CliHelp,
    /// `caller_credential_refusal`.
    CallerCredentialRefusal,
}

/// One counted list of words the plane tail states, for [`DoorView::plane_words`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneWords {
    /// `dialects`.
    Dialects,
    /// `scope_kinds`.
    ScopeKinds,
    /// `fee_units`.
    FeeUnits,
    /// `record_kinds`.
    RecordKinds,
    /// `egress_targets`.
    EgressTargets,
    /// `metric_lanes`.
    MetricLanes,
}

/// A row type of one of the plane tail's counted lists, for [`DoorView::plane_rows`]. Sealed: the
/// eight row lists `PlaneTail` states.
pub trait PlaneRow: sealed::PlaneRow + Copy {}

/// `plane_row!(Row => list, list_len; ...)`.
macro_rules! plane_row {
    ($($t:ident => $field:ident, $len:ident);+ $(;)?) => {$(
        impl sealed::PlaneRow for crate::abi::plane::$t {
            fn of(tail: &crate::abi::plane::PlaneTail) -> (*const Self, usize, &'static str) {
                (tail.$field, tail.$len, concat!("plane.", stringify!($field)))
            }
        }
        impl PlaneRow for crate::abi::plane::$t {}
    )+};
}

// Each is the `#[repr(C)]` row type of the `PlaneTail` list it names, counted by the field after it.
plane_row!(
    DialectAuth => dialect_auth, dialect_auth_len;
    OpClass => op_classes, op_classes_len;
    BillableClass => billable_classes, billable_classes_len;
    RouteCost => route_cost, route_cost_len;
    RecordChain => record_chains, record_chains_len;
    TrustKey => trust_keys, trust_keys_len;
    RefusalStatus => refusal_statuses, refusal_statuses_len;
    AdminRoute => admin_routes, admin_routes_len;
);

/// One billable class the plane tail states, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillableClassRow {
    /// The class.
    pub class: &'static str,
    /// Its family.
    pub family: &'static str,
}

impl DoorView {
    /// One text the plane tail states (empty = absent).
    ///
    /// # Panics
    ///
    /// As [`DoorView::kind_tail`] for a plane tail, or the text breaks the door contract.
    #[must_use]
    pub fn plane_text(&self, which: PlaneText) -> &'static str {
        let t = self.kind_tail::<crate::abi::plane::PlaneTail>();
        let (s, field) = match which {
            PlaneText::Scope => (t.scope, "plane.scope"),
            PlaneText::Label => (t.label, "plane.label"),
            PlaneText::SubjectNoun => (t.subject_noun, "plane.subject_noun"),
            PlaneText::AdminNoun => (t.admin_noun, "plane.admin_noun"),
            PlaneText::AuditKind => (t.audit_kind, "plane.audit_kind"),
            PlaneText::SigningDomain => (t.signing_domain, "plane.signing_domain"),
            PlaneText::SigningKidPrefix => (t.signing_kid_prefix, "plane.signing_kid_prefix"),
            PlaneText::CliHelp => (t.cli_help, "plane.cli_help"),
            PlaneText::CallerCredentialRefusal => (
                t.caller_credential_refusal,
                "plane.caller_credential_refusal",
            ),
        };
        text(s, field)
    }

    /// One counted list of words the plane tail states, as the raw list (for the kind's own
    /// checks, which take it).
    ///
    /// # Panics
    ///
    /// As [`DoorView::kind_tail`] for a plane tail, or the list breaks the door contract.
    #[must_use]
    pub fn plane_word_list(&self, which: PlaneWords) -> &'static [AbiStr] {
        let t = self.kind_tail::<crate::abi::plane::PlaneTail>();
        let (ptr, len, field) = match which {
            PlaneWords::Dialects => (t.dialects, t.dialects_len, "plane.dialects"),
            PlaneWords::ScopeKinds => (t.scope_kinds, t.scope_kinds_len, "plane.scope_kinds"),
            PlaneWords::FeeUnits => (t.fee_units, t.fee_units_len, "plane.fee_units"),
            PlaneWords::RecordKinds => (t.record_kinds, t.record_kinds_len, "plane.record_kinds"),
            PlaneWords::EgressTargets => (
                t.egress_targets,
                t.egress_targets_len,
                "plane.egress_targets",
            ),
            PlaneWords::MetricLanes => (t.metric_lanes, t.metric_lanes_len, "plane.metric_lanes"),
        };
        list(ptr, len, field)
    }

    /// One counted list of words the plane tail states, in stated order.
    ///
    /// # Panics
    ///
    /// As [`DoorView::plane_word_list`], or a word is not UTF-8.
    #[must_use]
    pub fn plane_words(&self, which: PlaneWords) -> Vec<&'static str> {
        self.plane_word_list(which)
            .iter()
            .map(|s| text(*s, "plane.word"))
            .collect()
    }

    /// One counted row list the plane tail states (its scalar fields; a billable class's texts
    /// through [`DoorView::billable_classes`]).
    ///
    /// # Panics
    ///
    /// As [`DoorView::kind_tail`] for a plane tail, or the list breaks the door contract.
    #[must_use]
    pub fn plane_rows<T: PlaneRow>(&self) -> &'static [T] {
        let (ptr, len, field) = T::of(self.kind_tail::<crate::abi::plane::PlaneTail>());
        list(ptr, len, field)
    }

    /// The billable classes the plane tail states, in stated order.
    ///
    /// # Panics
    ///
    /// As [`DoorView::plane_rows`], or a class or family is not UTF-8.
    #[must_use]
    pub fn billable_classes(&self) -> Vec<BillableClassRow> {
        self.plane_rows::<crate::abi::plane::BillableClass>()
            .iter()
            .map(|c| BillableClassRow {
                class: text(c.class, "plane.billable_class.class"),
                family: text(c.family, "plane.billable_class.family"),
            })
            .collect()
    }
}

// ── WHAT A PLUGIN WROTE INTO A LENT BUFFER ──────────────────────────────────────────────────────

/// The bytes a plugin wrote into `lent`, the buffer the test lent it (an `err_buf`, an `into`),
/// where its `out` states it wrote `len` (`field` names that length).
///
/// # Panics
///
/// `len` is more than the capacity the test lent.
#[must_use]
pub fn written<'b>(
    lent: &'b [u8],
    len: impl TryInto<usize> + Copy + core::fmt::Debug,
    field: &str,
) -> &'b [u8] {
    let n = len
        .try_into()
        .unwrap_or_else(|_| panic!("{field}: {len:?} is no length on this target"));
    assert!(
        n <= lent.len(),
        "{field}: the plugin states it wrote {n} bytes into a buffer of {}",
        lent.len()
    );
    &lent[..n]
}

/// [`written`], as text.
///
/// # Panics
///
/// As [`written`], or the bytes are not UTF-8.
#[must_use]
pub fn written_text<'b>(
    lent: &'b [u8],
    len: impl TryInto<usize> + Copy + core::fmt::Debug,
    field: &str,
) -> &'b str {
    let b = written(lent, len, field);
    core::str::from_utf8(b).unwrap_or_else(|_| panic!("{field}: not UTF-8: {b:?}"))
}

/// A Statement list as a slice. Called ONLY with a list read out of a [`DoorView`]'s Statement or
/// tail, whose `'static` entries the door contract promises.
fn list<T>(ptr: *const T, len: usize, field: &str) -> &'static [T] {
    if len == 0 {
        return &[];
    }
    assert!(!ptr.is_null(), "{field}: NULL with a count of {len}");
    assert!(ptr.is_aligned(), "{field}: misaligned");
    assert!(
        len <= isize::MAX as usize / size_of::<T>().max(1),
        "{field}: a count of {len} overflows the address space"
    );
    // SAFETY: non-NULL, aligned and within the address space; `len` live `'static` entries by the
    // door contract (the caller passes only a door's own list).
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// A Statement string's bytes. Called ONLY with a string read out of a [`DoorView`]'s Statement,
/// tail or row.
fn bytes(s: AbiStr, field: &str) -> &'static [u8] {
    list(s.ptr, s.len, field)
}

/// A Statement string as text.
fn text(s: AbiStr, field: &str) -> &'static str {
    let b = bytes(s, field);
    core::str::from_utf8(b).unwrap_or_else(|_| panic!("{field}: not UTF-8: {b:?}"))
}

#[cfg(test)]
#[path = "tests/test_support_tests.rs"]
mod tests;
