// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST SUPPORT: what a plugin's own tests need to drive its door and read its
//! Statement WITHOUT writing `unsafe` (BUSBAR-1.6.0.md l.272-274: a transport, store or export keeps
//! `unsafe` only in its reviewed `mod door`, and a plane, hook, auth or secret crate forbids it).
//! The one `unsafe` read of each kind lives here, once, reviewed, instead of once per plugin test.
//!
//! Five parts:
//!
//! * [`zeroed`] and `Default`: the all-zero value of a REVIEWED ABI struct (every slot `in`/`out`
//!   the contract states, and the row structs a test lays out beside them), re-exported from the
//!   contract, where the sealed list and `Default` on its types must live.
//! * [`DoorView`]: a door's Statement, its claims, declared answers, kind tail, claim rows and their
//!   facts, a plane tail's texts and counted lists, and its ops table, as Rust values.
//! * [`written`] / [`written_text`]: what a plugin wrote into a buffer the test lent it, bounded by
//!   the length its `out` states and the capacity the test lent.
//! * [`fake`]: a fake host whose services a test writes as safe Rust, the `in` read and the
//!   `ServiceOut` written for it; [`far`], a scripted far end for an op's exchange, every service
//!   pending once, so an op that asks the far end is driven through PENDING to its answer.
//! * [`reply`]: a door op called and its reply copied into owned values before it returns, so a
//!   test never holds a pointer into the plugin's leased or published memory.
//!
//! DEV-ONLY: it lives in the test kit, a plugin's `[dev-dependencies]` edge, so no shipped image
//! carries it (busbar-contract's own tests mount this source). It adds no `#[repr(C)]` type and
//! changes no layout. The one piece that writes a sealed credential's bytes stays inside the
//! contract, behind its dev-only `test-seal` feature: `busbar_contract::abi::sdk::test_support::chip`.
//!
//! THE SAFE SURFACE, PROVED IN PAIRS: each `compile_fail` below has a twin that differs from it in
//! the one forbidden spelling and MUST compile, so the failure is the guard's and nothing else's.
//!
//! `DoorView` reads no forged door function; the macro's door it reads:
//!
//! ```compile_fail
//! # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
//! # struct P;
//! # impl Life for P {
//! #     const CANCEL: u32 = 0;
//! #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
//! #         Ok(P)
//! #     }
//! #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
//! #         Ok(Refreshed::default())
//! #     }
//! # }
//! # mod plugin {
//! #     busbar_contract::plugin_door! {
//! #         ops: busbar_contract::abi::secret::Ops,
//! #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
//! #         lifecycle: life(super::P),
//! #     }
//! # }
//! # extern "C" fn forged() -> *const busbar_contract::abi::mechanism::door::Door {
//! #     core::ptr::null()
//! # }
//! # use busbar_contract::abi::sdk::door::MacroDoor;
//! fn main() {
//!     let _ = busbar_test_kit::test_support::DoorView::of(forged);
//! }
//! ```
//!
//! ```
//! # use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
//! # struct P;
//! # impl Life for P {
//! #     const CANCEL: u32 = 0;
//! #     fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
//! #         Ok(P)
//! #     }
//! #     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
//! #         Ok(Refreshed::default())
//! #     }
//! # }
//! # mod plugin {
//! #     busbar_contract::plugin_door! {
//! #         ops: busbar_contract::abi::secret::Ops,
//! #         statement: busbar_contract::abi::sdk::door::statement("p", "0", 1),
//! #         lifecycle: life(super::P),
//! #     }
//! # }
//! # extern "C" fn forged() -> *const busbar_contract::abi::mechanism::door::Door {
//! #     core::ptr::null()
//! # }
//! # use busbar_contract::abi::sdk::door::MacroDoor;
//! fn main() {
//!     let _ = busbar_test_kit::test_support::DoorView::of(plugin::MACRO_DOOR);
//! }
//! ```
//!
//! A fake host hands safe code no table; it lends its tables to an `open` alone:
//!
//! ```compile_fail
//! # use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! # use busbar_test_kit::test_support::{fake::FakeHost, zeroed};
//! fn main() {
//!     let host = FakeHost::new();
//!     let _ = host.services();
//! }
//! ```
//!
//! ```
//! # use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! # use busbar_test_kit::test_support::{fake::FakeHost, zeroed};
//! fn main() {
//!     let host = FakeHost::new();
//!     let _ = host.lend_to(zeroed::<OpenIn>());
//! }
//! ```
//!
//! What a fake host lent cannot outlive it; dropped first, it can:
//!
//! ```compile_fail
//! # use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! # use busbar_test_kit::test_support::{fake::FakeHost, zeroed};
//! fn main() {
//!     let host = FakeHost::new();
//!     let lent = host.lend_to(zeroed::<OpenIn>());
//!     drop(host);
//!     drop(lent);
//! }
//! ```
//!
//! ```
//! # use busbar_contract::abi::mechanism::lifecycle::OpenIn;
//! # use busbar_test_kit::test_support::{fake::FakeHost, zeroed};
//! fn main() {
//!     let host = FakeHost::new();
//!     let lent = host.lend_to(zeroed::<OpenIn>());
//!     drop(lent);
//!     drop(host);
//! }
//! ```

use core::mem::size_of;

use busbar_contract::abi::mechanism::call::{AbiStr, Op};
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::lifecycle::OpsHead;
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC};
use busbar_contract::abi::sdk::door::{KindOps, MacroDoor};

mod sealed {
    /// Only this module implements it: the reviewed kind tails.
    pub trait SealedTail {}
    /// Only this module implements it: the plane tail's counted row lists.
    pub trait PlaneRow: Sized + 'static {
        /// The list in `tail`: its pointer, its count and its field name.
        fn of(tail: &busbar_contract::abi::plane::PlaneTail) -> (*const Self, usize, &'static str);
    }
}

pub mod fake;
pub mod far;
pub mod reply;
pub mod test_in;

pub use busbar_contract::abi::sdk::test_support::{zeroed, AllZero};

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
    Store => busbar_contract::abi::store::StoreTail,
    Auth => busbar_contract::abi::auth::AuthTail,
    Hook => busbar_contract::abi::hook::Tail,
    Export => busbar_contract::abi::export::Tail,
    Plane => busbar_contract::abi::plane::PlaneTail,
    Transport => busbar_contract::abi::transport::TransportTail,
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

/// A plugin's door, read as the host reads it, through the [`MacroDoor`] the contract's own door
/// macro expanded beside it (`plugin_door!`'s `MACRO_DOOR`). An arbitrary door function is never
/// read: a safe caller cannot hand one in.
///
/// The pair proving it (`DoorView::of(forged)` refused, `DoorView::of(MACRO_DOOR)` compiling) sits
/// on the always-compiled [`MacroDoor`].
///
/// TRUST: a door the macro built answers a `'static` door whose Statement lists point at their
/// stated counts of live `'static` entries (the one-door contract the host's loader reads under).
/// This reader relies on exactly that, and checks what can be checked (the magic, NULL lists with a
/// count, alignment, the kind of a tail or table) before every read, panicking with the field it
/// refused.
///
/// WHAT THIS DOES NOT CLOSE: the Statement's CONTENT (its lists and their counts, every `AbiStr`,
/// `Blob` and kind tail) is the macro caller's own `const` data, written with the ABI's public
/// pointer/length fields; a count that disagrees with its storage is read as stated. That class is
/// closed by the root unsafe-ABI change on branch `lane-row159-abi-unsafe-fn` (the ABI's ptr/len
/// fields private behind `const` constructors from `'static` slices and strs).
#[derive(Debug, Clone, Copy)]
pub struct DoorView {
    door: &'static Door,
    statement: &'static Statement,
}

/// ONE SLOT OF A DOOR THE CONTRACT'S MACRO BUILT (status row 159): what [`DoorView::op`] answers
/// and [`reply::call_in`] enters. It names the door it is a slot of and which slot, and is made
/// nowhere else, so a test enters only a slot a door states, never a raw `Op`.
#[derive(Debug, Clone, Copy)]
pub struct ViewOp {
    op: Op,
    door: &'static Door,
    index: u32,
    /// The type of the slot's own `in`, from its kind's slot table (`None` for a table no kind
    /// states: a host's own test double).
    takes: Option<core::any::TypeId>,
}

/// THE `in` OF ONE SLOT, read off the kinds' own slot table (the `KindSlot` impls each kind's
/// `slot_structs!` states, status row 194): `Probe<C, N>` answers `C`'s slot-`N` `in` where `C`
/// states one (`Has`), and nothing where it does not (`Lacks`, reached only through one more
/// autoderef). Each table is named concretely below, so the choice is made per table and slot.
struct Probe<C, const N: u32>(core::marker::PhantomData<C>);

trait Has {
    fn in_type(&self) -> Option<core::any::TypeId>;
}

impl<C: busbar_contract::abi::sdk::door::KindSlot<N>, const N: u32> Has for &Probe<C, N> {
    fn in_type(&self) -> Option<core::any::TypeId> {
        Some(core::any::TypeId::of::<
            <C as busbar_contract::abi::sdk::door::KindSlot<N>>::In,
        >())
    }
}

trait Lacks {
    fn in_type(&self) -> Option<core::any::TypeId>;
}

impl<C, const N: u32> Lacks for Probe<C, N> {
    fn in_type(&self) -> Option<core::any::TypeId> {
        None
    }
}

/// Slot `index`'s `in` in the table `$c` names (slots 0 to 95; no kind states more).
macro_rules! slot_in_of {
    ($c:ty, $index:expr; $($n:literal),+) => {
        'slot: {
            $(
                if $index == $n {
                    break 'slot (&&Probe::<$c, $n>(core::marker::PhantomData)).in_type();
                }
            )+
            None
        }
    };
}

/// The `in` of slot `index` in table `C`, as `C`'s own slot table states it. (`&&Probe` is
/// the probe: the borrow is how the slot table is consulted.)
#[allow(clippy::needless_borrow)]
fn table_in<C: 'static>(index: u32) -> Option<core::any::TypeId> {
    use core::any::TypeId;
    macro_rules! tables {
        ($($t:ty),+) => {
            $(
                if TypeId::of::<C>() == TypeId::of::<$t>() {
                    return slot_in_of!($t, index; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95);
                }
            )+
        };
    }
    tables!(
        busbar_contract::abi::sdk::door::Lifecycle,
        busbar_contract::abi::plane::PlaneLifecycle,
        busbar_contract::abi::store::Ops,
        busbar_contract::abi::secret::Ops,
        busbar_contract::abi::auth::Ops,
        busbar_contract::abi::hook::Ops,
        busbar_contract::abi::export::Ops,
        busbar_contract::abi::plane::Ops,
        busbar_contract::abi::transport::Ops
    );
    None
}

// THE PROBE COVERS EVERY SLOT: no kind's table holds more slots than `slot_in_of!` reads (0 to 95).
// A kind that outgrows it fails to compile here, never skips its check.
const _: () = {
    use busbar_contract::abi::sdk::door::slot_count;
    assert!(slot_count::<busbar_contract::abi::store::Ops>() <= 96);
    assert!(slot_count::<busbar_contract::abi::secret::Ops>() <= 96);
    assert!(slot_count::<busbar_contract::abi::auth::Ops>() <= 96);
    assert!(slot_count::<busbar_contract::abi::hook::Ops>() <= 96);
    assert!(slot_count::<busbar_contract::abi::export::Ops>() <= 96);
    assert!(slot_count::<busbar_contract::abi::plane::Ops>() <= 96);
    assert!(slot_count::<busbar_contract::abi::transport::Ops>() <= 96);
};

/// The `in` type of slot `index` of a `T` door: its lifecycle's for a lifecycle slot, its kind's
/// own otherwise; `None` for a table no kind states (a host's own test double).
pub(crate) fn slot_in_type<T: KindOps>(index: u32) -> Option<core::any::TypeId> {
    if index < busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS {
        table_in::<T::Lifecycle>(index)
    } else {
        table_in::<T>(index)
    }
}

impl ViewOp {
    /// The slot's index in its kind's table (the mechanism's SLOT LAYOUT).
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The slot and the door it is a slot of, for [`reply`] alone.
    pub(crate) fn parts(self) -> (Op, &'static Door, u32) {
        (self.op, self.door, self.index)
    }

    /// The slot is entered over its own `in` type, `I`, and no other (status row 194): an `in` of
    /// another slot would hand it fields read as pointers it never was lent.
    ///
    /// # Panics
    ///
    /// `I` is not the slot's `in`.
    pub(crate) fn check_in<I: 'static>(self) {
        if let Some(takes) = self.takes {
            assert!(
                takes == core::any::TypeId::of::<I>(),
                "reply::call_in: the `in` is not slot {}'s own `in` ({})",
                self.index,
                core::any::type_name::<I>()
            );
        }
    }
}

// THE ONE WAY IN, pinned at compile time on every build of this module (this crate's own tests
// included, with or without the feature): `DoorView::of` takes a `MacroDoor` and nothing else. A
// change of its parameter to any door function breaks this line before any test runs.
const _: fn(MacroDoor) -> DoorView = DoorView::of;

impl DoorView {
    /// The door the macro built.
    ///
    /// # Panics
    ///
    /// A door without [`DOOR_MAGIC`], or a door with no Statement.
    #[must_use]
    pub fn of(door: MacroDoor) -> Self {
        let door: &'static Door = (door.door_fn())();
        assert_eq!(
            door.magic(),
            DOOR_MAGIC,
            "not a busbar door: its magic is wrong"
        );
        let st = door.statement();
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
        KindCode::from_raw(self.door.kind())
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
            self.door.kind(),
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

    /// ONE SLOT of the door's table, as [`reply::call_in`] enters it: `pick` names the slot
    /// (`|t| &t.head.open`, `|t| &t.resolve`), and the handle remembers which door and which slot
    /// it is. `None` when the door leaves the slot absent. A [`ViewOp`] is made here and nowhere
    /// else (status row 159).
    ///
    /// # Panics
    ///
    /// As [`DoorView::ops`], or `pick` answers a reference that is not a slot of the table.
    #[must_use]
    pub fn op<T: KindOps>(
        &self,
        pick: impl FnOnce(&'static T) -> &'static Option<Op>,
    ) -> Option<ViewOp> {
        let table = self.ops::<T>();
        let slot = pick(table);
        let base = core::ptr::from_ref(table) as usize;
        let at = core::ptr::from_ref(slot) as usize;
        let first = base + core::mem::offset_of!(OpsHead, validate);
        assert!(
            at >= first
                && at + size_of::<Option<Op>>() <= base + size_of::<T>()
                && (at - first).is_multiple_of(size_of::<Option<Op>>()),
            "DoorView::op: the picked reference is not a slot of the door's table"
        );
        let index = busbar_contract::abi::sdk::door::slot_at(at - base);
        (*slot).map(|op| ViewOp {
            op,
            door: self.door,
            index,
            takes: slot_in_type::<T>(index),
        })
    }

    /// The door's ops table, as the kind's `T`.
    ///
    /// # Panics
    ///
    /// The door is not of `T`'s kind, or its table is NULL, misaligned or shorter than `T`.
    #[must_use]
    pub fn ops<T: KindOps>(&self) -> &'static T {
        assert_eq!(
            self.door.kind(),
            T::KIND as u32,
            "the door is not of the kind whose table was asked for ({:?})",
            T::KIND
        );
        let head = self.door.ops();
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
        let tail = self.kind_tail::<busbar_contract::abi::transport::TransportTail>();
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
        impl sealed::PlaneRow for busbar_contract::abi::plane::$t {
            fn of(tail: &busbar_contract::abi::plane::PlaneTail) -> (*const Self, usize, &'static str) {
                (tail.$field, tail.$len, concat!("plane.", stringify!($field)))
            }
        }
        impl PlaneRow for busbar_contract::abi::plane::$t {}
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
        let t = self.kind_tail::<busbar_contract::abi::plane::PlaneTail>();
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
        let t = self.kind_tail::<busbar_contract::abi::plane::PlaneTail>();
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
        let (ptr, len, field) = T::of(self.kind_tail::<busbar_contract::abi::plane::PlaneTail>());
        list(ptr, len, field)
    }

    /// The billable classes the plane tail states, in stated order.
    ///
    /// # Panics
    ///
    /// As [`DoorView::plane_rows`], or a class or family is not UTF-8.
    #[must_use]
    pub fn billable_classes(&self) -> Vec<BillableClassRow> {
        self.plane_rows::<busbar_contract::abi::plane::BillableClass>()
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
