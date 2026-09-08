// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authority, the interner and the one implementor of the kernel's `Units` trait.
//!
//! Three things the design draws have, until now, existed in the tree only as test doubles: an
//! implementor of `busbar_kernel::teller::Units`, an implementor of
//! `busbar_kernel::inflight::ArrivalDoor`, and a live `busbar_contract::Registration`. This file is
//! where the production ones live, and it is the only place in the workspace entitled to name all
//! fourteen units at once.
//!
//! ## Fourteen units, twelve methods
//!
//! The mapping is not one-to-one and never was. Two of the twelve methods reach more than one unit,
//! three reach none, and five units are never reached through `Units` at all:
//!
//! | `Units` method | unit(s) reached |
//! |---|---|
//! | `arrival` | none — the kernel's own gate over the configured budgets |
//! | `decode` | the claimed plane, not a unit |
//! | `authenticate` | the auth unit |
//! | `verify` | the trust unit, reading the breaker unit's view |
//! | `approve` | the scope unit |
//! | `admit` | the admission unit, priced by the cost unit |
//! | `route` | the egress unit, over the breaker, egress-auth and transport-key units |
//! | `meter` | the usage unit |
//! | `audit` | the audit unit, then the ledger unit |
//! | `audit_refused` | the audit unit — the door a unit that never passed Admit leaves through |
//! | `encode` | the claimed plane, not a unit |
//! | `evidence` | the usage and cost units, read once by the exit path |
//!
//! Reached elsewhere, and bound by the root rather than by a step: the WAL unit sits under the
//! ledger on the durability path; the verbs unit is a destination at Route, holding the admin
//! token; the transport-key unit runs at listen, dial and upgrade, outside the loop entirely; the
//! egress-auth unit is called from inside Route by the egress unit; and the breaker unit is
//! consulted at Verify and recorded at Route without ever being a step of its own.
//!
//! ## One plane at a time
//!
//! The bodies arrive one plane at a time — admin first, then the other three, then the reference
//! plane last — and the first of them has landed. Every method therefore begins with the same
//! question: is this unit one the admin bindings opened? If it is, the step runs against the units
//! that plane composes over. If it is not, the step REFUSES, naming the step it refused at.
//!
//! The refusal is deliberate and is not a placeholder. A unit that reached this type on a plane
//! this root does not yet drive was routed to the wrong loop, and there are only two honest answers
//! to that: end it saying so, or panic. Serving it half-composed — arriving it, admitting it, and
//! then finding at Route that nothing knows what it is — would charge a request slot for a unit that
//! could never have been answered. A refusal at the first step costs nothing and says exactly what
//! happened, which is what makes the coexistence window safe to be in.

// The authenticate step's three seams live beside the other root modules; reached here by the
// name every call site uses.
pub use super::auth_bindings;

use std::sync::{Arc, LazyLock, Mutex};

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, Audit, Authenticate, Decision, Decode, Encode, Hold,
    Meter, Outcome, PrincipalId, Refusal, Route, UnitToken, UsageToken, VerifiedDestination,
    Verify,
};
use busbar_kernel::inflight::ArrivalDoor;
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
use busbar_unit_admission::{Door, InMemoryCells};
use busbar_unit_auth::{Auth, AuthChain};
use busbar_unit_egress::EgressUnit;
use busbar_unit_trust::Trust;

/// Take the kernel's seal. Boot only, once per process.
///
/// The seal is the node's whole authority: every token a unit is ever lent is minted from it, for
/// the length of one call, and there is no second way to obtain one. Calling this twice would give
/// a process two authorities, which is why the composition root calls it exactly once and hands the
/// kernel around by reference from there.
#[must_use]
pub fn new_kernel() -> busbar_kernel::teller::Kernel {
    busbar_kernel::teller::Kernel::new()
}

/// Open the vocabulary interner.
///
/// Config-derived open-vocabulary keys — a lane, a pool, a model, a provider host, a dialect name,
/// a loaded plugin's key — are leaked into `&'static str` exactly once, here, at registration. The
/// resulting allocation is fixed and countable; a leak per connection or per dial is a defect
/// rather than a variant of the rule. [`crate::root::vocabulary`] is what enforces the "exactly
/// once, and never after boot" half.
#[must_use]
pub fn new_registration() -> busbar_contract::Registration {
    busbar_contract::Registration::new()
}

// ---------------------------------------------------------------------------------------------
// The dated card history the root prices against
// ---------------------------------------------------------------------------------------------

/// **THE CURRENCY THIS NODE'S MONEY IS IN**, named once, here.
///
/// A 1.5.5 deployment's configured figures carry no currency at all
/// (`crates/busbar-core/src/config/mod.rs:1224`: "ABSTRACT cost units (no currency, no FX)") and its
/// `/usage` labels them `USD` through a synthetic serializer. So the node reads them as a card
/// naming exactly one currency, `USD`, whose minor unit is the cent every 1.5.5 figure was already
/// projected through — `nanos_per_minor() == 10_000_000`, bit-identical arithmetic, not one byte of
/// a released surface moved.
///
/// It is a function rather than an inlined `CurrencyCode::USD` at each call site because there are
/// three call sites and they must never disagree: the card is BUILT in this currency, the lookup is
/// ASKED for this currency, and the posting's cache RECORDS this currency. A second spelling is how
/// a node comes to price a card in one currency and read it in another and report the refusal as a
/// zero. The day a deployment declares its own, this is the one body that changes.
#[must_use]
pub fn node_currency() -> busbar_unit_cost::CurrencyCode {
    busbar_unit_cost::CurrencyCode::USD
}

/// A HISTORY PINNED BY ONE READER: the `Arc` it took at admission, and the snapshot it took with it.
///
/// The two travel together because neither is the pin on its own. The `Arc` alone would let a reader
/// see entries appended after it was admitted — an apply landing mid-body would reprice a request
/// halfway through, which is the exact hazard the pin exists to prevent. The seq alone would name a
/// snapshot of a history the reader no longer holds. Held as a pair, `view()` answers the same
/// entries for this reader's whole life however many applies land behind it.
///
/// `HistoryView` is a borrow, so it cannot be the thing that is stored; it is spelled out of this
/// pair on demand, which costs nothing — a slice and a number.
#[derive(Clone, Debug)]
pub struct PinnedHistory {
    history: Arc<busbar_unit_cost::History>,
    at: busbar_unit_cost::HistorySeq,
}

impl PinnedHistory {
    /// The snapshot this reader was admitted under.
    ///
    /// Everything with `seq <= at`, which is exactly the history as it stood at the door. An entry
    /// appended since is not in it and cannot be: the slice stops short of it.
    #[must_use]
    pub fn view(&self) -> busbar_unit_cost::HistoryView<'_> {
        self.history.snapshot(self.at)
    }

    /// The snapshot's own number — the figure a posting records so a reader can reproduce it.
    #[must_use]
    pub fn seq(&self) -> busbar_unit_cost::HistorySeq {
        self.at
    }

    /// A pin over a history a test built by hand, so a proof can name the instants its entries take
    /// effect at instead of racing the wall clock the holder reads.
    ///
    /// `cfg(test)` and nothing else compiles it: the shipped binary reaches a pin through
    /// [`RootHistory::pin`], which is the only construction that can produce one over the process's
    /// own history. A production caller able to assemble a snapshot out of parts is a caller able to
    /// price a request against a history the node never resolved.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(
        history: Arc<busbar_unit_cost::History>,
        at: busbar_unit_cost::HistorySeq,
    ) -> Self {
        PinnedHistory { history, at }
    }

    /// The same history, pinned at an EARLIER snapshot — the one construction that proves the seq is
    /// load-bearing, because both pins hold the identical `Arc`.
    #[cfg(test)]
    #[must_use]
    pub fn for_test_at(other: &PinnedHistory, at: busbar_unit_cost::HistorySeq) -> Self {
        PinnedHistory {
            history: Arc::clone(&other.history),
            at,
        }
    }
}

/// THE PROCESS'S ONE RATE-CARD HISTORY, and it lives in the root because a rate is a statement about
/// a deployment rather than about a plane. A plane reports what a unit consumed; what those
/// quantities are worth is read here, off the same configured figures the engine's own spend
/// projection derives from.
///
/// APPEND-ONLY, not swap-in-place. The engine rebuilds its projection's rates on every config apply
/// and reload; the root answers by APPENDING a dated entry that prices what happens after it. The
/// entry before it is not touched, not closed and not deleted — which is the whole design: a booked
/// line is never rewritten, so a posting that already happened goes on resolving to the card it was
/// earned under however many times an operator edits a price. Replacing the card, as this holder did
/// before, silently re-priced every past posting on the next read.
///
/// PINNED BY THE READER, not read twice. A unit takes its [`PinnedHistory`] at ADMISSION and prices
/// its whole life against that one snapshot, including the accrual that lands after its body has
/// drained. That is what makes the pricing a promise rather than a race: a request that opened
/// before an apply is billed on the history it was admitted under, and an apply landing mid-body
/// cannot reprice a request halfway through. The next admission takes the new head.
#[derive(Default)]
pub struct RootHistory {
    /// `None` until the boot resolution raises the rate-apply seam. Absent, a report is not priced
    /// and nothing is posted — the honest answer for a build that has read no configuration yet,
    /// rather than a fallback card whose figures no operator wrote.
    history: arc_swap::ArcSwapOption<busbar_unit_cost::History>,
    /// **THE ROOT'S OWN COUNT OF CONFIG RESOLUTIONS**, and that count is what an entry records as
    /// its policy epoch.
    ///
    /// The rate-apply seam carries the figures and nothing else — no epoch, by design
    /// (`crates/busbar-substrate/src/rate_apply.rs:14`) — so there is no engine number to copy here
    /// and inventing one that looked like the engine's would be worse than counting honestly. The
    /// boot resolution is epoch 0 and each apply after it is the next, which is a true statement
    /// about which generation of the deployment's configuration produced the entry. The day the seam
    /// carries the engine's own epoch, this counter is what it replaces.
    resolutions: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for RootHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootHistory").finish_non_exhaustive()
    }
}

impl RootHistory {
    /// The history as it stands, pinned at its head for the caller's whole life.
    ///
    /// The returned pair is the reader's to keep: an append after this call is seen by the NEXT
    /// caller and leaves this one reading the snapshot it was admitted under.
    #[must_use]
    pub fn pin(&self) -> Option<PinnedHistory> {
        let history = self.history.load_full()?;
        let at = history.head()?;
        Some(PinnedHistory { history, at })
    }

    /// **THE ONLY MUTATOR: APPEND.** Put `card` on the history effective from `now_ms`, and return
    /// the entry's number.
    ///
    /// The FIRST entry is effective from instant ZERO rather than from `now_ms`, and that is not a
    /// convenience. A first entry starting at boot would leave every instant before boot in a hole,
    /// and a hole is a refusal — so a posting whose arrival the node dated a millisecond early, or a
    /// legacy row carrying nothing finer than a UTC day, would price at nothing. Effective from zero
    /// with no end, one entry covers every instant, and a deployment that never edits a price is a
    /// single-entry history: arithmetically the previous release, to the byte.
    ///
    /// EVERY LATER ENTRY is effective from `now_ms` and closes nothing. The previous entry stays
    /// open-ended and stays exactly as it was written; the resolution rule takes the highest
    /// covering seq, so this entry out-ranks it from `now_ms` forward and the entry before it goes
    /// on answering for every instant before that, forever. Closing the old entry would be a write
    /// to a record that is already booked.
    ///
    /// Read-copy-update rather than load-then-store: two applies landing together would otherwise
    /// each clone the same history and the second's store would drop the first's entry on the floor,
    /// which is a price change that silently did not happen.
    pub fn apply(
        &self,
        card: busbar_unit_cost::RateCard,
        now_ms: u64,
    ) -> busbar_unit_cost::HistorySeq {
        let policy_epoch = self
            .resolutions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let appended = self.history.rcu(|current| {
            let mut next = match current {
                Some(history) => busbar_unit_cost::History::clone(history),
                None => busbar_unit_cost::History::new(),
            };
            let effective_from = if next.is_empty() { 0 } else { now_ms };
            next.append(busbar_unit_cost::CardEntryDraft {
                effective_from,
                effective_until: None,
                card: card.clone(),
                appended_at: now_ms,
                author: busbar_unit_cost::Author::Config { policy_epoch },
            });
            Some(Arc::new(next))
        });
        let _ = appended;
        self.history
            .load()
            .as_ref()
            .and_then(|h| h.head())
            .unwrap_or(busbar_unit_cost::HistorySeq::OPENING)
    }

    /// How many entries stand on the history. A read for the tests and for the operator surface that
    /// reports the head; it is never on a pricing path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.history.load().as_ref().map_or(0, |h| h.len())
    }

    /// Whether no configuration has been resolved yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The process's history holder, reached by the root's units and by nothing below them.
///
/// A `static` for the same reason the LLM node is one: the seam a unit is driven through is a bare
/// `fn` and a bare `fn` cannot capture, so the holder has to be reachable by name. It exists before
/// the boot that reads the configuration finishes, holding no history, which is exactly the state a
/// report arriving that early should be priced in — it isn't.
pub static ROOT_CARD: LazyLock<RootHistory> = LazyLock::new(RootHistory::default);

/// The configured rates, in the cost unit's own card.
///
/// A RELAY, AND DELIBERATELY NOTHING MORE. Reading the deployment's configuration is the root's;
/// turning those figures into a card is the cost unit's, on
/// [`busbar_unit_cost::RateCard::from_config`] — so the class fan-out, the absent/present branch and
/// the fee's clamp all happen where the card lives, and there is no arithmetic here to disagree with
/// it. No plane sees a rate at all.
///
/// THE ROOT'S, NOT A PLANE'S. The card this builds is the one every plane's exit prices against —
/// the holder above is the process's, reached by mcp, a2a, voice and admin exactly as it is by llm —
/// so the relay belongs beside the holder and the repricer rather than in one plane's unit file. It
/// lived in `units_llm` while llm was the only leg switched over, and a plane's unit file is
/// compiled out with its plane: any build without that plane's feature lost the root's ability to
/// price a card at all. The deletability of a plane is the whole point of the feature, so the thing
/// that must survive every deletion lives on the ungated side of the seam.
///
/// A deployment with no `rate_card:` builds an ABSENT card rather than no card at all, and the
/// difference matters: absent prices every class at nothing and still charges the flat fee, which is
/// exactly what the previous release bills for that deployment.
///
/// The card carries no version of its own any more. Which card a posting was priced against is the
/// number of the history entry that holds it, and that number belongs to the history: a card naming
/// itself would be a second identity that can disagree with the first. This relay builds the card;
/// appending it to the history is [`RootHistory::apply`]'s.
///
/// THE CURRENCY IS THE CALLER'S, and it is passed in rather than assumed. The configured figures
/// carry no currency of their own — a 1.5.5 deployment's rates are abstract cost units — so the
/// currency a card is built in is a statement about the NODE, made once at [`node_currency`], and
/// handed here. Defaulting it inside this relay would put a second answer to "what currency is this
/// node's money in" in a file that has no business deciding, and the two answers would be free to
/// drift.
pub(crate) fn card_from_config<'r>(
    rates: impl IntoIterator<Item = (&'r str, busbar_substrate::billing::RawTierRates)>,
    per_request_fee: i64,
    present: bool,
    currency: busbar_unit_cost::CurrencyCode,
) -> busbar_unit_cost::RateCard {
    // The substrate's neutral raw-rate view, lifted into the cost unit's own — four numbers copied
    // across a crate boundary, in the same canonical order, with nothing computed on the way.
    let lanes = present.then(|| {
        rates.into_iter().map(|(lane, raw)| {
            (
                lane,
                busbar_unit_cost::TierRates {
                    input: raw.input,
                    output: raw.output,
                    cache_read: raw.cache_read,
                    cache_write: raw.cache_write,
                },
            )
        })
    });
    busbar_unit_cost::RateCard::from_config_in(currency, lanes, per_request_fee)
}

/// The root, answering the engine's rate-apply seam.
///
/// The whole of the wiring: the engine resolved the deployment's rates — at boot or on a live apply —
/// and the root builds a card from the SAME two configured figures and APPENDS it to the history,
/// dated at the instant the apply landed. One configuration, two readings, and the apply moves both
/// or neither.
///
/// The instant is read HERE, once, from the same wall clock a unit's arrival is read from, so the
/// entry's `effective_from` and a posting's `arrived_ms` are two readings of one scale and a
/// comparison between them means what it says.
#[derive(Debug, Clone, Copy)]
pub struct CardRepricer;

impl busbar_substrate::rate_apply::RateApply for CardRepricer {
    fn rates_applied(&self, rates: &busbar_substrate::rate_apply::RawRates<'_>) {
        ROOT_CARD.apply(
            card_from_config(
                rates.lanes.iter().map(|(lane, r)| (lane.as_str(), *r)),
                rates.fee_cents,
                rates.present,
                node_currency(),
            ),
            busbar_substrate::store::now_ms(),
        );
    }
}

/// Install the root as the process's rate holder. Boot only, once.
pub fn install_card_repricer() {
    busbar_substrate::rate_apply::install_rate_apply(&CardRepricer);
}

/// The admission unit, standing at the in-flight table's arrival door.
///
/// The kernel's in-flight table takes a `&dyn ArrivalDoor` and, until this existed, the only
/// implementor in the tree was a test double — which made "a hold cannot exist without the unit's
/// own token" true everywhere except in the one place that mattered. The binding is a delegation
/// and nothing else: the admission unit already exports the constructor, and a root that computed
/// anything here would be a root deciding what a unit is for.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdmissionDoor;

impl ArrivalDoor for AdmissionDoor {
    fn arrival_hold(&self, principal: PrincipalId, token: &AdmitToken<Admit>) -> Hold {
        busbar_unit_admission::arrival_hold(principal, token)
    }
}

/// The store a node has before one is configured.
///
/// Every method answers that there is nothing there, which is what an unconfigured store IS. It is
/// not the production default — that is the loader's ABI-2 adapter over the configured store, and
/// the in-tree memory store when a config names none — it is what the composition holds until the
/// configured one is built.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingStore;

impl busbar_unit_verbs::store::Store for RefusingStore {
    fn chain_break(
        &self,
        _admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Err(busbar_unit_verbs::StoreError::Failed)
    }

    fn store_restore(
        &self,
        _admin: &busbar_caps::AdminToken,
        _backup_ref: &str,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Err(busbar_unit_verbs::StoreError::Failed)
    }

    fn reseal_epoch_floor(
        &self,
        _admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Err(busbar_unit_verbs::StoreError::Failed)
    }

    fn replay_new_verb(
        &self,
        _key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
        Ok(None)
    }

    fn commit_new_verb_replay(
        &self,
        _key: &(String, String),
        _response: &[u8],
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Ok(())
    }
}

/// The long-lived objects the root owns, behind the one trait the loop reaches a unit through.
///
/// Only the units with state across requests are fields. The other eight are facades — free
/// functions or unit structs the step calls with the facts it was handed — and holding an empty
/// value for each of them would be furniture rather than structure.
///
/// The cell store is deliberately the reference in-memory one at this step. Production wants
/// sharded, canonical-order locking rather than the single lock this takes, and the admission unit
/// says so in its own documentation; the store is a type parameter on the door precisely so
/// swapping it is a composition change and not a unit change.
pub struct ProductionUnits {
    /// The admission unit's long-lived door. Its ledger cells are hydrated once, at boot, and are
    /// never re-read on the request path.
    pub door: Door<InMemoryCells>,
    /// The egress unit's rotation memory. The walk itself is a per-request value.
    pub egress: EgressUnit,
    /// Every `(pool, destination)` breaker cell and every destination's lifetime budget, behind the
    /// port the egress unit reaches it through.
    ///
    /// There is exactly one of these and it is reached only here. Two breaker units would be two
    /// sets of cells: a trip recorded through one would be invisible to the other, and a lane the
    /// walk had benched would still read as ready at Verify.
    pub breaker: crate::root::adapters::BreakerAdapter,
    /// The authentication chain, resolved from configuration at boot.
    pub auth: Auth,
    /// The three seams the authenticate step is handed beside the request: the credential cache, the
    /// signed-key verifier and the revocation view.
    ///
    /// One per node rather than one per plane, for the reason the cache's own documentation gives
    /// about a flush: two caches would be two answers to "has this credential been seen", and an
    /// operator who flushed one would leave the other serving a verdict the flush was meant to have
    /// killed.
    pub auth_bindings: auth_bindings::AuthBindings,
    /// The trust unit. Stateless: it is handed the pool view and the kind facts per call.
    pub trust: Trust,
    /// The arrival door, bound to the admission unit and to nothing else.
    pub arrival_door: AdmissionDoor,
    /// The journal, the ledger and the audit unit's two chains.
    ///
    /// Behind one lock because all four are append-only and a unit's settlement touches more than
    /// one of them: the record is sealed, the ledger moves and the journal takes the batch, and a
    /// reader that saw two of the three would be reading a half-settled unit.
    /// Behind an `Arc` as well as the lock, because the five ledger views read the same four things
    /// this node writes. They hold a handle to THIS value rather than a copy of it taken at boot: a
    /// view over a copy would serve the figures the node had when it started listening, which is a
    /// worse answer than no figures at all because it looks like a current one. What the views take
    /// at request time is a snapshot under this lock, which is the same lock a settlement holds — so
    /// no read can see a unit half-settled, and no reader can write, because what crosses the seam
    /// is a value and never the ledger.
    pub durability: Arc<Mutex<crate::root::durability::Durability>>,
    /// What the usage unit meters against — built from the configured rate cards, never from the
    /// unit's own default, because an empty lane expansion disputes every pooled posting.
    pub meter_policy: crate::root::policy::MeterPolicyHandle,
    /// What the scope unit reads at Approve. Silence is a refusal.
    pub scope_policy: crate::root::policy::ScopePolicy,
    /// The admin plane's bindings: the seam an operation's body is reached through, and the table
    /// of admin units the loop is currently walking.
    ///
    /// One plane's bindings rather than five, because one plane has been switched. The other four
    /// arrive as their own fields as their own steps land, and until then their step methods say so
    /// rather than answering for a plane that is still served elsewhere.
    #[cfg(feature = "root-admin")]
    pub admin: crate::root::units_admin::AdminBinding,
    /// The store, behind the published ABI. The verbs unit's disaster-recovery subset and its
    /// sealed idempotency cache both reach it, and both reach the same one.
    pub store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    /// The credential the kernel lends the verbs unit for the length of an execution.
    ///
    /// Minted once, at boot, from the node's one authority — the second token in the tree minted
    /// outside the loop, for the same reason as the first: a kernel verb is a Route destination
    /// rather than a step, so no step's token stands in for it.
    pub admin_token: busbar_caps::AdminToken,
}

impl ProductionUnits {
    /// Assemble the units the loop reaches, over what the root already built.
    ///
    /// Everything expensive — opening a journal, hydrating the ledger cells, resolving the auth
    /// chain, reading the rate cards — has happened by the time this is called. This is the
    /// assembly, not the work. Every argument is a value configuration decided, which is the shape
    /// that makes it impossible to construct these units and forget one.
    // The argument list IS the point, and shortening it would cost the property the doc comment
    // above claims. Every parameter is one decision configuration made; bundling them into a struct
    // would give that struct a `Default`, and a `Default` is exactly how a deployment ends up with a
    // metering policy it never read its rate cards for. A long list that cannot be built wrong beats
    // a short one that can.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kernel: &busbar_kernel::teller::Kernel,
        auth_chain: AuthChain,
        durability: crate::root::durability::Durability,
        breaker_policy: crate::root::adapters::BreakerPolicy,
        meter_policy: crate::root::policy::MeterPolicyHandle,
        scope_policy: crate::root::policy::ScopePolicy,
        #[cfg(feature = "root-admin")] admin: crate::root::units_admin::AdminBinding,
        store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    ) -> Self {
        ProductionUnits::new_sharing(
            kernel,
            auth_chain,
            Arc::new(Mutex::new(durability)),
            breaker_policy,
            meter_policy,
            scope_policy,
            #[cfg(feature = "root-admin")]
            admin,
            store,
        )
    }

    /// The same assembly over a book somebody else owns.
    ///
    /// [`ProductionUnits::new`] takes the durability by value, which says the node it builds is the
    /// only thing that settles onto it — true of a node with one plane on the loop and false the
    /// moment a second plane's exit arm needs the same book. This takes the handle instead, so the
    /// caller keeps one and every arm that settles is settling onto the book these units read.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new_sharing(
        kernel: &busbar_kernel::teller::Kernel,
        auth_chain: AuthChain,
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        breaker_policy: crate::root::adapters::BreakerPolicy,
        meter_policy: crate::root::policy::MeterPolicyHandle,
        scope_policy: crate::root::policy::ScopePolicy,
        #[cfg(feature = "root-admin")] admin: crate::root::units_admin::AdminBinding,
        store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    ) -> Self {
        ProductionUnits {
            door: Door::new(InMemoryCells::new()),
            // The breaker unit's one diagnostic reaches the node's own logging rather than the
            // noop the crate defaults to. What an operator gets out of the binding is the line
            // saying an `error_map` entry they wrote names a class that does not exist; what the
            // request path gets is nothing at all, because the mapping was ignored before the
            // binding and is ignored after it.
            breaker: crate::root::adapters::BreakerAdapter::with_diagnostics(
                crate::root::adapters::root_diagnostics(),
                breaker_policy,
            ),
            egress: EgressUnit::new(),
            auth: Auth::new(auth_chain),
            // The unbound posture, which is the one a node has until it is handed a directory:
            // the cache is real, and the two authorities are absent rather than permissive. A
            // deployment whose keys are busbar's own binds them through
            // `ProductionUnits::with_auth_bindings` at boot, where the governance state exists.
            auth_bindings: auth_bindings::AuthBindings::without_directory(),
            trust: Trust,
            arrival_door: AdmissionDoor,
            durability,
            meter_policy,
            scope_policy,
            #[cfg(feature = "root-admin")]
            admin,
            store,
            // Minted once, at boot, from the node's one authority. The verbs unit is lent it for the
            // length of an execution and holds nothing after; there is no second way to obtain one.
            admin_token: kernel.admin_token(),
        }
    }

    /// The units an administrative listener needs, and only those.
    ///
    /// One plane has been switched onto the loop, and this is the composition for it: the journal is
    /// memory-buffered because the administrative surface writes no money and probes no directory,
    /// the metering policy is the empty one because the plane declares no meter classes to price
    /// against, and the store is the unconfigured one because no admin operation this root drives
    /// reaches the disaster-recovery subset. Every one of those is a decision this constructor
    /// MAKES rather than defaults into, and each is the reason the corresponding argument of
    /// [`ProductionUnits::new`] is not asked for here.
    ///
    /// When the other four planes switch, they come in through `new` with the configuration they
    /// actually need. This constructor exists because an admin-only node genuinely needs less, not
    /// because the rest is unfinished.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only(dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>) -> Self {
        // One value, two halves. The ledger is handed the write half and keeps it for the life of
        // the node; the read half stays here so the ledger views have somewhere to read the
        // previous release's rows from. They are the same rows because they are the same value —
        // a second recorder would be a second answer to what the dual write wrote.
        let rows = busbar_unit_ledger::legacy::RecordingRows::new();
        ProductionUnits::admin_only_over(dispatch, Box::new(rows.clone()), Arc::new(rows))
    }

    /// The same composition, over legacy rows the caller supplies both halves of.
    ///
    /// Split out because the two halves are one obligation: whatever the ledger dual-writes onto is
    /// what the reconciliation view has to read back, and a constructor that took only the write
    /// half would leave the view reading a different set of rows from the one the node writes. A
    /// caller passing two halves of different values is making that mistake explicitly rather than
    /// inheriting it.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only_over(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        write: Box<dyn busbar_unit_ledger::legacy::LegacyRows>,
        read: Arc<dyn crate::root::units_admin::LegacyRowsRead>,
    ) -> Self {
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            write,
        )
        .expect("a memory-buffered journal cannot fail to open");
        ProductionUnits::admin_only_sharing(dispatch, Arc::new(Mutex::new(durability)), read)
    }

    /// The same composition again, over a book the caller already opened.
    ///
    /// The one constructor a boot that serves more than the administrative listener can use. The
    /// other two open a book of their own, which is right for a node whose only settlements are the
    /// admin plane's; it is wrong the moment a second plane's exit arm settles, because that arm
    /// would be moving figures on a book these views cannot see. An operator reading the totals
    /// would get an empty table off a node that had been posting all day — and an empty table
    /// reconciles, so the emptiness would not even read as a fault.
    ///
    /// So the book arrives as an argument. The caller holds the same handle it passes here, and what
    /// every plane settles onto is what these views read.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only_sharing(
        dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>,
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        read: Arc<dyn crate::root::units_admin::LegacyRowsRead>,
    ) -> Self {
        let kernel = new_kernel();
        let mut units = ProductionUnits::new_sharing(
            &kernel,
            AuthChain::new(Vec::new(), false),
            Arc::clone(&durability),
            crate::root::adapters::BreakerPolicy::new(),
            crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
            crate::root::policy::ScopePolicy::new(),
            crate::root::units_admin::AdminBinding::new(dispatch),
            Arc::new(RefusingStore),
        );
        // The views are bound after the units are assembled rather than through the constructor,
        // because what they read is the durability the constructor took ownership of — the handle
        // does not exist until it has. Binding it here is what makes the served figures this node's
        // rather than an empty table that looks like a balanced one.
        units.admin.ledger = Arc::new(crate::root::units_admin::NodeLedger::new(durability, read));
        units
    }

    /// Bind the authenticate step's three seams to a node's virtual-key directory.
    ///
    /// Separate from [`ProductionUnits::new`] because the directory is not a value configuration
    /// decided — it is a live handle on the governance state, which exists only after the store is
    /// open and the keys are hydrated, and threading it through the constructor would make every
    /// caller that has no directory pass an absence.
    #[must_use]
    pub fn with_auth_bindings(mut self, bindings: auth_bindings::AuthBindings) -> Self {
        self.auth_bindings = bindings;
        self
    }

    /// Put the deployment's real chain in front of the authenticate step.
    ///
    /// Separate from the constructors for the same reason the bindings are: the chain a node runs is
    /// resolved from live governance state, which does not exist when the units are assembled. What
    /// it replaces is the OPEN door the assembly starts from — and that door is why this exists.
    /// With it, the authenticate step admitted every caller anonymously and the only thing deciding
    /// was the surface mounted underneath, so a credential the node had revoked was admitted at
    /// Authenticate and refused, if at all, several steps later by something that had never heard of
    /// the revocation.
    #[must_use]
    pub fn with_auth_chain(mut self, chain: AuthChain) -> Self {
        self.auth = Auth::new(chain);
        self
    }

    /// Bind the admin leg's CROSSED reads to the node's live facts.
    ///
    /// Separate from the constructors above for the same reason the ledger views' binding is set
    /// after assembly rather than passed through it: what these reads answer from is the running
    /// node's handle, which the composition holds and the assembly does not. An admin-only
    /// composition that never calls this answers off `UnboundFacts`, which routes nothing and
    /// says so.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn with_admin_facts(mut self, facts: Arc<dyn crate::root::units_admin::NodeFacts>) -> Self {
        self.admin.facts = facts;
        self
    }

    /// Whether this node's front door is open — no module and no keys arm.
    ///
    /// Read by the grant, because "no principal was resolved" and "the door is open" are the same
    /// fact stated from two sides, and the grant has to know which posture it is granting under.
    fn front_door_is_open(&self) -> bool {
        self.auth.chain().is_open()
    }

    /// The scope THIS caller's admin credential carries, or nothing at all.
    ///
    /// The previous release's rule, in its three arms and no more:
    ///
    /// 1. **No principal.** The explicit open administrative posture — a deployment that configured
    ///    no admin credential. Full, and dev-only, exactly as it has always been.
    /// 2. **The operator credential.** A roleless principal carrying the reserved id, which on this
    ///    node only the admin-token module mints. Full by definition: it IS the root credential.
    /// 3. **Anyone else roleless.** No grant. Not a narrower one — none — because a roleless
    ///    principal has nothing bound to read a scope out of, and inventing one would be this root
    ///    granting authority the deployment never wrote down.
    ///
    /// It returns an absence rather than a floor for the third arm because a floor is still a grant:
    /// `ReadOnly` would hand an unbound principal every read the surface has. The scope unit's matrix
    /// still decides what a grant reaches — the grant is the ceiling, the matrix is the door — and a
    /// caller holding no ceiling never reaches the door at all.
    fn admin_grant(&self, principal: &PrincipalId) -> Option<busbar_unit_verbs::VerbScope> {
        if self.front_door_is_open() {
            return Some(busbar_unit_verbs::VerbScope::Full);
        }
        if principal.as_str() == crate::root::auth_bindings::ADMIN_PRINCIPAL_ID {
            return Some(busbar_unit_verbs::VerbScope::Full);
        }
        None
    }
}

/// Every step below asks the same question first: which plane is this unit's? One plane has been
/// switched onto this loop, so the answer is either the admin plane or a plane whose own steps have
/// not landed yet. The unswitched answer is a refusal naming the step, never a panic and never a
/// silent pass: a unit that reached here on a plane this root does not yet drive was routed wrongly,
/// and the honest answer is to say so and end it rather than to serve it half-composed.
impl ProductionUnits {
    /// Whether this unit is one the admin bindings are walking.
    ///
    /// Membership of the table, not a guess from the context: the surface that opened the unit is
    /// what put it there, so a unit that is in the table is one this root composed and a unit that
    /// is not is one it did not.
    #[cfg(feature = "root-admin")]
    fn is_admin(&self, ctx: &UnitCtx) -> bool {
        self.admin.units.holds(ctx.key)
    }
}

// With no leg compiled, this root drives no plane at all: every step below refuses without reading
// the facts it was handed, so every step's arguments go unused. That is exactly the composition the
// ordering intends — the root is BUILT before any plane is SWITCHED onto it — and the allow says so
// for that one build rather than silencing an unread argument in a build that does drive a plane.
#[cfg_attr(not(feature = "root-admin"), allow(unused_variables))]
impl Units for ProductionUnits {
    fn arrival(&self, token: &UnitToken<Arrival>, ctx: &UnitCtx) -> Decision<Arrival> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::arrival(&self.admin, token, ctx);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn decode(&self, token: &UnitToken<Decode>, ctx: &UnitCtx) -> Decision<Decode> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::decode(&self.admin, token, ctx);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::DecodeFailed))
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::authenticate(
                &self.auth,
                &self.admin,
                &self.auth_bindings,
                token,
                ctx,
            );
        }
        Decision::refuse(
            token,
            Refusal::new(busbar_caps::ReasonCode::Unauthenticated),
        )
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        _trust: &busbar_caps::TrustToken,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::verify(&self.admin, token, ctx, principal);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::approve(
                &self.admin,
                self.admin_grant(principal),
                token,
                ctx,
                principal,
                destinations,
            );
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::ScopeDenied))
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        // The administrative surface charges through no configured group — a kernel verb is exempt
        // from the gauge entirely — so this door names none.
        _leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::admit(
                &self.admin,
                token,
                admit,
                ctx,
                principal,
                destinations,
            );
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::route(
                &self.admin,
                Arc::clone(&self.store),
                &self.admin_token,
                token,
                ctx,
                meter,
            );
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        ctx: &UnitCtx,
        provisional: &Outcome,
    ) -> Decision<Meter> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::meter(token, usage, ctx, provisional);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::Unpriced))
    }

    fn audit(&self, token: &UnitToken<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            let durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
            return crate::root::units_admin::audit(
                &self.admin,
                &durability.legacy,
                token,
                ctx,
                outcome,
            );
        }
        Decision::proceed(token, unclaimed_facts(outcome))
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            let durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
            return crate::root::units_admin::audit_refused(
                &self.admin,
                &durability.legacy,
                token,
                ctx,
                refusal,
            );
        }
        Decision::proceed(
            token,
            // The step is the decision's stamp. A refusal that reaches the refused-audit door
            // without one never came from a decision; the door itself is the latest step it could
            // have been raised at, which is a truer answer than a fixed sentinel.
            unclaimed_facts(&Outcome::Refused(
                refusal.step().unwrap_or(busbar_caps::StepName::Admit),
                refusal.reason(),
            )),
        )
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> Decision<Encode> {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::encode(&self.admin, token, ctx, outcome);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::DecodeFailed))
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        #[cfg(feature = "root-admin")]
        if self.is_admin(ctx) {
            return crate::root::units_admin::evidence(ctx);
        }
        // Nothing located, nothing accrued, no upstream candidate: a unit this root did not compose
        // reached no destination, and the settlement table's answer for that is zero on every row.
        Evidence::default()
    }
}

/// The operation class a unit no plane claimed is sealed under.
///
/// Its own word, and not a borrowed one. What happened is that the unit reached the root's audit
/// door without any plane on this node having composed it, which is neither a read nor a write of
/// anything an operator administers.
const OP_UNCLAIMED: &str = "unclaimed";

/// What the record says about a unit this root did not compose.
///
/// The admin plane's "the verb did not resolve" facts used to answer here, and they name an
/// administrative READ — so every unit of every other plane that reached this door was sealed as
/// one. A voice turn or a chat completion refused at the root is not an operator reading a
/// configuration page, and a record that says it was is wrong about the one thing an audit record
/// exists to state. Nothing here is derived from the admin plane, because nothing about this unit
/// is administrative.
fn unclaimed_facts(outcome: &Outcome) -> busbar_contract::AuditFacts {
    busbar_contract::AuditFacts {
        op_class: busbar_contract::OpClassId::new(OP_UNCLAIMED),
        finish: if outcome.is_completed() {
            busbar_contract::FinishClass::Complete
        } else {
            busbar_contract::FinishClass::Error
        },
    }
}

#[cfg(test)]
#[path = "tests/kernel.rs"]
mod tests;
