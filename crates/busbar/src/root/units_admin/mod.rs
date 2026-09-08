// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin plane, driven through the kernel.
//!
//! ## What changes and what does not
//!
//! The bytes an operator sees do not change. What changes is the path they travel: an admin request
//! used to reach its handler directly off a router, and now it reaches the same handler as the Route
//! leg of a unit that the kernel walked through authenticate, verify, approve, admit, meter, audit
//! and exit first. Every one of those steps is a real unit doing its real job — the auth unit
//! resolves the credential, the scope unit answers the 1.5.5 authorization matrix, the admission
//! unit reads the mutation rate class off the verbs unit's table — and the verb's own body is
//! executed exactly where it already lived.
//!
//! That last part is the whole discipline of this file. Not one line of an admin operation is
//! reimplemented here. The 66 legacy operations are reached through one seam, [`AdminDispatch`],
//! whose production implementation hands the request to the surface that already answers it; the
//! seam carries the whole answer — status, headers and body — so that a status code, a header or a
//! byte cannot be re-derived on the way back and cannot therefore drift.
//!
//! ## Why the answer travels as bytes through the verbs unit
//!
//! The verbs unit's execution seam returns a body. An admin answer is a status, a set of headers
//! and a body, and all three are pinned. Rather than widen a unit's trait to carry an HTTP shape it
//! has no business knowing about — the verbs unit is deliberately free of any transport — the root
//! packs the whole answer into the opaque byte string the seam already carries and unpacks it on the
//! far side. The verbs unit is content-agnostic about those bytes by design; making them structured
//! is the root's business, and doing it here is what keeps HTTP out of a unit.
//!
//! ## Where a step is deliberately observational
//!
//! The mutation rate class is computed here, from the verbs unit's own table, and it refuses a verb
//! the table forbids outright. It does not run a second window counter: the surface the request is
//! about to reach owns the counter whose refusals are byte-pinned, and two counters over one request
//! would consume two slots per call and refuse at half the documented rate. The class is the binding
//! the register asked for; the count stays where the pinned bytes are. A step that measured
//! something twice would not be more faithful, it would be wrong.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Audit, Authenticate, Decision, Decode, Encode, Meter,
    Outcome, PrincipalId, ReasonCode, Refusal, Route, UnitToken, Usage, UsageToken,
    VerifiedDestination, Verify,
};
use busbar_contract::UnitKey;
use busbar_kernel::teller::UnitCtx;
use busbar_plane_admin::verbs::ResolvedVerb;
use busbar_unit_auth::unit::AuthRequest;
use busbar_unit_scope::Scope;

use crate::root::ledger_identity::{LedgerSnapshot, LegacySnapshot};
use busbar_unit_verbs::rate::{MutationClass, CONFIG_CLASS_RULES};
use busbar_unit_verbs::{
    KernelVerb, VerbScope, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES, NEW_VERBS,
};

/// The transport an admin claim is declared over, and therefore the one a sealed destination for an
/// admin verb carries.
const ADMIN_TRANSPORT: &str = "http";

/// The scheme the admin claim declares, and the one this plane's units narrow to.
const ADMIN_SCHEME: &str = "admin-token";

/// Every scheme the admin claim DECLARES — its own, and the alternative beside it.
///
/// The auth unit's first check is that the plane narrowed to a scheme the claim actually offered,
/// and it asks that question of this list. A list holding only the alternatives would say the claim
/// never declared its own scheme, which would refuse every request on the plane before a credential
/// was looked at — so the claim's own scheme belongs in it, first, exactly as the claim states it.
const ADMIN_DECLARED_SCHEMES: &[&str] = &[ADMIN_SCHEME, "bearer"];

/// One admin request, exactly as it arrived.
///
/// Owned rather than borrowed because it outlives the call that built it: the kernel's step seam
/// hands a unit nothing but its context, so the request has to be somewhere the steps can find it,
/// and that somewhere is [`AdminUnits`] keyed by the unit's own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRequest {
    /// The request method.
    pub method: String,
    /// The request path, query string and all.
    pub path: String,
    /// The credential the caller presented, where one was.
    pub credential: Option<String>,
    /// The request headers, in arrival order, names lowercased.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
    /// The wall clock, in seconds, pinned at arrival. Every step reads this rather than the clock:
    /// a unit that read the clock twice could be admitted in one window and rate-classed in the
    /// next.
    pub at: u64,
    /// The key of the unit this request is walked as.
    ///
    /// Carried on the request because it has to cross the seam WITH it: the operation's body runs on
    /// a task the seam spawned, and the one effect a body can ask to outlive its own response — the
    /// drain — is attributed to the unit that asked for it. Without the key travelling here the
    /// attribution would have to be re-derived on the far side of a task boundary, which is another
    /// way of saying it would be guessed.
    pub unit: u64,
}

/// One admin answer, exactly as the surface that owns the operation produced it.
///
/// Status, headers and body together, because all three are pinned and none of them is derivable
/// from the others. An answer that carried only a body would force a status to be re-derived here,
/// and a re-derived status is a status that can differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAnswer {
    /// The status code.
    pub status: u16,
    /// The response headers, in emission order.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

impl AdminAnswer {
    /// Pack an answer into the opaque byte string the verbs unit's execution seam carries.
    ///
    /// A length-prefixed framing rather than a text format, so that a header value or a body may
    /// hold any byte at all — including the ones a text framing would have to escape — and come back
    /// identical. The point of this round trip is that it is lossless; a framing that could not
    /// carry an arbitrary byte would defeat it.
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 64);
        out.extend_from_slice(&self.status.to_be_bytes());
        let count = u32::try_from(self.headers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for (name, value) in self.headers.iter().take(count as usize) {
            push_bytes(&mut out, name.as_bytes());
            push_bytes(&mut out, value.as_bytes());
        }
        push_bytes(&mut out, &self.body);
        out
    }

    /// Unpack what [`AdminAnswer::pack`] wrote.
    ///
    /// `None` on anything that is not exactly the framing above. There is no lenient arm: the only
    /// producer of these bytes is `pack`, so a shape that does not parse is a defect in this file
    /// rather than an input to tolerate.
    #[must_use]
    pub fn unpack(bytes: &[u8]) -> Option<AdminAnswer> {
        let mut cursor = 0usize;
        let status = u16::from_be_bytes(take(bytes, &mut cursor, 2)?.try_into().ok()?);
        let count = u32::from_be_bytes(take(bytes, &mut cursor, 4)?.try_into().ok()?);
        let mut headers = Vec::with_capacity(header_capacity(count, bytes.len() - cursor));
        for _ in 0..count {
            let name = String::from_utf8(pull_bytes(bytes, &mut cursor)?.to_vec()).ok()?;
            let value = String::from_utf8(pull_bytes(bytes, &mut cursor)?.to_vec()).ok()?;
            headers.push((name, value));
        }
        let body = pull_bytes(bytes, &mut cursor)?.to_vec();
        if cursor != bytes.len() {
            return None;
        }
        Some(AdminAnswer {
            status,
            headers,
            body,
        })
    }
}

/// How much room to make for a frame's headers, given the bytes still in hand.
///
/// The count is a claim the frame makes about itself, and the loop reading the headers is what
/// checks it. Reserving on the claim alone hands an arbitrary allocation size to whoever wrote the
/// bytes — a truncated or corrupt row asking for billions of headers, which is not a parse failure
/// but a failed allocation, and a failed allocation is the process leaving rather than a `None`
/// coming back. Every header costs at least its two length prefixes on the wire, so the remaining
/// bytes bound how many there can actually be.
fn header_capacity(count: u32, remaining: usize) -> usize {
    const MIN_HEADER_BYTES: usize = 8;
    (count as usize).min(remaining / MIN_HEADER_BYTES)
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX) as usize;
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(&bytes[..len]);
}

fn take<'b>(bytes: &'b [u8], cursor: &mut usize, n: usize) -> Option<&'b [u8]> {
    let end = cursor.checked_add(n)?;
    let slice = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(slice)
}

fn pull_bytes<'b>(bytes: &'b [u8], cursor: &mut usize) -> Option<&'b [u8]> {
    let len = u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().ok()?) as usize;
    take(bytes, cursor, len)
}

/// The seam an admin operation's body is reached through.
///
/// One method, and it is the whole point of this file: the root does not know how any of the 66
/// legacy operations work, and this is the shape of not knowing. An implementation hands the request
/// to whatever already answers it and returns what that answered, unchanged.
pub trait AdminDispatch: Send + Sync {
    /// Execute one admin operation where its body lives, and answer with what it answered.
    fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer;
}

/// The dispatch a node has before it has mounted an admin surface.
///
/// It refuses every operation, which is the correct answer rather than a placeholder: a root that
/// has composed the loop but not yet mounted the surface has genuinely nowhere to send an admin
/// request, and answering `503` says exactly that. Building the units against this is what lets the
/// composition be tested without a listener.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingDispatch;

impl AdminDispatch for RefusingDispatch {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 503,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"error":{"code":"unavailable","message":"no administrative surface is mounted"}}"#
                .to_vec(),
        }
    }
}

// ── the ledger's read-only views ────────────────────────────────────────────────────────────────

/// The figures the five ledger views read.
///
/// A read seam and nothing else: four methods, none of which takes an argument and none of which
/// can change anything. That shape is the point. The views are the one part of the administrative
/// surface whose answer is not produced by the operation's own handler — there is no 1.5.5 handler
/// for a figure 1.5.5 never kept — so the root has to reach the ledger itself, and reaching it
/// through a seam that offers no way to write is what keeps "read-only admin surface" a property of
/// the type rather than a promise in a comment.
///
/// It is deliberately NOT the ledger. A `Ledger` can settle, adjust and transfer; a view has no
/// business holding one. What the root binds behind this is a snapshot of what the ledger holds,
/// taken under whatever lock the node keeps it behind, and what the views render is that snapshot.
pub trait LedgerView: Send + Sync {
    /// What the ledger posted, by row — the ledger side of the reconciliation identity.
    fn ledger_rows(&self) -> crate::root::ledger_identity::LedgerSnapshot;

    /// What the previous release's rows carry for the same cells — the other side of it.
    fn legacy_rows(&self) -> crate::root::ledger_identity::LegacySnapshot;

    /// The sealed checkpoints, oldest first.
    fn checkpoints(&self) -> Vec<busbar_unit_ledger::checkpoint::Checkpoint>;

    /// The marker the first boot after the upgrade sealed, if this deployment has migrated.
    fn migration_marker(&self) -> Option<busbar_unit_ledger::migration::MigrationMarker>;

    /// BOTH sides of the identity, as of one moment.
    ///
    /// The reconciliation view needs the two snapshots to be of the same instant, and reading them
    /// through the two methods above cannot promise that: a settlement landing between the two calls
    /// would leave the previous release's side holding a posting the ledger's side was read before,
    /// and the view would report a discrepancy that never existed. On a busy node that is not a rare
    /// race — it is every request.
    ///
    /// The default is the pair of reads, which is exactly right for a view whose answers do not move.
    /// A view over live figures overrides it to take both under one hold of whatever lock it keeps
    /// them behind, which is the only place that guarantee can be made.
    fn identity_snapshot(
        &self,
    ) -> (
        crate::root::ledger_identity::LedgerSnapshot,
        crate::root::ledger_identity::LegacySnapshot,
    ) {
        (self.ledger_rows(), self.legacy_rows())
    }

    /// SEAM `quantities-by-class`: the QUANTITIES the ledger holds for each row, by declared meter
    /// class.
    ///
    /// This is the half of the money model the views are built on. A sealed facts line records
    /// quantities by class and nothing else; the price is never stored, so a view that wants to
    /// show money has to be handed the quantities and derive it. Handing the view a stored amount
    /// instead would make the endpoint incapable of reflecting a rate row added after the fact,
    /// which is the one thing the append-only rate history exists to allow.
    ///
    /// The default is EMPTY, and empty means "this view has no quantities to give", never "these
    /// rows had no quantity". [`render_totals`] reads it that way: a row with no lines answers
    /// `null` for its priced sum rather than zero, because nothing here has been priced at nothing
    /// — nothing here has been priced at all.
    fn quantities(&self) -> QuantitySnapshot {
        QuantitySnapshot::new()
    }

    /// SEAM `rate-table-in-force`: the rates a read prices against, as of the read.
    ///
    /// `None` is "no operator has said what any of this costs", which is NOT "all of it is free".
    /// The distinction is the whole of ruling 5: free is an explicit zero row, and an absent row is
    /// a question nobody has answered. A view that collapsed the two would quietly invoice a
    /// deployment at nothing.
    fn rates_in_force(&self) -> Option<std::sync::Arc<busbar_unit_cost::RateCard>> {
        None
    }

    /// The node's CURRENT balances, per key and window — the `now` side of the identity.
    ///
    /// `verify` is the one operation that needs both sides of a delta, and the checkpoints above
    /// only carry the `since` side. The default is an empty book, which is the honest answer for a
    /// binding with no ledger behind it and is what keeps this addition additive: an existing
    /// implementor compiles unchanged and answers "this node has no balances", which is true of it.
    fn current_totals(
        &self,
    ) -> std::collections::BTreeMap<
        (
            busbar_unit_ledger::totals::TotalsKey,
            busbar_unit_ledger::totals::WindowStart,
        ),
        busbar_unit_ledger::totals::Totals,
    > {
        std::collections::BTreeMap::new()
    }
}

/// The quantities a ledger view hands out, by row, in the cost unit's own line shape.
///
/// `busbar_caps::UsageLine` rather than a shape declared here, because these lines are fed straight
/// back to `busbar_unit_cost` to be priced: a second shape would need a conversion, and a
/// conversion is arithmetic this module is not allowed to do.
pub type QuantitySnapshot =
    std::collections::BTreeMap<crate::root::ledger_identity::RowKey, Vec<busbar_caps::UsageLine>>;

/// The view a node has before a ledger is bound behind it.
///
/// Every answer is empty, and each emptiness is a statement rather than a placeholder: no rows were
/// posted, no rows were read, nothing has been sealed and this deployment has not migrated. A node
/// composed without a ledger genuinely has none of those things, and saying so is a true answer.
///
/// What it is NOT is a reconciliation that balances. Two empty snapshots do reconcile — trivially —
/// and that is honest here precisely because the emptiness is visible in the totals view beside it:
/// an operator reading `"rows": []` can see that the identity held over nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnopenedLedger;

impl LedgerView for UnopenedLedger {
    fn ledger_rows(&self) -> crate::root::ledger_identity::LedgerSnapshot {
        crate::root::ledger_identity::LedgerSnapshot::new()
    }

    fn legacy_rows(&self) -> crate::root::ledger_identity::LegacySnapshot {
        crate::root::ledger_identity::LegacySnapshot::new()
    }

    fn checkpoints(&self) -> Vec<busbar_unit_ledger::checkpoint::Checkpoint> {
        Vec::new()
    }

    fn migration_marker(&self) -> Option<busbar_unit_ledger::migration::MigrationMarker> {
        None
    }
}

/// The views over the figures THIS node holds.
///
/// The default [`UnopenedLedger`] is an honest answer for a node that has no ledger; it is the wrong
/// answer for one that does, because "no rows" and "no rows I was wired to read" are indistinguishable
/// from outside and only the first is a fact about the deployment.
///
/// ## What it holds, and why it is a handle rather than a copy
///
/// A handle on the node's own durability, behind the node's own lock. Not a snapshot taken when the
/// node was composed: that would freeze the served figures at boot, and a stale figure that still
/// looks like a current one is worse for an operator than an empty table. The snapshot is taken HERE,
/// per request, under the same lock a settlement holds — so no view can catch a unit half-settled,
/// with the ledger moved and the journal not yet appended.
///
/// ## Why it still cannot write
///
/// The lock is taken and a VALUE comes back out; nothing behind [`LedgerView`] hands out a `&mut` to
/// anything, and the four methods take no argument. The dual write is reached through
/// [`LegacyRowsRead`], which is the read half of a seam whose write half lives inside the ledger. So
/// "read-only administrative surface" stays a property of the types rather than of this comment.
///
/// ## The row width the node actually keeps
///
/// The reconciliation's row is `(bucket, day, lane, provider)`, because that is the width the
/// previous release's usage rows are queried at and the width a discrepancy can hide inside. A live
/// node's books are narrower: the ledger's cells are keyed by bucket and window, and the postings the
/// dual write produces carry the same two and no more — the serving lane and its provider are facts
/// about the request, and neither the books nor the row this crate writes retain them.
///
/// So both sides are read at the width the node keeps, with the lane and the provider EMPTY, and
/// that is not a narrowing of the check: the two snapshots are read at the same width, so a posting
/// the dual write lost is still a residual naming its bucket and its day. What it does mean is that
/// two lanes inside one bucket-day cannot cancel here the way the identity's full width forbids —
/// which is why the release's own gate on that identity is the test over both pricing paths, and
/// this view is the operator's read of the node rather than a second gate.
///
/// The fee count is zero on both sides for the same reason and it is zero on BOTH, never on one:
/// neither the books nor the previous release's posting carry one at this width, so the count half of
/// the identity compares two absences and reports nothing. A view that put a count on one side and a
/// zero on the other would report every row on a healthy node as out.
pub struct NodeLedger {
    durability: Arc<Mutex<crate::root::durability::Durability>>,
    legacy: Arc<dyn LegacyRowsRead>,
}

impl std::fmt::Debug for NodeLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeLedger").finish_non_exhaustive()
    }
}

impl NodeLedger {
    /// Bind the views to a node's durability and to the read half of its dual write.
    #[must_use]
    pub fn new(
        durability: Arc<Mutex<crate::root::durability::Durability>>,
        legacy: Arc<dyn LegacyRowsRead>,
    ) -> Self {
        NodeLedger { durability, legacy }
    }

    /// The lock, taken the way every other reader of it takes it.
    ///
    /// A poisoned lock is read through rather than refused. The panic that poisoned it happened
    /// somewhere else; the four things behind this lock are append-only, so what a reader sees is a
    /// prefix of the truth rather than a corrupted one, and refusing to serve an operator a figure
    /// because an unrelated unit panicked is the wrong trade on a diagnostic surface.
    fn lock(&self) -> std::sync::MutexGuard<'_, crate::root::durability::Durability> {
        self.durability.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The ledger's side, off a lock somebody already holds.
    fn rows_of(durability: &crate::root::durability::Durability) -> LedgerSnapshot {
        use crate::root::ledger_identity::{LedgerRow, RowKey};

        let mut rows = LedgerSnapshot::new();
        for ((key, window), totals) in durability.ledger.book().iter() {
            // A cell nothing has settled against is not a row. The books carry a cell as soon as a
            // hold opens on it, and serving those as rows of zero would put a line in front of an
            // operator for every key that was ever admitted and never billed. A cell whose settled
            // figure has been adjusted below zero is not a row that was posted either, which is why
            // this is a skip rather than a saturating cast that would report it as zero.
            if totals.settled <= 0 {
                continue;
            }
            let row = RowKey::new(
                key.bucket.as_str(),
                *window,
                WIDTH_THE_NODE_KEEPS,
                WIDTH_THE_NODE_KEEPS,
            );
            // Accumulated rather than inserted: one bucket-day can hold several cells — a dimension
            // and a scope apiece — and at the width this view reads they are one row.
            let entry: &mut LedgerRow = rows.entry(row).or_default();
            entry.priced_nanos = entry
                .priced_nanos
                .saturating_add(totals.settled.unsigned_abs());
        }
        rows
    }

    /// The previous release's side, off the same hold.
    ///
    /// The dual write happens inside the ledger's one book-moving function, which the node calls
    /// under this same lock — so a reader holding it sees a settlement's two halves together or
    /// neither, and never the ledger's half alone.
    fn legacy_rows_under_lock(&self) -> LegacySnapshot {
        use crate::root::ledger_identity::{LegacyRow, RowKey};

        // Nano-units accumulate per row and the projection to micro-units happens ONCE over the sum,
        // which is the ledger side's rule and has to be this side's too — projecting each posting
        // first would floor every sub-micro posting to nothing and report a busy row as short.
        //
        // Folded rather than copied: the answer is one entry per row the node has settled into,
        // which is a handful whatever the traffic since boot has been, and the postings themselves
        // are read where they already live. A view that took a copy of the whole history first paid
        // for every posting ever made, under the lock every settlement waits on.
        let mut nanos: std::collections::BTreeMap<RowKey, u128> = std::collections::BTreeMap::new();
        self.legacy.fold_postings(&mut |posting| {
            let row = RowKey::new(
                posting.bucket.as_str(),
                posting.window_start,
                WIDTH_THE_NODE_KEEPS,
                WIDTH_THE_NODE_KEEPS,
            );
            let entry = nanos.entry(row).or_default();
            *entry = entry.saturating_add(u128::from(posting.settled));
        });
        nanos
            .into_iter()
            .map(|(row, nanos)| {
                (
                    row,
                    LegacyRow {
                        spend_micros: busbar_unit_cost::micros_of(nanos),
                        billable_requests: 0,
                    },
                )
            })
            .collect()
    }
}

/// The lane and the provider a live node's books do not retain. See [`NodeLedger`].
const WIDTH_THE_NODE_KEEPS: &str = "";

impl LedgerView for NodeLedger {
    fn ledger_rows(&self) -> LedgerSnapshot {
        NodeLedger::rows_of(&self.lock())
    }

    fn legacy_rows(&self) -> LegacySnapshot {
        let _durability = self.lock();
        self.legacy_rows_under_lock()
    }

    /// Both sides under ONE hold, which is what makes the served residual a fact rather than a race.
    fn identity_snapshot(&self) -> (LedgerSnapshot, LegacySnapshot) {
        let durability = self.lock();
        (
            NodeLedger::rows_of(&durability),
            self.legacy_rows_under_lock(),
        )
    }

    fn checkpoints(&self) -> Vec<busbar_unit_ledger::checkpoint::Checkpoint> {
        self.lock().checkpoints.clone()
    }

    fn migration_marker(&self) -> Option<busbar_unit_ledger::migration::MigrationMarker> {
        self.lock().migration_marker()
    }

    /// SEAM `quantities-by-class`, UNFILLED ON THIS NODE, and named rather than faked.
    ///
    /// The node's book keeps BALANCES — a budget, a drawn figure, a settled figure per bucket,
    /// dimension, scope and window — and a balance is not a quantity. There is no `tokens_input`
    /// in it to hand back. The quantities live on the sealed facts line the metering step writes
    /// at the end of a unit, and the ledger row that carries them into the book is the landing
    /// this method is waiting for; until it arrives, this answers with nothing it has.
    ///
    /// Answering with nothing is the whole point of the seam being here rather than absent. The
    /// alternative — passing the book's settled figure off as a priced sum — would put a number in
    /// front of an operator that no rate row produced and that no rate row added later could ever
    /// move, which is precisely the stored price the model forbids.
    fn quantities(&self) -> QuantitySnapshot {
        QuantitySnapshot::new()
    }

    /// The card the process is holding, which IS the rate table in force for a read taken now.
    ///
    /// A relay and no more: the holder is the root's, the card is the cost unit's, and this method
    /// adds nothing to either. Pinned rather than borrowed, so a `PUT /config/settings` landing
    /// between two rows of one response cannot price the first half of the table on one card and
    /// the second half on another.
    fn rates_in_force(&self) -> Option<std::sync::Arc<busbar_unit_cost::RateCard>> {
        crate::root::kernel::ROOT_CARD.pin()
    }

    /// The live book, copied under the same lock every other read here takes.
    fn current_totals(
        &self,
    ) -> std::collections::BTreeMap<
        (
            busbar_unit_ledger::totals::TotalsKey,
            busbar_unit_ledger::totals::WindowStart,
        ),
        busbar_unit_ledger::totals::Totals,
    > {
        self.lock()
            .ledger
            .book()
            .iter()
            .map(|(key, totals)| (key.clone(), *totals))
            .collect()
    }
}

/// The read half of the dual write.
///
/// [`busbar_unit_ledger::legacy::LegacyRows`] is a WRITE trait and deliberately so — the unit's job
/// is to say what was posted and hand it over, never to read a shape it does not own. But the
/// reconciliation identity needs both sides, and the previous release's side of it is exactly what
/// that write produced. So the root asks for the read half separately, as its own seam, and a
/// binding that can only be written to simply does not offer one.
///
/// Keeping the two halves apart is what stops the views acquiring a way to write: nothing behind
/// this trait can move a row, and the value the node dual-writes through is reached from here only
/// as a list of what it already took.
pub trait LegacyRowsRead: Send + Sync {
    /// Every posting the dual write put onto the previous release's rows, in the order it made them.
    ///
    /// A COPY of the whole history, which is what makes it the wrong thing for a view to ask for:
    /// the aggregate a view renders is a handful of rows whatever the node has settled, and the
    /// copy is the only part of the work that grows with the traffic since boot. Kept for a caller
    /// that genuinely wants the postings themselves; every view goes through [`fold_postings`].
    ///
    /// [`fold_postings`]: Self::fold_postings
    fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting>;

    /// Show each posting to a fold, in the order the dual write made them, without copying any.
    ///
    /// The form a view reads through. What a view builds is a per-row sum, so it needs to SEE each
    /// posting once and to keep none of them — and the default below is the honest fallback for a
    /// binding that can only hand over a copy, not the shape the production one takes.
    fn fold_postings(&self, take: &mut dyn FnMut(&busbar_unit_ledger::legacy::LegacyPosting)) {
        for posting in self.postings() {
            take(&posting);
        }
    }
}

impl LegacyRowsRead for busbar_unit_ledger::legacy::RecordingRows {
    fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting> {
        self.written()
    }

    fn fold_postings(&self, take: &mut dyn FnMut(&busbar_unit_ledger::legacy::LegacyPosting)) {
        self.fold_written(take);
    }
}

// ── the crossed reads ───────────────────────────────────────────────────────────────────────────
//
// WHO ANSWERS an operation, as opposed to how one is walked. The seam the loop reads a node's own
// facts through, the closed set of operations that have CROSSED to it, and the renderers that write
// those answers' bytes. Its own file because it is its own question and because the migration adds
// to it one operation at a time — see the module's own header.
mod crossed;
pub(crate) use crossed::{render_crossed_view, CROSSED_VERBS};
pub use crossed::{HandleFacts, NodeFacts, UnboundFacts};

/// The verbs unit's governance seam, bound to whatever executes an admin operation.
///
/// Every one of the trait's methods is a delegation. `execute_legacy` is the one that carries the
/// 66; `execute_new_verb` carries the 17, which reach the same seam because the surface that answers
/// them is the same surface. `execute_ledger_read` carries the 5 ledger views, and it is the one
/// method that does NOT reach the dispatch: there is no 1.5.5 handler behind a figure 1.5.5 never
/// kept, so the answer is rendered here, from the bound view. The four governance-store methods
/// answer from the request the dispatch already ran, because minting a key IS an admin operation and
/// there is no second place this root is entitled to mint one.
pub struct CoreGovernance {
    dispatch: Arc<dyn AdminDispatch>,
    /// The figures the five ledger views read. Held beside the dispatch rather than behind it
    /// because the two answer different halves of the surface and neither can stand in for the
    /// other: a dispatch handed a ledger path would answer the 404 its router has for it.
    ledger: Arc<dyn LedgerView>,
    /// The node facts the CROSSED reads answer from. A third seam beside the dispatch
    /// and the ledger, for the reason the ledger is a second one: the dispatch's whole content is
    /// "ask the surface underneath", and a verb that has crossed must not be able to reach it.
    facts: Arc<dyn NodeFacts>,
    /// The request the current unit is executing, so the seam's argument-free methods can reach it.
    /// One unit at a time per governance value, which is what the root guarantees by building one
    /// per unit rather than sharing one across them.
    request: AdminRequest,
    verb: KernelVerb,
}

impl CoreGovernance {
    /// Bind the governance seam for one unit.
    #[must_use]
    pub fn new(
        dispatch: Arc<dyn AdminDispatch>,
        ledger: Arc<dyn LedgerView>,
        facts: Arc<dyn NodeFacts>,
        verb: KernelVerb,
        request: AdminRequest,
    ) -> Self {
        CoreGovernance {
            dispatch,
            ledger,
            facts,
            request,
            verb,
        }
    }

    /// Run the operation and pack its whole answer.
    fn run(&self) -> Vec<u8> {
        self.dispatch.execute(self.verb, &self.request).pack()
    }
}

impl busbar_unit_verbs::Governance for CoreGovernance {
    fn group_exists(&self, _name: &str) -> bool {
        // The surface that owns groups is the one that answers whether a group exists, and it
        // answers it inside the operation rather than as a question the root may ask beforehand.
        // Answering `true` here is not a claim that the group exists: it is the statement that this
        // root does not adjudicate group existence, and that the operation's own 404 is the answer.
        true
    }

    fn actual_parent(&self, _name: &str) -> Option<String> {
        None
    }

    fn provision_group(
        &self,
        _admin: &busbar_caps::AdminToken,
        _group: &str,
        _parent: &str,
    ) -> Result<(), busbar_unit_verbs::GovernanceError> {
        Ok(())
    }

    fn mint_key(
        &self,
        _admin: &busbar_caps::AdminToken,
        _group: Option<&str>,
    ) -> Result<busbar_unit_verbs::MintedKey, busbar_unit_verbs::GovernanceError> {
        // A minted secret is revealed by the operation's own response and by nothing else. The root
        // does not hold one, does not copy one out of a body and does not re-render one: the answer
        // the dispatch produced is what leaves, byte for byte.
        Err(busbar_unit_verbs::GovernanceError::Validation)
    }

    fn rotate_key(
        &self,
        _admin: &busbar_caps::AdminToken,
        _id: &str,
    ) -> Result<busbar_unit_verbs::RotateOutcome, busbar_unit_verbs::GovernanceError> {
        Err(busbar_unit_verbs::GovernanceError::Validation)
    }

    fn execute_legacy(
        &self,
        verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
        // A VERB THAT HAS CROSSED DOES NOT REACH THE DISPATCH. The unit still calls this method for
        // it — the sixty-six are one entry point on the unit's side, and which of them the loop
        // produces the answer for is the composition's question, not the unit's — so the branch is
        // here, before the seam that asks the surface underneath. There is nothing to ask: the route
        // was deleted in the commit that crossed the verb.
        if let Some(answer) = render_crossed_view(verb, self.facts.as_ref(), &self.request) {
            return Ok(answer.pack());
        }
        Ok(self.run())
    }

    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
        // A verb this root answers itself is answered here and never handed on. The fall-through
        // below is the surface underneath, which has no route for any of the 1.6.0 verbs and
        // answers 404 — so a verb that reaches it has passed every gate and then been told it does
        // not exist, which is the shipped defect these arms close one at a time.
        if let Some(body) = render_new_verb(verb, self.ledger.as_ref()) {
            return Ok(ledger_answer(body).pack());
        }
        Ok(self.run())
    }

    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
        // The request body is deliberately unread. Every view is a `GET` whose whole identity is its
        // path, so a body would be an argument to an operation that takes none — and an operation
        // that quietly read one would have a second way to be asked a question, which is exactly the
        // kind of surface a closed table exists to prevent.
        let body = render_ledger_view(verb, self.ledger.as_ref())
            .ok_or(busbar_unit_verbs::GovernanceError::NotFound)?;
        Ok(ledger_answer(body).pack())
    }
}

/// The answer a ledger view produces: a 200 carrying JSON, and no other header.
///
/// Nothing here is derived from a legacy response, because there is no legacy response to derive it
/// from — these paths did not exist. `content-type` is the one header a JSON body needs; a
/// `content-length` is the transport's to add, and adding one here would be this root deciding a
/// framing detail the listener already owns.
fn ledger_answer(body: Vec<u8>) -> AdminAnswer {
    AdminAnswer {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
    }
}

/// The bytes one of the new 1.6.0 verbs answers with, or `None` for a verb this root does not yet
/// answer itself.
///
/// `None` is not an error and not a refusal: it means the verb is still handed to the surface
/// underneath, which is where every one of them was before this arm existed. The arms land one per
/// commit, so this function shrinking the `None` set IS the migration, and a verb that moved has to
/// move here and in the partition pin together.
fn render_new_verb(verb: KernelVerb, view: &dyn LedgerView) -> Option<Vec<u8>> {
    match verb {
        KernelVerb::Verify => Some(render_verify(view).into_bytes()),
        _ => None,
    }
}

/// `verify` — the reconciliation identity, per balance, as a change since the last sealed
/// checkpoint.
///
/// ## Why a failing verify is still a 200
///
/// The verb answers the question it was asked. An operator runs it to find out whether the books
/// close, and "the books do not close" is an answer, not a failure to answer — refusing here would
/// mean the one tool for finding an imbalance stops working exactly when there is one. `ok` carries
/// the verdict and the status carries whether the question was understood.
///
/// ## Where every figure comes from
///
/// Not from here. The per-balance deltas are `busbar_unit_cost::IdentityDeltaView::between`, which
/// is checked against `busbar_unit_ledger::identity::residual` by an agreement test in this crate's
/// own test directory. This function reads two maps, pairs them by key, and renders. It does no
/// arithmetic on money at all — the only sums below are counts of nodes and balances.
fn render_verify(view: &dyn LedgerView) -> String {
    let checkpoints = view.checkpoints();
    let now = view.current_totals();
    // The `since` side. The last sealed checkpoint is the anchor the identity is measured from; a
    // node with none has never sealed, so every balance is measured from zero, which is what it
    // was.
    let since = checkpoints.last();

    let mut out = String::from("{\"since\":");
    match since {
        Some(cp) => {
            out.push_str("{\"checkpoint_seq\":");
            out.push_str(&cp.checkpoint_seq.to_string());
            out.push_str(",\"node\":");
            out.push_str(&cp.node.to_string());
            out.push_str(",\"anchored_at\":");
            out.push_str(&cp.wall.to_string());
            out.push('}');
        }
        None => out.push_str("null"),
    }

    // The chains, as the anchor sealed them. A head is a claim about one node's log, and the three
    // fields are what an auditor needs to go and check it against that node.
    out.push_str(",\"chains\":[");
    if let Some(cp) = since {
        for (i, head) in cp.heads.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"node\":");
            out.push_str(&head.node.to_string());
            out.push_str(",\"node_seq\":");
            out.push_str(&head.node_seq.to_string());
            out.push_str(",\"head_hash\":");
            json_string(&hex32(&head.hash), &mut out);
            out.push('}');
        }
    }
    out.push(']');

    // Whether the sealed checkpoints form a sequence. Two checkpoints sharing a sequence number, or
    // going backwards, mean the anchor cannot be used to measure from — which is a different
    // failure from an imbalance and is reported as its own field rather than folded into `ok`'s
    // reason.
    let checkpoints_resolve = checkpoints
        .windows(2)
        .all(|pair| pair[0].checkpoint_seq < pair[1].checkpoint_seq);
    out.push_str(",\"checkpoints_resolve\":");
    out.push_str(if checkpoints_resolve { "true" } else { "false" });

    // The identity, per balance, over the UNION of the two sides. Iterating `now` alone would step
    // straight past a balance the checkpoint sealed and the book has since lost, which is precisely
    // the shape of a lost posting.
    let mut keys: Vec<&(
        busbar_unit_ledger::totals::TotalsKey,
        busbar_unit_ledger::totals::WindowStart,
    )> = now.keys().collect();
    if let Some(cp) = since {
        for key in cp.totals.keys() {
            if !now.contains_key(key) {
                keys.push(key);
            }
        }
    }
    keys.sort_unstable();

    let mut all_close = true;
    out.push_str(",\"identity\":[");
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let (totals_key, window) = *key;
        let since_terms = since
            .and_then(|cp| cp.totals.get(*key))
            .map(terms_of)
            .unwrap_or_default();
        let now_terms = now.get(*key).map(terms_of).unwrap_or_default();
        let delta = busbar_unit_cost::IdentityDeltaView::between(
            totals_key.bucket.to_string(),
            totals_key.dimension.to_string(),
            totals_key.scope.to_string(),
            *window,
            &since_terms,
            &now_terms,
        );
        all_close &= delta.closes;
        out.push_str(&delta.to_json());
    }
    out.push(']');

    // `ok` is the conjunction of every verdict this document carries, so a reader that branches on
    // one field branches on all of them.
    out.push_str(",\"ok\":");
    out.push_str(if checkpoints_resolve && all_close {
        "true"
    } else {
        "false"
    });
    out.push('}');
    out
}

/// One balance's figures in the cost unit's carrier shape.
///
/// A field copy and one call to the ledger unit's own `overdraft_carried()`. Deliberately not a
/// place where a term is combined, reordered or renamed: the whole value of the view is that the
/// numbers in it are the books' numbers.
fn terms_of(totals: &busbar_unit_ledger::totals::Totals) -> busbar_unit_cost::IdentityTerms {
    busbar_unit_cost::IdentityTerms {
        settled: totals.settled,
        open_holds: totals.open_holds,
        open_slice_remainders: totals.open_slice_remainders,
        unreconciled: totals.unreconciled,
        adjustments: totals.adjustments,
        overdraft_carried: totals.overdraft_carried(),
        cross_window_transfers: totals.cross_window_transfers,
        drawn: totals.drawn,
    }
}

/// The bytes one ledger view answers with, or `None` for a verb that is not one.
///
/// `None` is reachable only if the closed table and this match ever disagree, which is a defect in
/// this file rather than a request to forgive — so it becomes a `NotFound` at the call site rather
/// than a body invented for a verb nobody wrote one for.
fn render_ledger_view(verb: KernelVerb, view: &dyn LedgerView) -> Option<Vec<u8>> {
    Some(match verb {
        KernelVerb::GetLedgerTotals => render_totals(
            &view.ledger_rows(),
            &view.quantities(),
            view.rates_in_force().as_deref(),
        )
        .into_bytes(),
        KernelVerb::GetLedgerCheckpoints => render_checkpoints(&view.checkpoints()).into_bytes(),
        KernelVerb::GetLedgerReconciliation => {
            let (ledger, legacy) = view.identity_snapshot();
            render_reconciliation(&ledger, &legacy).into_bytes()
        }
        KernelVerb::GetLedgerMigration => {
            render_migration(view.migration_marker().as_ref()).into_bytes()
        }
        KernelVerb::GetLedgerOpenapiJson => LEDGER_OPENAPI_ADDITIVE.as_bytes().to_vec(),
        _ => return None,
    })
}

/// The document describing the 1.6.0 ledger operations.
///
/// A SECOND document, served at a path of its own, and that is the whole of the design's answer to
/// how a new operation gets documented without moving a byte of the pinned one. The 1.5.5
/// `openapi.json` is a fixed artefact: a client that fetched it before the upgrade and after it gets
/// the same bytes, so nothing that reads it can be surprised by a path it does not know. An operator
/// who wants the new surface asks for the new document by name.
///
/// It is `include_str!` of a committed file rather than a literal here for the same reason the
/// verbs unit reads its conformance fixture that way: a document is an artefact somebody reviews as
/// a document, and a test below parses this same file to check it describes exactly the operations
/// the closed table declares.
const LEDGER_OPENAPI_ADDITIVE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/openapi-1.6.0-additive.json"
));

/// One JSON string, quoted and escaped.
///
/// Written out rather than taken from a serialization crate because this crate does not depend on
/// one on the request path, and because the escape set is small and closed: the two characters JSON
/// requires escaping, the five it names short forms for, and every remaining control character as a
/// `\u` escape. A bucket, lane or provider name comes from a deployment's configuration and may hold
/// any of them, so escaping is not optional here — an unescaped quote would end the string early and
/// hand a reader a different document from the one this rendered.
fn json_string(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// One money figure, as a decimal string.
///
/// Every figure the ledger keeps is a 128-bit integer and JSON's number is a double, which is exact
/// only to 2^53. A nano-unit total on a busy deployment passes that in a day, and a figure that
/// silently loses its last digits on the way to an operator is worse than no figure at all — the
/// number still LOOKS like money. So money is a string and a count is a number, and the rule is
/// stated in the served document rather than left for a reader to infer from one row's magnitude.
fn json_amount(value: i128, out: &mut String) {
    out.push('"');
    out.push_str(&value.to_string());
    out.push('"');
}

/// Thirty-two bytes as lower-case hex.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `GET /api/v1/admin/ledger/totals` — the QUANTITIES the ledger holds per bucket, day, lane and
/// provider, and what they come to at the rates in force when the read is taken.
///
/// The row width is the reconciliation's row width, and deliberately so: this view and the
/// reconciliation view are two readings of one set of rows, so a discrepancy an operator finds in
/// one can be looked up in the other by the same four-part name.
///
/// ## Why the money is derived here and not read
///
/// PRICE IS NEVER STORED. What a unit leaves behind is a sealed line of quantities by declared
/// class; money is a conversion applied when somebody asks, against the rate row in force. So this
/// view publishes the quantities as the truth and the amount as a DERIVATION, and the difference is
/// not presentational: a rate row added later — including one back-dated, which the append-only
/// history allows — changes what this endpoint answers on the next read, with nothing rewritten and
/// no posted line touched. A view that echoed a stored amount could not do that, and an operator
/// who had mispriced a lane would have to choose between a wrong figure and a rewritten history.
///
/// ## No arithmetic here
///
/// Every figure below comes out of `busbar_unit_cost`. This function chooses the rows, hands the
/// lines and the fee count over, and writes down the answer; it does not add, multiply, divide or
/// truncate. That is the same rule the reconciliation view keeps by calling
/// `ledger_identity::reconcile` instead of re-deriving the identity: an endpoint that did its own
/// arithmetic could disagree with the code that gates the release, and then there would be two
/// answers and no way to tell which one was the money.
///
/// ## `null` is a real answer, and it is not zero
///
/// `priced_micros` is `null` where there is nothing to price against — no rate card in force, or no
/// quantity lines for the row. Neither of those means free. Free is an explicit zero rate row, and
/// an absent one is a question no operator has answered yet; collapsing them would report a
/// deployment nobody has priced as a deployment that costs nothing.
///
/// ## Two money figures, because there are two questions
///
/// `settled_micros` is the BOOK'S BALANCE: what this row drew against its bucket and posted when
/// its units ended, which is the figure the budget was enforced on. `priced_micros` is what those
/// same quantities are worth at the rates in force NOW. On a deployment whose rates have not moved
/// they agree; where a rate row has been added since, they differ, and the difference is the
/// repricing — visible, attributable to the row that caused it, and achieved without editing a
/// single posted line. Publishing one number would force a choice between showing the operator a
/// cap they can reconcile and showing them a price they can invoice.
fn render_totals(
    rows: &crate::root::ledger_identity::LedgerSnapshot,
    quantities: &QuantitySnapshot,
    rates: Option<&busbar_unit_cost::RateCard>,
) -> String {
    let mut out = String::from("{\"rows\":[");
    for (i, (row, figures)) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"bucket\":");
        json_string(&row.bucket, &mut out);
        out.push_str(",\"day\":");
        out.push_str(&row.day.to_string());
        out.push_str(",\"lane\":");
        json_string(&row.lane, &mut out);
        out.push_str(",\"provider\":");
        json_string(&row.provider, &mut out);

        let lines: &[busbar_caps::UsageLine] =
            quantities.get(row).map(Vec::as_slice).unwrap_or_default();
        out.push_str(",\"quantities\":{");
        for (j, line) in lines.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            json_string(line.class.as_str(), &mut out);
            out.push(':');
            out.push_str(&line.quantity.to_string());
        }
        out.push('}');

        out.push_str(",\"fee_count\":");
        out.push_str(&figures.fee_count.to_string());

        // THE BOOK'S BALANCE, AND IT IS NOT THE PRICE. This is what the node drew against the
        // bucket and posted when the unit ended — the figure the budget was enforced on, at the
        // rates in force at that moment. It is served beside the derived amount rather than
        // instead of it because the two answer different questions and an operator needs both:
        // "what did this consume of my cap" is settled, "what is this worth today" is priced.
        // They differ exactly when a rate row has been added since, which is a fact worth being
        // able to see rather than one to hide by publishing a single number.
        out.push_str(",\"settled_micros\":");
        json_amount(i128::from(figures.micros()), &mut out);

        out.push_str(",\"priced_micros\":");
        match rates {
            Some(card) if !lines.is_empty() => {
                // The one call that turns quantities into money, made where the money law lives.
                // The fee is included because a flat fee is the `requests` class priced per unit,
                // and a total that showed the metered classes and quietly dropped the fee would be
                // a figure nobody could reconcile against their bill.
                let micros = busbar_unit_cost::derive_spend_micros(
                    card,
                    std::iter::once((row.lane.as_str(), lines)),
                    figures.fee_count,
                    true,
                );
                json_amount(i128::from(micros), &mut out);
            }
            _ => out.push_str("null"),
        }
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// `GET /api/v1/admin/ledger/checkpoints` — the sealed figures, and whether each seal verifies.
///
/// `body_hash_verifies` is served beside the hash rather than instead of it. The hash is what an
/// auditor re-derives independently; the boolean is this node's own answer for the same question,
/// and serving both is what lets the two be compared rather than trusted.
fn render_checkpoints(checkpoints: &[busbar_unit_ledger::checkpoint::Checkpoint]) -> String {
    let mut out = String::from("{\"checkpoints\":[");
    for (i, cp) in checkpoints.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"checkpoint_seq\":");
        out.push_str(&cp.checkpoint_seq.to_string());
        out.push_str(",\"node\":");
        out.push_str(&cp.node.to_string());
        out.push_str(",\"wall\":");
        out.push_str(&cp.wall.to_string());
        out.push_str(",\"backup_watermark\":");
        out.push_str(&cp.backup_watermark.to_string());
        out.push_str(",\"store_seq_high_water\":");
        out.push_str(&cp.store_seq_high_water.to_string());
        out.push_str(",\"body_hash\":");
        json_string(&hex32(&cp.body_hash), &mut out);
        out.push_str(",\"body_hash_verifies\":");
        out.push_str(if cp.body_hash_verifies() {
            "true"
        } else {
            "false"
        });
        // The signature's PRESENCE is a fact an operator needs; its bytes are not something an
        // administrative read hands out. A checkpoint nobody signed and a checkpoint whose signature
        // this response withheld would otherwise look the same.
        out.push_str(",\"signed\":");
        out.push_str(if cp.signature.is_some() {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"heads\":[");
        for (j, head) in cp.heads.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str("{\"node\":");
            out.push_str(&head.node.to_string());
            out.push_str(",\"node_seq\":");
            out.push_str(&head.node_seq.to_string());
            out.push_str(",\"hash\":");
            json_string(&hex32(&head.hash), &mut out);
            out.push('}');
        }
        out.push_str("],\"totals\":[");
        for (j, ((key, window), totals)) in cp.totals.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            render_totals_cell(key, *window, totals, &mut out);
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

/// One sealed balance, as the checkpoint holds it.
///
/// Six figures the earlier rendering carried are GONE, and their absence is the money model rather
/// than a narrowing of the view: `open_slice_remainders`, `adjustments`, `overdraft_carried_in`,
/// `overdraft_carried_out`, `disputed`, `open_dispute_count` and `oldest_dispute_age_secs` were
/// the columns a correction moved. A sealed line is written once at the end of a unit and never
/// edited, so nothing in this node can put a figure in any of them, and a column that can only
/// ever read zero is a promise the surface cannot keep. The book still holds the fields; this view
/// stops publishing a correction surface that has no corrections behind it.
fn render_totals_cell(
    key: &busbar_unit_ledger::totals::TotalsKey,
    window: busbar_unit_ledger::totals::WindowStart,
    totals: &busbar_unit_ledger::totals::Totals,
    out: &mut String,
) {
    out.push_str("{\"bucket\":");
    json_string(key.bucket.as_str(), out);
    out.push_str(",\"dimension\":");
    json_string(&key.dimension.to_string(), out);
    out.push_str(",\"scope\":");
    json_string(&key.scope.to_string(), out);
    out.push_str(",\"window\":");
    out.push_str(&window.to_string());
    for (name, amount) in [
        ("budget", totals.budget),
        ("drawn", totals.drawn),
        ("released", totals.released),
        ("settled", totals.settled),
        ("open_holds", totals.open_holds),
        ("unreconciled", totals.unreconciled),
        ("cross_window_transfers", totals.cross_window_transfers),
    ] {
        out.push_str(",\"");
        out.push_str(name);
        out.push_str("\":");
        json_amount(amount, out);
    }
    // The one count left on the cell. A count and not an amount: an age in seconds is not money,
    // and the string-vs-number rule this document states turns on exactly that.
    out.push_str(",\"oldest_open_hold_age_secs\":");
    out.push_str(&totals.oldest_open_hold_age_secs.to_string());
    out.push('}');
}

/// `GET /api/v1/admin/ledger/reconciliation` — the residual against the previous release's rows.
///
/// The arithmetic is NOT here. `ledger_identity::reconcile` is the one implementation of the
/// identity, and this view calls it: an operator reading this endpoint and a test asserting the
/// books balance are looking at the same number computed by the same function, which is the only
/// arrangement in which the endpoint can be believed. Rendering a second derivation here would make
/// the endpoint capable of disagreeing with the check that gates the release.
fn render_reconciliation(
    ledger: &crate::root::ledger_identity::LedgerSnapshot,
    legacy: &crate::root::ledger_identity::LegacySnapshot,
) -> String {
    let discrepancies = crate::root::ledger_identity::reconcile(ledger, legacy);
    let mut out = String::from("{\"holds\":");
    out.push_str(if discrepancies.is_empty() {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"discrepancies\":[");
    for (i, d) in discrepancies.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"bucket\":");
        json_string(&d.row.bucket, &mut out);
        out.push_str(",\"day\":");
        out.push_str(&d.row.day.to_string());
        out.push_str(",\"lane\":");
        json_string(&d.row.lane, &mut out);
        out.push_str(",\"provider\":");
        json_string(&d.row.provider, &mut out);
        out.push_str(",\"residual\":{\"accounted\":");
        json_amount(d.spend.accounted, &mut out);
        out.push_str(",\"drawn\":");
        json_amount(d.spend.drawn, &mut out);
        out.push_str(",\"amount\":");
        json_amount(d.spend.amount(), &mut out);
        out.push_str("},\"ledger_fee_count\":");
        out.push_str(&d.ledger_fee_count.to_string());
        out.push_str(",\"legacy_billable_requests\":");
        out.push_str(&d.legacy_billable_requests.to_string());
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// `GET /api/v1/admin/ledger/migration` — the marker the first boot after the upgrade sealed.
///
/// `migrated` is a field of its own rather than something a reader infers from a null marker,
/// because the two facts an operator is actually asking about — "has this deployment opened its
/// balances" and "what did it open them at" — fail separately, and a reader who has to derive the
/// first from the absence of the second will eventually derive it wrong.
fn render_migration(marker: Option<&busbar_unit_ledger::migration::MigrationMarker>) -> String {
    let Some(m) = marker else {
        return String::from("{\"migrated\":false,\"marker\":null}");
    };
    let mut out = String::from("{\"migrated\":true,\"marker\":{\"checkpoint_seq\":");
    out.push_str(&m.checkpoint_seq.to_string());
    out.push_str(",\"node\":");
    out.push_str(&m.node.to_string());
    out.push_str(",\"sealed_at\":");
    out.push_str(&m.sealed_at.to_string());
    out.push_str(",\"body_hash\":");
    json_string(&hex32(&m.body_hash), &mut out);
    out.push_str(",\"balances\":");
    out.push_str(&m.balances.to_string());
    out.push_str(",\"cells_read\":");
    out.push_str(&m.cells_read.to_string());
    out.push_str(",\"rate_card_version\":");
    out.push_str(&m.rate_card_version.to_string());
    out.push_str("}}");
    out
}

/// The table of admin units the kernel is currently walking.
///
/// The kernel's step seam hands a unit its context and nothing else, which is correct — a step has
/// no business being handed a request it might read a second time — so the request lives here,
/// keyed by the unit's own key, and every step reads exactly the field it needs. An entry is
/// inserted before the unit runs and removed when it ends; an entry that outlived its unit would be
/// a leak per request, which is the one thing an interning root may not do.
#[derive(Default)]
pub struct AdminUnits {
    inner: Mutex<HashMap<UnitKey, AdminInFlight>>,
}

/// What one in-flight admin unit carries between its steps.
#[derive(Debug, Clone)]
struct AdminInFlight {
    request: AdminRequest,
    verb: Option<ResolvedVerb>,
    granted: Option<VerbScope>,
    /// Who the auth unit said is calling, as the loop sealed it. Kept here rather than re-derived
    /// downstream because the credential that was presented is NOT the identity that was resolved:
    /// the identity is what a record attributes to, and the credential is a secret that must not
    /// travel past the step that verified it.
    principal: Option<PrincipalId>,
    answer: Option<AdminAnswer>,
}

impl std::fmt::Debug for AdminUnits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminUnits").finish_non_exhaustive()
    }
}

impl AdminUnits {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        AdminUnits {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Open a unit: its request is now readable by every step that runs under this key.
    pub fn open(&self, key: UnitKey, request: AdminRequest) {
        let mut table = self.lock();
        table.insert(
            key,
            AdminInFlight {
                request,
                verb: None,
                granted: None,
                principal: None,
                answer: None,
            },
        );
    }

    /// Close a unit and take whatever it answered. Called once, on the exit path.
    pub fn close(&self, key: UnitKey) -> Option<AdminAnswer> {
        let mut table = self.lock();
        table.remove(&key).and_then(|unit| unit.answer)
    }

    /// How many units are open. Zero between requests is the property that says nothing leaked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this unit is one the admin bindings opened.
    ///
    /// The one question every step asks before it does anything: membership of this table is what
    /// makes a unit this root's to walk, and a unit that is not in it is one the root did not
    /// compose and must not answer for.
    #[must_use]
    pub fn holds(&self, key: UnitKey) -> bool {
        self.lock().contains_key(&key)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<UnitKey, AdminInFlight>> {
        // A poisoned table is a table whose entries are still exactly what they were: the panic
        // that poisoned it happened in a step, and a step writes one field. Recovering is what keeps
        // one unit's panic from ending every other unit on the node.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn request(&self, key: UnitKey) -> Option<AdminRequest> {
        self.lock().get(&key).map(|u| u.request.clone())
    }

    fn verb(&self, key: UnitKey) -> Option<ResolvedVerb> {
        self.lock().get(&key).and_then(|u| u.verb)
    }

    fn granted(&self, key: UnitKey) -> Option<VerbScope> {
        self.lock().get(&key).and_then(|u| u.granted)
    }

    fn set_verb(&self, key: UnitKey, verb: ResolvedVerb) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.verb = Some(verb);
        }
    }

    fn set_granted(&self, key: UnitKey, granted: VerbScope) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.granted = Some(granted);
        }
    }

    /// Keep the identity the auth step resolved, for the two steps downstream that attribute to it.
    fn set_principal(&self, key: UnitKey, principal: PrincipalId) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.principal = Some(principal);
        }
    }

    fn principal(&self, key: UnitKey) -> Option<PrincipalId> {
        self.lock().get(&key).and_then(|u| u.principal.clone())
    }

    fn answer(&self, key: UnitKey) -> Option<AdminAnswer> {
        self.lock().get(&key).and_then(|u| u.answer.clone())
    }

    fn set_answer(&self, key: UnitKey, answer: AdminAnswer) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.answer = Some(answer);
        }
    }
}

/// Everything the admin steps are composed over.
///
/// Held by [`crate::root::kernel::ProductionUnits`] as one field, so that the twelve step methods
/// read one thing rather than five. The dispatch is the seam to where the verbs' bodies live; the
/// units table is where an in-flight request waits between steps.
pub struct AdminBinding {
    /// The seam an operation's body is reached through.
    pub dispatch: Arc<dyn AdminDispatch>,
    /// The figures the five 1.6.0 ledger views read.
    ///
    /// A second seam beside the dispatch, not a widening of it. The 66 legacy operations and the 13
    /// money-governance verbs all reach a surface that already answers them; the views reach
    /// figures that surface never kept, so they need somewhere else to reach, and giving them their
    /// own read-only seam is what stops the dispatch from acquiring a way to read money.
    pub ledger: Arc<dyn LedgerView>,
    /// The requests currently being walked.
    pub units: AdminUnits,
}

// There is no `PostureView` seam.
//
// It existed to read two sealed gates — the operator-key ceremony's state and the dual-control
// posture — that the owner's 2026-09-08 ruling deleted. A seam that resolves a question nobody asks
// is not neutral: it is a place for a future caller to reintroduce the policy the ruling moved out
// of busbar, so it goes rather than being left bound to a permissive default.

impl std::fmt::Debug for AdminBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminBinding")
            .field("in_flight", &self.units.len())
            .finish_non_exhaustive()
    }
}

impl AdminBinding {
    /// Bind the admin steps over a dispatch.
    ///
    /// The ledger views answer from [`UnopenedLedger`] until a root binds a real one through
    /// [`AdminBinding::with_ledger_view`]. That default is a decision rather than an oversight: a
    /// node composed without a ledger has no postings, no seals and no migration, and the views say
    /// so. What it must never do is claim a reconciliation over figures it never read, and it does
    /// not — the totals view beside it reports the empty set the identity held over.
    #[must_use]
    pub fn new(dispatch: Arc<dyn AdminDispatch>) -> Self {
        AdminBinding {
            dispatch,
            ledger: Arc::new(UnopenedLedger),
            units: AdminUnits::new(),
        }
    }

    /// Bind the ledger views to the figures a node actually holds.
    #[must_use]
    pub fn with_ledger_view(mut self, ledger: Arc<dyn LedgerView>) -> Self {
        self.ledger = ledger;
        self
    }
}

/// The kernel verb the closed table's row names.
///
/// The plane resolves a request to a row; this turns that row's name into the verbs unit's own
/// closed enumeration, which is what the rate class, the scope and the execution all key on. The two
/// tables were extracted from the same pinned tag, so a row with no verb is a drift between them
/// and is reported as such rather than defaulted.
/// The join is METHOD and PATH, not the operation's name.
///
/// Both tables were extracted from the same pinned document, but they kept two different columns of
/// it: the plane snake-cases the `operationId` and the executing unit keeps it as the document spelt
/// it, so `get_audit` and `GetAudit` are the same operation under two spellings. The method and the
/// templated path are the SAME bytes in both, because both copied them verbatim, so joining on them
/// is joining on what the document actually pinned rather than on a casing convention either crate
/// is free to change.
///
/// The 1.6.0 additions have no row in the pinned document at all — they are new surface — so they
/// join by name, which is the only thing they have. The plane flags its HTTP bindings for them as a
/// judgment call, which is exactly why they must not be joined on a path.
#[must_use]
pub fn kernel_verb(resolved: &ResolvedVerb) -> Option<KernelVerb> {
    if let Some(row) = LEGACY_VERBS
        .iter()
        .find(|row| row.method == resolved.method && row.path == resolved.template)
    {
        return Some(row.verb);
    }
    NEW_VERBS
        .iter()
        .chain(LEDGER_VERBS.iter())
        .chain(NAMED_SURFACES.iter())
        .copied()
        .find(|verb| verb_name(*verb) == resolved.verb)
}

/// The design's own spelling of a 1.6.0 verb, as the plane's table names it.
///
/// The two crates were written against the same list and spell it two ways — one in the enumeration's
/// Rust casing, one in the operation-name casing the plane's table uses. This is the one place the
/// two spellings meet, so it is the one place either can change without the other noticing, which is
/// why the round trip below is a test rather than a comment.
fn verb_name(verb: KernelVerb) -> &'static str {
    match verb {
        KernelVerb::Verify => "verify",
        KernelVerb::PlaneFacts => "plane_facts",
        KernelVerb::PlaneRecordWrite => "plane_record_write",
        KernelVerb::ChainBreak => "chain_break",
        KernelVerb::StoreRestore => "store_restore",
        KernelVerb::ResealEpochFloor => "reseal_epoch_floor",
        KernelVerb::SetOverdraftCeiling => "set_overdraft_ceiling",
        KernelVerb::SetDisputeMaxAge => "set_dispute_max_age",
        KernelVerb::CommitUpgrade => "commit_upgrade",
        KernelVerb::ResolveDispute => "resolve_dispute",
        KernelVerb::ResolveSlice => "resolve_slice",
        KernelVerb::Adjust => "adjust",
        KernelVerb::AmendRateHistory => "amend_rate_history",
        KernelVerb::GetLedgerTotals => "get_ledger_totals",
        KernelVerb::GetLedgerCheckpoints => "get_ledger_checkpoints",
        KernelVerb::GetLedgerReconciliation => "get_ledger_reconciliation",
        KernelVerb::GetLedgerMigration => "get_ledger_migration",
        KernelVerb::GetLedgerOpenapiJson => "get_ledger_openapi_json",
        _ => "",
    }
}

/// The mutation rate class the verbs unit's table puts a verb in.
///
/// This is the binding the register asked for: the class comes off `CONFIG_CLASS_RULES`, the table
/// the crate ships and the composition root supplies to it, rather than off the blast-radius-blind
/// default the crate warned about. The class is what a caller is limited by; the window count itself
/// stays with the surface whose refusal bytes are pinned, per this module's own header.
#[must_use]
pub fn mutation_class(verb: KernelVerb) -> MutationClass {
    MutationClass::for_verb(verb, CONFIG_CLASS_RULES)
}

// ── the twelve steps, as the admin plane runs them ──────────────────────────────────────────────

/// Step 0. The kernel's own gate.
///
/// An admin unit arrives on the administrative listener, which the design exempts from the in-flight
/// cap for the reason the exemption exists: the surface an operator reaches to find out why the node
/// is shedding must answer while it is shedding. So the gate here reads the arrival and passes it;
/// the budgets it would otherwise apply are the data listener's.
pub(crate) fn arrival(
    binding: &AdminBinding,
    token: &UnitToken<busbar_caps::Arrival>,
    ctx: &UnitCtx,
) -> Decision<busbar_caps::Arrival> {
    let _ = binding;
    Decision::proceed(
        token,
        busbar_contract::ArrivalRecord {
            source: String::new(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec![ADMIN_TRANSPORT],
        },
    )
    .tap_admin(ctx)
}

/// Step 0b. The plane says what shape arrived.
///
/// The plane's closed table is the only thing consulted. A pair it does not declare is an
/// unsupported operation, which is a decode refusal and not a later one: nothing downstream should
/// be asked to authorize an operation that does not exist.
pub(crate) fn decode(
    binding: &AdminBinding,
    token: &UnitToken<Decode>,
    ctx: &UnitCtx,
) -> Decision<Decode> {
    let Some(request) = binding.units.request(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed));
    };
    match busbar_plane_admin::verbs::resolve(&request.method, &request.path) {
        None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        Some(resolved) => {
            binding.units.set_verb(ctx.key, resolved);
            Decision::proceed(token, resolved.op_class())
        }
    }
}

/// Step 1. Who is calling, through the auth unit and its admin posture.
///
/// The posture is the claim's: the admin scheme, narrowed within the alternatives the claim
/// declares, over the chain the deployment configured. The unit is handed the pinned arrival clock
/// rather than a fresh reading, and it is told this is a new unit, which is what makes the
/// revocation set apply.
///
/// The three seams the step needs — the credential cache, the key verifier and the revocation view —
/// come as the node's ONE set rather than three arguments a caller has to remember to fill in. That
/// distinction is the whole of it: `new_unit: true` says "the revocation set applies to this one",
/// and a set nothing supplies revokes nothing, so an absence here would be a revoked credential that
/// still opens the administrative surface.
pub(crate) fn authenticate(
    auth: &busbar_unit_auth::Auth,
    binding: &AdminBinding,
    bindings: &crate::root::auth_bindings::AuthBindings,
    token: &UnitToken<Authenticate>,
    ctx: &UnitCtx,
) -> Decision<Authenticate> {
    let Some(request) = binding.units.request(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::Unauthenticated));
    };
    auth.resolve(
        &AuthRequest {
            candidate: request.credential.as_deref(),
            scheme: Some(ADMIN_SCHEME),
            declared_schemes: ADMIN_DECLARED_SCHEMES,
            expected_aud: None,
            in_handshake: false,
            now: request.at,
            new_unit: true,
        },
        bindings.cache(),
        bindings.keys(),
        bindings.revocations(),
        // No challenge is ever pending on this plane: the administrative claim declares no
        // handshake, so there is no earlier round for one to have come from.
        None,
        token,
    )
}

/// Step 2. Where the unit may go.
///
/// Exactly one place, and it is not a priced one: the kernel verb the table resolved. A sealed
/// destination as the money side spells it carries a LANE — the priced axis a charge sits on — and
/// an admin unit has none, because a kernel verb is not dialled and is not billed. So the verified
/// set is deliberately EMPTY, and that emptiness is the fact the rest of the loop reads: no upstream
/// candidate, therefore no request slot drawn and no flat fee posted, whatever the deployment
/// configured the fee to be.
///
/// The step still runs and still refuses: a unit whose verb the table never resolved has nowhere to
/// go at all, which is a different thing from having nowhere PRICED to go, and the two are answered
/// differently here.
pub(crate) fn verify(
    binding: &AdminBinding,
    token: &UnitToken<Verify>,
    ctx: &UnitCtx,
    principal: &PrincipalId,
) -> Decision<Verify> {
    // The first step the loop hands the resolved identity to, so it is the step that keeps it. Every
    // later step that has to say WHO reads it from here rather than from the request, because the
    // request carries the presented credential and a credential is not an identity.
    binding.units.set_principal(ctx.key, principal.clone());
    match binding.units.verb(ctx.key) {
        None => Decision::refuse(token, Refusal::new(ReasonCode::NoDestination)),
        Some(_resolved) => Decision::proceed(token, Vec::new()),
    }
}

/// Step 3. Whether the caller may do this at all, through the scope unit's admin lookup.
///
/// The lookup is the 1.5.5 authorization matrix as data: method and path decide the scope, never the
/// body. The grant the caller holds is compared against it, and a grant the caller does not hold is
/// a scope refusal at this step rather than a surprise inside the operation.
pub(crate) fn approve(
    binding: &AdminBinding,
    granted: Option<VerbScope>,
    token: &UnitToken<Approve>,
    ctx: &UnitCtx,
    _principal: &PrincipalId,
    _destinations: &[VerifiedDestination],
) -> Decision<Approve> {
    // A caller holding no grant at all is refused here, before the operation is reached. An absent
    // grant is not a narrow one: there is no scope to compare the matrix against, so there is
    // nothing this step could admit.
    let Some(granted) = granted else {
        return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
    };
    let Some(request) = binding.units.request(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
    };
    let needed = busbar_unit_scope::admin_required_scope(&request.method, &request.path);
    binding.units.set_granted(ctx.key, granted);
    if !granted.allows(scope_as_verb_scope(needed)) {
        return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
    }
    Decision::proceed(token, busbar_contract::ScopeFacts::default())
}

/// The scope unit and the verbs unit spell the same two-rung split with two types. Neither is wrong
/// and neither is the other's: one is the admin surface's matrix, the other is what a credential
/// carries. The root is what says they are the same split, and this is where it says it.
fn scope_as_verb_scope(scope: Scope) -> VerbScope {
    match scope {
        Scope::ReadOnly => VerbScope::ReadOnly,
        Scope::Full => VerbScope::Full,
    }
}

/// Step 4. The door.
///
/// An admin unit's verified set is a kernel verb and nothing else, so it draws no dimension and
/// takes no concurrency lease: the design says the admin API answers at a saturated `concurrent` cap
/// and this zero-hold admission is how. What the step DOES do is read the mutation rate class off
/// the verbs unit's table — the binding the composition root owes that crate — and refuse a verb the
/// table forbids outright.
pub(crate) fn admit(
    binding: &AdminBinding,
    token: &UnitToken<Admit>,
    _admit: &AdmitToken<Admit>,
    ctx: &UnitCtx,
    _principal: &PrincipalId,
    _destinations: &[VerifiedDestination],
) -> Decision<Admit> {
    let Some(resolved) = binding.units.verb(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    let Some(verb) = kernel_verb(&resolved) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    // The class is read here — that is the binding — and read is ALL it is. `Forbidden` in this
    // vocabulary does not mean the verb is refused; it means the verb is not a mutation and the
    // mutation budget therefore does not apply to it, which is why the unit's own admission
    // short-circuits past the limiter on it rather than denying. Reading it as a refusal turned
    // every read on the surface into a 403, which is exactly the kind of thing a vocabulary shared
    // between two crates invites.
    let _class = mutation_class(verb);
    Decision::proceed(token, Admission::ZeroHold)
}

/// Step 5. The verb runs, where its body lives.
///
/// The verbs unit is what executes it — it is the crate that holds the admin token and the closed
/// verb enumeration — and the governance seam under it is what reaches the surface the operation
/// already belongs to. The whole answer comes back and is put where the exit path will find it.
///
/// The five ledger views travel this same path and are not special-cased here. They reach
/// `Verbs::execute` like every other verb, are scope-checked and rate-classed by the same two lines,
/// and differ only in which method of the governance seam the unit calls at the end of it — which is
/// the unit's decision, from its own closed table, and not this step's.
pub(crate) fn route(
    binding: &AdminBinding,
    store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    admin: &busbar_caps::AdminToken,
    token: &UnitToken<Route>,
    ctx: &UnitCtx,
    _meter: &busbar_kernel::teller::AccrualMeter,
) -> Decision<Route> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    let Some(verb) = kernel_verb(&resolved) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    let granted = binding
        .units
        .granted(ctx.key)
        .unwrap_or(scope_as_verb_scope(
            busbar_unit_scope::admin_required_scope(&request.method, &request.path),
        ));

    // THE ONE PLACE THE CHOICE IS MADE. Route is this plane's destination, and a destination is
    // where a composition says which of the unit's entry points an operation reaches. Written as a
    // named question rather than an inline pair so that "these two verbs and no others" is a fact
    // with a test on it instead of a condition to re-read.
    if mints_its_own_identity(verb) {
        let answer = binding.dispatch.execute(verb, &request);
        binding.units.set_answer(ctx.key, answer);
        return Decision::proceed(token, busbar_contract::RoutePlan::default());
    }

    let verbs = busbar_unit_verbs::Verbs::new(
        CoreGovernance::new(
            Arc::clone(&binding.dispatch),
            Arc::clone(&binding.ledger),
            Arc::clone(&binding.facts),
            verb,
            request.clone(),
        ),
        StoreRef(store),
        ArrivalNonce(request.at),
        PackedReplay,
        CONFIG_CLASS_RULES,
    );

    // The same identity the record attributes to, so the rate-limit bucket, the audit row and the
    // maker half of the maker-checker rule all name one actor. Keying any of them on the credential
    // instead let one principal be two by presenting a second token.
    let actor = actor_of(binding, ctx.key);
    // THE THREE DISASTER-RECOVERY VERBS REACH THE STORE, not the governance seam. They are new
    // verbs and are admitted exactly as every other new verb is — scope, then rate class — but
    // their effect lands on `Store` rather than on a handler, and the unit gives each of them its
    // own entry point for precisely that reason.
    // Sending them through `execute` sent them to `execute_new_verb`, which asks the mounted router
    // for a path that release never had: the gates passed, and the caller got a
    // 404 from the surface underneath. Breaking a journal chain is not an operation that should be
    // able to look like it happened when it did not, nor to look like it did not when it had.
    if let Some(recovery) = recovery_verb(verb) {
        let ran = match recovery {
            RecoveryVerb::ChainBreak => verbs.chain_break(admin, &actor, granted, request.at),
            RecoveryVerb::StoreRestore => {
                // The backup the operator named. There is no default and no empty one: restoring
                // "whatever the store thinks" is the single most destructive thing this surface can
                // be asked to do by accident, so a request that names none is refused before the
                // ceremony rather than resolved to something.
                match backup_ref_of(&request.body) {
                    Some(backup_ref) => {
                        verbs.store_restore(admin, &actor, granted, request.at, &backup_ref)
                    }
                    None => {
                        return Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed));
                    }
                }
            }
            RecoveryVerb::ResealEpochFloor => {
                verbs.reseal_epoch_floor(admin, &actor, granted, request.at)
            }
        };
        return match ran {
            Ok(()) => {
                binding.units.set_answer(ctx.key, applied_answer());
                Decision::proceed(token, busbar_contract::RoutePlan::default())
            }
            Err(refusal) => Decision::refuse(token, Refusal::new(verbs_reason(refusal.reason))),
        };
    }

    match verbs.execute(verb, admin, &actor, granted, request.at, &request.body) {
        Ok(packed) => match AdminAnswer::unpack(&packed) {
            Some(answer) => {
                binding.units.set_answer(ctx.key, answer);
                Decision::proceed(token, busbar_contract::RoutePlan::default())
            }
            // The only producer of these bytes is this file's own packer, so a shape that does not
            // parse is this file being wrong rather than an input to forgive.
            None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        },
        Err(refusal) => Decision::refuse(token, Refusal::new(verbs_reason(refusal.reason))),
    }
}

/// The three verbs whose effect lands on the store rather than on a handler.
///
/// Named as a closed enumeration of its own rather than matched inline, so "these three and no
/// others" is a fact with a test on it. The verbs unit draws the same line from the other side: it
/// gives each of them a method, and gives `execute` no arm that could reach one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryVerb {
    ChainBreak,
    StoreRestore,
    ResealEpochFloor,
}

/// Which recovery verb this is, or `None` for a verb whose effect is the governance seam's.
fn recovery_verb(verb: KernelVerb) -> Option<RecoveryVerb> {
    match verb {
        KernelVerb::ChainBreak => Some(RecoveryVerb::ChainBreak),
        KernelVerb::StoreRestore => Some(RecoveryVerb::StoreRestore),
        KernelVerb::ResealEpochFloor => Some(RecoveryVerb::ResealEpochFloor),
        _ => None,
    }
}

/// Where one admin verb's answer is PRODUCED.
///
/// Not where the request is admitted — every verb on this surface walks the same twelve steps — but
/// which side of the last one writes the bytes. The distinction is the whole subject of the admin
/// leg's migration: an operation crosses when the loop starts producing its answer and the surface
/// underneath stops, and both halves of that have to be true at once or the same request has two
/// answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnsweredBy {
    /// The loop produces the bytes itself, from a seam it holds. The surface underneath is not asked
    /// and has no route for the path.
    Loop,
    /// The loop hands the request to the administrative surface `busbar-core` mounts and returns
    /// what that answered, unchanged — status, headers and body together.
    LegacySurface,
}

/// Which side answers one verb, as DATA rather than as a sentence somebody has to keep true.
///
/// The two arms below are the same two closed enumerations [`route`] branches on, read from the one
/// place each is defined: the three recovery verbs from [`recovery_verb`], and the ledger views from
/// the executing unit's own `LEDGER_VERBS`. Nothing here is a transcription — a verb added to either
/// list appears here without this function being edited, which is what makes it safe to join a test
/// against.
///
/// It is deliberately NOT derived from `route`'s control flow, because a table derived from the code
/// it is meant to check agrees with any code. What checks it is the pin beside this crate's other
/// admin tests: it serves the surface underneath and asks it, path by path, which of the 88 it has a
/// route for — and requires that set to be exactly the complement of this function's `Loop`.
#[must_use]
pub fn answered_by(verb: KernelVerb) -> AnsweredBy {
    if recovery_verb(verb).is_some() {
        // Their effect lands on `Store` through the unit's own per-verb entry points; the governance
        // seam is never reached and the surface underneath has never had a route for them.
        return AnsweredBy::Loop;
    }
    if CROSSED_VERBS.contains(&verb) {
        // One of the sixty-six that has CROSSED: the loop reads the node's tables through its own
        // seam and renders, and the route this operation was mounted on is gone.
        return AnsweredBy::Loop;
    }
    if busbar_unit_verbs::LEDGER_VERBS.contains(&verb) {
        // There is no 1.5.5 handler behind a figure 1.5.5 never kept, so `execute_ledger_read`
        // renders these from the bound `LedgerView` rather than asking the dispatch.
        return AnsweredBy::Loop;
    }
    AnsweredBy::LegacySurface
}

/// What an operation that changed something and has nothing to say answers with.
///
/// A recovery verb's whole result is its effect: the chain broke, the store restored, the floor
/// resealed. There is no document to return and none was ever specified, so the answer carries no
/// body and declares no content type — inventing a document here would put a schema on the wire that
/// nothing describes and that a client would then be entitled to depend on.
fn applied_answer() -> AdminAnswer {
    AdminAnswer {
        status: 204,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// The backup a `store_restore` request names, or `None` when it names none.
///
/// A deliberately small reader for a deliberately small document: one field, whose value is a JSON
/// string. Written out rather than taken from a serialization crate because this crate carries none
/// on the request path, and because getting it wrong in the permissive direction is what would let a
/// malformed body restore something the operator did not ask for. Anything this does not understand
/// — a missing field, a value that is not a string, an unterminated one — is `None`, and `None` is
/// a refusal at the call site.
fn backup_ref_of(body: &[u8]) -> Option<String> {
    const FIELD: &str = "\"backup_ref\"";
    let text = std::str::from_utf8(body).ok()?;
    let after = &text[text.find(FIELD)? + FIELD.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let mut chars = after.strip_prefix('"')?.chars();
    let mut value = String::new();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                '/' => value.push('/'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'b' => value.push('\u{08}'),
                'f' => value.push('\u{0c}'),
                'u' => {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    value.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                // An escape this reader does not know is a document it does not understand, and a
                // backup reference is the last field to guess at.
                _ => return None,
            },
            c => value.push(c),
        }
    }
    // An empty reference names nothing, which is the same refusal as naming no field at all.
    (!value.is_empty()).then_some(value)
}

/// Whether the operation's own surface has already minted the identity this answer carries.
///
/// True for exactly the two credential-MINTING verbs, and the verbs unit's own debug assertion says
/// the same thing from the other side: they must never come through its general execution path,
/// because they have dedicated methods with their own idempotency handling that mint through the
/// governance seam and render through the replay encoder.
///
/// This root does not mint. The surface that owns those operations mints and renders the one-time
/// secret itself, and it has already done so by the time the answer comes back, so asking the unit
/// to mint a second identity for an answer that already carries one would be two mints for one
/// request — exactly what the dedicated methods exist to prevent. For those two the seam is reached
/// directly: the verb is still the closed table's, the step is still Route and the body still lives
/// where it lived; what is skipped is a minting path this composition has no use for.
fn mints_its_own_identity(verb: KernelVerb) -> bool {
    matches!(verb, KernelVerb::PostKeys | KernelVerb::PostKeysIdRotate)
}

/// The identity an administrative record attributes this unit to.
///
/// The resolved principal the auth step produced, and NEVER the bytes the caller presented. A record
/// written from the credential is a record that publishes a live bearer secret to everyone entitled
/// to read the administrative history — which is a wider set than the set entitled to hold the
/// secret — and it also attributes two callers sharing one token to two different actors while
/// attributing one caller rotating a token to one actor per rotation.
///
/// `None` where no identity was resolved, which is the answer the audit doors act on: a unit refused
/// at or before Authenticate has no actor, so the previous release's chain takes no row for it. The
/// literal that used to stand in was the CONFIGURED administrator's name, which made every refused
/// unauthenticated mutation a row in that operator's own history.
fn resolved_actor(binding: &AdminBinding, key: UnitKey) -> Option<String> {
    binding.units.principal(key).map(|p| p.as_str().to_string())
}

/// What a step that must name somebody uses when the identity did not resolve.
///
/// Reached only by Route, and Route is downstream of Authenticate — a unit that reaches it has a
/// principal, so this is the shape of an impossibility rather than a fallback anything exercises.
/// It is NOT what the audit doors use: those decline to write at all, because a record naming a
/// non-participant is a worse answer than no record.
const UNRESOLVED_ACTOR: &str = "admin";

/// The identity a step that cannot decline is handed. See [`UNRESOLVED_ACTOR`].
fn actor_of(binding: &AdminBinding, key: UnitKey) -> String {
    resolved_actor(binding, key).unwrap_or_else(|| UNRESOLVED_ACTOR.to_string())
}

/// The verbs unit's refusal vocabulary, said in the kernel's.
///
/// Two closed lists that name the same events. Mapping them here rather than merging them keeps a
/// unit's reasons its own — the verbs unit may gain a reason the kernel has no step for, and the
/// kernel may gain a step no verb reaches.
fn verbs_reason(reason: busbar_unit_verbs::ReasonCode) -> ReasonCode {
    use busbar_unit_verbs::ReasonCode as V;
    match reason {
        V::Unauthorized => ReasonCode::ScopeDenied,
        V::RateLimited => ReasonCode::RateLimited,
        V::NotFound => ReasonCode::NoDestination,
        V::IdempotencyInFlight | V::Conflict => ReasonCode::OpenSlotBusy,
        V::Validation => ReasonCode::DecodeFailed,
        V::StoreError | V::Internal => ReasonCode::DurabilityUnavailable,
    }
}

/// Step 6. What the unit cost.
///
/// Zero, and reported as zero rather than left unreported. The design's admin row declares no meter
/// classes at all — deliberately — so there is no class for a line to be reported against, and an
/// empty report is the accurate one. This is also what pins the admin cell's zero fee and zero
/// request postings under a non-zero configured fee: nothing was metered because nothing priced was
/// reached.
pub(crate) fn meter(
    token: &UnitToken<Meter>,
    usage: &UsageToken,
    _ctx: &UnitCtx,
    _provisional: &Outcome,
) -> Decision<Meter> {
    match Usage::report(usage, Vec::new()) {
        Ok(reported) => Decision::proceed(token, reported),
        Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::Unpriced)),
    }
}

/// Step 7. The end, sealed onto the previous release's administrative chain.
///
/// The chain is `busbar-unit-audit`'s legacy one: the mutation history an operator's `/audit` page
/// has always read, moved rather than rewritten, so that a digest change cannot silently report every
/// deployment's history as tampered. A read is not a mutation and is not appended; the chain is a
/// record of what changed.
pub(crate) fn audit(
    binding: &AdminBinding,
    legacy: &busbar_unit_audit::AuditLog,
    token: &UnitToken<Audit>,
    ctx: &UnitCtx,
    outcome: &Outcome,
) -> Decision<Audit> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        return Decision::proceed(
            token,
            unresolved_facts(
                binding
                    .units
                    .request(ctx.key)
                    .map(|request| request.method)
                    .as_deref(),
                outcome,
            ),
        );
    };
    if !resolved.read_only {
        if let Some(actor) = resolved_actor(binding, ctx.key) {
            legacy.record_by(resolved.verb, &request.path, outcome_word(outcome), &actor);
        }
    }
    Decision::proceed(
        token,
        busbar_contract::AuditFacts {
            op_class: resolved.op_class(),
            finish: finish_of(outcome),
        },
    )
}

/// Step 7, the other door. A unit that never passed Admit was charged nothing, and the chain records
/// the attempt rather than pretending it did not happen.
pub(crate) fn audit_refused(
    binding: &AdminBinding,
    legacy: &busbar_unit_audit::AuditLog,
    token: &UnitToken<Audit>,
    ctx: &UnitCtx,
    refusal: &Refusal,
) -> Decision<Audit> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        // THE REFUSAL THAT HAPPENED, not one composed here. This arm used to seal every unresolved
        // unit as a decode failure raised at Decode, whatever it had actually been refused for: a
        // revoked credential, a denied scope and a saturated store all left one record, saying the
        // bytes did not parse. That is the single thing an audit record exists to state, and it was
        // the field this door overwrote. The step is the decision's own stamp where it carries one,
        // and the door itself is the latest step it could have been raised at where it does not.
        return Decision::proceed(
            token,
            unresolved_facts(
                binding
                    .units
                    .request(ctx.key)
                    .map(|request| request.method)
                    .as_deref(),
                &Outcome::Refused(
                    refusal.step().unwrap_or(busbar_caps::StepName::Audit),
                    refusal.reason(),
                ),
            ),
        );
    };
    // A REFUSAL BEFORE THE IDENTITY RESOLVED APPENDS NOTHING. The previous release's chain is what
    // an operator's history page reads, and for an unauthenticated administrative request it holds
    // no row at all — the credential was never accepted, so no principal ever acted. Writing one
    // anyway put a mutation in the history under the configured administrator's name for a request
    // that administrator never made, which is worse than a gap: an anonymous caller could grow that
    // operator's history one refused `DELETE` at a time. The attempt is still reported — it is the
    // refusal the caller receives and the sealed facts below — it is simply not attributed to
    // somebody who was not there.
    if !resolved.read_only {
        if let Some(actor) = resolved_actor(binding, ctx.key) {
            legacy.record_by(
                resolved.verb,
                &request.path,
                busbar_unit_audit::OUTCOME_REJECTED,
                &actor,
            );
        }
    }
    Decision::proceed(
        token,
        busbar_contract::AuditFacts {
            op_class: resolved.op_class(),
            finish: busbar_contract::FinishClass::Error,
        },
    )
}

/// What the record says about a unit whose verb never resolved.
///
/// It still ended, and it still has an operation class, because "the table declares no such
/// operation" IS an answer: the surface was asked a question and said no. Naming a class here
/// rather than leaving one unset is what keeps every sealed end comparable.
///
/// WHICH class is read off the method, not fixed. Every unresolved unit used to seal as
/// `admin_read`, so an unrouted `DELETE` and an unrouted `GET` came out of the record as the same
/// event — an operator reading a page. That answer is right for one of them and wrong for the other
/// in the direction that matters: the record under-reports the attempted blast radius, which is
/// exactly the column somebody reviewing an administrative history is reading for. A method the
/// request never carried (there is no request at all, so nothing was asked of any resource) stays
/// a read, because a unit that never presented a method attempted no mutation.
pub(crate) fn unresolved_facts(
    method: Option<&str>,
    outcome: &Outcome,
) -> busbar_contract::AuditFacts {
    busbar_contract::AuditFacts {
        op_class: busbar_contract::OpClassId::new(match method {
            Some(method) if !is_read_method(method) => OP_UNRESOLVED_WRITE,
            _ => OP_UNRESOLVED_READ,
        }),
        finish: finish_of(outcome),
    }
}

/// The two operation classes the admin plane seals a resolved unit under, spelt here for the
/// unresolved ones so that both halves of the record use one vocabulary. Taken from the plane's own
/// table rather than invented, because a class this file coined would be a third word for a split
/// the surface already has two.
const OP_UNRESOLVED_READ: &str = "admin_read";
/// See [`OP_UNRESOLVED_READ`].
const OP_UNRESOLVED_WRITE: &str = "admin_write";

/// Whether this method reads. The two the HTTP specification defines as safe, and nothing else —
/// an unknown method is not one of them, so it seals as a write, which is the conservative
/// direction for a column an audit review is read for.
fn is_read_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn outcome_word(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Completed => busbar_unit_audit::OUTCOME_APPLIED,
        _ => busbar_unit_audit::OUTCOME_REJECTED,
    }
}

fn finish_of(outcome: &Outcome) -> busbar_contract::FinishClass {
    match outcome {
        Outcome::Completed => busbar_contract::FinishClass::Complete,
        _ => busbar_contract::FinishClass::Error,
    }
}

/// Step 8. The bytes that leave.
///
/// The answer the operation produced is already whole — status, headers and body — so there is
/// nothing for this step to render. It hands back an empty frame and the exit path is what carries
/// the answer out, which is the shape that makes it impossible for a byte to be re-derived here.
pub(crate) fn encode(
    binding: &AdminBinding,
    token: &UnitToken<Encode>,
    ctx: &UnitCtx,
    _outcome: &Outcome,
) -> Decision<Encode> {
    let bytes = binding
        .units
        .answer(ctx.key)
        .map(|answer| answer.body)
        .unwrap_or_default();
    Decision::proceed(
        token,
        busbar_contract::Frame {
            direction: busbar_contract::Direction::Outbound,
            stream: busbar_contract::StreamId(0),
            bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(bytes.as_slice())),
            meta: busbar_contract::FrameMeta {
                bytes: bytes.len() as u64,
                transport_units: None,
                status: None,
                status_code: None,
                retry_after_secs: None,
            },
        },
    )
}

/// What the settlement table reads.
///
/// Every field is the zero one, and each zero is a statement. Nothing was located because nothing
/// was metered; there is no upstream candidate because an admin unit's verified set is a kernel verb,
/// which is exactly what makes its `requests` draw and its flat fee both zero under a configured
/// non-zero fee.
#[must_use]
pub(crate) fn evidence(_ctx: &UnitCtx) -> busbar_kernel::teller::Evidence {
    busbar_kernel::teller::Evidence {
        upstream_candidate: false,
        ..Default::default()
    }
}

/// A small extension used only to keep the arrival step's shape readable; it changes nothing.
trait TapAdmin: Sized {
    fn tap_admin(self, _ctx: &UnitCtx) -> Self {
        self
    }
}

impl<S: busbar_caps::Step> TapAdmin for Decision<S> {}

/// The store the verbs unit is handed, behind the published ABI.
///
/// A thin newtype rather than a second implementation: the adapter the loader already builds is what
/// answers, and this exists only because the unit takes its store by value while the root holds one
/// for the whole node.
struct StoreRef(Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>);

impl busbar_unit_verbs::store::Store for StoreRef {
    fn chain_break(
        &self,
        admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.chain_break(admin)
    }

    fn store_restore(
        &self,
        admin: &busbar_caps::AdminToken,
        backup_ref: &str,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.store_restore(admin, backup_ref)
    }

    fn reseal_epoch_floor(
        &self,
        admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.reseal_epoch_floor(admin)
    }

    fn replay_new_verb(
        &self,
        key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
        self.0.replay_new_verb(key)
    }

    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.commit_new_verb_replay(key, response)
    }
}

/// The nonce a one-time secret is bound to.
///
/// Drawn from the operating system's own source, not derived from the secret it protects. The
/// arrival epoch is mixed in so that two nonces drawn in one process cannot collide through a source
/// that returned the same bytes twice; the entropy is what makes it unpredictable and the epoch is
/// only what makes it distinct.
struct ArrivalNonce(u64);

impl busbar_unit_verbs::NonceSource for ArrivalNonce {
    fn fill(&self, buf: &mut [u8; 16]) {
        let mut material = [0u8; 16];
        getrandom_into(&mut material);
        *buf = mix_arrival(material, self.0);
    }
}

/// The epoch half of the draw, separated from the source so it can be stated rather than sampled.
///
/// Unpredictability comes from the material and cannot be asserted about a random draw; DISTINCTNESS
/// comes from the arrival epoch and can be, which is why the two are split here: two units that
/// arrived at different moments cannot collide even if the source handed them the same bytes twice.
fn mix_arrival(material: [u8; 16], at: u64) -> [u8; 16] {
    let mut out = material;
    for (slot, byte) in out.iter_mut().zip(at.to_be_bytes().iter()) {
        *slot ^= *byte;
    }
    out
}

/// Draw unpredictable bytes from the node's own source.
///
/// The source is the substrate's, which is the operating system's: the same fail-closed draw a key
/// secret and a plane's replay nonce are minted from. Reaching it rather than re-deriving one here
/// is the whole point — a composition root that mints its own entropy has a second entropy source to
/// get wrong, and this one had.
///
/// What it had been was a keyed hash of a STACK ADDRESS. That is not entropy: the address is the
/// same on every call from the same frame, so the only thing varying was the hasher's key, and the
/// second half was the first half hashed again — 64 bits of source, presented as 128.
///
/// The material arrives hex-encoded and is read back a byte at a time rather than through a decoder,
/// because the one thing wanted from it is 16 bytes and adding a crate edge to a composition root to
/// halve a string is a poor trade. A pair of digits that does not parse cannot happen — the encoder
/// on the other side of the call writes hex — and if it ever did, the byte is left as the source's
/// own zero rather than silently substituted.
fn getrandom_into(buf: &mut [u8; 16]) {
    let Ok(drawn) = busbar_substrate::plane::approvals::nonce() else {
        // The OS source refusing is not survivable for a secret this binds, and it is also not
        // something this root can refuse from: the seam it fills is infallible. So the buffer is
        // left as the caller's zeroes and the epoch below is what still distinguishes it — an
        // unmistakably degraded nonce rather than a plausible-looking one that is not random.
        return;
    };
    let (pairs, _) = drawn.as_bytes().as_chunks::<2>();
    for (slot, pair) in buf.iter_mut().zip(pairs) {
        let hi = (pair[0] as char).to_digit(16);
        let lo = (pair[1] as char).to_digit(16);
        if let (Some(hi), Some(lo)) = (hi, lo) {
            *slot = ((hi << 4) | lo) as u8;
        }
    }
}

/// The replay encoder.
///
/// A replayed answer is the bytes the first answer sent, not a fresh rendering of the same facts. A
/// re-render would mint a second one-time secret over the same identity, which is exactly the defect
/// the register named; this returns what was written and nothing else.
struct PackedReplay;

impl busbar_unit_verbs::ReplayEncoder<busbar_unit_verbs::MintedKeyOutcome> for PackedReplay {
    fn encode(&self, value: &busbar_unit_verbs::MintedKeyOutcome) -> Vec<u8> {
        // Reached only on the unit's own key-minting path, which this root does not take: the
        // operation's own surface mints and renders, so there is no second rendering here to get
        // wrong. The identity is enough to key a replay slot and carries no secret.
        value.id.as_bytes().to_vec()
    }
}

// ── the mount: one HTTP surface, one loop, one answer ───────────────────────────────────────────
//
// In its own file (`admin_mount.rs`), re-exported here so every caller — `main.rs`, the tests
// below — still names it at `root::units_admin::…` exactly as before.
mod admin_mount;
pub(crate) use admin_mount::*;

#[cfg(test)]
#[path = "tests/units_admin.rs"]
mod tests;
