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
    ApprovalState, KernelVerb, PostureCtx, VerbScope, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES,
    NEW_VERBS,
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
}

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
        let mut nanos: std::collections::BTreeMap<RowKey, u128> = std::collections::BTreeMap::new();
        for posting in self.legacy.postings() {
            let row = RowKey::new(
                posting.bucket.as_str(),
                posting.window_start,
                WIDTH_THE_NODE_KEEPS,
                WIDTH_THE_NODE_KEEPS,
            );
            let entry = nanos.entry(row).or_default();
            *entry = entry.saturating_add(u128::from(posting.settled));
        }
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
    fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting>;
}

impl LegacyRowsRead for busbar_unit_ledger::legacy::RecordingRows {
    fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting> {
        self.written()
    }
}

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
        verb: KernelVerb,
        request: AdminRequest,
    ) -> Self {
        CoreGovernance {
            dispatch,
            ledger,
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
        _verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
        Ok(self.run())
    }

    fn execute_new_verb(
        &self,
        _verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
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

/// The bytes one ledger view answers with, or `None` for a verb that is not one.
///
/// `None` is reachable only if the closed table and this match ever disagree, which is a defect in
/// this file rather than a request to forgive — so it becomes a `NotFound` at the call site rather
/// than a body invented for a verb nobody wrote one for.
fn render_ledger_view(verb: KernelVerb, view: &dyn LedgerView) -> Option<Vec<u8>> {
    Some(match verb {
        KernelVerb::GetLedgerTotals => render_totals(&view.ledger_rows()).into_bytes(),
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

/// `GET /api/v1/admin/ledger/totals` — what the ledger posted, per bucket, day, lane and provider.
///
/// The row width is the reconciliation's row width, and deliberately so: this view and the
/// reconciliation view are two readings of one set of rows, so a discrepancy an operator finds in
/// one can be looked up in the other by the same four-part name.
fn render_totals(rows: &crate::root::ledger_identity::LedgerSnapshot) -> String {
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
        out.push_str(",\"priced_nanos\":\"");
        out.push_str(&figures.priced_nanos.to_string());
        out.push_str("\",\"priced_micros\":");
        json_amount(i128::from(figures.micros()), &mut out);
        out.push_str(",\"fee_count\":");
        out.push_str(&figures.fee_count.to_string());
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
        ("open_slice_remainders", totals.open_slice_remainders),
        ("adjustments", totals.adjustments),
        ("unreconciled", totals.unreconciled),
        ("overdraft_carried_in", totals.overdraft_carried_in),
        ("overdraft_carried_out", totals.overdraft_carried_out),
        ("cross_window_transfers", totals.cross_window_transfers),
        ("disputed", totals.disputed),
    ] {
        out.push_str(",\"");
        out.push_str(name);
        out.push_str("\":");
        json_amount(amount, out);
    }
    for (name, count) in [
        (
            "oldest_open_hold_age_secs",
            totals.oldest_open_hold_age_secs,
        ),
        ("open_dispute_count", totals.open_dispute_count),
        ("oldest_dispute_age_secs", totals.oldest_dispute_age_secs),
    ] {
        out.push_str(",\"");
        out.push_str(name);
        out.push_str("\":");
        out.push_str(&count.to_string());
    }
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
    /// A second seam beside the dispatch, not a widening of it. The 66 legacy operations and the 17
    /// money-governance verbs all reach a surface that already answers them; the views reach
    /// figures that surface never kept, so they need somewhere else to reach, and giving them their
    /// own read-only seam is what stops the dispatch from acquiring a way to read money.
    pub ledger: Arc<dyn LedgerView>,
    /// Where the money-governance posture is read from.
    ///
    /// A third seam, and it has to be one: the two gates the 17 verbs are checked against are sealed
    /// state, not request state, so nothing on the request can answer them and nothing this file
    /// holds is entitled to decide them. Bound to [`UnsealedPosture`] until a root binds a reader for
    /// the journal the ceremony writes.
    pub posture: Arc<dyn PostureView>,
    /// The requests currently being walked.
    pub units: AdminUnits,
}

/// Where the two sealed gates a money-governance verb is checked against are read from.
///
/// The verbs unit takes both as plain values and says so: resolving them is the integrator's, which
/// is this file. What the integrator may NOT do is invent them — a posture invented at the call site
/// is a gate that reports whatever the call site wrote rather than what the fleet sealed, which is
/// the same thing as no gate at all in one direction and an unliftable refusal in the other.
///
/// So the answer is an option, and `None` means "this node cannot read what the fleet sealed". A
/// verb whose posture is unresolved is refused by the verbs unit rather than admitted under a
/// guessed one, which is the only safe reading: a reader that has stopped working must not look like
/// a fleet that never ran a ceremony.
pub trait PostureView: Send + Sync {
    /// The posture this verb is checked against, and this actor's approval standing for it.
    ///
    /// The actor is named because the approval half is per-maker: whether an `approve` exists for a
    /// pending mutation, and whether its approver is somebody other than the principal now asking,
    /// is a question about this caller and not about the node.
    fn resolve(&self, verb: KernelVerb, actor: &str) -> Option<(PostureCtx, ApprovalState)>;
}

/// The posture of a node that has sealed no policy at all.
///
/// Exactly what the design says a fresh install and an upgrade are, said as data rather than assumed
/// at the call site: no operator ceremony has run, so the irreducible verbs that need one are
/// refused, and dual control is single, so every other mutation applies immediately. The approval
/// standing is `NotYetApproved` because nothing has approved anything — under `Single` it is never
/// consulted, and stating the true value rather than a convenient one is what stops this default
/// from becoming a pass the moment a real posture is bound beside it.
///
/// This is a statement about a node with no journal, NOT a fallback for one whose journal could not
/// be read. That case answers `None` and is refused.
#[derive(Debug, Default)]
pub struct UnsealedPosture;

impl PostureView for UnsealedPosture {
    fn resolve(&self, _verb: KernelVerb, _actor: &str) -> Option<(PostureCtx, ApprovalState)> {
        Some((
            PostureCtx {
                operator: busbar_unit_verbs::OperatorState::Unset,
                dual_control: busbar_unit_verbs::DualControl::Single,
            },
            ApprovalState::NotYetApproved,
        ))
    }
}

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
            posture: Arc::new(UnsealedPosture),
            units: AdminUnits::new(),
        }
    }

    /// Bind the ledger views to the figures a node actually holds.
    #[must_use]
    pub fn with_ledger_view(mut self, ledger: Arc<dyn LedgerView>) -> Self {
        self.ledger = ledger;
        self
    }

    /// Bind the money-governance gates to the posture a fleet actually sealed.
    #[must_use]
    pub fn with_posture_view(mut self, posture: Arc<dyn PostureView>) -> Self {
        self.posture = posture;
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
        KernelVerb::SetOperatorKey => "set_operator_key",
        KernelVerb::SetEscrow => "set_escrow",
        KernelVerb::ChainBreak => "chain_break",
        KernelVerb::StoreRestore => "store_restore",
        KernelVerb::ResealEpochFloor => "reseal_epoch_floor",
        KernelVerb::SetDualControl => "set_dual_control",
        KernelVerb::SetOverdraftCeiling => "set_overdraft_ceiling",
        KernelVerb::SetDisputeMaxAge => "set_dispute_max_age",
        KernelVerb::CommitUpgrade => "commit_upgrade",
        KernelVerb::ResolveDispute => "resolve_dispute",
        KernelVerb::ResolveSlice => "resolve_slice",
        KernelVerb::Adjust => "adjust",
        KernelVerb::ExportKeyset => "export_keyset",
        KernelVerb::Approve => "approve",
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
    granted: VerbScope,
    token: &UnitToken<Approve>,
    ctx: &UnitCtx,
    _principal: &PrincipalId,
    _destinations: &[VerifiedDestination],
) -> Decision<Approve> {
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
    // Both gates come from the seam, together, because they are one question about one fleet asked
    // at one moment. An unresolvable posture travels as `None` and the verbs unit refuses the verb
    // for it: the two gates exist to stop an irreversible money operation, so a node that cannot say
    // what its fleet sealed must not run one.
    let resolved_posture = binding.posture.resolve(verb, &actor);
    let (posture, approval) = match resolved_posture {
        Some((posture, approval)) => (Some(posture), approval),
        None => (None, busbar_unit_verbs::ApprovalState::NotYetApproved),
    };

    match verbs.execute(
        verb,
        admin,
        &actor,
        granted,
        request.at,
        posture,
        approval,
        &request.body,
    ) {
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
/// The fallback is a literal rather than the credential for the same reason: a unit refused before
/// the identity was resolved has no actor to name, and saying so is the honest record.
fn actor_of(binding: &AdminBinding, key: UnitKey) -> String {
    binding
        .units
        .principal(key)
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| UNRESOLVED_ACTOR.to_string())
}

/// What an administrative record names when no identity was resolved for the unit.
const UNRESOLVED_ACTOR: &str = "admin";

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
        V::InsufficientApprovers | V::SelfApproval | V::PayloadMismatch | V::ApprovalPending => {
            ReasonCode::HookVeto
        }
        V::OperatorUnset => ReasonCode::ScopeDenied,
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
        return Decision::proceed(token, unresolved_facts(outcome));
    };
    if !resolved.read_only {
        legacy.record_by(
            resolved.verb,
            &request.path,
            outcome_word(outcome),
            &actor_of(binding, ctx.key),
        );
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
    _refusal: &Refusal,
) -> Decision<Audit> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        return Decision::proceed(
            token,
            unresolved_facts(&Outcome::Refused(
                busbar_caps::StepName::Decode,
                ReasonCode::DecodeFailed,
            )),
        );
    };
    if !resolved.read_only {
        legacy.record_by(
            resolved.verb,
            &request.path,
            busbar_unit_audit::OUTCOME_REJECTED,
            &actor_of(binding, ctx.key),
        );
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
/// operation" IS an admin-read answer: the surface was asked a question and said no. Naming a class
/// here rather than leaving one unset is what keeps every sealed end comparable.
pub(crate) fn unresolved_facts(outcome: &Outcome) -> busbar_contract::AuditFacts {
    busbar_contract::AuditFacts {
        op_class: busbar_contract::OpClassId::new("admin_read"),
        finish: finish_of(outcome),
    }
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

/// The node an admin request is answered by.
///
/// Everything a request needs and nothing it does not: the kernel that mints its tokens, the units
/// its steps run against, and the in-flight table its hold lives in. Built once at boot and shared
/// by every request, which is what makes the counts the canary balances node-wide rather than
/// per-request.
#[cfg(feature = "root-admin")]
pub struct AdminNode {
    kernel: busbar_kernel::teller::Kernel,
    units: crate::root::kernel::ProductionUnits,
    inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    canary: busbar_caps::Canary,
    next_key: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "root-admin")]
impl AdminNode {
    /// Compose the node an admin request is answered by.
    #[must_use]
    pub fn new(
        kernel: busbar_kernel::teller::Kernel,
        units: crate::root::kernel::ProductionUnits,
    ) -> Self {
        AdminNode {
            kernel,
            units,
            // The administrative listener is outside the in-flight cap entirely — the design says
            // so, and for the reason the exemption exists: the surface an operator reaches to find
            // out why the node is shedding has to answer while it is shedding. The table is still
            // real, because a hold still has to live somewhere.
            inflight: busbar_kernel::inflight::InFlight::new(0, 0),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
            next_key: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Walk one admin request through the loop and answer with what it produced.
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a request that used
    /// to reach its handler directly. What comes back is what the operation's own surface answered:
    /// this function chooses the PATH, never the bytes.
    pub fn answer(&self, request: AdminRequest) -> AdminAnswer {
        let key = UnitKey::new(
            self.next_key
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        self.units.admin.units.open(key, request);

        let arrival = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &self.units.arrival_door,
            PrincipalId::new("admin"),
        );
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            admin_listener: true,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival,
            now: busbar_substrate::store::now_ms(),
        });

        let answer = match entered {
            // The table is uncapped for this listener, so this arm is the table declining for a
            // reason that is not capacity. It is still an answer rather than a panic.
            Err(_refused) => unavailable_answer(),
            Ok(slot) => {
                let ctx = UnitCtx {
                    key,
                    origin: busbar_caps::OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: true,
                    // An admin unit's whole verified set is a kernel verb, which is what exempts it
                    // from the concurrency gauge — and what makes the admin API answer at a
                    // saturated cap.
                    kernel_verb_only: true,
                };
                let mut leases = busbar_kernel::slice::LeaseSet::new();
                let meter = busbar_kernel::teller::AccrualMeter::new();
                let ended = busbar_kernel::teller::run_unit(
                    &self.kernel,
                    &self.units,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: &mut leases,
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                    },
                );
                self.inflight.remove(key);
                // The loop ran; the answer is whatever Route put there. A unit refused before Route
                // has none, and the refusal it ended on is what the surface renders.
                self.units
                    .admin
                    .units
                    .answer(key)
                    .unwrap_or_else(|| refused_answer(&ended))
            }
        };

        // Close last, whatever happened. An entry that outlived its unit is the leak per request
        // this root may not have.
        let _ = self.units.admin.units.close(key);
        answer
    }
}

/// What a unit that never reached Route answers with.
///
/// The plane's own error envelope, which is the previous release's: the caller is the same caller
/// and the shape is pinned. What is NOT pinned to one value is the status — the surface has ten of
/// them and the loop knows which one this unit earned, so the ending is read rather than replaced
/// by a single word.
#[cfg(feature = "root-admin")]
fn refused_answer(ended: &busbar_kernel::teller::Ended) -> AdminAnswer {
    match ended {
        busbar_kernel::teller::Ended::Settled { end, .. } => answer_for(end.outcome()),
        // The node's own sweep took the hold first, which means this unit is not going to produce an
        // answer at all. That is the node being unable to serve the request, not the caller being
        // told no.
        busbar_kernel::teller::Ended::AlreadySettled => unavailable_answer(),
    }
}

/// The surface's answer for one ending.
///
/// The vocabulary is the previous release's admin envelope and nothing here invents a status: each
/// arm is a reason the loop can end on paired with the status that release already gave the same
/// condition. `forbidden` stays the answer for the two authorization endings AND for an ending this
/// table does not name, so an ending nobody has mapped cannot quietly become a new status on a
/// surface a caller has pinned.
#[cfg(feature = "root-admin")]
fn answer_for(outcome: Outcome) -> AdminAnswer {
    let (status, code) = match outcome {
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => match reason {
            // A body or a verb the plane could not read is a bad request, not a denied one.
            ReasonCode::DecodeFailed => (400, "invalid_request"),
            // Nothing on this surface answers that method and path.
            ReasonCode::NoDestination => (404, "not_found"),
            // The caller is inside its rights and the node is over a limit.
            ReasonCode::OverBudget | ReasonCode::InFlightCap => (429, "rate_limited"),
            // The node cannot record what the operation would do, so it does not do it. An
            // administrative write that cannot be journalled is unavailability, not refusal.
            ReasonCode::DurabilityUnavailable | ReasonCode::StaleSlice => (503, "unavailable"),
            _ => (403, "forbidden"),
        },
        _ => (403, "forbidden"),
    };
    error_answer(status, code)
}

/// One error answer in the surface's envelope.
///
/// The single construction site, so a status and its code cannot be paired differently in two
/// places — which is the shape the previous release's own admin error rendering has.
#[cfg(feature = "root-admin")]
fn error_answer(status: u16, code: &str) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: format!(r#"{{"error":{{"code":"{code}","message":"{code}"}}}}"#).into_bytes(),
    }
}

/// What a node that cannot take the unit at all answers with.
#[cfg(feature = "root-admin")]
fn unavailable_answer() -> AdminAnswer {
    AdminAnswer {
        status: 503,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: br#"{"error":{"code":"unavailable","message":"unavailable"}}"#.to_vec(),
    }
}

/// The dispatch that hands an operation to the surface that already answers it.
///
/// The seam's production half, and deliberately the thinnest thing in the file: it rebuilds the
/// request the caller sent, hands it to the router the operation is mounted on, and returns that
/// router's whole response. No status is computed here, no header is added and no body is touched —
/// and that is the property the oracle measures.
/// One operation, handed across the boundary between the loop and the runtime.
///
/// The request goes one way and the answer comes back the other, on a channel the caller owns. The
/// pair travels together so the async side never has to know which of several outstanding calls it
/// is answering.
#[cfg(feature = "root-admin")]
type Errand = (AdminRequest, std::sync::mpsc::SyncSender<AdminAnswer>);

#[cfg(feature = "root-admin")]
pub struct RouterDispatch {
    errands: tokio::sync::mpsc::UnboundedSender<Errand>,
}

#[cfg(feature = "root-admin")]
impl RouterDispatch {
    /// Bind the seam to a mounted router, and start the task that drives it.
    ///
    /// **Why a channel and not `Handle::block_on`.** The loop is synchronous and runs on a blocking
    /// worker; the router is asynchronous. Blocking on a runtime handle from inside a blocking
    /// worker is legal on some runtime flavours and a panic on others, which makes it a thing that
    /// works until the deployment's shape changes — a single-worker node panicked on the exact call
    /// a multi-worker node served. A channel is flavour-independent: the blocking side waits on a
    /// standard-library receiver, which knows nothing about runtimes, and the async side is an
    /// ordinary task. The seam is the same seam; only the way it is crossed stopped depending on
    /// how the node was configured.
    #[must_use]
    pub fn new(inner: axum::Router, runtime: &tokio::runtime::Handle) -> Self {
        let (errands, mut inbox) = tokio::sync::mpsc::unbounded_channel::<Errand>();
        runtime.spawn(async move {
            while let Some((request, reply)) = inbox.recv().await {
                let inner = inner.clone();
                // One task per operation, so a slow verb cannot hold up the one behind it — the
                // surface was concurrent before the switch and stays concurrent through it.
                tokio::spawn(async move {
                    let _ = reply.send(call(inner, &request).await);
                });
            }
        });
        RouterDispatch { errands }
    }
}

/// Hand one request to the router and take its whole answer.
#[cfg(feature = "root-admin")]
async fn call(inner: axum::Router, request: &AdminRequest) -> AdminAnswer {
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder()
        .method(request.method.as_str())
        .uri(request.path.as_str());
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let Ok(http) = builder.body(axum::body::Body::from(request.body.clone())) else {
        // A method, path or header the http types themselves will not carry. That is a request
        // this surface cannot make sense of, which is the 400 answer and not the 403 one: nothing
        // here was denied, it was unreadable.
        return error_answer(400, "invalid_request");
    };

    // The router's own error type is uninhabited: a mounted axum router answers, and failing is not
    // among the things it can do. So there is no error arm to write here, and writing one anyway
    // would be a branch that can never be taken pretending to be a fallback that could be.
    let response = inner.oneshot(http).await.unwrap_or_else(|e| match e {});
    let (parts, body) = response.into_parts();
    // The surface answered and its body did not come back. Serving the status with an EMPTY body
    // was the worst of the available answers: a 200 whose document is missing reads, to every
    // client and every operator dashboard, as an operation that succeeded and returned nothing.
    // The node could not produce the answer, and that is what it says.
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return unavailable_answer();
    };
    AdminAnswer {
        status: parts.status.as_u16(),
        headers: header_pairs(&parts.headers),
        body: bytes.to_vec(),
    }
}

#[cfg(feature = "root-admin")]
impl AdminDispatch for RouterDispatch {
    fn execute(&self, _verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        if self.errands.send((request.clone(), reply)).is_err() {
            // The driving task is gone, which happens only as the node itself goes away. There is
            // no surface left to ask, and saying so is the only answer left.
            return unavailable_answer();
        }
        answer.recv().unwrap_or_else(|_| unavailable_answer())
    }
}

/// Header names and values as owned pairs, in emission order.
///
/// A header value is bytes rather than text, and this is the one place that matters: rendering it
/// lossily here would change a byte the oracle compares. Everything the admin surface emits is
/// ASCII, so the conversion is exact — and it is written as a conversion rather than an assumption
/// so that a value which was not would be visible rather than silent.
#[cfg(feature = "root-admin")]
fn header_pairs(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// One answer as the response this listener writes.
///
/// Written once because two paths reach it: the request that ran and the one this wrap refused
/// before the loop was entered. A second builder would be a second chance for the two to differ.
#[cfg(feature = "root-admin")]
fn http_response(answer: AdminAnswer) -> axum::http::Response<axum::body::Body> {
    let mut response = axum::http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        response = response.header(name.as_str(), value.as_str());
    }
    response
        .body(axum::body::Body::from(answer.body))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .expect("an empty 500 always builds")
        })
}

/// Wrap a mounted admin surface so every request on it travels through the kernel.
///
/// The router that goes in is the one that already answers; the router that comes out answers the
/// same operations through the loop. The seam between them is [`RouterDispatch`], so the inner
/// router remains the only thing that knows what any of these operations do.
///
/// The loop is synchronous and the router is not, so the walk runs on a blocking worker and the one
/// await inside it — the inner router's own — is driven on the runtime this was handed. That is the
/// honest ordering: Route drives the seam, the seam drives the surface, and the answer comes back
/// through the steps that are still to run.
///
/// `request_body_max_bytes` is the operator's own ingress cap, the same figure the mounted router's
/// body limit was built with. It is a parameter rather than a constant because this wrap reads the
/// body BEFORE that limit gets a chance to: a cap written down twice is a cap that can differ, and
/// the one that matters is the one the deployment configured.
#[cfg(feature = "root-admin")]
pub fn mount(
    inner: axum::Router,
    kernel: busbar_kernel::teller::Kernel,
    request_body_max_bytes: usize,
    build_units: impl FnOnce(Arc<dyn AdminDispatch>) -> crate::root::kernel::ProductionUnits,
) -> axum::Router {
    let runtime = tokio::runtime::Handle::current();
    // THIS COMPOSITION HAS AN EXIT PATH, so the one operation whose effect outlives its own
    // response — the restart — hands that effect to it instead of starting it mid-flight. Declared
    // here because this is where the loop is put in front of the surface: the operation's own
    // surface is unchanged and does not know which composition it is answering under.
    busbar_core::admin::restart::drain_released_at_exit();
    let dispatch: Arc<dyn AdminDispatch> = Arc::new(RouterDispatch::new(inner.clone(), &runtime));
    let node = Arc::new(AdminNode::new(kernel, build_units(dispatch)));

    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let node = Arc::clone(&node);
            let inner = inner.clone();
            async move {
                use tower::ServiceExt;

                // THE CLAIM IS WHAT DECIDES. The admin plane claims one path pattern and nothing
                // else, and this listener carries routes that are deliberately outside it: the
                // health probe answers on both listeners with the auth chain bypassed entirely, and
                // it is not an administrative verb. Walking those through a loop whose decode step
                // reads a table they were never in would refuse a route that has always answered.
                // So the claim is asked first, and a path outside it goes straight to the surface it
                // already reached.
                let path = req.uri().path().to_string();
                let claimed = path.starts_with(busbar_contract::surface::ADMIN_PREFIX);

                // AND THE TABLE IS WHAT DECIDES WHICH UNIT. Inside the claim, the plane declares a
                // closed table of operations, and a method-and-path pair outside it is not a unit
                // this plane has — it is a request the surface's own fallback already answers, with
                // the 404 or the 405 that release pinned. Manufacturing a status here for a pair
                // this plane never claimed would be the root inventing an answer it has no basis
                // for, and the whole point of the seam is that it never does that.
                let declared =
                    busbar_plane_admin::verbs::resolve(req.method().as_str(), &path).is_some();
                if !claimed || !declared {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                // A BODY BIGGER THAN THE OPERATOR'S CAP IS NOT THIS WRAP'S TO ANSWER. The mounted
                // surface carries that cap and the answer release pinned for exceeding it, and
                // this wrap reads the body first — so a request that DECLARES more than the cap
                // goes straight there rather than being buffered into this node's memory on the
                // way to being rejected anyway.
                let declared = req
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok());
                if declared.is_some_and(|len| len > request_body_max_bytes) {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                let (parts, body) = req.into_parts();
                // AND A BODY THAT COULD NOT BE READ IS NOT AN EMPTY ONE. Read to the same cap, so
                // an undeclared length cannot buffer without bound either; and where the read does
                // not finish, the request is refused. It used to become an empty body — which a
                // mutating verb would go on to execute, with whatever an empty document means to
                // it, on a request the caller never finished sending.
                let Ok(bytes) = axum::body::to_bytes(body, request_body_max_bytes).await else {
                    return http_response(error_answer(400, "invalid_request"));
                };
                let request = AdminRequest {
                    method: parts.method.as_str().to_string(),
                    path: parts
                        .uri
                        .path_and_query()
                        .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
                    credential: parts
                        .headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.trim_start_matches("Bearer ").to_string()),
                    headers: header_pairs(&parts.headers),
                    body: bytes.to_vec(),
                    at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                };
                let answer = tokio::task::spawn_blocking(move || node.answer(request))
                    .await
                    .unwrap_or_else(|_| unavailable_answer());

                let response = http_response(answer);

                // THE END OF THE EXIT PATH: whatever this unit asked to outlive its response is
                // released HERE, with the response built and handed back and nothing left that can
                // change a byte of it. For the one operation that asks — the restart — that is the
                // graceful drain, which the surface used to begin from inside its own handler. It
                // still begins at the same point relative to the answer; what moved is the steps
                // that now sit between the handler and this line, and they no longer sit between
                // the drain and the write. Every other unit releases nothing, which costs one
                // atomic read.
                busbar_core::admin::restart::release_asked_drain();
                response
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The legacy ring binds no clock of its own; a pinned one keeps records comparable.
    #[derive(Debug)]
    struct PinnedClock;
    impl busbar_unit_audit::Clock for PinnedClock {
        fn now(&self) -> u64 {
            1_700_000_000
        }
    }

    fn a_request() -> AdminRequest {
        AdminRequest {
            method: "GET".to_string(),
            path: "/api/v1/admin/audit?limit=4".to_string(),
            credential: Some("admin-token".to_string()),
            headers: vec![("accept".to_string(), "application/json".to_string())],
            body: Vec::new(),
            at: 1_700_000_000,
        }
    }

    /// The round trip is the whole reason the answer travels as bytes: a status, a header value and
    /// a body all come back exactly as they went in, including bytes a text framing would mangle.
    #[test]
    fn an_answer_survives_the_round_trip_through_the_verbs_seam() {
        let answer = AdminAnswer {
            status: 409,
            headers: vec![
                ("etag".to_string(), "\"7\"".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            body: vec![0x00, 0xff, b'{', b'}', 0x0a],
        };
        let packed = answer.pack();
        assert_eq!(AdminAnswer::unpack(&packed), Some(answer));
    }

    /// A body this wrap cannot read is refused, and one too big for the operator's cap is not read
    /// here at all.
    ///
    /// Both used to end in the same place: an empty body, handed to whichever mutating verb the
    /// path named, which then executed whatever an empty document means to it on a request the
    /// caller never finished sending. And the read was unbounded, so the cap the deployment
    /// configured was applied by a layer this wrap had already buffered past.
    #[cfg(feature = "root-admin")]
    #[tokio::test]
    async fn a_body_the_wrap_will_not_read_is_refused_rather_than_emptied() {
        use tower::ServiceExt;

        let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
        let wrapped = mount(
            inner,
            busbar_kernel::teller::Kernel::new(),
            4,
            crate::root::kernel::ProductionUnits::admin_only,
        );

        // Longer than the cap and no declared length: the read stops at the cap and the request is
        // refused, rather than becoming a document nobody sent.
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/admin/keys")
            .body(axum::body::Body::from(b"0123456789".to_vec()))
            .expect("the request builds");
        let response = wrapped
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), 400);

        // A declared length past the cap is the mounted surface's own answer to give, and this wrap
        // does not buffer the body to find that out.
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/admin/keys")
            .header(axum::http::header::CONTENT_LENGTH, "10")
            .body(axum::body::Body::from(b"0123456789".to_vec()))
            .expect("the request builds");
        let response = wrapped.oneshot(request).await.expect("the router answers");
        assert_eq!(
            response.status(),
            200,
            "the request reached the surface below, which is where the cap is enforced"
        );
    }

    /// A unit that reached no answer is rendered under the status its ending earned.
    ///
    /// One 403 for every ending told an operator that a journal it could not write, a body it could
    /// not read and a scope it did not hold were the same thing, and told a client that a request
    /// worth retrying was one that never would be. The two authorization endings keep the answer
    /// they had, and so does an ending this table does not name.
    #[cfg(feature = "root-admin")]
    #[test]
    fn a_refused_units_status_is_the_one_its_ending_earned() {
        let status = |reason| answer_for(Outcome::Refused(busbar_caps::StepName::Admit, reason));
        assert_eq!(status(ReasonCode::DecodeFailed).status, 400);
        assert_eq!(status(ReasonCode::NoDestination).status, 404);
        assert_eq!(status(ReasonCode::InFlightCap).status, 429);
        assert_eq!(status(ReasonCode::OverBudget).status, 429);
        assert_eq!(status(ReasonCode::DurabilityUnavailable).status, 503);
        assert_eq!(status(ReasonCode::ScopeDenied).status, 403);
        assert_eq!(status(ReasonCode::Unauthenticated).status, 403);
        assert_eq!(
            status(ReasonCode::PlanePanic).status,
            403,
            "an ending nobody mapped keeps the pinned answer rather than inventing one"
        );

        // A failure past the door renders the same way a refusal before it does: what the caller is
        // owed is the reason, and the side of the door it happened on is not the caller's business.
        assert_eq!(
            answer_for(Outcome::Failed(
                busbar_caps::StepName::Route,
                ReasonCode::DurabilityUnavailable
            )),
            error_answer(503, "unavailable")
        );

        // And the envelope is the surface's, whatever the status.
        assert_eq!(
            status(ReasonCode::NoDestination).body,
            br#"{"error":{"code":"not_found","message":"not_found"}}"#.to_vec()
        );
        assert_eq!(
            status(ReasonCode::NoDestination).headers,
            vec![("content-type".to_string(), "application/json".to_string())]
        );
    }

    /// The only producer of the framing is the packer. Anything else is this file being wrong, and
    /// a lenient parse would turn that into a silently wrong answer.
    #[test]
    fn a_shape_the_packer_did_not_write_has_no_answer() {
        assert_eq!(AdminAnswer::unpack(&[]), None);
        assert_eq!(AdminAnswer::unpack(&[0, 200, 0, 0, 0, 1]), None);
        let mut trailing = AdminAnswer {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        }
        .pack();
        trailing.push(0);
        assert_eq!(AdminAnswer::unpack(&trailing), None);
    }

    /// A count is a claim about bytes that are not there, not an instruction to go and find room
    /// for them. The frame below says it carries four billion headers in three bytes: the answer is
    /// `None`, and no room is made for the claim on the way to it.
    #[test]
    fn a_header_count_larger_than_the_frame_is_refused_not_reserved() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&200u16.to_be_bytes());
        frame.extend_from_slice(&u32::MAX.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0]);
        assert_eq!(AdminAnswer::unpack(&frame), None);

        // What the frame could actually be carrying, not what it says it is.
        assert_eq!(header_capacity(u32::MAX, 3), 0);
        assert_eq!(header_capacity(u32::MAX, 4_096), 512);
        // An honest count is still reserved for in full.
        assert_eq!(header_capacity(2, 4_096), 2);
    }

    /// A mutation's record names the caller, and never the bytes the caller presented.
    ///
    /// Both doors are walked, because both write a row and either one leaking is the whole leak: the
    /// completed mutation and the refused one. The credential in the fixture is deliberately not a
    /// substring of the identity, so "the row does not contain the credential" and "the row is the
    /// identity" are two independent assertions rather than one restated.
    ///
    /// The chain this writes to is the one an operator's audit page reads and a store persists, so a
    /// row carrying a live bearer token publishes it to everybody entitled to read history — a wider
    /// set than the set entitled to hold the token.
    #[test]
    fn a_recorded_mutation_names_the_principal_and_not_the_credential() {
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let binding = AdminBinding::new(Arc::new(RefusingDispatch));

        let rows = |completed: bool| -> Vec<busbar_unit_audit::legacy::AuditEntry> {
            let log = busbar_unit_audit::AuditLog::with(
                Box::new(PinnedClock),
                Box::new(busbar_unit_audit::NoSeam),
            );
            let key = UnitKey::new(1);
            let mut request = a_request();
            request.method = "PUT".to_string();
            request.path = "/api/v1/admin/config/settings".to_string();
            request.credential = Some("sk-live-the-presented-secret".to_string());
            binding.units.open(key, request);
            let ctx = UnitCtx {
                key,
                origin: busbar_caps::OriginKind::Client,
                session: None,
                generation: busbar_kernel::registry::Generation::FIRST,
                admin_listener: true,
                kernel_verb_only: true,
            };
            let decode_token: UnitToken<Decode> = UnitToken::mint(&seal);
            let _ = decode(&binding, &decode_token, &ctx).into_result(&seal);
            let verify_token: UnitToken<Verify> = UnitToken::mint(&seal);
            let _ = verify(
                &binding,
                &verify_token,
                &ctx,
                &PrincipalId::new("key_operator_7"),
            )
            .into_result(&seal);

            let audit_token: UnitToken<Audit> = UnitToken::mint(&seal);
            if completed {
                let _ = audit(&binding, &log, &audit_token, &ctx, &Outcome::Completed)
                    .into_result(&seal);
            } else {
                let _ = audit_refused(
                    &binding,
                    &log,
                    &audit_token,
                    &ctx,
                    &Refusal::new(ReasonCode::ScopeDenied),
                )
                .into_result(&seal);
            }
            binding.units.close(key);
            log.export()
        };

        for completed in [true, false] {
            let entries = rows(completed);
            assert_eq!(entries.len(), 1, "the mutation was not recorded");
            assert_eq!(
                entries[0].principal, "key_operator_7",
                "the record does not name the identity the auth step resolved"
            );
            assert!(
                !entries[0]
                    .principal
                    .contains("sk-live-the-presented-secret"),
                "the presented credential reached the administrative chain"
            );
        }
    }

    /// The two money-governance gates are the fleet's, and the route step reads them rather than
    /// writing them.
    ///
    /// Three postures over the same step, and each one is a different failure if the seam is not
    /// consulted. Under a fleet that sealed dual control, one principal's export is REFUSED — a step
    /// that wrote `approved` for itself would let a single operator take the keyset out of a node
    /// whose whole reason for sealing the posture was that no single operator can. Under a fleet that
    /// HAS run the ceremony, a disaster-recovery verb is ADMITTED — a step that wrote `unset` for
    /// itself refused the very operators who ran the ceremony, permanently and with no way to lift
    /// it. And a posture the node cannot read at all is refused rather than guessed.
    #[test]
    #[cfg(feature = "root-admin")]
    fn a_money_governance_verb_is_checked_against_the_posture_the_fleet_sealed() {
        struct Sealed(Option<(PostureCtx, ApprovalState)>);
        impl PostureView for Sealed {
            fn resolve(
                &self,
                _verb: KernelVerb,
                _actor: &str,
            ) -> Option<(PostureCtx, ApprovalState)> {
                self.0
            }
        }

        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let admin = crate::root::kernel::new_kernel().admin_token();

        let under = |path: &str, sealed: Sealed| -> Result<(), ReasonCode> {
            let binding =
                AdminBinding::new(Arc::new(AnsweringDispatch)).with_posture_view(Arc::new(sealed));
            let key = UnitKey::new(1);
            let mut request = a_request();
            request.method = "POST".to_string();
            request.path = path.to_string();
            binding.units.open(key, request);
            let ctx = UnitCtx {
                key,
                origin: busbar_caps::OriginKind::Client,
                session: None,
                generation: busbar_kernel::registry::Generation::FIRST,
                admin_listener: true,
                kernel_verb_only: true,
            };
            let decode_token: UnitToken<Decode> = UnitToken::mint(&seal);
            decode(&binding, &decode_token, &ctx)
                .into_result(&seal)
                .expect("the plane's table declares this operation");
            binding.units.set_granted(key, VerbScope::Full);
            let token: UnitToken<Route> = UnitToken::mint(&seal);
            let outcome = route(
                &binding,
                Arc::new(RefusingStore),
                &admin,
                &token,
                &ctx,
                &busbar_kernel::teller::AccrualMeter::new(),
            )
            .into_result(&seal);
            binding.units.close(key);
            outcome.map(|_| ()).map_err(|refusal| refusal.reason())
        };

        let required = Sealed(Some((
            PostureCtx {
                operator: busbar_unit_verbs::OperatorState::Unset,
                dual_control: busbar_unit_verbs::DualControl::Required,
            },
            ApprovalState::NotYetApproved,
        )));
        assert!(
            under("/api/v1/admin/export-keyset", required).is_err(),
            "one principal exported the keyset out of a fleet that sealed dual control"
        );

        let ceremony_run = Sealed(Some((
            PostureCtx {
                operator: busbar_unit_verbs::OperatorState::Set,
                dual_control: busbar_unit_verbs::DualControl::Single,
            },
            ApprovalState::NotYetApproved,
        )));
        assert_eq!(
            under("/api/v1/admin/chain-break", ceremony_run),
            Ok(()),
            "a fleet that ran the ceremony was still refused for not having run it"
        );

        assert_eq!(
            under("/api/v1/admin/adjust", Sealed(None)),
            Err(ReasonCode::DecodeFailed),
            "a verb whose posture the node cannot read was admitted under a guessed one"
        );
    }

    /// The posture a node with no sealed journal is in is the one the design names for a fresh
    /// install, and it is that node's TRUE state rather than a permissive default: the ceremony has
    /// not run, so the irreducible verbs that need one are still refused.
    #[test]
    fn an_unsealed_node_reports_the_posture_a_fresh_install_is_actually_in() {
        let (posture, approval) = UnsealedPosture
            .resolve(KernelVerb::Adjust, "admin")
            .expect("a node with no journal knows what it has not sealed");
        assert_eq!(posture.operator, busbar_unit_verbs::OperatorState::Unset);
        assert_eq!(posture.dual_control, busbar_unit_verbs::DualControl::Single);
        assert_eq!(approval, ApprovalState::NotYetApproved);
    }

    /// Both tables were extracted from the same pinned tag. Every row the plane decodes to has to
    /// name a verb the executing unit knows, or the root would be binding an operation to nothing.
    #[test]
    fn every_row_the_plane_decodes_names_a_verb_the_unit_knows() {
        let mut unmatched = Vec::new();
        for row in busbar_plane_admin::verbs::table() {
            if kernel_verb(&row).is_none() {
                unmatched.push(row.verb);
            }
        }
        assert!(
            unmatched.is_empty(),
            "rows with no kernel verb: {unmatched:?}"
        );
    }

    /// The 66 join on method and path — the columns the pinned document fixed — and all 66 of them
    /// do. A row that fell through to the name join would be a legacy operation matched on a casing
    /// convention rather than on what the tag actually pinned.
    #[test]
    fn all_sixty_six_legacy_rows_join_on_the_pinned_method_and_path() {
        let joined = busbar_plane_admin::verbs::table()
            .iter()
            .filter(|row| {
                LEGACY_VERBS
                    .iter()
                    .any(|legacy| legacy.method == row.method && legacy.path == row.template)
            })
            .count();
        assert_eq!(joined, 66);
    }

    /// The two spellings of one operation's name really are two spellings, and the join does not
    /// depend on either of them. This is the finding that made the join what it is, kept as a test
    /// so that a future crate quietly agreeing on one casing does not look like a fix.
    #[test]
    fn the_two_tables_spell_one_operations_name_two_ways() {
        let audit = busbar_plane_admin::verbs::resolve("GET", "/api/v1/admin/audit")
            .expect("audit is in the plane's table");
        let row = LEGACY_VERBS
            .iter()
            .find(|row| row.method == "GET" && row.path == "/api/v1/admin/audit")
            .expect("audit is in the unit's table");
        assert_eq!(audit.verb, "get_audit");
        assert_eq!(row.operation_id, "GetAudit");
        assert_eq!(kernel_verb(&audit), Some(KernelVerb::GetAudit));
    }

    /// The rate class comes off the shipped table, not off the blast-radius-blind default: a config
    /// mutation is limited at the config budget and an ordinary read is forbidden from mutating at
    /// all.
    #[test]
    fn the_rate_class_is_the_shipped_table_and_not_the_default() {
        assert_eq!(
            mutation_class(KernelVerb::PostConfigApply),
            MutationClass::Config
        );
        assert_eq!(
            mutation_class(KernelVerb::PostConfigReload),
            MutationClass::Config
        );
        assert_eq!(
            mutation_class(KernelVerb::PostRestart),
            MutationClass::Config
        );
        assert_eq!(
            mutation_class(KernelVerb::PutAdminAuth),
            MutationClass::Config
        );
        assert_eq!(mutation_class(KernelVerb::PostKeys), MutationClass::Crud);
        assert_eq!(
            mutation_class(KernelVerb::PostPluginsInspect),
            MutationClass::PluginInspect
        );
        // `Forbidden` names a verb the MUTATION budget does not apply to — every read is one. It is
        // not a refusal, and an admit step that read it as one turned every read on the surface into
        // a 403. That is the hazard a vocabulary shared between two crates invites, so the reading
        // is pinned here rather than left to the name.
        assert_eq!(
            mutation_class(KernelVerb::GetAudit),
            MutationClass::Forbidden
        );
        assert_eq!(MutationClass::Forbidden.limit(), 0);
        assert!(
            busbar_unit_scope::admin_required_scope("GET", "/api/v1/admin/audit")
                == Scope::ReadOnly
        );
    }

    /// The two spellings of the two-rung split are one split. If they ever stopped agreeing, a
    /// read-only credential would be admitted to a mutation or a full one refused a read.
    #[test]
    fn the_two_spellings_of_the_scope_split_agree() {
        assert_eq!(scope_as_verb_scope(Scope::ReadOnly), VerbScope::ReadOnly);
        assert_eq!(scope_as_verb_scope(Scope::Full), VerbScope::Full);
        assert!(VerbScope::Full.allows(VerbScope::ReadOnly));
        assert!(!VerbScope::ReadOnly.allows(VerbScope::Full));
    }

    /// An entry that outlived its unit would be a leak per request. Opening and closing is the whole
    /// lifecycle, and the table is empty between requests.
    #[test]
    fn a_unit_leaves_the_table_when_it_ends() {
        let units = AdminUnits::new();
        let key = UnitKey::new(7);
        assert!(units.is_empty());
        units.open(key, a_request());
        assert_eq!(units.len(), 1);
        assert_eq!(
            units.request(key).map(|r| r.method),
            Some("GET".to_string())
        );
        assert_eq!(units.close(key), None);
        assert!(units.is_empty());
    }

    /// What the exit path settles for an admin unit: nothing located, no upstream candidate, and
    /// therefore no request slot and no flat fee, whatever the deployment configured the fee to be.
    #[test]
    fn an_admin_unit_settles_at_zero_requests_and_zero_fee() {
        let ctx = UnitCtx {
            key: UnitKey::new(1),
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        let evidence = evidence(&ctx);
        assert!(!evidence.upstream_candidate);
        assert_eq!(
            busbar_kernel::teller::requests_drawn(ctx.origin, evidence.upstream_candidate),
            0
        );
        assert_eq!(busbar_kernel::teller::fee_count(&evidence.fee).0, 0);
    }

    /// The nonce is drawn, not derived. Two draws over the same unit must not agree, or a one-time
    /// secret's placeholder would be predictable from the secret it protects.
    #[test]
    fn two_nonces_over_one_unit_do_not_agree() {
        use busbar_unit_verbs::NonceSource;
        let source = ArrivalNonce(1_700_000_000);
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        source.fill(&mut first);
        source.fill(&mut second);
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 16]);
    }

    /// Both halves of the nonce are drawn, and the second is not the first said again.
    ///
    /// The source it replaced hashed a stack address — the same address on every call from the same
    /// frame — and then hashed its own first output to make the second half, so a 128-bit nonce
    /// carried at most 64 bits of source and the back half was a function of the front. This walks
    /// enough draws that either half repeating, or the two halves agreeing, would show.
    ///
    /// What this cannot assert is unpredictability, which is a property of the SOURCE and not of any
    /// finite sample: it is held by reaching the substrate's own operating-system draw — the one a
    /// key secret is minted from — rather than by anything checkable here.
    #[test]
    fn both_halves_of_a_nonce_are_drawn_and_neither_repeats() {
        use busbar_unit_verbs::NonceSource;
        use std::collections::HashSet;

        let source = ArrivalNonce(1_700_000_000);
        let mut fronts = HashSet::new();
        let mut backs = HashSet::new();
        for _ in 0..512 {
            let mut drawn = [0u8; 16];
            source.fill(&mut drawn);
            assert_ne!(drawn, [0u8; 16], "the source handed back nothing");
            assert_ne!(
                drawn[..8],
                drawn[8..],
                "the two halves of one nonce agree, so one of them is the other"
            );
            fronts.insert(drawn[..8].to_vec());
            backs.insert(drawn[8..].to_vec());
        }
        assert_eq!(fronts.len(), 512, "a front half repeated across draws");
        assert_eq!(backs.len(), 512, "a back half repeated across draws");
    }

    /// The other half of the nonce, and the half a random draw cannot be asserted about: the arrival
    /// epoch is what makes two units' nonces distinct, so a source that handed two units the same
    /// bytes still cannot make them collide. It touches the first eight bytes and leaves the rest of
    /// the material alone, which is what keeps the entropy the entropy.
    #[test]
    fn the_arrival_epoch_is_what_makes_two_units_nonces_distinct() {
        let material = [7u8; 16];
        assert_ne!(
            mix_arrival(material, 1_700_000_000),
            mix_arrival(material, 1_700_000_001)
        );
        assert_ne!(mix_arrival(material, 1_700_000_000), material);
        assert_eq!(mix_arrival(material, 0), material);
        assert_eq!(mix_arrival(material, u64::MAX)[8..], material[8..]);
    }

    /// Route is the one place that chooses between the unit's general execution path and its two
    /// dedicated minting methods, and the choice is exactly the two credential-minting verbs. Every
    /// other verb on the keys surface — reading them, revoking one, listing a key's usage — goes
    /// through the general path, because none of them mints an identity.
    #[test]
    fn only_the_two_minting_verbs_are_reached_through_the_seam_directly() {
        assert!(mints_its_own_identity(KernelVerb::PostKeys));
        assert!(mints_its_own_identity(KernelVerb::PostKeysIdRotate));
        for verb in [
            KernelVerb::GetKeys,
            KernelVerb::GetKeysId,
            KernelVerb::PatchKeysId,
            KernelVerb::DeleteKeysId,
            KernelVerb::PostKeysIdRevoke,
            KernelVerb::GetKeysIdUsage,
            KernelVerb::PostSigningKeyRotate,
            KernelVerb::GetAudit,
        ] {
            assert!(
                !mints_its_own_identity(verb),
                "{verb:?} mints nothing and belongs on the general path"
            );
        }
    }

    /// A store that holds one replay slot, so the root's own adapter can be driven over it.
    #[derive(Default)]
    struct ReplaySlots(Mutex<HashMap<(String, String), Vec<u8>>>);

    impl busbar_unit_verbs::store::Store for ReplaySlots {
        fn chain_break(
            &self,
            _admin: &busbar_caps::AdminToken,
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            Ok(())
        }

        fn store_restore(
            &self,
            _admin: &busbar_caps::AdminToken,
            _backup_ref: &str,
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            Ok(())
        }

        fn reseal_epoch_floor(
            &self,
            _admin: &busbar_caps::AdminToken,
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            Ok(())
        }

        fn replay_new_verb(
            &self,
            key: &(String, String),
        ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
            Ok(self
                .0
                .lock()
                .expect("no test panics under this lock")
                .get(key)
                .cloned())
        }

        fn commit_new_verb_replay(
            &self,
            key: &(String, String),
            response: &[u8],
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            self.0
                .lock()
                .expect("no test panics under this lock")
                .insert(key.clone(), response.to_vec());
            Ok(())
        }
    }

    /// A replayed idempotency key answers with the FIRST answer's bytes, through the root's own
    /// store adapter and its own packing. Byte-identical is the property: a re-render would mint a
    /// second one-time secret over one identity, and the whole reason the answer travels as opaque
    /// bytes is that there is no decode step here that could.
    #[test]
    fn a_replayed_idempotency_key_answers_the_first_answers_bytes() {
        use busbar_unit_verbs::store::Store;

        let answer = AdminAnswer {
            status: 201,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"id":"vk_1","secret":"once"}"#.to_vec(),
        };
        let first = answer.pack();
        let key = ("idem-1".to_string(), "POST /api/v1/admin/keys".to_string());

        let store = StoreRef(Arc::new(ReplaySlots::default()));
        assert_eq!(
            store.replay_new_verb(&key).expect("the slot reads"),
            None,
            "a key never seen has nothing to replay"
        );
        store
            .commit_new_verb_replay(&key, &first)
            .expect("the slot commits");

        let replayed = store
            .replay_new_verb(&key)
            .expect("the slot reads")
            .expect("a committed key replays");
        assert_eq!(replayed, first);
        assert_eq!(AdminAnswer::unpack(&replayed), Some(answer));
    }

    /// What the replay encoder writes: an identity, and never the secret beside it. The identity is
    /// enough to key a slot and carries nothing a second holder could present.
    #[test]
    fn the_replay_encoder_carries_an_identity_and_never_a_secret() {
        use busbar_unit_verbs::ReplayEncoder;

        let admin = crate::root::kernel::new_kernel().admin_token();
        let outcome = busbar_unit_verbs::MintedKeyOutcome {
            id: "vk_1".to_string(),
            secret: busbar_caps::SecretOnce::mint(&admin, 42, UnitKey::new(1), "body.secret"),
            expires_at: None,
        };
        let bytes = PackedReplay.encode(&outcome);
        assert_eq!(bytes, b"vk_1");
        assert_eq!(
            PackedReplay.encode(&outcome),
            bytes,
            "two encodings of one outcome are one answer"
        );
    }

    /// The dispatch a test drives the loop against: it answers, and its answer is recognisable, so a
    /// step that refused before Route is told apart from one that reached it.
    #[cfg(feature = "root-admin")]
    struct AnsweringDispatch;

    #[cfg(feature = "root-admin")]
    impl AdminDispatch for AnsweringDispatch {
        fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
            AdminAnswer {
                status: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: br#"{"entries":[]}"#.to_vec(),
            }
        }
    }

    /// A directory whose whole opinion is the denylist.
    #[cfg(feature = "root-admin")]
    struct Denylist(bool);

    #[cfg(feature = "root-admin")]
    impl crate::root::auth_bindings::VirtualKeyDirectory for Denylist {
        fn verify(
            &self,
            _credential: &str,
            _now: u64,
            _expected_aud: Option<&str>,
        ) -> Option<crate::root::auth_bindings::KeyFacts> {
            None
        }

        fn revoked(&self, _credential: &str) -> bool {
            self.0
        }
    }

    /// Walk one request through the whole loop against a node whose directory revokes everything, or
    /// nothing.
    #[cfg(feature = "root-admin")]
    fn answer_under_denylist(revoked: bool) -> AdminAnswer {
        let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch))
            .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                Denylist(revoked),
            )));
        AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_request())
    }

    /// A revoked credential is refused on the root leg, and refused BEFORE the operation runs.
    ///
    /// This is the seam the step was handed three absences for: revocation gates new units, an admin
    /// unit is always a new unit, and a set nothing supplies revokes nothing — so an unbound step
    /// would have let a revoked credential through the front door of the administrative surface. The
    /// control is the same request over a directory that revokes nobody, which reaches the operation
    /// and comes back with its answer.
    #[cfg(feature = "root-admin")]
    #[test]
    fn a_revoked_credential_is_refused_before_the_operation_runs() {
        assert_eq!(
            answer_under_denylist(false).status,
            200,
            "a credential on nobody's denylist reaches the operation"
        );
        let refused = answer_under_denylist(true);
        assert_eq!(refused.status, 403);
        assert_eq!(refused, error_answer(403, "forbidden"));
    }

    /// A binding holding one open unit, with the decode step run so the verb is resolved exactly as
    /// the loop resolves it. Returns the binding and the context every later step reads the unit
    /// through, so a cell drives the real steps rather than a table it filled in by hand.
    #[cfg(feature = "root-admin")]
    fn a_bound_unit(request: AdminRequest) -> (AdminBinding, UnitCtx, busbar_caps::KernelSeal) {
        let binding = AdminBinding::new(Arc::new(AnsweringDispatch));
        let key = UnitKey::new(1);
        binding.units.open(key, request);
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        // Decode is what puts the verb in the table. A cell that called `set_verb` itself would be
        // asserting over a row the loop never wrote.
        let _ = decode(&binding, &UnitToken::mint(&seal), &ctx);
        (binding, ctx, seal)
    }

    /// Where an admin unit may go, and what that costs it.
    ///
    /// THE verify STEP, over the loop. The gating contract is that a destination the caller cannot
    /// reach is refused before Admit draws a bucket, and this plane answers it in a shape worth
    /// pinning precisely BECAUSE the admin principal is exempt and full: there is no scope to cap,
    /// so the only destination question left is whether the verb resolved at all — and the step
    /// still refuses, with `NoDestination`, for a path the table never named.
    ///
    /// The other half is the one the money path reads. A resolved verb proceeds with an EMPTY
    /// verified set, and that emptiness is not an oversight: a sealed destination carries a LANE,
    /// the priced axis a charge sits on, and a kernel verb is not dialled and not billed. So the
    /// empty set IS the fact that makes the admin unit draw no request slot and post no fee,
    /// whatever the deployment configured the fee to be. A verify that returned one destination
    /// would put an admin request on the priced axis, and nothing downstream would object.
    #[cfg(feature = "root-admin")]
    #[test]
    fn a_verb_the_table_never_named_has_nowhere_to_go_and_a_resolved_one_has_nowhere_priced() {
        let principal = PrincipalId::new("admin");

        // A path no row names: the unit has nowhere to go at all, and is refused here.
        let mut unknown = a_request();
        unknown.path = "/api/v1/admin/not-a-real-operation".to_string();
        let (binding, ctx, seal) = a_bound_unit(unknown);
        assert!(
            binding.units.verb(ctx.key).is_none(),
            "the fixture must be a path the table never resolved"
        );
        let refusal = verify(&binding, &UnitToken::mint(&seal), &ctx, &principal)
            .into_result(&seal)
            .expect_err("a verb that resolved to nothing has nowhere to go");
        assert_eq!(refusal.reason(), ReasonCode::NoDestination);

        // A real operation: it proceeds, and it proceeds to nowhere PRICED.
        let (binding, ctx, seal) = a_bound_unit(a_request());
        assert!(
            binding.units.verb(ctx.key).is_some(),
            "the fixture must be a path the table did resolve"
        );
        let destinations = verify(&binding, &UnitToken::mint(&seal), &ctx, &principal)
            .into_result(&seal)
            .expect("a resolved verb has somewhere to go");
        assert!(
            destinations.is_empty(),
            "an admin unit that sealed a destination would sit on the priced axis"
        );
    }

    /// One admin unit seals exactly one entry on the chain, and a read seals none.
    ///
    /// THE audit STEP, over the loop. The rig column reads the fresh four-op chain from the outside;
    /// this reads the same chain from the step that writes it, which is where "exactly one" is
    /// actually decided. Three answers, and each is a different way the step could be wrong:
    ///
    /// - a mutating verb appends exactly ONE entry, under the operation's own name and the applied
    ///   outcome — not zero, and not one per step that ran;
    /// - a READ appends none, because the chain is a record of what changed and a listing changed
    ///   nothing. A chain that grew on every GET would bury the mutations an operator came to find;
    /// - a unit refused before Admit still appends one, under the rejected outcome, because the
    ///   attempt happened and a chain that recorded only successes is the one an attacker wants.
    ///
    /// The chain is verified after each, so the entries are linked rather than merely counted.
    #[cfg(feature = "root-admin")]
    #[test]
    fn one_admin_unit_seals_exactly_one_entry_and_a_read_seals_none() {
        let legacy = busbar_unit_audit::AuditLog::with(
            Box::new(PinnedClock),
            Box::new(busbar_unit_audit::NoSeam),
        );

        // A mutation: an operator-key write, on the mutating side of the closed split.
        let mut mutating = a_request();
        mutating.method = "POST".to_string();
        mutating.path = "/api/v1/admin/operator-key".to_string();
        let (binding, ctx, seal) = a_bound_unit(mutating);
        let resolved = binding
            .units
            .verb(ctx.key)
            .expect("the operator-key write is a row the table names");
        assert!(!resolved.read_only, "the fixture must be a mutation");

        let before = legacy.len();
        let _ = audit(
            &binding,
            &legacy,
            &UnitToken::mint(&seal),
            &ctx,
            &Outcome::Completed,
        );
        assert_eq!(legacy.len(), before + 1, "one unit, one entry");
        let entry = legacy.list(1).pop().expect("the entry just sealed");
        assert_eq!(entry.action, resolved.verb);
        assert_eq!(entry.outcome, busbar_unit_audit::OUTCOME_APPLIED);
        // The fixture never ran Verify, so the record names the unresolved actor -- never the
        // credential the request presented, which is a secret and stays out of the chain.
        assert_eq!(entry.principal, UNRESOLVED_ACTOR);
        assert!(!entry.principal.contains("admin-token"));
        assert!(legacy.verify(), "the chain is linked");

        // A read changes nothing and records nothing.
        let (binding, ctx, seal) = a_bound_unit(a_request());
        assert!(
            binding
                .units
                .verb(ctx.key)
                .expect("the audit listing is a row the table names")
                .read_only,
            "the fixture must be a read"
        );
        let before = legacy.len();
        let _ = audit(
            &binding,
            &legacy,
            &UnitToken::mint(&seal),
            &ctx,
            &Outcome::Completed,
        );
        assert_eq!(legacy.len(), before, "a read is not a mutation");

        // A refused mutation is recorded as an attempt, not dropped.
        let mut mutating = a_request();
        mutating.method = "POST".to_string();
        mutating.path = "/api/v1/admin/operator-key".to_string();
        let (binding, ctx, seal) = a_bound_unit(mutating);
        let before = legacy.len();
        let _ = audit_refused(
            &binding,
            &legacy,
            &UnitToken::mint(&seal),
            &ctx,
            &Refusal::new(ReasonCode::OverBudget),
        );
        assert_eq!(legacy.len(), before + 1, "the attempt is on the chain");
        let entry = legacy.list(1).pop().expect("the entry just sealed");
        assert_eq!(entry.outcome, busbar_unit_audit::OUTCOME_REJECTED);
        assert!(legacy.verify(), "the chain is still linked");
    }

    // ── the five ledger views ───────────────────────────────────────────────────────────────────

    /// The day the fixture's postings fall in.
    const A_DAY: u64 = 1_767_225_600;

    /// A ledger with something in it.
    ///
    /// Deliberately not balanced: one row reconciles and one does not, so a test that asserted the
    /// residual is zero would be asserting something about a table of zeros rather than about the
    /// identity. The unbalanced row is short by a known amount, which is the figure the
    /// reconciliation view has to report.
    struct SeededLedger;

    impl SeededLedger {
        /// The row whose two sides disagree, and by how much in micro-units.
        const SHORT_ROW: (&'static str, &'static str, &'static str) = ("key-1", "lane-b", "prov-y");
        const SHORT_BY_MICROS: i64 = 250;
    }

    impl LedgerView for SeededLedger {
        fn ledger_rows(&self) -> crate::root::ledger_identity::LedgerSnapshot {
            use crate::root::ledger_identity::{LedgerRow, RowKey};
            [
                (
                    RowKey::new("key-1", A_DAY, "lane-a", "prov-x"),
                    LedgerRow {
                        priced_nanos: 7_000_000,
                        fee_count: 2,
                    },
                ),
                (
                    RowKey::new(
                        SeededLedger::SHORT_ROW.0,
                        A_DAY,
                        SeededLedger::SHORT_ROW.1,
                        SeededLedger::SHORT_ROW.2,
                    ),
                    LedgerRow {
                        priced_nanos: 1_000_000,
                        fee_count: 1,
                    },
                ),
            ]
            .into_iter()
            .collect()
        }

        fn legacy_rows(&self) -> crate::root::ledger_identity::LegacySnapshot {
            use crate::root::ledger_identity::{LegacyRow, RowKey};
            [
                (
                    RowKey::new("key-1", A_DAY, "lane-a", "prov-x"),
                    LegacyRow {
                        spend_micros: 7_000,
                        billable_requests: 2,
                    },
                ),
                (
                    RowKey::new(
                        SeededLedger::SHORT_ROW.0,
                        A_DAY,
                        SeededLedger::SHORT_ROW.1,
                        SeededLedger::SHORT_ROW.2,
                    ),
                    LegacyRow {
                        // The ledger accounted for 1_000 micro-units against 1_250 drawn, so the
                        // books are short by 250 on this row and by nothing on the other.
                        spend_micros: 1_000 + SeededLedger::SHORT_BY_MICROS,
                        billable_requests: 1,
                    },
                ),
            ]
            .into_iter()
            .collect()
        }

        fn checkpoints(&self) -> Vec<busbar_unit_ledger::checkpoint::Checkpoint> {
            use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

            let mut totals = std::collections::BTreeMap::new();
            totals.insert(
                (
                    TotalsKey::new(
                        BucketId::new("key-1"),
                        CapDimension::NanoUnits,
                        BucketScope::All,
                    ),
                    A_DAY,
                ),
                busbar_unit_ledger::totals::Totals {
                    settled: 8_000,
                    drawn: 8_250,
                    ..busbar_unit_ledger::totals::Totals::zero()
                },
            );
            vec![busbar_unit_ledger::checkpoint::Checkpoint::seal(
                4,
                1,
                1_700_000_000,
                Vec::new(),
                totals,
                0,
                0,
                None,
            )
            .expect("an unsigned seal cannot fail")]
        }

        fn migration_marker(&self) -> Option<busbar_unit_ledger::migration::MigrationMarker> {
            Some(busbar_unit_ledger::migration::MigrationMarker {
                checkpoint_seq: 0,
                node: 1,
                sealed_at: 1_699_999_000,
                body_hash: [7u8; 32],
                balances: 3,
                cells_read: 11,
                rate_card_version: 5,
            })
        }
    }

    /// The five paths, in the order the closed table declares them.
    const LEDGER_PATHS: &[&str] = &[
        "/api/v1/admin/ledger/totals",
        "/api/v1/admin/ledger/checkpoints",
        "/api/v1/admin/ledger/reconciliation",
        "/api/v1/admin/ledger/migration",
        "/api/v1/admin/ledger/openapi.json",
    ];

    fn a_ledger_request(path: &str) -> AdminRequest {
        AdminRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            credential: Some("admin-token".to_string()),
            headers: vec![("accept".to_string(), "application/json".to_string())],
            body: Vec::new(),
            at: 1_700_000_000,
        }
    }

    /// Walk one request through the whole loop against a node whose ledger holds the fixture.
    #[cfg(feature = "root-admin")]
    fn answer_over_seeded_ledger(request: AdminRequest) -> AdminAnswer {
        let mut units =
            crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
        units.admin =
            AdminBinding::new(Arc::new(AnsweringDispatch)).with_ledger_view(Arc::new(SeededLedger));
        AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
    }

    /// Every view answers, through the whole loop, with a JSON document of its own.
    ///
    /// "Of its own" is half the assertion. The dispatch this node is built over answers every verb
    /// with the same recognisable body, so a view that had fallen through to it — which is exactly
    /// what would happen if the executing unit stopped recognising a ledger verb — would still come
    /// back 200 and still be JSON. Requiring five distinct bodies, none of them the dispatch's, is
    /// what makes the green mean the ledger was read rather than the router.
    #[cfg(feature = "root-admin")]
    #[test]
    fn every_ledger_view_answers_from_the_ledger_and_not_from_the_dispatch() {
        let mut bodies = Vec::new();
        for path in LEDGER_PATHS {
            let answer = answer_over_seeded_ledger(a_ledger_request(path));
            assert_eq!(answer.status, 200, "{path} did not answer");
            assert_eq!(
                answer.headers,
                vec![("content-type".to_string(), "application/json".to_string())],
                "{path} carried a header the view does not set"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(parsed.is_object(), "{path} did not answer a JSON object");
            assert_ne!(
                answer.body, br#"{"entries":[]}"#,
                "{path} fell through to the dispatch"
            );
            bodies.push(answer.body);
        }
        let mut distinct = bodies.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            LEDGER_PATHS.len(),
            "two views answered the same bytes"
        );
    }

    /// The figures each view serves are the figures the ledger holds, field by field.
    #[cfg(feature = "root-admin")]
    #[test]
    fn each_view_serves_the_figures_the_ledger_holds() {
        let body = |path: &str| -> serde_json::Value {
            serde_json::from_slice(&answer_over_seeded_ledger(a_ledger_request(path)).body)
                .expect("valid JSON")
        };

        let totals = body("/api/v1/admin/ledger/totals");
        let rows = totals["rows"].as_array().expect("rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["bucket"], "key-1");
        assert_eq!(rows[0]["day"], A_DAY);
        assert_eq!(rows[0]["lane"], "lane-a");
        assert_eq!(rows[0]["provider"], "prov-x");
        // Money is text and a count is a number — the rule the served document states.
        assert_eq!(rows[0]["priced_nanos"], "7000000");
        assert_eq!(rows[0]["priced_micros"], "7000");
        assert_eq!(rows[0]["fee_count"], 2);

        let checkpoints = body("/api/v1/admin/ledger/checkpoints");
        let sealed = checkpoints["checkpoints"].as_array().expect("checkpoints");
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0]["checkpoint_seq"], 4);
        assert_eq!(sealed[0]["node"], 1);
        assert_eq!(sealed[0]["body_hash_verifies"], true);
        assert_eq!(
            sealed[0]["signed"], false,
            "an unsigned seal reports as unsigned"
        );
        let cells = sealed[0]["totals"].as_array().expect("totals");
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0]["bucket"], "key-1");
        assert_eq!(cells[0]["settled"], "8000");
        assert_eq!(cells[0]["drawn"], "8250");
        assert_eq!(
            sealed[0]["body_hash"]
                .as_str()
                .expect("a hash is text")
                .len(),
            64,
            "a digest is served as 64 hex characters"
        );

        let migration = body("/api/v1/admin/ledger/migration");
        assert_eq!(migration["migrated"], true);
        assert_eq!(migration["marker"]["checkpoint_seq"], 0);
        assert_eq!(migration["marker"]["balances"], 3);
        assert_eq!(migration["marker"]["cells_read"], 11);
        assert_eq!(migration["marker"]["rate_card_version"], 5);
        assert_eq!(
            migration["marker"]["body_hash"],
            "0707070707070707070707070707070707070707070707070707070707070707"
        );

        let document = body("/api/v1/admin/ledger/openapi.json");
        assert_eq!(document["info"]["version"], "1.6.0");
    }

    /// A node whose ledger has nothing in it says so, rather than reporting a balance it never read.
    ///
    /// The views here are bound to the node's own durability, and that durability is genuinely
    /// empty: nothing settled, nothing sealed, nothing migrated. Each emptiness is a fact about this
    /// node rather than a placeholder — which is exactly what the two tests below establish by
    /// settling on the same composition and watching the same endpoints change.
    #[cfg(feature = "root-admin")]
    #[test]
    fn an_unopened_ledger_answers_empty_rather_than_absent() {
        let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let body = |path: &str| -> serde_json::Value {
            let answer = node.answer(a_ledger_request(path));
            assert_eq!(answer.status, 200, "{path}");
            serde_json::from_slice(&answer.body).expect("valid JSON")
        };
        assert_eq!(
            body("/api/v1/admin/ledger/totals")["rows"],
            serde_json::json!([])
        );
        assert_eq!(
            body("/api/v1/admin/ledger/checkpoints")["checkpoints"],
            serde_json::json!([])
        );
        assert_eq!(body("/api/v1/admin/ledger/migration")["migrated"], false);
        assert_eq!(
            body("/api/v1/admin/ledger/migration")["marker"],
            serde_json::Value::Null
        );
        // The identity over two empty snapshots holds, and it is honest here only because the
        // totals view beside it reports the empty set it held over.
        assert_eq!(body("/api/v1/admin/ledger/reconciliation")["holds"], true);
    }

    /// THE ONE THAT MATTERS: the residual an operator reads is the residual the identity computes.
    ///
    /// Not "a residual of the same magnitude" — the same function's answer. The endpoint calls
    /// `ledger_identity::reconcile`, so a second derivation cannot creep into the rendering and make
    /// the surface capable of disagreeing with the check that gates the release. This test computes
    /// the identity itself, from the same two snapshots, and requires the served figures to be it.
    #[cfg(feature = "root-admin")]
    #[test]
    fn the_reconciliation_served_is_the_identitys_own_answer() {
        let view = SeededLedger;
        let expected =
            crate::root::ledger_identity::reconcile(&view.ledger_rows(), &view.legacy_rows());
        assert_eq!(
            expected.len(),
            1,
            "the fixture must have exactly one row out, or the comparison is vacuous"
        );

        let served: serde_json::Value = serde_json::from_slice(
            &answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/reconciliation"))
                .body,
        )
        .expect("valid JSON");

        assert_eq!(served["holds"], false);
        let rows = served["discrepancies"].as_array().expect("discrepancies");
        assert_eq!(rows.len(), expected.len());
        for (row, d) in rows.iter().zip(expected.iter()) {
            assert_eq!(row["bucket"], d.row.bucket);
            assert_eq!(row["day"], d.row.day);
            assert_eq!(row["lane"], d.row.lane);
            assert_eq!(row["provider"], d.row.provider);
            assert_eq!(row["residual"]["accounted"], d.spend.accounted.to_string());
            assert_eq!(row["residual"]["drawn"], d.spend.drawn.to_string());
            assert_eq!(row["residual"]["amount"], d.spend.amount().to_string());
            assert_eq!(row["ledger_fee_count"], d.ledger_fee_count);
            assert_eq!(row["legacy_billable_requests"], d.legacy_billable_requests);
        }

        // And the number is the one the fixture was built to be out by, so a rendering that served
        // the right field of the wrong row would still fail.
        assert_eq!(
            rows[0]["residual"]["amount"],
            (-i128::from(SeededLedger::SHORT_BY_MICROS)).to_string()
        );
        assert_eq!(rows[0]["lane"], SeededLedger::SHORT_ROW.1);
    }

    // ── the views over the node's OWN ledger ─────────────────────────────────────────────────────

    /// The two buckets the settling fixture posts against, and what each settles in nano-units.
    #[cfg(feature = "root-admin")]
    const KEPT: (&str, u64) = ("vk_kept", 7_000_000);
    #[cfg(feature = "root-admin")]
    const LOST: (&str, u64) = ("vk_lost", 1_000_000);

    /// A dual-write binding that drops the postings for one named bucket on the floor.
    ///
    /// The failure it stands in for is real and is the one the identity exists to catch: the books
    /// moved, value was delivered, and the previous release's rows never heard about it. The ledger
    /// is unaffected — this is a binding the ledger writes THROUGH, so a node built over it settles
    /// exactly as any other node does and only the parity obligation is broken.
    #[cfg(feature = "root-admin")]
    #[derive(Clone)]
    struct RowsThatLose {
        drop_bucket: &'static str,
        kept: Arc<Mutex<Vec<busbar_unit_ledger::legacy::LegacyPosting>>>,
    }

    #[cfg(feature = "root-admin")]
    impl RowsThatLose {
        fn new(drop_bucket: &'static str) -> Self {
            RowsThatLose {
                drop_bucket,
                kept: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[cfg(feature = "root-admin")]
    impl busbar_unit_ledger::legacy::LegacyRows for RowsThatLose {
        fn write(
            &mut self,
            posting: &busbar_unit_ledger::legacy::LegacyPosting,
        ) -> Result<(), busbar_unit_ledger::legacy::LegacyWriteError> {
            if posting.bucket != self.drop_bucket {
                self.kept
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(posting.clone());
            }
            Ok(())
        }
    }

    #[cfg(feature = "root-admin")]
    impl LegacyRowsRead for RowsThatLose {
        fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting> {
            self.kept.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    /// Settle one unit against the node's own durability, through the same function the loop's exit
    /// path settles through — so what the views read is what a served request would have left.
    #[cfg(feature = "root-admin")]
    fn settle_on(units: &crate::root::kernel::ProductionUnits, bucket: &str, nanos: u64) {
        use busbar_caps::{
            step::Admit, AdmitToken, Hold, KernelSeal, LedgerToken, MeterClassId, PrincipalId,
            QuantitySource, Usage, UsageLine, UsageToken,
        };
        use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

        let seal = KernelSeal::acquire_for_kernel();
        let key = TotalsKey::new(
            BucketId::new(bucket),
            CapDimension::NanoUnits,
            BucketScope::All,
        );
        let usage = Usage::report(
            &UsageToken::mint(&seal),
            vec![UsageLine {
                class: MeterClassId::new("nano_units"),
                quantity: nanos,
                source: QuantitySource::Count,
                estimated: false,
            }],
        )
        .expect("one line");

        let token = busbar_caps::DurabilityToken::mint(&seal);
        let mut durability = units.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.ledger.record_hold_opened(&key, A_DAY, nanos);
        durability
            .settle(
                &crate::root::durability::Settling {
                    key: &key,
                    window: A_DAY,
                    durability: &token,
                    step: busbar_caps::StepName::Meter,
                    stamp: crate::root::durability::PostingStamp {
                        rate_card_version: 3,
                        wall: 1_700_000_000,
                        mono: 42,
                    },
                },
                Hold::open(
                    &AdmitToken::<Admit>::mint(&seal),
                    PrincipalId::new(bucket),
                    nanos,
                ),
                u128::from(nanos),
                &usage,
                &LedgerToken::mint(&seal),
            )
            .expect("the memory-buffered journal takes it");
    }

    /// A node that has settled both fixture units, over a dual write that may have lost one of them.
    #[cfg(feature = "root-admin")]
    fn a_node_that_settled(lose: Option<&'static str>) -> crate::root::kernel::ProductionUnits {
        let units = match lose {
            None => {
                let rows = busbar_unit_ledger::legacy::RecordingRows::new();
                crate::root::kernel::ProductionUnits::admin_only_over(
                    Arc::new(AnsweringDispatch),
                    Box::new(rows.clone()),
                    Arc::new(rows),
                )
            }
            Some(bucket) => {
                let rows = RowsThatLose::new(bucket);
                crate::root::kernel::ProductionUnits::admin_only_over(
                    Arc::new(AnsweringDispatch),
                    Box::new(rows.clone()),
                    Arc::new(rows),
                )
            }
        };
        settle_on(&units, KEPT.0, KEPT.1);
        settle_on(&units, LOST.0, LOST.1);
        units
    }

    /// THE ONE THAT MATTERS FOR A LIVE NODE: a settlement this node made is in the figures it
    /// serves.
    ///
    /// Not a fixture bound behind the seam — the node's own durability, settled through the same
    /// function the loop settles through, read back through the served endpoint. A view bound to
    /// anything other than this node's ledger answers an empty table here, which is exactly what the
    /// unbound default answers and exactly what this test refuses.
    ///
    /// Both halves are asserted because they fail separately. `totals` says the posting reached the
    /// books; `reconciliation` says the identity was computed over the rows the node actually holds,
    /// and it is asserted against a node whose dual write LOST one of the two settlements — so a
    /// reconciliation rendered over two empty snapshots, which balances trivially, cannot pass it.
    #[cfg(feature = "root-admin")]
    #[test]
    fn a_settled_posting_is_in_the_figures_this_node_serves() {
        let units = a_node_that_settled(None);
        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let body = |path: &str| -> serde_json::Value {
            let answer = node.answer(a_ledger_request(path));
            assert_eq!(answer.status, 200, "{path}");
            serde_json::from_slice(&answer.body).expect("valid JSON")
        };

        let rows = body("/api/v1/admin/ledger/totals");
        let rows = rows["rows"].as_array().expect("rows");
        assert_eq!(
            rows.len(),
            2,
            "the two settlements this node made are not in the totals it serves"
        );
        let row = rows
            .iter()
            .find(|r| r["bucket"] == KEPT.0)
            .expect("the settled bucket is named");
        assert_eq!(row["day"], A_DAY);
        assert_eq!(row["priced_nanos"], KEPT.1.to_string());
        assert_eq!(row["priced_micros"], (KEPT.1 / 1_000).to_string());

        // The dual write kept both, so the identity holds — over two rows rather than over nothing,
        // which the totals beside it just established.
        assert_eq!(body("/api/v1/admin/ledger/reconciliation")["holds"], true);
    }

    /// And the reconciliation names the row the dual write lost, by the amount it lost.
    #[cfg(feature = "root-admin")]
    #[test]
    fn the_reconciliation_names_a_row_this_nodes_dual_write_lost() {
        let units = a_node_that_settled(Some(LOST.0));
        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let served: serde_json::Value = serde_json::from_slice(
            &node
                .answer(a_ledger_request("/api/v1/admin/ledger/reconciliation"))
                .body,
        )
        .expect("valid JSON");

        assert_eq!(
            served["holds"], false,
            "a settlement the previous release's rows never saw reconciled anyway"
        );
        let out = served["discrepancies"].as_array().expect("discrepancies");
        assert_eq!(out.len(), 1, "exactly the lost row must be named: {served}");
        assert_eq!(out[0]["bucket"], LOST.0);
        assert_eq!(out[0]["day"], A_DAY);
        // The ledger accounted for the whole posting against nothing drawn, so the residual is the
        // posting, in micro-units, positive.
        assert_eq!(
            out[0]["residual"]["amount"],
            (LOST.1 / 1_000).to_string(),
            "the residual is not the settlement that went missing"
        );
    }

    /// The other two views are this node's too: the seal it made and the marker it sealed.
    ///
    /// Both are on the same composition that answered empty above, so the change is the node's own
    /// act rather than a fixture swapped in behind the seam. The checkpoint is asserted through its
    /// sealed balances, which is the half the journal deliberately does not carry — a view rebuilt
    /// from the chain could not answer it at all.
    #[cfg(feature = "root-admin")]
    #[test]
    fn the_seal_and_the_marker_this_node_made_are_the_ones_it_serves() {
        use busbar_unit_ledger::migration::MigrationRecords as _;
        use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

        let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let token = busbar_caps::DurabilityToken::mint(&seal);
        let marker = busbar_unit_ledger::migration::MigrationMarker {
            checkpoint_seq: 0,
            node: 0,
            sealed_at: 1_699_999_000,
            body_hash: [9u8; 32],
            balances: 2,
            cells_read: 5,
            rate_card_version: 4,
        };

        {
            let mut durability = units.durability.lock().expect("durability lock");
            let mut totals = std::collections::BTreeMap::new();
            totals.insert(
                (
                    TotalsKey::new(
                        BucketId::new(KEPT.0),
                        CapDimension::NanoUnits,
                        BucketScope::All,
                    ),
                    A_DAY,
                ),
                busbar_unit_ledger::totals::Totals {
                    settled: 8_000,
                    ..busbar_unit_ledger::totals::Totals::zero()
                },
            );
            let checkpoint = busbar_unit_ledger::checkpoint::Checkpoint::seal(
                7,
                0,
                1_700_000_100,
                Vec::new(),
                totals,
                0,
                0,
                None,
            )
            .expect("an unsigned seal cannot fail");
            durability
                .journal_checkpoint(&checkpoint, &token, busbar_caps::StepName::Meter)
                .expect("the memory-buffered journal takes it");
            durability
                .migration_records(&token, busbar_caps::StepName::Meter)
                .write_marker(&marker)
                .expect("the marker goes on the chain");
        }

        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let body = |path: &str| -> serde_json::Value {
            serde_json::from_slice(&node.answer(a_ledger_request(path)).body).expect("valid JSON")
        };

        let sealed = body("/api/v1/admin/ledger/checkpoints");
        let sealed = sealed["checkpoints"].as_array().expect("checkpoints");
        assert_eq!(sealed.len(), 1, "the seal this node made is not served");
        assert_eq!(sealed[0]["checkpoint_seq"], 7);
        assert_eq!(sealed[0]["body_hash_verifies"], true);
        assert_eq!(
            sealed[0]["totals"][0]["settled"], "8000",
            "the sealed balances the journal does not carry"
        );

        let served = body("/api/v1/admin/ledger/migration");
        assert_eq!(served["migrated"], true);
        assert_eq!(served["marker"]["sealed_at"], marker.sealed_at);
        assert_eq!(served["marker"]["balances"], marker.balances);
        assert_eq!(served["marker"]["cells_read"], marker.cells_read);
        assert_eq!(
            served["marker"]["rate_card_version"],
            marker.rate_card_version
        );
    }

    /// A caller the node will not authenticate gets from a ledger view exactly what it gets from
    /// the legacy read that touches the same money — byte for byte, including the status.
    ///
    /// Stated as an equality against `GET /usage` rather than against a literal, because the claim
    /// the design makes about these verbs is not "they answer 403"; it is that their auth posture is
    /// the SAME one. A literal would still pass on the day the shared posture changed and the views
    /// were left behind.
    ///
    /// The refused case is a credential the node's directory has revoked. That is what an
    /// unauthenticated caller IS on this composition: the admin-only node's chain is open, so a
    /// request carrying no credential at all is admitted — for the views exactly as for `/usage`,
    /// which the second half asserts. Choosing the reachable refusal over the unreachable one is
    /// what keeps this test about the posture the two share rather than about a 401 this node never
    /// produces.
    #[cfg(feature = "root-admin")]
    #[test]
    fn a_ledger_view_answers_an_unauthenticated_caller_exactly_as_the_legacy_usage_read_does() {
        let under = |path: &str, credential: Option<&str>, revoked: bool| -> AdminAnswer {
            let mut request = a_ledger_request(path);
            request.credential = credential.map(ToString::to_string);
            let units =
                crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch))
                    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                        Denylist(revoked),
                    )));
            AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
        };

        let refused = under("/api/v1/admin/usage", Some("admin-token"), true);
        assert_ne!(
            refused.status, 200,
            "the control must actually be a refusal, or this test compares two successes"
        );
        for path in LEDGER_PATHS {
            assert_eq!(
                under(path, Some("admin-token"), true),
                refused,
                "{path} does not refuse a revoked credential the way /usage does"
            );
        }

        // And the other half: where `/usage` admits a caller carrying no credential, so does every
        // view. The bodies differ — they are different operations — but the admission does not.
        let admitted = under("/api/v1/admin/usage", None, false);
        assert_eq!(admitted.status, 200, "the open chain admits the control");
        for path in LEDGER_PATHS {
            assert_eq!(
                under(path, None, false).status,
                admitted.status,
                "{path} does not admit a credential-less caller the way /usage does"
            );
        }
    }

    /// The scope gate is live on this path, and the views sit on the rung the legacy read sits on.
    ///
    /// Two halves, and both are needed. A credential granted `read-only` reaches every view — which
    /// is the whole point of putting them on that rung — and the SAME credential is refused a
    /// mutation on the same surface, which is what proves the gate is a gate rather than an absence.
    /// Without the second half, a step that had stopped checking scope altogether would pass the
    /// first.
    #[test]
    fn a_read_only_credential_reaches_every_view_and_still_no_mutation() {
        let binding = AdminBinding::new(Arc::new(RefusingDispatch));
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();

        let decide = |path: &str, method: &str, granted: VerbScope| -> bool {
            let key = UnitKey::new(1);
            let mut request = a_ledger_request(path);
            request.method = method.to_string();
            binding.units.open(key, request);
            let ctx = UnitCtx {
                key,
                origin: busbar_caps::OriginKind::Client,
                session: None,
                generation: busbar_kernel::registry::Generation::FIRST,
                admin_listener: true,
                kernel_verb_only: true,
            };
            let token: UnitToken<Approve> = UnitToken::mint(&seal);
            let decision = approve(
                &binding,
                granted,
                &token,
                &ctx,
                &PrincipalId::new("admin"),
                &[],
            );
            binding.units.close(key);
            decision.into_result(&seal).is_ok()
        };

        for path in LEDGER_PATHS {
            assert!(
                decide(path, "GET", VerbScope::ReadOnly),
                "{path} refused a read-only credential"
            );
            assert!(
                decide(path, "GET", VerbScope::Full),
                "{path} refused a full credential"
            );
        }
        assert!(
            !decide("/api/v1/admin/config/settings", "PUT", VerbScope::ReadOnly),
            "the scope gate is not checking anything: a read-only credential reached a mutation"
        );
    }

    /// Both of the unit's own answers about a ledger verb put it on the read side, and the plane's
    /// row agrees. Three tables, one split — and the rate class is the one that bites: a view whose
    /// class fell through to `Crud` would spend a mutation slot every time somebody looked at a
    /// balance, and would eventually refuse an operator's config change because of it.
    #[test]
    fn a_ledger_view_is_read_only_in_every_table_that_has_an_opinion() {
        for path in LEDGER_PATHS {
            let row = busbar_plane_admin::verbs::resolve("GET", path)
                .unwrap_or_else(|| panic!("{path} is not in the plane's table"));
            assert!(
                row.read_only,
                "{path} is not read-only in the plane's table"
            );
            assert_eq!(
                row.op_class(),
                busbar_contract::ids::OpClassId::new("admin_read")
            );

            let verb = kernel_verb(&row).unwrap_or_else(|| panic!("{path} names no kernel verb"));
            assert!(LEDGER_VERBS.contains(&verb), "{path} is not a ledger verb");
            assert_eq!(
                busbar_unit_verbs::required_scope(verb),
                busbar_unit_verbs::required_scope(KernelVerb::GetUsage),
                "{path} does not require what the legacy /usage read requires"
            );
            assert_eq!(
                mutation_class(verb),
                MutationClass::Forbidden,
                "{path} would spend a mutation slot per read"
            );
            assert_eq!(
                busbar_unit_scope::admin_required_scope("GET", path),
                Scope::ReadOnly
            );
        }
    }

    /// A ledger verb never reaches the dispatch, and never reaches the posture check either.
    ///
    /// The governance seam is the boundary the two facts meet at, so it is where they are asserted:
    /// a recording seam that would notice a legacy or new-verb call, and a `PostureCtx` that refuses
    /// every mutation. A view answering under that posture is a view no ceremony gates.
    #[test]
    fn a_view_reaches_neither_the_dispatch_nor_the_posture_check() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingDispatch(Arc<AtomicUsize>);
        impl AdminDispatch for CountingDispatch {
            fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
                self.0.fetch_add(1, Ordering::Relaxed);
                // A recognisable answer rather than a realistic one: if a view ever reached the
                // dispatch, the count below is what says so, and the body only has to be something
                // no view would produce.
                AdminAnswer {
                    status: 599,
                    headers: Vec::new(),
                    body: b"the dispatch was reached".to_vec(),
                }
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let admin = crate::root::kernel::new_kernel().admin_token();

        for verb in LEDGER_VERBS {
            let verbs = busbar_unit_verbs::Verbs::new(
                CoreGovernance::new(
                    Arc::new(CountingDispatch(Arc::clone(&calls))),
                    Arc::new(SeededLedger),
                    *verb,
                    a_ledger_request("/api/v1/admin/ledger/totals"),
                ),
                RefusingStore,
                ArrivalNonce(1),
                PackedReplay,
                CONFIG_CLASS_RULES,
            );
            let packed = verbs
                .execute(
                    *verb,
                    &admin,
                    "admin",
                    VerbScope::ReadOnly,
                    1_700_000_000,
                    // The posture a fleet is in before its operator ceremony has run, under which
                    // every one of the 17 money-governance verbs is refused. A view answers anyway,
                    // because there is nothing for an operator to have approved about a read.
                    Some(busbar_unit_verbs::PostureCtx {
                        operator: busbar_unit_verbs::OperatorState::Unset,
                        dual_control: busbar_unit_verbs::DualControl::Required,
                    }),
                    busbar_unit_verbs::ApprovalState::NotYetApproved,
                    b"",
                )
                .unwrap_or_else(|r| panic!("{verb:?} was refused: {r:?}"));
            let answer = AdminAnswer::unpack(&packed).expect("the view packs an answer");
            assert_eq!(answer.status, 200);
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "a ledger view reached the dispatch, which has no handler for it"
        );

        // The control: a money-governance verb under the same posture IS refused, so the green above
        // is the views being exempt rather than the posture check being unbound.
        let verbs = busbar_unit_verbs::Verbs::new(
            CoreGovernance::new(
                Arc::new(CountingDispatch(Arc::clone(&calls))),
                Arc::new(SeededLedger),
                KernelVerb::Adjust,
                a_ledger_request("/api/v1/admin/adjust"),
            ),
            RefusingStore,
            ArrivalNonce(1),
            PackedReplay,
            CONFIG_CLASS_RULES,
        );
        assert!(verbs
            .execute(
                KernelVerb::Adjust,
                &admin,
                "admin",
                VerbScope::Full,
                1_700_000_000,
                Some(busbar_unit_verbs::PostureCtx {
                    operator: busbar_unit_verbs::OperatorState::Unset,
                    dual_control: busbar_unit_verbs::DualControl::Required,
                }),
                busbar_unit_verbs::ApprovalState::NotYetApproved,
                b"",
            )
            .is_err());
    }

    /// The additive document describes exactly the operations the closed table declares, and not one
    /// path the pinned 1.5.5 document already has.
    ///
    /// That second clause is the additivity claim itself. "Additive" is not a promise that the new
    /// document is small; it is the statement that nothing in it collides with a path a 1.5.5 client
    /// already knows, so the two documents can be read side by side without either contradicting the
    /// other.
    #[test]
    fn the_additive_document_describes_the_ledger_views_and_nothing_the_pinned_one_has() {
        let additive: serde_json::Value =
            serde_json::from_str(LEDGER_OPENAPI_ADDITIVE).expect("the additive document is JSON");
        let paths = additive["paths"].as_object().expect("it declares paths");

        let mut declared: Vec<&str> = paths.keys().map(String::as_str).collect();
        declared.sort_unstable();
        let mut expected: Vec<&str> = LEDGER_PATHS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            declared, expected,
            "the document and the closed table declare different operations"
        );

        for (path, item) in paths {
            let op = &item["get"];
            assert!(
                op.is_object(),
                "{path} is described under a method the table does not declare"
            );
            assert_eq!(
                op["x-busbar-required-scope"], "read-only",
                "{path} is documented at a scope it is not served at"
            );
            let operation_id = op["operationId"].as_str().expect("an operationId");
            let verb = busbar_plane_admin::verbs::resolve("GET", path)
                .expect("the table declares it")
                .verb;
            assert_eq!(
                snake_of(operation_id),
                verb,
                "{path}: the document's operationId is not the table's verb"
            );
        }

        let pinned: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
        )))
        .expect("the pinned fixture is JSON");
        let pinned_paths = pinned["paths"].as_object().expect("it declares paths");
        for path in paths.keys() {
            assert!(
                !pinned_paths.contains_key(path),
                "{path} collides with a path the pinned 1.5.5 document already declares"
            );
        }
        // And from the other side: the served 1.5.5 document has no ledger path at all, which is
        // what leaving the released document's bytes alone means.
        assert!(
            !pinned_paths
                .keys()
                .any(|p| p.starts_with("/api/v1/admin/ledger/")),
            "the pinned document has grown a ledger path"
        );
    }

    /// `GetLedgerTotals` -> `get_ledger_totals`, so the test above can compute the expected verb
    /// name rather than hand-transcribing a second copy of the five-row mapping.
    fn snake_of(operation_id: &str) -> String {
        let mut out = String::new();
        for (i, c) in operation_id.chars().enumerate() {
            if c.is_uppercase() {
                if i != 0 {
                    out.push('_');
                }
                out.extend(c.to_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// A string a deployment configured is escaped on the way out, so a name holding a quote cannot
    /// end the document early and hand a reader a different one from the one this rendered.
    #[test]
    fn a_configured_name_cannot_break_out_of_the_document() {
        use crate::root::ledger_identity::{LedgerRow, LedgerSnapshot, RowKey};

        let hostile = "a\"b\\c\nd\te\u{1}";
        let mut rows = LedgerSnapshot::new();
        rows.insert(
            RowKey::new(hostile, A_DAY, hostile, hostile),
            LedgerRow {
                priced_nanos: 1,
                fee_count: 0,
            },
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&render_totals(&rows)).expect("a hostile name still renders JSON");
        assert_eq!(parsed["rows"][0]["bucket"], hostile);
        assert_eq!(parsed["rows"][0]["lane"], hostile);
        assert_eq!(parsed["rows"][0]["provider"], hostile);
    }
}
