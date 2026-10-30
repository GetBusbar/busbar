// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin plane: its steps, called directly.
//!
//! ## What changes and what does not
//!
//! The bytes an operator sees do not change. An admin request reaches its handler as the Route step
//! of a unit whose steps ran first, in the loop's order: decode, authenticate, verify, approve,
//! admit ([`decide`]). Every one of those steps does its real job — the auth door resolves the
//! credential, the scope unit answers the 1.5.5 authorization matrix, the admission step reads the
//! mutation rate class off the verbs unit's table — and the verb's own body is executed exactly
//! where it already lived. The unit's one audit record is sealed on the node's book at its end.
//!
//! The steps are called, not walked through the kernel's teller loop: a kernel verb holds nothing,
//! is charged nothing and takes no lease, so the hold, the in-flight slot and the settling exit a
//! priced unit needs have no work to do here.
//!
//! Not one line of an admin operation is reimplemented here. The 66 legacy operations are reached
//! through one seam, [`AdminDispatch`], whose production implementation hands the request to the
//! surface that already answers it; the seam carries the whole answer — status, headers and body —
//! so that a status code, a header or a byte cannot be re-derived on the way back and cannot
//! therefore drift. The verbs unit passes that answer through as its governance seam's own
//! `Answer` type, untouched.
//!
//! ## Where a step is deliberately observational
//!
//! The mutation rate class is computed here, from the verbs unit's own table, and it refuses a verb
//! the table forbids outright. It does not run a second window counter: the surface the request is
//! about to reach owns the counter whose refusals are byte-pinned, and two counters over one request
//! would consume two slots per call and refuse at half the documented rate. The class is the binding
//! the register asked for; the count stays where the pinned bytes are. A step that measured
//! something twice would not be more faithful, it would be wrong.

use std::sync::{Arc, Mutex};

use busbar_contract::authz::Scope;
use busbar_contract::caps::{Grant, Outcome, PrincipalId, ReasonCode};
use busbar_contract::UnitKey;
use busbar_core_admin::admin_codec::verbs::ResolvedVerb;
use busbar_kernel_audit::{expose, AuditChain, AuditKeySet, AuditRecord};

use busbar_core_admin::rate::{MutationClass, CONFIG_CLASS_RULES};
use busbar_core_admin::{KernelVerb, VerbScope, NEW_VERBS};
#[cfg(test)]
use busbar_core_admin::{AUDIT_VERBS, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES};
use busbar_kernel_ledger::cost::{Money, MoneyError};

/// One admin request, exactly as it arrived.
///
/// Owned, because it crosses to the task the operation's body runs on ([`AdminDispatch`]).
///
/// NO derived `Debug` — see the hand-written impl below. This value holds the operator's LIVE
/// credential, twice.
#[derive(Clone, PartialEq, Eq)]
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
    /// The key of the unit this request is answered as.
    ///
    /// Carried on the request because it has to cross the seam WITH it: the operation's body runs on
    /// a task the seam spawned, and the one effect a body can ask to outlive its own response — the
    /// drain — is attributed to the unit that asked for it. Without the key travelling here the
    /// attribution would have to be re-derived on the far side of a task boundary, which is another
    /// way of saying it would be guessed.
    pub unit: u64,
}

/// `Debug` REDACTS the presented credential — the field, and the header value it arrived in.
///
/// A derived `Debug` prints `credential: Some("<the operator's live admin token>")` verbatim into
/// any `{:?}` of this value or of anything holding it: a tracing line, a panic message, an
/// `assert_eq!` failure in CI. Redacting the field alone would not be a fix, because
/// `admin_mount::header_pairs` copies EVERY arriving header in verbatim, so the same bytes sit one
/// line below it as `authorization: Bearer <token>` or `x-admin-token: <token>`.
///
/// The header redaction is matched by VALUE, not by header name, and that is deliberate: the reader
/// that decides which carriers count (`admin_mount::presented_credential`) owns those wire names,
/// and a second copy of a wire name here is a wire name that can be written two ways. Whatever
/// carrier the credential came in, the bytes are the same bytes, and those are what this matches —
/// which also catches the `Bearer `-prefixed form, where the header value merely CONTAINS the
/// credential rather than equalling it. Where nothing was presented, nothing is redacted: the
/// redaction never manufactures a credential out of an absent one.
///
/// Everything else prints as itself. `method`, `path`, `at` and `unit` are not secrets, and `body`
/// keeps the derived rendering it always had — the admin surface's credential carriers are headers,
/// and a request body that needed hiding would be a different finding with a different fix.
impl std::fmt::Debug for AdminRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "<redacted>";
        let presented = self.credential.as_deref().filter(|c| !c.is_empty());
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let shown = match presented {
                    Some(credential) if value.contains(credential) => REDACTED,
                    _ => value.as_str(),
                };
                (name.as_str(), shown)
            })
            .collect();
        f.debug_struct("AdminRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("credential", &self.credential.as_ref().map(|_| REDACTED))
            .field("headers", &headers)
            .field("body", &self.body)
            .field("at", &self.at)
            .field("unit", &self.unit)
            .finish()
    }
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

/// One row of the one ledger, priced: a bucket's current window, its counts priced at the card each
/// was earned under (MONEY-DESIGN §3: money is counts x the card, computed in core).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    /// The bucket: a key's id.
    pub bucket: String,
    /// The window the counts are in, as the unix second it opens at (`0` = the all-time window).
    pub day: u64,
    /// The priced figure, in nano-units: the one function's figure (scale six) at nano scale.
    pub priced_nanos: u128,
    /// Billable requests in the window: the fee base.
    pub fee_count: u64,
}

/// A row the card refused to price (#42): it is withheld from the figures and named, never served
/// as the priced remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRow {
    /// The bucket.
    pub bucket: String,
    /// The window, as the unix second it opens at.
    pub day: u64,
    /// The refusal, in the one function's own words.
    pub refusal: String,
}

/// The one ledger as the views read it, as of one read: every priced row, and every refused one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PricedLedger {
    /// The priced rows, in bucket order. A row nothing was counted in is not a row.
    pub rows: Vec<LedgerRow>,
    /// The rows the card refused to price.
    pub refused: Vec<RefusedRow>,
}

/// The figures the ledger views read: THE ONE LEDGER, the configured store's usage counts, priced
/// by the dated rate card in core. A read seam and nothing else: it cannot change anything.
pub trait LedgerView: Send + Sync {
    /// Every key's usage row for its current window, priced.
    ///
    /// # Errors
    ///
    /// The store could not be read; the answer names why, for the node's log only.
    fn priced(&self) -> Result<PricedLedger, String>;
}

/// The view a node has before a ledger is bound behind it: no rows, which is the truth about a node
/// composed with no governance store.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnopenedLedger;

impl LedgerView for UnopenedLedger {
    fn priced(&self) -> Result<PricedLedger, String> {
        Ok(PricedLedger::default())
    }
}

/// THE VIEWS OVER THE ONE LEDGER: the live governance state's usage rows, read through the same
/// cell [`busbar_kernel::governance::GovState::usage_for`] answers `/keys/{id}/usage` from and
/// priced by the same function, so the ledger views and the key usage read are one money. Read off
/// the live snapshot per call, so a config apply is what the next read sees.
pub struct CountsLedger {
    app: Arc<busbar_kernel::state::AppHandle>,
}

impl std::fmt::Debug for CountsLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountsLedger").finish_non_exhaustive()
    }
}

impl CountsLedger {
    /// The views over `app`'s live governance state.
    #[must_use]
    pub fn new(app: Arc<busbar_kernel::state::AppHandle>) -> Self {
        CountsLedger { app }
    }
}

impl LedgerView for CountsLedger {
    fn priced(&self) -> Result<PricedLedger, String> {
        let app = self.app.load();
        let Some(gov) = app.governance.clone() else {
            return Ok(PricedLedger::default());
        };
        let now = busbar_kernel::store::now();
        // The reads reach the store: off the runtime's workers, as the journal's own reads are.
        crate::root::durability::off_runtime(|| priced_keys(&gov, &app.cost, now))
    }
}

/// Every key's own bucket, current window, priced: one row per key with anything counted, a refused
/// row for a key whose counts the card will not price.
///
/// # Errors
///
/// The store could not list the keys or read a durable row.
pub fn priced_keys(
    gov: &busbar_kernel::governance::GovState,
    cost: &busbar_kernel::cost::CostModel,
    now: u64,
) -> Result<PricedLedger, String> {
    let mut keys = gov.all_keys().map_err(|e| e.to_string())?;
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    let mut ledger = PricedLedger::default();
    for key in keys {
        let bucket = gov
            .priced_bucket(cost, &key.id, busbar_kernel::governance::WINDOW_TOTAL, now)
            .map_err(|e| e.to_string())?;
        match bucket.spend {
            Ok(spend) => {
                let micros = u128::try_from(spend.micros()).unwrap_or(0);
                if micros == 0 && bucket.billable_requests == 0 {
                    continue;
                }
                ledger.rows.push(LedgerRow {
                    bucket: key.id,
                    day: bucket.window_start,
                    priced_nanos: micros.saturating_mul(1_000),
                    fee_count: bucket.billable_requests,
                });
            }
            Err(refusal) => ledger.refused.push(RefusedRow {
                bucket: key.id,
                day: bucket.window_start,
                refusal: refusal.to_string(),
            }),
        }
    }
    Ok(ledger)
}

// ── the audit chain's three reads ───────────────────────────────────────────────────────────────

/// The evidence the three 1.6.0 audit-chain reads answer from.
///
/// A read seam and nothing else, for the same reason [`LedgerView`] is one: the answers are not
/// produced by any operation's own 1.5.5 handler — there was no such surface — so the root has to
/// reach the chain itself, and reaching it through a seam that offers no way to append is what keeps
/// "read-only" a property of the type rather than a promise in a comment. Nothing behind it can seal
/// a record, mint a key or move a head.
///
/// It is deliberately NOT the chain. An [`AuditChain`] can SEAL; a read of it
/// has no business holding one that it could. What the trait hands a reader is a borrow, for the
/// duration of one render, under whatever lock the node keeps the chain behind.
///
/// PULL, NEVER PUSH. Everything here ANSWERS. No implementation of it opens an outbound connection,
/// holds a cloud credential or phones anybody — which is exactly what lets an airgapped operator
/// `curl` their own evidence and a firewalled node be audited at all.
pub trait AuditView: Send + Sync {
    /// Show the chain, and the records this node still holds, to ONE reader, as of ONE moment.
    ///
    /// One method rather than two, and a borrow rather than a copy, and both are load-bearing. One
    /// method, because the range read folds the anchor this node published at or before the window's
    /// end into the same body as the window's records: reading the two through separate calls would
    /// let a seal landing between them tie a window to a head it does not belong under, which is the
    /// same race a two-call read always opens. A borrow, because
    /// [`AuditChain`] is not `Clone` — deliberately, it holds the signing key —
    /// so a seam that handed one out would be handing out the ability to sign.
    ///
    /// The records are an OPTION, and `None` is not an empty window. `None` is "this node retains no
    /// sealed records at all", which is a true and common state — a node whose records went to the
    /// journal and were pruned has a chain, a head and no records — and it is a different fact from
    /// "no records fall in the window you asked for". `docs/design/BUSBAR-1.6.0.md:2079`: a gap and
    /// a measurement must never be the same output. The head read answers either way.
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>));

    /// [`AuditView::read`] for the records at positions `from` through `to`: a view whose records
    /// outlive what it holds in memory answers an older window from where it keeps them. The
    /// default is [`AuditView::read`].
    fn read_window(
        &self,
        _from: u64,
        _to: u64,
        take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>),
    ) {
        self.read(take);
    }

    /// The PUBLIC halves of every key this node has signed records under.
    ///
    /// Public halves only, and there is no path from this seam to a secret one:
    /// [`AuditKeySet`] holds verifying keys and nothing else. Keys are only
    /// ever added — a key dropped from this answer makes every record it signed unverifiable, which
    /// from outside is indistinguishable from those records having been forged.
    fn keys(&self) -> AuditKeySet;

    /// What this node's boot could not read back or verify of its journal. Empty for a view with
    /// no journal, and for a node that booted clean.
    fn restart_findings(&self) -> Vec<String> {
        Vec::new()
    }

    /// What a walk of this node's retained audit chain finds: a record whose digest, link or
    /// position does not hold, or whose signature does not verify. Empty for a view with no chain.
    fn retained_audit_findings(&self) -> Vec<String> {
        Vec::new()
    }

    /// What a walk of EVERY CHAIN THE CONFIGURED STORE KEEPS finds — this node's and every other
    /// node's the registry names — against the deployment keyset. Empty with no store behind it.
    fn stored_chain_findings(&self) -> Vec<String> {
        Vec::new()
    }
}

/// The chain reads over the evidence THIS node holds.
///
/// A handle on the node's own durability, behind the node's own lock: a snapshot taken when the
/// node was composed would freeze the published
/// head at boot, and a stale head that still looks like a current one is worse for an auditor than
/// no answer at all. The head is read HERE, per request, under the lock a seal holds — so no read
/// can catch the chain half-sealed.
///
/// ## The records
///
/// Each unit this node serves seals ONE record where its one line is written
/// ([`crate::root::durability::Durability::seal_unit`]), and the journal keeps it whole
/// (`audit.v4`). The node holds the newest [`crate::root::durability::AUDIT_RING`] in memory as a
/// cache; a range read older than the cache is answered by reading the journal back
/// ([`crate::root::durability::Durability::audit_window`]), so retention never loses a record the
/// chain holds and a window is never answered as empty because the cache let it go.
pub struct NodeAudit {
    durability: Arc<Mutex<crate::root::durability::Durability>>,
}

impl std::fmt::Debug for NodeAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeAudit").finish_non_exhaustive()
    }
}

impl NodeAudit {
    /// Bind the three chain reads to a node's durability.
    #[must_use]
    pub fn new(durability: Arc<Mutex<crate::root::durability::Durability>>) -> Self {
        NodeAudit { durability }
    }

    /// The lock, taken the way every other reader of it takes it. A poisoned lock is read through:
    /// what is behind it is append-only, so a reader sees a prefix of the truth.
    fn lock(&self) -> std::sync::MutexGuard<'_, crate::root::durability::Durability> {
        self.durability.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl AuditView for NodeAudit {
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>)) {
        let durability = self.lock();
        take(&durability.record, Some(&durability.audit_records));
    }

    /// A window the cache covers is answered under one hold of the lock. An older one is read off
    /// the chain as of one hold and WITHOUT the lock — the read scans the store, and every unit's
    /// settle waits on this lock (THE DESIGN §11.2) — then answered under a second hold, with what
    /// was sealed in between added from the cache so the records and the chain's head are still of
    /// one moment ([`Durability::audit_window_since`]).
    ///
    /// [`Durability::audit_window_since`]: crate::root::durability::Durability::audit_window_since
    fn read_window(
        &self,
        from: u64,
        to: u64,
        take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>),
    ) {
        use crate::root::durability::AuditWindowAt;
        loop {
            let (chain, sealed_before) = {
                let durability = self.lock();
                match durability.audit_window_at(from, to) {
                    AuditWindowAt::Cached(records) => {
                        take(&durability.record, Some(&records));
                        return;
                    }
                    AuditWindowAt::OnChain {
                        chain,
                        sealed_before,
                    } => (chain, sealed_before),
                }
            };
            // A window the journal would not read back is not answered at all, which the range
            // read renders as the store failure it is; never as an empty window.
            let Some(mut records) = chain.audit_window(from, to) else {
                return;
            };
            let durability = self.lock();
            if durability.audit_window_since(&mut records, sealed_before, from, to) {
                take(&durability.record, Some(&records));
                return;
            }
            // More was sealed while the chain was read than the cache still holds: read it again.
        }
    }

    fn keys(&self) -> AuditKeySet {
        // The public half of the key this chain signs with, where it was given one. A node that was
        // given none answers with an EMPTY set, and that is the truth about it: nothing it sealed
        // carries a signature, so there is no key with which to check one. What the set must never
        // do is carry a key the node does not sign with. The checkpoints read verifies against the
        // same set (Q71(3): one keyset).
        crate::root::durability::keyset_of(&self.lock().record)
    }

    fn restart_findings(&self) -> Vec<String> {
        self.lock().restart_findings.clone()
    }

    fn retained_audit_findings(&self) -> Vec<String> {
        self.lock().retained_audit_findings()
    }

    /// The inputs under the journal's lock, the walk (which reads the store) without it.
    fn stored_chain_findings(&self) -> Vec<String> {
        let Some((lane, own, keys)) = self.lock().stored_walk_inputs() else {
            return Vec::new();
        };
        crate::root::durability::walk_stored_chains(&lane, own, &keys).findings
    }
}

/// The window a range read names, as `?from=&to=`.
///
/// BOTH are required, and a read that names neither is refused rather than widened. A query names
/// ARGUMENTS to an operation, and `from`/`to` are this operation's arguments — so a range read with
/// no window is not "the whole chain", it is a caller that did not say what it wanted, and
/// answering it with a default window would be this file choosing an auditor's question for them.
/// `to` before `from` is an inverted window, which selects nothing and is a malformed argument
/// rather than an empty answer.
///
/// A window that runs off either end of what the node holds is NOT an error: it is simply shorter,
/// which is [`expose::range_body`]'s own rule and stays its.
fn audit_window(target: &str) -> Option<(u64, u64)> {
    let (_, query) = target.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    let (mut from, mut to) = (None, None);
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        match name {
            "from" => from = Some(value.parse::<u64>().ok()?),
            "to" => to = Some(value.parse::<u64>().ok()?),
            _ => {}
        }
    }
    let (from, to) = (from?, to?);
    (from <= to).then_some((from, to))
}

/// The bytes one audit-chain read answers with.
///
/// Every refusal here is a DIFFERENT fact, and keeping them apart is the point of the function
/// (`docs/design/BUSBAR-1.6.0.md:2079`):
///
/// * `Validation` (400) — the range read named no window, or named one that selects nothing. The
///   caller's arguments are wrong and the node is fine.
/// * `NotFound` (404) — the node retains no records to answer a window from. The node is fine and
///   the caller's arguments are fine; the evidence is not kept. An empty `records` array would have
///   said the window was empty, which is a different and false thing.
/// * `Store` (500) — the bound view did not answer at all. A seam that returns without showing its
///   reader anything is broken, and a broken instrument must not report an empty chain.
///
/// The head and key reads answer from what the node holds whatever the records situation is: a chain
/// with nothing on it renders a null head, which is a true answer and a legitimate state.
fn render_audit_view(
    verb: KernelVerb,
    target: &str,
    view: &dyn AuditView,
) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
    use busbar_core_admin::GovernanceError;
    match verb {
        KernelVerb::GetAuditHead => {
            let mut body = None;
            view.read(&mut |chain, _records| {
                body = Some(expose::head_body(chain));
            });
            body.map(String::into_bytes).ok_or(GovernanceError::Store)
        }
        KernelVerb::GetAuditRange => {
            let (from, to) = audit_window(target).ok_or(GovernanceError::Validation)?;
            // Two layers, and they are two different answers: the outer says whether the view
            // answered, the inner says whether it retains records to answer with.
            let mut answered: Option<Option<String>> = None;
            view.read_window(from, to, &mut |chain, records| {
                answered =
                    Some(records.map(|records| expose::range_body(chain, records, from, to)));
            });
            match answered {
                None => Err(GovernanceError::Store),
                Some(None) => Err(GovernanceError::NotFound),
                Some(Some(body)) => Ok(body.into_bytes()),
            }
        }
        KernelVerb::GetAuditKeys => Ok(expose::keys_body(&view.keys()).into_bytes()),
        // Reachable only if the closed table and this match ever disagree, which is a defect in this
        // file rather than a request to forgive.
        _ => Err(GovernanceError::NotFound),
    }
}

/// Whether a pool name is one this node has configured — the `adjust` verb's pool check (owner
/// ruling Q64/Q67). A predicate rather than a list so a root can answer it from the LIVE
/// configuration, which a config apply may change.
pub type PoolKnown = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The pool check of a node no root bound a configuration to: it knows no pool.
fn no_pools() -> PoolKnown {
    Arc::new(|_| false)
}

/// The verbs unit's governance seam, bound to whatever executes an admin operation.
///
/// Every one of the trait's methods is a delegation. `execute_legacy` is the one that carries the
/// 66; `execute_new_verb` carries the 17, which reach the same seam because the surface that answers
/// them is the same surface. `execute_ledger_read` carries the 5 ledger views and `execute_audit_read`
/// the 3 chain reads, and those two are the methods that do NOT reach the dispatch: there is no
/// 1.5.5 handler behind a figure 1.5.5 never kept or a chain 1.5.5 never sealed, so the answer is
/// rendered here, from the bound view. The four governance-store methods
/// answer from the request the dispatch already ran, because minting a key IS an admin operation and
/// there is no second place this root is entitled to mint one.
pub struct CoreGovernance {
    dispatch: Arc<dyn AdminDispatch>,
    /// The figures the five ledger views read. Held beside the dispatch rather than behind it
    /// because the two answer different halves of the surface and neither can stand in for the
    /// other: a dispatch handed a ledger path would answer the 404 its router has for it.
    ledger: Arc<dyn LedgerView>,
    /// The evidence the three audit-chain reads answer from, where a root bound any.
    ///
    /// An OPTION, and the ledger beside it is not, because the two absences are different facts. A
    /// node with no ledger has no postings and says so in the view's own body; a node with no chain
    /// bound cannot say anything about a chain at all, and an empty head is a claim that it sealed
    /// nothing. The first is a measurement over an empty set, the second is no measurement —
    /// `docs/design/BUSBAR-1.6.0.md:2079`, and the reason `None` refuses rather than renders.
    audit: Option<Arc<dyn AuditView>>,
    /// The request the current unit is executing, so the seam's argument-free methods can reach it.
    /// One unit at a time per governance value, which is what the root guarantees by building one
    /// per unit rather than sharing one across them.
    request: AdminRequest,
    verb: KernelVerb,
    /// Where a sealed rate-card amendment is made durable, where a root bound one. `None` refuses
    /// `amend_rate_history` (`Store`): a correction nothing can record is not applied.
    amendments: Option<Arc<AmendmentJournal>>,
    /// THE NODE'S AMENDMENT JOURNAL (item 404), where a root bound it: what `verify` checks as
    /// held. `None` is a binding no root gave one, which holds no amendments to check.
    node_amendments: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,
    /// Who submitted this unit's call.
    attribution: AmendAttribution,
    /// The scope the caller was admitted under. `adjust` hands it to the kernel half, which
    /// refuses anything below `full` whatever the verbs unit decided. `ReadOnly` until a root says
    /// otherwise, so an unbound scope corrects nothing.
    granted: VerbScope,
    /// Which pool names `adjust` accepts (Q64/Q67): the node's configured pools. Knows none until
    /// a root binds them, so an unbound node refuses every correction's pool.
    pools: PoolKnown,
    /// Where `adjust` lands: the node's live usage counts.
    adjuster: adjust::UsageAdjuster,
    /// Which planes this node serves, for `plane_facts` and `plane_record_write` (Q71(2)). Knows
    /// none until a root binds the registry, so an unbound node answers every plane `404`.
    planes: PlaneLookup,
    /// Where `plane_record_write` lands its record. `None` refuses the write (`Store`): a record
    /// nothing kept was not written.
    records: Option<PlaneRecordSink>,
    /// The node's `Idempotency-Key` replay cache for the two Q71(2) writes (contract D-3).
    replays: Arc<bound::ReplayCache>,
    /// Where a key is claimed so a retry after a restart or on another node runs nothing twice.
    replay_store: Option<bound::ReplayStore>,
    /// The kernel's trust book, for the three trust verbs. No keys until a root binds it.
    trust: TrustDesk,
}

impl CoreGovernance {
    /// Bind the governance seam for one unit.
    #[must_use]
    pub fn new(
        dispatch: Arc<dyn AdminDispatch>,
        ledger: Arc<dyn LedgerView>,
        audit: Option<Arc<dyn AuditView>>,
        verb: KernelVerb,
        request: AdminRequest,
    ) -> Self {
        CoreGovernance {
            dispatch,
            ledger,
            audit,
            request,
            verb,
            amendments: None,
            node_amendments: None,
            attribution: AmendAttribution {
                principal: String::new(),
            },
            granted: VerbScope::ReadOnly,
            pools: no_pools(),
            adjuster: adjust::no_ledger(),
            planes: no_planes(),
            records: None,
            replays: Arc::new(bound::ReplayCache::new()),
            replay_store: None,
            trust: no_trust(),
        }
    }

    /// Bind the kernel's trust book (the three trust verbs).
    #[must_use]
    pub fn trusting(mut self, trust: TrustDesk) -> Self {
        self.trust = trust;
        self
    }

    /// Bind the node's `Idempotency-Key` replay cache (contract D-3) and the store its keys are
    /// claimed in.
    #[must_use]
    pub fn replaying(
        mut self,
        replays: Arc<bound::ReplayCache>,
        store: Option<bound::ReplayStore>,
    ) -> Self {
        self.replays = replays;
        self.replay_store = store;
        self
    }

    /// Bind the node's amendment journal (`verify`).
    #[must_use]
    pub fn noting(
        mut self,
        journal: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,
    ) -> Self {
        self.node_amendments = journal;
        self
    }

    /// Bind the planes this node serves and where a plane record is written (Q71(2)).
    #[must_use]
    pub fn planed(mut self, planes: PlaneLookup, records: Option<PlaneRecordSink>) -> Self {
        self.planes = planes;
        self.records = records;
        self
    }

    /// Bind the pool names `adjust` accepts (Q64/Q67).
    #[must_use]
    pub fn pooled(mut self, pools: PoolKnown) -> Self {
        self.pools = pools;
        self
    }

    /// Bind where `adjust` lands.
    #[must_use]
    pub fn adjusting(mut self, adjuster: adjust::UsageAdjuster) -> Self {
        self.adjuster = adjuster;
        self
    }

    /// Bind the scope the caller was admitted under.
    #[must_use]
    pub fn granted(mut self, granted: VerbScope) -> Self {
        self.granted = granted;
        self
    }

    /// Bind where an amendment is recorded and who is asking for it.
    #[must_use]
    pub fn amending(
        mut self,
        amendments: Option<Arc<AmendmentJournal>>,
        attribution: AmendAttribution,
    ) -> Self {
        self.amendments = amendments;
        self.attribution = attribution;
        self
    }

    /// Run the operation and take its whole answer.
    fn run(&self) -> AdminAnswer {
        self.dispatch.execute(self.verb, &self.request)
    }
}

impl busbar_core_admin::Governance for CoreGovernance {
    type Answer = AdminAnswer;

    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        Ok(self.run())
    }

    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        // `amend_rate_history` is the one new verb whose effect is NOT the mounted router's:
        // its correction lands on this root's own dated rate-card history, which no 1.5.5 handler
        // knows about. The scope and rate class were already run by the verbs unit before this seam
        // was reached, and that is the whole of its authorization: a plain scoped verb (#77(9),
        // OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md` l.2279 — no verb carries dual control, escrow
        // or operator signatures). This half speaks only to the correction's own shape and effect.
        if verb == KernelVerb::AmendRateHistory {
            return amend_rate_history_effect(
                &crate::root::kernel::ROOT_CARD,
                self.amendments.as_deref(),
                request,
                self.request.at,
                &self.attribution,
            );
        }
        // `adjust` (MONEY-DESIGN §4): a correction to a key's COUNTS, as a signed delta on the one
        // ledger, applied at once. Its scope and rate class ran in the verbs unit before this seam;
        // the effect re-checks the scope and refuses a delta that would take a count below zero.
        if verb == KernelVerb::Adjust {
            let scope = match self.granted {
                VerbScope::Full => busbar_contract::authz::Scope::Full,
                VerbScope::ReadOnly => busbar_contract::authz::Scope::ReadOnly,
            };
            return adjust::adjust_effect(request, scope, &*self.pools, &self.adjuster);
        }
        // The four verbs owner answer Q71(2) binds (see `bound`). Admitted by the verbs unit — scope
        // and rate class — before this seam was reached; none of them is the mounted router's.
        match verb {
            KernelVerb::Verify => {
                return bound::verify_effect(
                    self.ledger.as_ref(),
                    self.audit.as_deref(),
                    self.node_amendments.as_deref(),
                );
            }
            KernelVerb::PlaneFacts => {
                return bound::plane_facts_effect(&self.request.path, &*self.planes);
            }
            // ARCHITECT 2026-10-06: the operator's trust decisions, on the kernel's trust book.
            // Idempotent by their own rule (the same key twice is the same answer), so no replay.
            KernelVerb::GetTrust => {
                return bound::trust_list_effect(&self.trust);
            }
            KernelVerb::TrustApprove | KernelVerb::TrustRevoke => {
                let ruling = if verb == KernelVerb::TrustApprove {
                    busbar_kernel::trust::book::Ruling::Approve
                } else {
                    busbar_kernel::trust::book::Ruling::Revoke
                };
                return bound::trust_decide_effect(request, ruling, &self.trust);
            }
            // The two writes replay under contract D-3: a retry carrying the same `Idempotency-Key`
            // with the same body answers the first answer, byte for byte, and runs nothing again.
            KernelVerb::PlaneRecordWrite => {
                return bound::replayable(
                    &self.replays,
                    self.replay_store.as_ref(),
                    verb,
                    &self.attribution.principal,
                    &self.request,
                    request,
                    || {
                        bound::plane_record_write_effect(
                            request,
                            self.request.at,
                            &*self.planes,
                            self.records.as_ref(),
                        )
                    },
                );
            }
            KernelVerb::CommitUpgrade => {
                return bound::replayable(
                    &self.replays,
                    self.replay_store.as_ref(),
                    verb,
                    &self.attribution.principal,
                    &self.request,
                    request,
                    || {
                        bound::commit_upgrade_effect(
                            request,
                            self.request.at,
                            &self.attribution.principal,
                            self.amendments.as_deref(),
                        )
                    },
                );
            }
            _ => {}
        }
        Ok(self.run())
    }

    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        // The request body is deliberately unread. Every view is a `GET` whose whole identity is its
        // path, so a body would be an argument to an operation that takes none — and an operation
        // that quietly read one would have a second way to be asked a question, which is exactly the
        // kind of surface a closed table exists to prevent.
        let body = render_ledger_view(verb, self.ledger.as_ref())?;
        Ok(json_answer(body))
    }

    fn execute_audit_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        // The request body is deliberately unread, and the request PATH deliberately is. All three
        // reads are `GET`s: the head and the key set take no arguments at all, and the range read
        // takes its window as a query string, because a query names ARGUMENTS to an operation and
        // `from`/`to` are arguments. A body here would be a second way to ask the same question,
        // which is exactly what a closed table exists to prevent.
        let view = self
            .audit
            .as_deref()
            .ok_or(busbar_core_admin::GovernanceError::NotFound)?;
        render_audit_view(verb, &self.request.path, view).map(json_answer)
    }
}

/// The answer a ledger view or an audit-chain read produces: a 200 carrying JSON, and no other
/// header.
///
/// Nothing here is derived from a legacy response, because there is no legacy response to derive it
/// from — these paths did not exist. `content-type` is the one header a JSON body needs; a
/// `content-length` is the transport's to add, and adding one here would be this root deciding a
/// framing detail the listener already owns.
fn json_answer(body: Vec<u8>) -> AdminAnswer {
    AdminAnswer {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
    }
}

/// Whether `view` already holds `correction`: an amendment entry by the same author for the same
/// reason over the same window, carrying every figure the correction names. That is what the same
/// body produces each time it is applied, so a second one is a replay.
fn already_applied(
    view: busbar_kernel_ledger::cost::HistoryView<'_>,
    correction: &crate::root::kernel::Correction,
) -> bool {
    view.entries().iter().any(|entry| {
        matches!(
            entry.author(),
            busbar_kernel_ledger::cost::Author::Amend { .. }
        ) && entry.author() == &correction.author
            && entry.effective_from() == correction.effective_from
            && entry.effective_until() == correction.effective_until
            && correction.fee.is_none_or(|fee| entry.card().fee() == fee)
            && correction.cells.iter().all(|(cell, nanos)| {
                entry
                    .card()
                    .lane_rates(&cell.lane)
                    .filter(|rates| rates.class_priced(&cell.class))
                    .map(|rates| rates.nanos_per_unit(&cell.class))
                    == Some(*nanos)
            })
    })
}

/// The effect half of `amend_rate_history`: decode the correction, validate its shape, append
/// the back-dated entry to this root's dated rate-card history, and answer with the entry it
/// sealed.
///
/// The append is [`crate::root::kernel::RootHistory::amend`], which rewrites nothing: the entry the
/// correction out-ranks stays exactly as booked, and recompute reprices the corrected window against
/// the new entry. Every refusal here is a client-safe `GovernanceError`: a malformed body, a window
/// that corrects nothing, or a correction that moves no price is `Validation` (400); a history with
/// no opening entry to correct is `NotFound` (404). The verb's scope (`full`) and rate class ran
/// before this seam, so this half assumes an admitted call and adjudicates the correction itself:
/// its shape and its effect.
///
/// A PLAIN SCOPED VERB (#77(9), OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md` l.2279: "no verb
/// carries dual control, escrow or operator signatures. Each verb is a plain scoped verb authorized
/// by the per-verb allow-list on the admin token"; #24 l.2202 makes it a real verb and no more). The
/// body carries no signer and no signature, and a body that still names `operator_fingerprint` or
/// `signature` has them ignored like any other member this verb does not read: nothing about the
/// correction is verified against an operator key, because there is none.
///
/// It names no figure on the wire. The corrected rates go into the card, never into the answer, so
/// the control surface stays free of money vocabulary; the answer is the seq an invoice will cite,
/// the window it corrected and the digest of why.
fn amend_rate_history_effect(
    history: &crate::root::kernel::RootHistory,
    journal: Option<&AmendmentJournal>,
    body: &[u8],
    arrival_secs: u64,
    attribution: &AmendAttribution,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    use busbar_contract::abi::sdk::digest::sha256;
    use busbar_core_admin::GovernanceError;

    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;

    // The window the correction prices. `effective_from` is required; `effective_until` is optional
    // and, where present, must lie strictly after it — an empty or inverted window corrects nothing.
    let effective_from = obj
        .get("effective_from")
        .and_then(serde_json::Value::as_u64)
        .ok_or(GovernanceError::Validation)?;
    let effective_until = match obj.get("effective_until") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or(GovernanceError::Validation)?),
    };
    if effective_until.is_some_and(|until| until <= effective_from) {
        return Err(GovernanceError::Validation);
    }
    // A CORRECTION IS BACK-DATED OR IT IS NOT A CORRECTION (#79 "an entry whose
    // `effective_from` lies in the past"). A window that opens after the instant the correction
    // arrived prices a future no booked line has reached yet: that is a forward price, which is a
    // configuration write, and an amendment signed today must not be able to stand in for one.
    // `arrival_secs` is the second the call arrived in, so its first instant is never after it.
    if effective_from > arrival_secs.saturating_mul(1000) {
        return Err(GovernanceError::Validation);
    }
    // AN AMEND IS BOUNDED AND ENDS BEFORE IT ARRIVED (MONEY-DESIGN section 3a "Amends"). An open-ended
    // change is a card apply, which goes through `PUT /config/settings` and its rules; a window
    // reaching past the arrival would price instants nothing has posted yet, as a forward price.
    match effective_until {
        None => return Err(GovernanceError::Validation),
        Some(until) if until > arrival_secs.saturating_mul(1000) => {
            return Err(GovernanceError::Validation)
        }
        Some(_) => {}
    }

    // NO SIGNER AND NO SIGNATURE (#77(9)). The answer and the history entry name no signer; the
    // durable `v3` record keeps its `operator_fingerprint` / `signature` slots (no record shape
    // moves) and this node writes them empty, because no operator signs a correction.

    // The reason is free text and is not the record; its SHA-256 is, so the sealed entry is
    // fixed-width and the text cannot be edited under it.
    let reason = obj
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(GovernanceError::Validation)?;
    let reason_hash: [u8; 32] = sha256(reason.as_bytes());

    // **A CORRECTION MAY NOT NAME A DENOMINATION**, and one that tries is REFUSED rather than
    // accepted-and-ignored (#66 `BUSBAR-1.6.0.md:528`: money is UNITLESS abstract cost).
    //
    // THIS IS THE DEFECT THIS FIELD EXISTED AS. The key used to be read into a currency code, and a
    // currency code decided a ROUNDING SCALE: `"currency":"JPY"` moved the divisor from ten million
    // nano-units per minor unit to a billion, so the SAME rate figures on a corrected card became a
    // hundred times different money — with no conversion, no restatement, and nothing on the
    // amendment record to say the scale had moved. An operator correcting a typo in one rate could
    // reprice a whole window by two orders of magnitude by typing three letters.
    //
    // Tolerating the key silently would leave exactly that bug with an extra step, so the shape
    // refuses it: a body carrying `currency` at all is a body written against a contract this node
    // does not honour, and an amendment is the last place to guess what its author meant. The scale
    // is now `NANOS_PER_CENT`, a constant no request can name.
    if obj.contains_key("currency") {
        return Err(GovernanceError::Validation);
    }
    // The corrected cells. A correction must move at least one figure — a rate or the fee — because
    // an amendment that changes no price is a history append and nothing else. A fee it does not
    // name stays the fee in force: the corrected card is the card in force for the window with the
    // named cells set (`Correction::draft_over`), never a card of the named cells alone.
    //
    // A NEGATIVE FEE IS REFUSED HERE, at the signing door, and never reaches the card (item 29). The
    // card's constructor clamps a fee at zero, so a `-5` used to be SEALED into the append-only
    // history as a card charging `0` under a signature that covers `per_request_fee=-5`: an entry
    // whose figure is not the figure its signer signed, and a window silently repriced to free. A
    // fee below zero is not a price; the correction naming one is malformed, and a refusal appends
    // nothing.
    let per_request_fee = match obj.get("per_request_fee") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let fee = v.as_i64().ok_or(GovernanceError::Validation)?;
            if fee < 0 {
                return Err(GovernanceError::Validation);
            }
            Some(fee)
        }
    };
    let mut entries: Vec<(busbar_kernel_ledger::cost::LaneClass, u64)> = Vec::new();
    if let Some(rates) = obj.get("rates") {
        for row in rates.as_array().ok_or(GovernanceError::Validation)? {
            let r = row.as_object().ok_or(GovernanceError::Validation)?;
            let lane = r
                .get("lane")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(GovernanceError::Validation)?;
            let class = r
                .get("class")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(GovernanceError::Validation)?;
            // THE WIRE KEEPS ITS DECIMAL; THE CARD GETS AN INTEGER, EXACTLY OR NOT AT ALL. The rate
            // is written in micro-units per unit — the decimal form 1.5.5's own rate card took — and
            // becomes the card's integer nano-units here, at the edge, with no float arithmetic. A
            // figure finer than one nano-unit, negative, or too large is REFUSED: rounding it would
            // seal a price the signer did not sign.
            let nanos = match r.get("micro_per_unit") {
                Some(serde_json::Value::Number(n)) => exact_nano_rate(&n.to_string()),
                _ => None,
            }
            .ok_or(GovernanceError::Validation)?;
            entries.push((
                busbar_kernel_ledger::cost::LaneClass::new(lane, class),
                nanos,
            ));
        }
    }
    if entries.is_empty() && per_request_fee.is_none() {
        return Err(GovernanceError::Validation);
    }

    // The append. Milliseconds, because the history dates every instant in them; a correction written
    // "now" is written at the arrival it was admitted under, never a fresh clock read.
    let appended_at_ms = arrival_secs.saturating_mul(1000);

    // THE DURABLE RECORD, WRITTEN AHEAD OF THE APPEND (item 30). The only trail an amendment used to
    // leave was the root's legacy admin ring: a thousand in-memory entries behind a seam that does
    // nothing, four strings and no figure — erased by a thousand admin calls or one restart. The
    // record now goes onto the node's one journal, carrying every figure the correction sealed, the
    // principal that submitted it and the canonical bytes of the correction.
    //
    // AHEAD, not after: an amendment the journal will not take is REFUSED (`Store`) and the history
    // is not touched, so no correction can price a window without its durable record. And the
    // converse: a record the journal chained but could not keep yet is retained and lands ahead of
    // the next append (`AmendmentJournal::seal_policy`), so its correction is applied as the chain
    // will hold it (#79) and answered 503 "do not re-submit" below. A history with
    // no opening entry is refused first, so a record is never written for a correction that would
    // then not apply (the holder never returns to empty once resolved).
    //
    // THE CORRECTED CARD IS RESOLVED BEFORE THE RECORD (#79): the card in force for the window with
    // the named cells set. A window no single card prices — a config apply or an earlier
    // correction resolves part of it — or a cell on a plane whose billing is off has no one card to
    // correct: a correction that cannot say what it corrects is malformed (`Validation`, 400), and
    // nothing is recorded or appended. Split it at the boundary and sign each part.
    //
    // A CORRECTION THAT WOULD CUT INSIDE A STORED ROW IS REFUSED (OWNER ruling #32, 2026-09-29): a
    // metering row is one UTC day per price era priced at its own first instant, so a boundary
    // inside one reprices the whole row or none of it. Refused the same way, before anything is recorded.
    if history.is_empty() {
        return Err(GovernanceError::NotFound);
    }
    // THE HISTORY KEPT IN THE STORE takes the amend as an entry of its own (MONEY-DESIGN section 3a):
    // nothing goes on the journal.
    let in_store = history.keeps_store();
    let journal = if in_store {
        None
    } else {
        Some(journal.ok_or(GovernanceError::Store)?)
    };
    // WHERE THE STORE KEEPS THE JOURNAL, nothing is recorded while it is refusing the journal's
    // records: the correction is refused 503 with the reason (ARCHITECT 2026-10-07 H3 ruling (d)).
    if let Some(Err(why)) = journal.map(AmendmentJournal::admit) {
        return Ok(bound::journal_unavailable(&why));
    }
    let sealed_at: std::cell::Cell<Option<u64>> = std::cell::Cell::new(None);
    let correction = crate::root::kernel::Correction {
        effective_from,
        effective_until,
        appended_at: appended_at_ms,
        author: busbar_kernel_ledger::cost::Author::Amend { reason_hash },
        cells: entries,
        fee: per_request_fee,
    };
    let seq = history
        .amend_by(&correction, &attribution.principal, |card, base| {
            // A CORRECTION APPLIES ONCE. The body names the window, the cells, the fee
            // and the reason, and nothing that makes one submission different from the next — so
            // the same bytes, sent again after a later correction moved the window on, would put
            // the earlier price back with no new operator act. Under the apply lock (this closure
            // runs inside it, ahead of the seal), a correction the history already holds — same
            // reason, same window, same figures — is refused and nothing is recorded. Re-asserting
            // a price on purpose is a new correction: send it with the reason it is being
            // re-asserted for.
            if history
                .pin()
                .is_some_and(|pinned| already_applied(pinned.view(), &correction))
            {
                return Err(GovernanceError::Conflict);
            }
            let record = AmendmentRecord {
                effective_from,
                effective_until,
                amended_at_ms: appended_at_ms,
                sealed_over: Some(base),
                sealed_fee: card.fee(),
                rates: correction
                    .cells
                    .iter()
                    .map(|(cell, _)| (cell.lane.clone(), cell.class.clone()))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .map(|(lane, class)| {
                        // The figure the corrected card SEALED for each named cell — not the
                        // decimal the body spelt.
                        let nanos = card
                            .lane_rates(&lane)
                            .filter(|rates| rates.class_priced(&class))
                            .map(|rates| rates.nanos_per_unit(&class));
                        (lane, class, nanos)
                    })
                    .collect(),
                operator_fingerprint: String::new(),
                reason_hash,
                principal: attribution.principal.clone(),
                // The record's posture slot keeps its shape: one principal, no checker (#77(9)).
                dual_control: "single".to_string(),
                signed_payload: canonical_amend_payload(obj),
                signature: String::new(),
            };
            match journal {
                Some(journal) => journal
                    .seal_policy(amendment_body(&record), arrival_secs)
                    .map(|(node_seq, _)| sealed_at.set(Some(node_seq))),
                None => Ok(()),
            }
        })
        .map_err(|refused| match refused {
            crate::root::kernel::AmendRefused::NoHistory => GovernanceError::NotFound,
            crate::root::kernel::AmendRefused::NoSoleCard => GovernanceError::Validation,
            crate::root::kernel::AmendRefused::CutsRow(boundary) => {
                tracing::warn!(
                    boundary,
                    "amend_rate_history refused: the correction's boundary falls inside a metering \
                     row (a UTC day per price era) and would reprice all of it or none of it; \
                     correct from a UTC day boundary or the start of the card in force"
                );
                GovernanceError::Validation
            }
            crate::root::kernel::AmendRefused::Seal(e) => e,
            crate::root::kernel::AmendRefused::Store(why) => {
                tracing::warn!("amend_rate_history refused: {why}");
                GovernanceError::Store
            }
        })?;
    // AND THE ANSWER WAITS FOR THE STORE (ARCHITECT 2026-10-07 H3 ruling (d)). The correction is on
    // the chain and in force on this node, as the chain says; until the store has acknowledged it, a
    // restart elsewhere could not read it back, so it is not answered as done.
    if let (Some(node_seq), Some(journal)) = (sealed_at.get(), journal) {
        if let Err(why) = journal.acked(node_seq) {
            return Ok(bound::journal_unavailable(&format!(
                "the correction is sealed at journal position {node_seq} and not yet kept by the \
                 store: {why}; do not re-submit"
            )));
        }
    }

    let mut out = String::new();
    out.push_str("{\"history_seq\":");
    out.push_str(&seq.get().to_string());
    out.push_str(",\"effective_from\":");
    out.push_str(&effective_from.to_string());
    out.push_str(",\"effective_until\":");
    match effective_until {
        Some(until) => out.push_str(&until.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"amended_at\":");
    out.push_str(&appended_at_ms.to_string());
    out.push_str(",\"reason_sha256\":");
    json_string(&hex::encode(reason_hash), &mut out);
    out.push('}');
    Ok(json_answer(out.into_bytes()))
}

/// Who asked for a correction — the fact the verbs unit resolved at Route and the durable amendment
/// record states.
#[derive(Debug, Clone)]
pub struct AmendAttribution {
    /// The authenticated principal that submitted the correction.
    pub principal: String,
}

/// The domain tag every durable amendment record's body opens with, so a `Policy`-class journal
/// record is recognisable as a rate-card amendment without guessing.
///
/// `v2` states, per cell, whether the sealed card PRICED it: a `v1` record wrote an unpriced cell
/// as nanos 0, which a restart read back as a free cell where the live card refused it (#42).
///
/// `v3` records a correction OVER THE CARD IN FORCE ([`AmendmentRecord::sealed_over`]): its cells
/// are set on the card that priced the window, every other cell and plane card kept, and it names
/// that card's entry and digest so a restart rebuilds it over that card or refuses it.
pub const AMENDMENT_RECORD_TAG: &str = "busbar/rate-amendment/v3";

/// The `v2` tag: a record whose cells were the WHOLE sealed card, still read and rebuilt as that.
const AMENDMENT_RECORD_TAG_V2: &str = "busbar/rate-amendment/v2";

/// The tag a record written before [`AMENDMENT_RECORD_TAG`] carried, still read: every cell on it
/// reads back as the figure it holds, which is all a `v1` record can say.
const AMENDMENT_RECORD_TAG_V1: &str = "busbar/rate-amendment/v1";

/// One sealed rate-card amendment, as the node's journal keeps it: every figure the correction put
/// on the history, who submitted it, and the canonical bytes of the correction.
///
/// The `operator_fingerprint`, `dual_control` and `signature` slots keep the `v3` shape a record
/// already on a journal was written in. Under #77(9) (OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md`
/// l.2279: no verb carries dual control or operator signatures) this node writes them as the empty
/// fingerprint, `single` and the empty signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendmentRecord {
    /// Start of the corrected window, milliseconds.
    pub effective_from: u64,
    /// End of the corrected window, milliseconds; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When the correction was admitted, milliseconds.
    pub amended_at_ms: u64,
    /// `Some` (every record this node writes, `v3`): the cells are set OVER the card in force for
    /// the window, and this is that card's entry number and digest, written at amend time. A
    /// restart rebuilds the entry over the entry at that number holding that card, or refuses it
    /// ([`crate::root::kernel::CorrectionRefused`]). `None` for a `v1`/`v2` record, whose cells
    /// and fee were the whole card it sealed.
    pub sealed_over: Option<crate::root::kernel::CorrectionBase>,
    /// THE SEALED CARD'S FEE, MINOR UNITS — named `sealed_fee` and not the wire spelling.
    ///
    /// This is the journal's own internal record shape, not the wire: it stores what the sealed
    /// [`busbar_kernel_ledger::cost::RateCard`] already resolved (`card.fee()`), never the
    /// operator's raw JSON field. Kept off the `per_request_fee`/`fee_cents` spellings on purpose —
    /// `[rules.one-pricing-site.fee_allowed.amend-rate-history]` reviews exactly four reads of that
    /// wire name in this file (the parse, the shape refusal, the relay to the `Correction`, and
    /// the signed payload's own key literal); a durable record's encode/decode is not one of them,
    /// and giving it the wire's own name would silently spend two of the grant's four slots on a
    /// binary journal format that was never reviewed as a wire reader.
    pub sealed_fee: i64,
    /// `(lane, class, nanos_per_unit)` for every cell the correction named, as the card sealed it.
    /// `None` is a cell the card could not represent: UNPRICED, so a hit on it refuses (#42) — never
    /// a zero.
    pub rates: Vec<(String, String, Option<u64>)>,
    /// Empty on every record this node writes (#77(9): no operator signs a correction); a record
    /// written before that ruling holds `sha256(operator key)`, hex.
    pub operator_fingerprint: String,
    /// `sha256(reason)`.
    pub reason_hash: [u8; 32],
    /// The authenticated principal that submitted it.
    pub principal: String,
    /// `single` on every record this node writes (#77(9): no verb carries dual control).
    pub dual_control: String,
    /// The canonical payload of the correction ([`canonical_amend_payload`]).
    pub signed_payload: Vec<u8>,
    /// Empty on every record this node writes (#77(9)); a record written before that ruling holds
    /// the detached ed25519 signature, hex.
    pub signature: String,
}

/// The journal body of an [`AmendmentRecord`]: length-prefixed fields in a fixed order.
#[must_use]
pub fn amendment_body(record: &AmendmentRecord) -> Vec<u8> {
    let mut body = busbar_kernel_wal::BodyWriter::new();
    body.text(if record.sealed_over.is_some() {
        AMENDMENT_RECORD_TAG
    } else {
        AMENDMENT_RECORD_TAG_V2
    });
    body.num(record.effective_from);
    body.num(u64::from(record.effective_until.is_some()));
    body.num(record.effective_until.unwrap_or(0));
    body.num(record.amended_at_ms);
    if let Some(base) = &record.sealed_over {
        body.num(base.seq.get());
        body.bytes(&base.card_digest);
    }
    body.figure(i128::from(record.sealed_fee));
    body.num(record.rates.len() as u64);
    for (lane, class, nanos) in &record.rates {
        body.text(lane);
        body.text(class);
        body.num(u64::from(nanos.is_some()));
        body.num(nanos.unwrap_or(0));
    }
    body.text(&record.operator_fingerprint);
    body.bytes(&record.reason_hash);
    body.text(&record.principal);
    body.text(&record.dual_control);
    body.bytes(&record.signed_payload);
    body.text(&record.signature);
    body.finish()
}

/// Read an [`AmendmentRecord`] back off a journal body, or `None` for a body that is not one.
#[must_use]
pub fn amendment_from_body(body: &[u8]) -> Option<AmendmentRecord> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            Some(head)
        }
        fn num(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        fn figure(&mut self) -> Option<i128> {
            Some(i128::from_le_bytes(self.take(16)?.try_into().ok()?))
        }
        fn bytes(&mut self) -> Option<&'a [u8]> {
            let len = usize::try_from(self.num()?).ok()?;
            self.take(len)
        }
        fn text(&mut self) -> Option<String> {
            String::from_utf8(self.bytes()?.to_vec()).ok()
        }
    }
    let mut r = Reader(body);
    let (v2, v3) = match r.text()?.as_str() {
        AMENDMENT_RECORD_TAG => (true, true),
        AMENDMENT_RECORD_TAG_V2 => (true, false),
        AMENDMENT_RECORD_TAG_V1 => (false, false),
        _ => return None,
    };
    let effective_from = r.num()?;
    let has_until = r.num()?;
    let until = r.num()?;
    let amended_at_ms = r.num()?;
    let sealed_over = if v3 {
        Some(crate::root::kernel::CorrectionBase {
            seq: busbar_kernel_ledger::cost::HistorySeq(r.num()?),
            card_digest: r.bytes()?.try_into().ok()?,
        })
    } else {
        None
    };
    let sealed_fee = i64::try_from(r.figure()?).ok()?;
    let n = r.num()?;
    let mut rates = Vec::new();
    for _ in 0..n {
        let (lane, class) = (r.text()?, r.text()?);
        let priced = if v2 { r.num()? } else { 1 };
        let nanos = r.num()?;
        let nanos = match priced {
            0 => None,
            1 => Some(nanos),
            _ => return None,
        };
        rates.push((lane, class, nanos));
    }
    let record = AmendmentRecord {
        effective_from,
        effective_until: (has_until == 1).then_some(until),
        amended_at_ms,
        sealed_over,
        sealed_fee,
        rates,
        operator_fingerprint: r.text()?,
        reason_hash: r.bytes()?.try_into().ok()?,
        principal: r.text()?,
        dual_control: r.text()?,
        signed_payload: r.bytes()?.to_vec(),
        signature: r.text()?,
    };
    r.0.is_empty().then_some(record)
}

/// Where a sealed rate-card amendment is made durable: the node's ONE journal, as a `Policy`-class
/// record (a card entry is a pricing-policy generation), through the same token-gated append every
/// other journal record takes.
///
/// Not the admin ring and not a store of its own. The journal is on disk where the operator named a
/// data directory and kept by the configured store otherwise (its v3 record slots, read back at
/// boot); it is never pruned by volume, it replays after a restart, and it gives the amendment a
/// POSITION relative to the postings it reprices.
///
/// WHERE THE STORE IS THE JOURNAL'S DURABILITY (no data directory), a durable verb answers only
/// once the store ACKNOWLEDGED its record (ARCHITECT 2026-10-07 H3 ruling (d)): [`Self::admit`]
/// refuses before anything is recorded while the store is refusing the journal's records, and
/// [`Self::acked`] waits for the record's acknowledgement before the verb answers 200. Either
/// refusal is a 503 with the reason (`bound::journal_unavailable`).
pub struct AmendmentJournal {
    book: Arc<Mutex<crate::root::durability::Durability>>,
    token: Grant<busbar_contract::caps::DurableWrite>,
}

impl std::fmt::Debug for AmendmentJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmendmentJournal").finish_non_exhaustive()
    }
}

impl AmendmentJournal {
    /// Record amendments onto `book`'s journal under `token`.
    #[must_use]
    pub fn new(
        book: Arc<Mutex<crate::root::durability::Durability>>,
        token: Grant<busbar_contract::caps::DurableWrite>,
    ) -> Self {
        AmendmentJournal { book, token }
    }

    /// Append one amendment record, dated `wall_secs`.
    ///
    /// # Errors
    ///
    /// `Store` when the record can never land ([`Self::seal_policy`]) — the caller then refuses the
    /// amendment rather than applying a correction nothing recorded.
    pub fn record(
        &self,
        record: &AmendmentRecord,
        wall_secs: u64,
    ) -> Result<(), busbar_core_admin::GovernanceError> {
        self.seal_policy(amendment_body(record), wall_secs)
            .map(|_| ())
    }

    /// The durable verb's gate, BEFORE it records anything: `Err` with the reason while the store
    /// is where this journal is kept and is refusing its records (or the lane to it is full). A
    /// journal on a disk always admits.
    ///
    /// # Errors
    ///
    /// The reason the store is not taking the journal's records.
    pub fn admit(&self) -> Result<(), String> {
        let lane = {
            let durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
            if !durability.durable_in_store() {
                return Ok(());
            }
            durability.lane().cloned()
        };
        lane.map_or(Ok(()), |lane| lane.healthy())
    }

    /// WAIT FOR THE STORE TO ACKNOWLEDGE the record this journal sealed at `node_seq` (and so every
    /// record before it), at most [`crate::root::durability::ACK_DEADLINE`], without the book's
    /// lock. A journal on a disk answers at once: the disk took it.
    ///
    /// A record the log still OWES is not kept, on a disk or in the store: its write, its sync or
    /// its hand-over to the store failed, and the log retained it to write ahead of the next append
    /// ([`Self::seal_policy`]).
    ///
    /// # Errors
    ///
    /// The log still owes the record, or the store refused or did not answer in time. The record
    /// stays on the chain and is offered again.
    pub fn acked(&self, node_seq: u64) -> Result<(), String> {
        let (lane, node) = {
            let durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
            let node = durability.journal.node();
            let owed = durability.journal.log().owed().iter().any(|record| {
                let (of, seq) = record.identity();
                of == node && seq <= node_seq
            });
            if owed {
                return Err(
                    "the journal could not make the record durable; it is retained on \
                     this node's journal and written ahead of the next record"
                        .to_string(),
                );
            }
            if !durability.durable_in_store() {
                return Ok(());
            }
            (durability.lane().cloned(), node)
        };
        lane.map_or(Ok(()), |lane| {
            lane.wait_acked(node, node_seq, crate::root::durability::ACK_DEADLINE)
        })
    }

    /// Append one `Policy`-class record whose body the caller built, dated `wall_secs`, and answer
    /// with its node sequence and chain hash — the position an operator cites it by.
    ///
    /// SEALED IS SEALED, KEPT OR NOT (#79). The journal chains the record before the log is asked to
    /// take it, and a log that could not make it durable RETAINS it and writes it ahead of the next
    /// append (`busbar-kernel-wal` `Journal::append`, `Wal::append_batch`): it reaches the chain a
    /// restart rebuilds from. So a `DurabilityLost` the log holds or owes the record for answers
    /// its position like any other seal — the caller applies what it records and asks
    /// [`Self::acked`], which says it is not kept yet.
    ///
    /// # Errors
    ///
    /// `Store` when the log neither holds nor owes the record, so it can never land; the caller
    /// then refuses. A log that retains on every arm never answers it.
    pub fn seal_policy(
        &self,
        body: Vec<u8>,
        wall_secs: u64,
    ) -> Result<(u64, [u8; 32]), busbar_core_admin::GovernanceError> {
        let entry = busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Policy, body)
            .at(wall_secs, 0);
        let mut durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
        match durability.journal.append(
            &self.token,
            busbar_contract::caps::StepName::Route,
            &[entry],
        ) {
            Ok(ack) => {
                let sealed = ack
                    .sealed
                    .last()
                    .ok_or(busbar_core_admin::GovernanceError::Store)?;
                Ok((sealed.node_seq, sealed.hash))
            }
            Err(_lost) => {
                // The record was sealed last, so it is the number just below the journal's next
                // and the chain's head.
                let journal = &durability.journal;
                let sealed = (journal.node(), journal.next_seq().saturating_sub(1));
                let log = journal.log();
                if log.holds(sealed.0, sealed.1)
                    || log.owed().iter().any(|r| r.identity() == sealed)
                {
                    Ok((sealed.1, journal.head()))
                } else {
                    Err(busbar_core_admin::GovernanceError::Store)
                }
            }
        }
    }

    /// The node sequence of the newest record on this journal: at or past every record sealed on it
    /// before the call — an amendment the node amendment journal's sink put on this book as it was
    /// sealed included (`durability::bind_amendments`).
    #[must_use]
    pub fn sealed_through(&self) -> u64 {
        self.book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .next_seq()
            .saturating_sub(1)
    }
}

/// A rate in micro-units per unit, as its decimal TEXT, to the integer nano-units per unit the card
/// holds — exactly, or `None`. `1.5` is `1500`, `0.001` is `1`, `2e-3` is `2`; `0.0015` (a
/// half-nano-unit), a negative figure and one past `u64` are `None`. Decimal digits are shifted,
/// never multiplied as a float, so no value is rounded into a price nobody wrote.
fn exact_nano_rate(text: &str) -> Option<u64> {
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (text, 0),
    };
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        // Zero, however spelled (`-0.0` included): the operator configured the cell free.
        return Some(0);
    }
    if negative {
        return None;
    }
    // Nano-units are micro-units shifted three places left.
    let shift = i64::from(exponent) + 3 - i64::try_from(fraction.len()).ok()?;
    let digits = if shift < 0 {
        let cut = usize::try_from(-shift).ok()?;
        let keep = digits.len().checked_sub(cut)?;
        if !digits[keep..].bytes().all(|b| b == b'0') {
            return None;
        }
        &digits[..keep]
    } else {
        digits
    };
    let mut value: u64 = if digits.is_empty() {
        0
    } else {
        digits.parse().ok()?
    };
    for _ in 0..shift.max(0) {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

/// The canonical bytes of a correction, as the durable amendment record keeps them.
///
/// A domain-separated, order-fixed serialization of the correction's SEMANTIC fields — everything the
/// amendment means, and nothing about how it was transported: every field is rendered from the
/// parsed body, in a fixed order, each on its own line, so two spellings of the same JSON record the
/// same bytes. Nothing verifies a signature over them (#77(9)); the bytes stay on the record so an
/// auditor reads exactly what was corrected.
fn canonical_amend_payload(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
    let mut payload = String::from("busbar/amend-rate-history/v1\n");
    // `currency` is NOT in this list, and its absence is load-bearing rather than tidy: the field
    // is refused at the shape above (#66 — money is unitless, and a denomination decided a rounding
    // scale), so a body that carried one never reaches this function. A key nothing can send is a
    // key nothing can sign.
    for key in [
        "effective_from",
        "effective_until",
        "per_request_fee",
        "reason",
        "rates",
    ] {
        payload.push_str(key);
        payload.push('=');
        let value = obj.get(key).unwrap_or(&serde_json::Value::Null);
        payload.push_str(&serde_json::to_string(value).unwrap_or_default());
        payload.push('\n');
    }
    payload.into_bytes()
}

/// The bytes one ledger view answers with, or `NotFound` for a verb that is not one.
///
/// Every figure is THE ONE LEDGER'S: the store's usage counts priced by the card in core
/// ([`LedgerView::priced`]). `NotFound` is reachable only if the closed table and this match ever
/// disagree, which is a defect in this file rather than a request to forgive. A store that cannot be
/// read fails the read as `Store`; a row the card refuses to price (#42) is withheld and named
/// under `refused`, never served as a figure.
fn render_ledger_view(
    verb: KernelVerb,
    view: &dyn LedgerView,
) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
    let priced = || {
        view.priced().map_err(|why| {
            tracing::warn!(why = %why, "a ledger view could not read the ledger's counts");
            busbar_core_admin::GovernanceError::Store
        })
    };
    Ok(match verb {
        KernelVerb::GetLedgerTotals => render_totals(&priced()?)
            .map_err(|_| busbar_core_admin::GovernanceError::Store)?
            .into_bytes(),
        // NO CHECKPOINT IS SEALED: the ledger is the store's counts, and there is no second book
        // whose figures a checkpoint would seal (MONEY-DESIGN §3c, "Long units").
        KernelVerb::GetLedgerCheckpoints => b"{\"checkpoints\":[]}".to_vec(),
        KernelVerb::GetLedgerReconciliation => render_reconciliation(&priced()?).into_bytes(),
        // NOTHING TO MIGRATE: 1.6.0 reads the rows 1.5.5 wrote as the ledger itself, so no opening
        // balance is ever sealed and no marker exists.
        KernelVerb::GetLedgerMigration => b"{\"migrated\":false,\"marker\":null}".to_vec(),
        // THE ONE DOCUMENT, at the path the ledger views named for theirs, generated from the code.
        KernelVerb::GetLedgerOpenapiJson => {
            busbar_core_admin::v1::json::openapi_document().into_bytes()
        }
        _ => return Err(busbar_core_admin::GovernanceError::NotFound),
    })
}

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

/// The `refused` list the totals and reconciliation views serve: one entry per row the card refused
/// to price, naming the bucket, the window as the `day` its row is keyed by, and the refusal.
fn render_refused(refused: &[RefusedRow], out: &mut String) {
    out.push_str(",\"refused\":[");
    for (i, row) in refused.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"bucket\":");
        json_string(&row.bucket, out);
        out.push_str(",\"dimension\":\"nano-units\",\"scope\":\"all\",\"day\":");
        out.push_str(&row.day.to_string());
        out.push_str(",\"lane\":\"\",\"refusal\":");
        json_string(&row.refusal, out);
        out.push('}');
    }
    out.push(']');
}

/// `GET /api/v1/admin/ledger/totals` — what the ledger's counts come to: one row per key, its current
/// window, its counts priced at the card each was earned under (#79), the fee included, by the same
/// function `/keys/{id}/usage` answers from. The node keeps no lane or provider width on a bucket,
/// so both are empty.
fn render_totals(ledger: &PricedLedger) -> Result<String, MoneyError> {
    let mut out = String::from("{\"rows\":[");
    for (i, row) in ledger.rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"bucket\":");
        json_string(&row.bucket, &mut out);
        out.push_str(",\"day\":");
        out.push_str(&row.day.to_string());
        out.push_str(",\"lane\":\"\",\"provider\":\"\",\"priced_nanos\":\"");
        out.push_str(&row.priced_nanos.to_string());
        out.push_str("\",\"priced_micros\":");
        json_amount(
            i128::from(Money::of_nanos(row.priced_nanos)?.micros_i64()?),
            &mut out,
        );
        out.push_str(",\"fee_count\":");
        out.push_str(&row.fee_count.to_string());
        out.push('}');
    }
    out.push(']');
    render_refused(&ledger.refused, &mut out);
    out.push('}');
    Ok(out)
}

/// `GET /api/v1/admin/ledger/reconciliation` — whether every count the ledger holds is priced. There
/// is ONE ledger, so there is no second set of rows to disagree with it: the identity holds unless
/// the card refused a row, which is named.
fn render_reconciliation(ledger: &PricedLedger) -> String {
    let mut out = String::from("{\"holds\":");
    out.push_str(if ledger.refused.is_empty() {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"discrepancies\":[]");
    render_refused(&ledger.refused, &mut out);
    out.push('}');
    out
}

/// ONE ADMIN REQUEST, AS ITS STEPS WALK IT: the request, and what each step decided about it.
///
/// Owned by the one call that answers the request ([`AdminNode::answer`]) and handed to each step in
/// turn, so a step reads exactly the field it needs and nothing outlives the request: there is no
/// node-wide table for an entry to leak from.
#[derive(Debug)]
pub(crate) struct AdminWalk {
    request: AdminRequest,
    verb: Option<ResolvedVerb>,
    granted: Option<VerbScope>,
    /// The per-verb allow-list the door identified the caller with, when its bindings grant verbs
    /// BY NAME (#77(9) l.2279); `None` = the rung alone decides, as it did in 1.5.5.
    listed: Option<busbar_kernel::auth::VerbAllowList>,
    /// Who the auth step said is calling, kept from Verify on. The credential that was presented is
    /// NOT the identity that was resolved: the identity is what a record attributes to, and the
    /// credential is a secret that must not travel past the step that verified it.
    principal: Option<PrincipalId>,
    answer: Option<AdminAnswer>,
}

impl AdminWalk {
    /// A request no step has looked at yet.
    #[must_use]
    pub(crate) fn new(request: AdminRequest) -> Self {
        AdminWalk {
            request,
            verb: None,
            granted: None,
            listed: None,
            principal: None,
            answer: None,
        }
    }
}

/// THE ADMIN DOOR: one request's verdict on the deployment's admin chain. Production binds
/// [`live_admin_door`], which reads the LIVE snapshot per call; a test states its own posture.
pub type AdminDoorFn = Arc<dyn Fn(&AdminRequest) -> busbar_kernel::auth::AdminDoor + Send + Sync>;

/// A test's explicit OPEN door: the `admin_auth: []` posture, stated rather than defaulted.
#[cfg(test)]
pub(crate) fn open_door() -> AdminDoorFn {
    Arc::new(|_: &AdminRequest| busbar_kernel::auth::AdminDoor::Open)
}

/// A test's door over an identity chain, judged on the presented credential by the rule the
/// kernel's scope resolution applies to a roleless principal: the operator's id holds the full
/// tier, any other identity earns no grant (authenticated, not authorized).
#[cfg(test)]
pub(crate) fn door_of_chain(chain: busbar_kernel_identity::AuthChain) -> AdminDoorFn {
    use busbar_kernel::auth::AdminDoor;
    use busbar_kernel_identity::chain::ChainVerdict;
    Arc::new(
        move |request: &AdminRequest| match chain.run_chain(request.credential.as_deref()) {
            ChainVerdict::Open => AdminDoor::Open,
            ChainVerdict::Denied => AdminDoor::Denied,
            ChainVerdict::Identified { principal, .. } => {
                let grants = if principal.id == crate::root::auth_bindings::ADMIN_PRINCIPAL_ID {
                    busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full)
                } else {
                    busbar_contract::authz::Grants::default()
                };
                let principal = busbar_contract::auth::Principal::from_id(principal.id);
                AdminDoor::Identified(principal, grants)
            }
        },
    )
}

/// Everything the admin steps are composed over.
///
/// Held by [`crate::root::kernel::ProductionUnits`] as one field, so that the steps read one thing
/// rather than five. The dispatch is the seam to where the verbs' bodies live.
pub struct AdminBinding {
    /// The seam an operation's body is reached through.
    pub dispatch: Arc<dyn AdminDispatch>,
    /// THE ADMIN DOOR the authenticate step asks (see [`AdminDoorFn`]). Required at construction:
    /// there is no default door, so an unwired one is a compile error, never a silent open door.
    pub door: AdminDoorFn,
    /// The figures the five 1.6.0 ledger views read.
    ///
    /// A second seam beside the dispatch, not a widening of it. The 66 legacy operations and the 17
    /// money-governance verbs all reach a surface that already answers them; the views reach
    /// figures that surface never kept, so they need somewhere else to reach, and giving them their
    /// own read-only seam is what stops the dispatch from acquiring a way to read money.
    pub ledger: Arc<dyn LedgerView>,
    /// The evidence the three 1.6.0 audit-chain reads answer from.
    ///
    /// A fourth seam, beside the ledger for the same reason the ledger is beside the dispatch: what
    /// a chain read answers with is not money and not a mounted router's response, and an integrator
    /// that bound one of those has not thereby bound this. `None` is a node no root gave a chain to,
    /// and it REFUSES the three reads rather than rendering an empty head — an unbound chain and a
    /// chain that has sealed nothing are different facts, and only the second is a measurement.
    pub audit: Option<Arc<dyn AuditView>>,
    /// Where a sealed rate-card amendment is made durable: the node's own journal. `None` until a
    /// root binds one, and `amend_rate_history` refuses while it is `None` — an amendment is never
    /// applied without its durable record (item 30).
    pub amendments: Option<Arc<AmendmentJournal>>,
    /// THE NODE'S AMENDMENT JOURNAL (item 404): the one its `App` carries, which `verify` checks as
    /// held. `None` until a root binds it.
    pub node_amendments: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,
    /// The configured store an `Idempotency-Key` is claimed in, so a retry after a restart or on
    /// another node never runs a write twice (`busbar_core_admin::idempotency::durable`). `None`
    /// until a root binds one: a composition with no store has nowhere to keep a claim, and its keys
    /// answer for its own process only.
    pub replay_store: Option<bound::ReplayStore>,
    /// Which pool names an `adjust` may name (Q64/Q67): the node's CONFIGURED pools, read live.
    /// Knows none until a root binds them, so a node composed without a configuration refuses every
    /// correction's pool rather than accepting one it cannot check.
    pub pools: PoolKnown,
    /// Where an `adjust` lands: the node's live usage counts, the one ledger. A store failure for
    /// every correction until a root binds one.
    pub adjuster: adjust::UsageAdjuster,
    /// Which planes this node serves, and what each declares (`plane_facts`, `plane_record_write`;
    /// Q71(2)). Knows none until a root binds the registry over its live configuration (Law 7).
    pub planes: PlaneLookup,
    /// Where `plane_record_write` lands a record: the plane-facing store seam. `None` until a root
    /// binds one, and the verb then refuses rather than accept a write nothing keeps.
    pub records: Option<PlaneRecordSink>,
    /// The kernel's trust book the three trust verbs read and decide over (ARCHITECT 2026-10-06).
    /// No keys until a root binds the kernel's composed services.
    pub trust: TrustDesk,
    /// THE NODE'S `Idempotency-Key` REPLAY CACHE for `plane_record_write` and `commit_upgrade`
    /// (contract D-3). Node-level, because a unit's governance value lives for one request; what
    /// outlives the process is the claim in [`AdminBinding::replay_store`].
    pub replays: Arc<std::sync::OnceLock<Arc<bound::ReplayCache>>>,
    /// THE NODE'S MUTATION LIMITER for the verbs unit: built once, here, with the binding, and
    /// handed to every `Verbs` the route step builds. A `Verbs` lives for one request, so the
    /// limiter it used to build for itself saw an empty window on every call and never refused.
    /// It spends only the new verbs; a legacy verb is spent by the mounted surface's own limiter,
    /// so each request is counted by exactly one of the two.
    pub mutations: Arc<busbar_core_admin::rate::MutationLimiter>,
}

impl std::fmt::Debug for AdminBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminBinding").finish_non_exhaustive()
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
    pub fn new(dispatch: Arc<dyn AdminDispatch>, door: AdminDoorFn) -> Self {
        AdminBinding {
            dispatch,
            door,
            ledger: Arc::new(UnopenedLedger),
            audit: None,
            amendments: None,
            node_amendments: None,
            replay_store: None,
            pools: no_pools(),
            adjuster: adjust::no_ledger(),
            planes: no_planes(),
            records: None,
            trust: no_trust(),
            replays: Arc::new(std::sync::OnceLock::new()),
            mutations: Arc::new(busbar_core_admin::rate::MutationLimiter::new()),
        }
    }

    /// Bind the pool names an `adjust` may name to the node's configured pools (Q64/Q67).
    #[must_use]
    pub fn with_pools(mut self, pools: PoolKnown) -> Self {
        self.pools = pools;
        self
    }

    /// Bind the ledger views to the figures a node actually holds.
    #[must_use]
    pub fn with_ledger_view(mut self, ledger: Arc<dyn LedgerView>) -> Self {
        self.ledger = ledger;
        self
    }

    /// Bind the three chain reads to the evidence a node actually holds.
    ///
    /// Until a root calls this the three verbs refuse with a `NotFound` that says the node has no
    /// chain bound — never with an empty head, which would be a node claiming it had sealed nothing.
    #[must_use]
    pub fn with_audit_view(mut self, audit: Arc<dyn AuditView>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Bind the journal a sealed rate-card amendment is recorded on.
    #[must_use]
    pub fn with_amendment_journal(mut self, journal: Arc<AmendmentJournal>) -> Self {
        self.amendments = Some(journal);
        self
    }

    /// Bind the node's amendment journal (item 404): the one its `App` carries.
    #[must_use]
    pub fn with_node_amendments(
        mut self,
        journal: Arc<busbar_kernel_audit::amend::NodeAmendments>,
    ) -> Self {
        self.node_amendments = Some(journal);
        self
    }
}

/// The kernel verb the closed table's row names: the row of the one table in `busbar-core-admin`
/// with that method and templated path. A row with no verb cannot exist; `None` is a request line
/// the table does not declare.
#[must_use]
pub fn kernel_verb(resolved: &ResolvedVerb) -> Option<KernelVerb> {
    busbar_core_admin::verb::verb_for(resolved.method, resolved.template)
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

// ── the steps, as the admin surface runs them ──────────────────────────────────────────────────

/// THE ADMIN UNIT'S DECISION, step by step, in the loop's order: decode, authenticate, verify,
/// approve, admit, then the verb itself at Route.
///
/// Called directly, not walked as a kernel unit. An admin unit holds nothing, is charged nothing and
/// draws no lease (a kernel verb is exempt from the gauge), so the hold cell, the in-flight slot and
/// the settling exit a priced unit needs would be furniture here. What stays is the order and the
/// stamp: a refusal before the verb ran ends the unit `Refused` at the step that decided it, and a
/// verb that refused ends it `Failed` at Route — exactly the endings the loop sealed.
pub(crate) fn decide(
    units: &crate::root::kernel::ProductionUnits,
    walk: &mut AdminWalk,
) -> Outcome {
    use busbar_contract::caps::StepName;
    let at = |step: StepName| move |reason: ReasonCode| Outcome::Refused(step, reason);
    let ran = decode(walk)
        .map_err(at(StepName::Decode))
        .and_then(|()| {
            authenticate(&units.admin, &units.auth_bindings, walk)
                .map_err(at(StepName::Authenticate))
        })
        .and_then(|principal| verify(walk, &principal).map_err(at(StepName::Verify)))
        .and_then(|()| approve(walk).map_err(at(StepName::Approve)))
        .and_then(|()| admit(walk).map_err(at(StepName::Admit)))
        .and_then(|()| {
            route(&units.admin, units.store.clone(), &units.admin_token, walk)
                .map_err(|reason| Outcome::Failed(StepName::Route, reason))
        });
    match ran {
        Ok(()) => Outcome::Completed,
        Err(ended) => ended,
    }
}

/// Decode. The plane's closed table is the only thing consulted. A pair it does not declare is an
/// unsupported operation, which is a decode refusal and not a later one: nothing downstream should
/// be asked to authorize an operation that does not exist.
pub(crate) fn decode(walk: &mut AdminWalk) -> Result<(), ReasonCode> {
    match busbar_core_admin::admin_codec::verbs::resolve(&walk.request.method, &walk.request.path) {
        None => Err(ReasonCode::DecodeFailed),
        Some(resolved) => {
            walk.verb = Some(resolved);
            Ok(())
        }
    }
}

/// Authenticate. Who is calling: THE ADMIN DOOR, the one admin chain every admin door answers from.
///
/// The binding's [`AdminDoorFn`] judges the request on the deployment's LIVE `admin_auth` chain
/// (`busbar_kernel::auth::admin_door`, the kernel middleware's own verdict), so a chain an operator
/// configured — empty, the operator token, an external module — and a `PUT /admin-auth` that swaps
/// it are what this step answers from, with no restart. The door's grants are kept on the walk for
/// the approve step. Revocation then gates the identification, over the one set the node keeps: an
/// admin unit is always a new unit, and a set nothing supplies revokes nothing.
pub(crate) fn authenticate(
    binding: &AdminBinding,
    bindings: &crate::root::auth_bindings::AuthBindings,
    walk: &mut AdminWalk,
) -> Result<PrincipalId, ReasonCode> {
    let request = &walk.request;
    let revoked = || {
        bindings
            .revocations()
            .zip(request.credential.as_deref())
            .is_some_and(|(set, credential)| set.is_revoked(credential))
    };
    let (principal, grants, listed) = match (binding.door)(request) {
        busbar_kernel::auth::AdminDoor::Open => (
            busbar_kernel_identity::principal::ANONYMOUS.to_string(),
            busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
            None,
        ),
        busbar_kernel::auth::AdminDoor::Identified(principal, grants) => {
            if revoked() {
                return Err(ReasonCode::Revoked);
            }
            (principal.id, grants, None)
        }
        busbar_kernel::auth::AdminDoor::Listed(principal, grants, list) => {
            if revoked() {
                return Err(ReasonCode::Revoked);
            }
            (principal.id, grants, Some(list))
        }
        busbar_kernel::auth::AdminDoor::Denied => return Err(ReasonCode::Unauthenticated),
    };
    // The two-rung matrix the approve step compares against: the highest rung the grants reach, or
    // no grant at all (identified, not authorized: 403).
    use busbar_contract::authz::Scope as Rung;
    if grants.allows(Rung::Full) {
        walk.granted = Some(VerbScope::Full);
    } else if grants.allows(Rung::ReadOnly) {
        walk.granted = Some(VerbScope::ReadOnly);
    }
    // The verbs the caller holds BY NAME, for approve to read beside the rung (#77(9) l.2279).
    if listed.is_some() {
        walk.listed = listed;
    }
    Ok(PrincipalId::new(principal))
}

/// Verify. Where the unit may go: the kernel verb the table resolved, which is not a priced place —
/// a kernel verb is not dialled and is not billed, so an admin unit seals no destination and draws
/// no request slot and no flat fee, whatever the deployment configured the fee to be.
///
/// The step still refuses: a unit whose verb the table never resolved has nowhere to go at all. And
/// it is the step that keeps the resolved identity: every later step that has to say WHO reads it
/// from here rather than from the request, because the request carries the presented credential and
/// a credential is not an identity.
pub(crate) fn verify(walk: &mut AdminWalk, principal: &PrincipalId) -> Result<(), ReasonCode> {
    walk.principal = Some(principal.clone());
    match walk.verb {
        None => Err(ReasonCode::NoDestination),
        Some(_resolved) => Ok(()),
    }
}

/// Approve. Whether the caller may do this at all, through the scope unit's admin lookup.
///
/// The lookup is the 1.5.5 authorization matrix as data: method and path decide the scope, never the
/// body. The grant the caller holds is compared against it, and a grant the caller does not hold is
/// a scope refusal at this step rather than a surprise inside the operation.
pub(crate) fn approve(walk: &AdminWalk) -> Result<(), ReasonCode> {
    // A caller holding no grant at all is refused here, before the operation is reached. An absent
    // grant is not a narrow one: there is no scope to compare the matrix against.
    let Some(granted) = walk.granted else {
        return Err(ReasonCode::ScopeDenied);
    };
    let needed =
        busbar_kernel::admin::scope::admin_required_scope(&walk.request.method, &walk.request.path);
    if !granted.allows(scope_as_verb_scope(needed)) {
        return Err(ReasonCode::ScopeDenied);
    }
    // THE PER-VERB ALLOW-LIST (#77(9), OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md` l.2279): a
    // caller holding verbs BY NAME is admitted only to a verb its list reaches — the closed table's
    // name for this operation, as decode resolved it — and refused with the same scope ending as a
    // rung it does not hold. A caller with no list is decided by the rung alone, as before.
    if let Some(list) = &walk.listed {
        let verb = walk.verb.map(|resolved| resolved.verb);
        if !list.admits(verb, needed) {
            return Err(ReasonCode::ScopeDenied);
        }
    }
    Ok(())
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

/// Admit. An admin unit draws no dimension and takes no concurrency lease: the admin API answers at
/// a saturated `concurrent` cap. What the step does is read the mutation rate class off the verbs
/// unit's table — the binding the composition root owes that crate — for a verb the table names.
pub(crate) fn admit(walk: &AdminWalk) -> Result<(), ReasonCode> {
    let verb = walk
        .verb
        .as_ref()
        .and_then(kernel_verb)
        .ok_or(ReasonCode::NoDestination)?;
    // The class is read here — that is the binding — and read is ALL it is. `Forbidden` in this
    // vocabulary does not mean the verb is refused; it means the verb is not a mutation and the
    // mutation budget therefore does not apply to it. Reading it as a refusal turned every read on
    // the surface into a 403.
    let _class = mutation_class(verb);
    Ok(())
}

/// Route. The verb runs, where its body lives.
///
/// The verbs unit is what executes it — it is the crate that holds the admin token and the closed
/// verb enumeration — and the governance seam under it is what reaches the surface the operation
/// already belongs to. The whole answer comes back and is kept on the walk.
///
/// The five ledger views travel this same path and are not special-cased here. They reach
/// `Verbs::execute` like every other verb, are scope-checked and rate-classed by the same two lines,
/// and differ only in which method of the governance seam the unit calls at the end of it.
pub(crate) fn route(
    binding: &AdminBinding,
    store: crate::root::kernel::VerbStoreHandle,
    admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    walk: &mut AdminWalk,
) -> Result<(), ReasonCode> {
    let verb = walk
        .verb
        .as_ref()
        .and_then(kernel_verb)
        .ok_or(ReasonCode::NoDestination)?;
    // THE GRANT APPROVE CHECKED, and nothing in its place. Approve refuses a caller holding none, so
    // a walk here without one skipped that step: it is refused, never handed the endpoint's own
    // required scope as if it held it.
    let granted = walk.granted.ok_or(ReasonCode::ScopeDenied)?;
    let request = &walk.request;

    // THE ONE PLACE THE CHOICE IS MADE. Written as a named question rather than an inline pair so
    // that "these two verbs and no others" is a fact with a test on it instead of a condition to
    // re-read.
    if mints_its_own_identity(verb) {
        walk.answer = Some(binding.dispatch.execute(verb, request));
        return Ok(());
    }

    // The same identity the record attributes to, so the rate-limit bucket and the audit row name
    // one actor. Keying either on the credential instead let one principal be two by presenting a
    // second token. Every verb is a plain scoped verb (#77(9), OWNER-LOCKED,
    // `docs/design/BUSBAR-1.6.0.md` l.2279), authorized by the grant Approve checked.
    let actor = actor_of(walk);

    let verbs = busbar_core_admin::Verbs::new(
        CoreGovernance::new(
            Arc::clone(&binding.dispatch),
            Arc::clone(&binding.ledger),
            binding.audit.clone(),
            verb,
            request.clone(),
        )
        .amending(
            binding.amendments.clone(),
            AmendAttribution {
                principal: actor.clone(),
            },
        )
        .noting(binding.node_amendments.clone())
        .granted(granted)
        .pooled(Arc::clone(&binding.pools))
        .adjusting(Arc::clone(&binding.adjuster))
        .planed(Arc::clone(&binding.planes), binding.records.clone())
        .trusting(Arc::clone(&binding.trust))
        .replaying(
            Arc::clone(
                binding
                    .replays
                    .get_or_init(|| Arc::new(bound::ReplayCache::new())),
            ),
            binding.replay_store.clone(),
        ),
        store,
        CONFIG_CLASS_RULES,
        Arc::clone(&binding.mutations),
    );

    // THE TWO DISASTER-RECOVERY VERBS REACH THE STORE, not the governance seam. They are admitted
    // exactly as every other new verb is — scope, then rate class — but their effect lands on
    // `Store` rather than on a handler. Sending them through `execute` sent them to
    // `execute_new_verb`, which asks the mounted router for a path that release never had: the gates
    // passed, and the caller got a 404 from the surface underneath.
    let answer = if let Some(recovery) = recovery_verb(verb) {
        let ran = match recovery {
            RecoveryVerb::ChainBreak => verbs.chain_break(admin, &actor, granted, request.at),
            RecoveryVerb::StoreRestore => {
                // The backup the operator named. There is no default and no empty one: restoring
                // "whatever the store thinks" is the single most destructive thing this surface can
                // be asked to do by accident, so a request that names none is refused before it
                // reaches the store rather than resolved to something.
                let backup_ref = backup_ref_of(&request.body).ok_or(ReasonCode::DecodeFailed)?;
                verbs.store_restore(admin, &actor, granted, request.at, &backup_ref)
            }
        };
        ran.map(|()| applied_answer())
    } else {
        verbs.execute(verb, admin, &actor, granted, request.at, &request.body)
    };
    walk.answer = Some(answer.map_err(|refusal| verbs_reason(refusal.reason))?);
    Ok(())
}

/// The two verbs whose effect lands on the store rather than on a handler.
///
/// Named as a closed enumeration of its own rather than matched inline, so "these two and no
/// others" is a fact with a test on it. The verbs unit draws the same line from the other side: it
/// gives each of them a method, and gives `execute` no arm that could reach one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryVerb {
    ChainBreak,
    StoreRestore,
}

/// Which recovery verb this is, or `None` for a verb whose effect is the governance seam's.
fn recovery_verb(verb: KernelVerb) -> Option<RecoveryVerb> {
    match verb {
        KernelVerb::ChainBreak => Some(RecoveryVerb::ChainBreak),
        KernelVerb::StoreRestore => Some(RecoveryVerb::StoreRestore),
        _ => None,
    }
}

/// What an operation that changed something and has nothing to say answers with.
///
/// A recovery verb's whole result is its effect: the chain broke (a restore is refused, never
/// answered here, row 187). There is no document to return and none was ever specified, so the answer carries no
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
/// `None` where no identity was resolved: a unit refused at or before Authenticate has no actor.
fn resolved_actor(walk: &AdminWalk) -> Option<String> {
    walk.principal.as_ref().map(|p| p.as_str().to_string())
}

/// What a step that must name somebody uses when the identity did not resolve.
///
/// Reached only by Route, and Route is downstream of Authenticate — a unit that reaches it has a
/// principal, so this is the shape of an impossibility rather than a fallback anything exercises.
const UNRESOLVED_ACTOR: &str = "admin";

/// The identity a step that cannot decline is handed. See [`UNRESOLVED_ACTOR`].
fn actor_of(walk: &AdminWalk) -> String {
    resolved_actor(walk).unwrap_or_else(|| UNRESOLVED_ACTOR.to_string())
}

/// The verbs unit's refusal vocabulary, said in the kernel's.
///
/// Two closed lists that name the same events. Mapping them here rather than merging them keeps a
/// unit's reasons its own — the verbs unit may gain a reason the kernel has no step for, and the
/// kernel may gain a step no verb reaches.
fn verbs_reason(reason: busbar_core_admin::ReasonCode) -> ReasonCode {
    use busbar_core_admin::ReasonCode as V;
    match reason {
        V::Unauthorized => ReasonCode::ScopeDenied,
        V::RateLimited => ReasonCode::RateLimited,
        V::NotFound => ReasonCode::NoDestination,
        V::IdempotencyInFlight | V::Conflict => ReasonCode::OpenSlotBusy,
        V::Validation => ReasonCode::DecodeFailed,
        V::StoreError | V::Internal => ReasonCode::DurabilityUnavailable,
    }
}

/// Audit. The end, stated as the facts the unit's one record seals — for every ending, admitted or
/// refused.
///
/// There is ONE administrative ring — the kernel's durable one, and it is what an operator's
/// `/audit` page reads. A 1.5.5 verb's row is written onto it by the core-admin handler as the
/// mutation applies, so this step writes none for those (a second copy was item 237). A ROOT-ONLY
/// mutating verb has no core-admin handler to write it, so this step writes its one row onto that
/// same ring ([`seal_root_only`]): `applied` only for a 2xx answer the operation produced, every
/// other end `rejected`. Beyond that the step decides the operation class and the finish.
pub(crate) fn audit(walk: &AdminWalk, ended: &Outcome) -> busbar_contract::AuditFacts {
    let Some(resolved) = walk.verb else {
        // THE ENDING THAT HAPPENED, not one composed here: a revoked credential, a denied scope and
        // an undeclared operation each leave the record of what they were refused for.
        return unresolved_facts(Some(&walk.request.method), ended);
    };
    let applied = matches!(ended, Outcome::Completed)
        && walk
            .answer
            .as_ref()
            .is_some_and(|answer| (200..300).contains(&answer.status));
    seal_root_only(walk, &resolved, applied);
    busbar_contract::AuditFacts {
        op_class: resolved.op_class(),
        finish: finish_of(ended),
    }
}

/// ONE row on the kernel's durable administrative ring for a ROOT-ONLY mutating verb — a 1.6.0 verb
/// (`NEW_VERBS`, reads excluded) whose effect lands on this root or its store, where no core-admin
/// handler exists to write the row. A unit refused before its identity resolved writes nothing: no
/// principal acted, and a row naming one would attribute the attempt to somebody who was not there.
fn seal_root_only(walk: &AdminWalk, resolved: &ResolvedVerb, applied: bool) {
    let root_only =
        !resolved.read_only && kernel_verb(resolved).is_some_and(|v| NEW_VERBS.contains(&v));
    if let (true, Some(actor)) = (root_only, resolved_actor(walk)) {
        let outcome = if applied {
            busbar_kernel::audit_ring::OUTCOME_APPLIED
        } else {
            busbar_kernel::audit_ring::OUTCOME_REJECTED
        };
        busbar_kernel::audit_ring::AUDIT.record_by(
            resolved.verb,
            resolved.template,
            outcome,
            &actor,
        );
    }
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

fn finish_of(outcome: &Outcome) -> busbar_contract::FinishClass {
    match outcome {
        Outcome::Completed => busbar_contract::FinishClass::Complete,
        _ => busbar_contract::FinishClass::Error,
    }
}

// ── the mount: one HTTP surface, one loop, one answer ───────────────────────────────────────────
//
// In its own file (`admin_mount.rs`), re-exported here so every caller — `main.rs`, the tests
// below — still names it at `root::units_admin::…` exactly as before.
mod admin_mount;
pub(crate) use admin_mount::*;

// ── `adjust` and the bound verbs: sibling modules, re-exported here ─────────────────────────────
mod adjust;
pub use adjust::live_adjuster;
pub(crate) mod bound;
pub use bound::{
    live_admin_door, live_planes, live_records, live_replay_store, no_planes, no_trust,
    PlaneLookup, PlaneRecordSink, TrustDesk,
};

#[cfg(test)]
#[path = "tests/units_admin.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/admin_unit_records.rs"]
mod admin_unit_records;
