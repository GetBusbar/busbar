// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log — moved here from the previous release, unchanged.
//!
//! Every admin MUTATION is recorded, success AND failure, so a credential probing the surface or an
//! operator asking "who changed what" leaves a trail.
//!
//! ## What "unchanged" means here, precisely
//!
//! Eight wire fields, in the order they have always been in. One further field carrying provenance
//! that is skipped on the wire, so an encoded record has eight fields and not nine. A digest that is
//! the hexadecimal SHA-256 of the previous hash, sequence, timestamp, action, resource, outcome and
//! principal, joined by vertical bars. A genesis previous hash that is the empty string. A ring
//! bounded at a thousand entries, pruned oldest-first. A restore that seeds the ring from what was
//! persisted and resumes the sequence after the highest restored one.
//!
//! Any of those moving would not break a feature — it would make the read-back surface return
//! something different from what it returned yesterday, and make every persisted chain fail to
//! verify. So each of them is a test in this crate rather than a sentence in this comment.
//!
//! ## Sharing a mechanism is not sharing a buffer
//!
//! This log is admin-mutation-only and its working set is a bounded ring. An admin mutation is
//! operator-rate; a tool call is request-rate. Pouring one into the other means a busy afternoon of
//! tool calls evicts every admin row, so "who changed this registration" stops being answerable at
//! exactly the moment an incident makes somebody ask — and the loss is silent, because a ring that
//! pruned looks identical to a ring that was never written to. Two populations that churn at
//! different rates do not share one bounded buffer, and they still do not.
//!
//! ## The two things this crate does not carry
//!
//! The CLOCK and the DURABLE SEAM. In the previous release those were reached through the host
//! directly; here they are a trait and a trait, because this crate has no host to reach through. The
//! behaviour is the same in the way that matters: the clock is read ONCE per mutation and the same
//! reading is used for the ring's sealed record and for the durable emit, so the two cannot end up
//! with timestamps a second apart.

use serde::{Deserialize, Serialize};

use super::chain::{ChainLabels, ChainedRecord, Digest, Framing};

/// One admin audit record.
///
/// The digest is the hexadecimal SHA-256 of the previous hash, sequence, timestamp, action,
/// resource, outcome and principal joined by vertical bars, and the previous hash is the preceding
/// entry's digest. Recomputing the chain detects any altered, reordered or deleted entry — detection,
/// not prevention. A compromised host can still rewrite the whole chain; prevention is shipping the
/// log off-box to something that host cannot reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number, one-based, unique within a process lifetime.
    pub seq: u64,
    /// Unix seconds when the mutation was attempted.
    pub ts: u64,
    /// The action, as a noun and a verb — for example `hook.register`.
    pub action: String,
    /// The resource acted on, for example `hook:compress`. Never a secret.
    pub resource: String,
    /// Stable outcome token: applied when the mutation committed, rejected when nothing changed.
    pub outcome: String,
    /// WHO: the authenticated principal that attempted the mutation. Attribution, never a
    /// credential.
    pub principal: String,
    /// The preceding entry's digest. Empty for the first entry of the process, or for the oldest
    /// retained entry whose predecessor was pruned.
    pub prev_hash: String,
    /// This entry's own digest: the tamper-evidence.
    pub hash: String,
    /// TRUE only for entries THIS process appended live. Seeded entries — restored from a durable
    /// store — are false. Skipped on the wire, which gives the right default on the encoded and
    /// store-seeding paths; the live append sets it explicitly.
    ///
    /// It is the provenance marker the restore witnesses assert on, and it is the ninth field of the
    /// struct and the non-field of the wire. That distinction is the whole reason it is called out.
    #[serde(skip)]
    pub recorded_here: bool,
}

/// The fields a caller supplies for one admin audit entry.
///
/// The sequence, the previous hash and the hash are NOT here: they are the chain's own business,
/// allocated under the ring lock and sealed by the chain, so no call site can supply a position or
/// a link of its own choosing.
#[derive(Debug, Clone)]
pub struct AuditInput {
    /// Unix seconds.
    pub ts: u64,
    /// The action.
    pub action: String,
    /// The resource.
    pub resource: String,
    /// The outcome token.
    pub outcome: String,
    /// The principal.
    pub principal: String,
}

/// THE SCOPE OF THIS CHAIN: the whole log.
///
/// Other streams chain per principal or per task because they are request-rate and multi-tenant; the
/// admin mutation log is one operator-rate sequence for the whole process, so its scope is a
/// constant and the mechanism's foreign-scope check can never fire on it. Naming it anyway is what
/// lets ONE verifier walk every stream.
pub const ADMIN_LOG: &str = "admin";

/// The outcome token for a mutation that committed.
pub const OUTCOME_APPLIED: &str = "applied";
/// The outcome token for a mutation that changed nothing.
pub const OUTCOME_REJECTED: &str = "rejected";
/// The outcome token for a mutation that partly succeeded.
pub const OUTCOME_DEGRADED: &str = "degraded";

/// How many entries the in-memory ring retains. Bounds memory, not history — the durable seam keeps
/// the full log.
pub const MAX_AUDIT_ENTRIES: usize = 1000;

/// Every action name the previous release's admin surface writes.
///
/// Twenty-seven written literally at their call sites, plus six composed at run time from a named-map
/// section and a verb. They are listed here as one array so that "the set did not change" is a thing
/// a test can assert, rather than something a reviewer would have to reconstruct by grepping.
pub const AUDIT_ACTIONS: [&str; 33] = [
    "admin.restart",
    "auth.admin_chain_put",
    "auth.cache_flush",
    "config.apply",
    "config.reload",
    "config.rollback",
    "config.settings",
    "group.create",
    "group.delete",
    "group.patch",
    "group.provision",
    "group.replace",
    "hook.delete",
    "hook.register",
    "hook.replace",
    "hook.settings",
    "key.create",
    "key.delete",
    "key.patch",
    "key.revoke",
    "key.rotate",
    "overlay.reset",
    "plugin.install",
    "plugin.reload",
    "plugin.remove",
    "plugin.rollback",
    "signing_key.report",
    // The named-map family, composed at run time as the section's singular noun and the mutation's
    // verb. Written out rather than composed here, because the point of the list is to be readable.
    "identity-provider.replace",
    "identity-provider.settings",
    "identity-provider.delete",
    "exporter.replace",
    "exporter.settings",
    "exporter.delete",
];

impl ChainedRecord for AuditEntry {
    type Input = AuditInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the admin audit chain",
        scope: "log",
    };
    /// PIPE-SEPARATED because that is how the entries already on disk were written. A new record
    /// type takes the length-prefixed framing instead.
    const FRAMING: Framing = Framing::PipeSeparated;

    fn scope_of(&self) -> &str {
        ADMIN_LOG
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }

    fn hash(&self) -> &str {
        &self.hash
    }

    fn link(_scope: &str, seq: u64, prev_hash: String, input: AuditInput) -> Self {
        AuditEntry {
            seq,
            ts: input.ts,
            action: input.action,
            resource: input.resource,
            outcome: input.outcome,
            principal: input.principal,
            prev_hash,
            hash: String::new(),
            // Reached only from the live append: THIS process is writing it right now.
            recorded_here: true,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// The digest over the previous hash, sequence, timestamp, action, resource, outcome and
    /// principal, fed field by field rather than formatted here. Note there is no scope field: this
    /// chain has exactly one scope, so nothing distinguishes it.
    fn digest_fields(&self, d: &mut Digest) {
        d.text(&self.prev_hash)
            .num(self.seq)
            .num(self.ts)
            .text(&self.action)
            .text(&self.resource)
            .text(&self.outcome)
            .text(&self.principal);
    }
}

/// Where the timestamp on a mutation comes from.
///
/// A trait rather than a direct call, because this crate has no host to ask. The important property
/// is not which clock it is — it is that it is read ONCE per mutation, and the same reading goes to
/// the ring and to the durable seam. Reading it twice would let one mutation carry two timestamps up
/// to a second apart, which is exactly the kind of small divergence that makes two copies of a log
/// impossible to reconcile later.
pub trait Clock: Send + Sync {
    /// Unix seconds, now.
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// The durable path a recorded mutation also goes down.
///
/// The ring is a hot cache of the recent tail and keeps no durable state; the seam is what persists
/// the record, seeds the read-back, and is restored and verified at boot. It is fire-and-forget by
/// design: it NEVER fails the mutation it records, because losing the ability to change
/// configuration when a store is unreachable would be worse than a gap in a log that is already
/// being alarmed on.
pub trait DurableSeam: Send + Sync {
    /// Persist one recorded mutation. The same timestamp the ring sealed is passed in.
    fn emit(&self, ts: u64, action: &str, resource: &str, outcome: &str, principal: &str);
}

/// A seam that does nothing, for a deployment that keeps only the ring.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSeam;

impl DurableSeam for NoSeam {
    fn emit(&self, _ts: u64, _action: &str, _resource: &str, _outcome: &str, _principal: &str) {}
}

/// The in-memory admin audit ring.
///
/// Appending is append-only and bounded, pruning the oldest past the cap — a hot cache of the recent
/// tail. Listing returns most-recent-first. It holds NO durable state: it is ephemeral by
/// construction, started fresh on every boot. Interior-mutable so it can be a shared global, exactly
/// as it was.
pub struct AuditLog {
    entries: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
    seq: std::sync::atomic::AtomicU64,
    clock: Box<dyn Clock>,
    seam: Box<dyn DurableSeam>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field(
                "retained",
                &self
                    .entries
                    .lock()
                    .map(|q| q.len())
                    .unwrap_or_else(|e| e.into_inner().len()),
            )
            .finish()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        AuditLog::new()
    }
}

impl AuditLog {
    /// A fresh ring on the system clock, with no durable seam behind it.
    pub fn new() -> Self {
        AuditLog::with(Box::new(SystemClock), Box::new(NoSeam))
    }

    /// A fresh ring on a given clock and seam.
    pub fn with(clock: Box<dyn Clock>, seam: Box<dyn DurableSeam>) -> Self {
        AuditLog {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            seq: std::sync::atomic::AtomicU64::new(1),
            clock,
            seam,
        }
    }

    /// Record one mutation attempt.
    ///
    /// Never fails: a poisoned lock is recovered, because losing the audit log to a panic elsewhere
    /// would be worse than proceeding. Bounded ring, pruning the oldest past the cap. WITH principal
    /// attribution: every mutation, success AND failure, is attributed to who attempted it.
    ///
    /// The position is allocated INSIDE the entries lock so that it matches insertion order.
    /// Fetching it before taking the lock let two concurrent recorders interleave — the one with the
    /// higher number took the lock first and pushed first — producing out-of-order sequences in the
    /// ring. Under the lock, a relaxed ordering is sufficient: the lock is the ordering point.
    pub fn record_by(&self, action: &str, resource: &str, outcome: &str, principal: &str) {
        // ONE clock read for this mutation, shared by the sealed ring record below AND the durable
        // emit after it.
        let ts = self.clock.now();
        {
            let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Chain to the most recent entry, before any prune.
            let prev_hash = q.back().map(|e| e.hash.clone()).unwrap_or_default();
            // The ring allocates the POSITION — it must, under this lock, to match insertion order
            // — and the chain builds and digests the record. The caller's payload and the chain's
            // position arrive through different arguments, so no call site can supply either.
            let entry: AuditEntry = super::chain::seal(
                ADMIN_LOG,
                seq,
                prev_hash,
                AuditInput {
                    ts,
                    action: action.to_string(),
                    resource: resource.to_string(),
                    outcome: outcome.to_string(),
                    principal: principal.to_string(),
                },
            );
            while q.len() >= MAX_AUDIT_ENTRIES {
                q.pop_front();
            }
            q.push_back(entry);
        }
        // THE CHOKEPOINT FEED onto the durable seam. Recording a mutation is the ONE place a
        // mutation is recorded, so this ONE call — with the SAME timestamp sealed above — is the
        // durable write.
        self.seam.emit(ts, action, resource, outcome, principal);
    }

    /// Export the retained ring, oldest first.
    pub fn export(&self) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }

    /// Seed the ring from a snapshot, replacing what is there and resuming the sequence AFTER the
    /// highest restored one, so entries recorded after a restart chain on without reusing a
    /// position.
    ///
    /// Whatever this is handed came from OUTSIDE the live append stream by definition, even when the
    /// list was produced by this same process's export. Skipping the provenance flag on the wire only
    /// clears it on an encoded round trip; this path never encodes, so it clears it explicitly.
    pub fn load(&self, mut entries: Vec<AuditEntry>) {
        for e in &mut entries {
            e.recorded_here = false;
        }
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let max_seq = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        q.clear();
        q.extend(entries);
        self.seq
            .fetch_max(max_seq + 1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Restore the ring from what a store persisted, verifying it first.
    ///
    /// The records are verified as a WINDOW, not a whole chain: the durable store keeps the rest, so
    /// the oldest restored record's predecessor may legitimately have been pruned. A break is
    /// returned rather than swallowed — and the ring is seeded anyway, because a detected tamper
    /// must not be able to stop all further evidence being recorded.
    pub fn restore_from_store(
        &self,
        entries: Vec<AuditEntry>,
    ) -> Result<(), super::chain::ChainBreak> {
        let verdict = super::chain::verify_window(&entries);
        self.load(entries);
        verdict
    }

    /// Verify the chain over the RETAINED entries.
    ///
    /// A WINDOW, not a whole chain: the ring is bounded, so the oldest retained entry's previous
    /// hash may point at a digest that has been pruned and only its own digest can be checked.
    pub fn verify(&self) -> bool {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let window: Vec<AuditEntry> = q.iter().cloned().collect();
        super::chain::verify_window(&window).is_ok()
    }

    /// A page of entries newest-first, optionally filtered by exact action and resource: skip, then
    /// take. Absent filters match everything.
    pub fn list_filtered(
        &self,
        offset: usize,
        limit: usize,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .rev()
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// The most recent entries, newest first, unfiltered.
    pub fn list(&self, limit: usize) -> Vec<AuditEntry> {
        self.list_filtered(0, limit, None, None)
    }

    /// How many entries the ring is holding.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
