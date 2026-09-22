// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log — every admin MUTATION is recorded, success AND failure, so a credential
//! probing the surface or an operator asking "who changed what" leaves a trail.
//!
//! ## ONE STREAM, on the CORE chain
//!
//! The hash chain here is [`crate::audit`]'s: one append, one digest, one verifier, shared with other
//! chains elsewhere in the codebase that log their own request-rate activity. This file used to own a
//! third copy of that machinery. What it owns now is the RECORD, via `impl ChainedRecord for AuditEntry`, plus a bounded
//! IN-PROCESS ring of the recent tail — a hot cache, never the system of record.
//!
//! ## Where durability lives — the ONE durable path
//!
//! Durability is the neutral journal seam's ([`crate::plane::auditlog`]): [`AuditLog::record_by`] is
//! the ONE place an admin mutation is recorded, and it feeds that mutation onto the store-backed
//! durable seam, which persists the hash-chained record into `plane_records`, seeds the read-model ring
//! `GET /audit` serves, and is restored + verified at boot. This ring keeps NO durable state: it is a
//! bounded in-process VecDeque, ephemeral by construction (started fresh on every boot), retained for
//! the in-process tamper-evidence checks the audit unit tests assert on. There is ONE durable audit
//! path: the store-backed journal seam, which is the sole write, read, boot-restore and verify path.
//! (A separate durable audit table with its own sink, write-through, restore and rebase no longer
//! exists — the seam is authoritative.)
//!
//! **Sharing the mechanism is not sharing the buffer, and the difference is load-bearing.** This log
//! is admin-MUTATION-ONLY and its working set is a bounded ring of [`MAX_AUDIT_ENTRIES`]. An admin
//! mutation is operator-rate; a tool call is REQUEST-rate. Pouring one into the other means a busy
//! afternoon of tool calls evicts every admin row, so "who changed this registration" stops being
//! answerable at exactly the moment an incident makes somebody ask — and the loss is silent, because
//! a ring that pruned looks identical to a ring that was never written to. Two populations that
//! churn at different rates do not share one bounded buffer, and they still do not.
//!
//! Audit is process-wide state (NOT config-derived), so it lives as a global rather than on the
//! swappable `App` snapshot — it survives a config apply naturally.

use serde::Serialize;

use crate::audit::{ChainLabels, ChainedRecord, Digest, Framing};

/// One admin audit record. `outcome` is a stable token tooling can branch on. The record is
/// HASH-CHAINED for tamper-EVIDENCE: `hash = sha256(prev_hash | seq | ts | action | resource |
/// outcome | principal)` FRAMED UNDER THIS RECORD'S OWN `scheme` (see [`AuditEntry::scheme`]), and
/// `prev_hash` is the preceding entry's `hash`. Recomputing the chain detects any
/// altered/reordered/deleted entry (detection, not prevention; a compromised host can still rewrite
/// the whole chain; prevention is shipping the log off-box to a SIEM).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct AuditEntry {
    /// Monotonic sequence number (1-based), unique within a process lifetime.
    pub seq: u64,
    /// Unix seconds when the mutation was attempted.
    pub ts: u64,
    /// The action, `noun.verb` (e.g. `hook.register`, `hook.delete`).
    pub action: String,
    /// The resource acted on (e.g. `hook:compress`). Never a secret.
    pub resource: String,
    /// Stable outcome token: `applied` (mutation committed) | `rejected` (validation/conflict, nothing
    /// changed).
    pub outcome: String,
    /// WHO: the authenticated principal id that attempted the mutation (`admin` for the operator
    /// token; a virtual-key id or an external module's principal id otherwise; `anonymous` for the
    /// explicit open admin posture). Attribution, never a credential.
    pub principal: String,
    /// The preceding entry's `hash` (empty for the first entry of the process, or the oldest retained
    /// entry whose predecessor was pruned).
    pub prev_hash: String,
    /// `sha256(prev_hash | seq | ts | action | resource | outcome | principal)`: the tamper-evidence digest.
    pub hash: String,
    /// WHICH FRAMING RULES this entry was sealed under: [`AUDIT_SCHEME_PIPE`] (1) or
    /// [`AUDIT_SCHEME_LENGTH_PREFIXED`] (2) — see `crate::audit::Framing`.
    ///
    /// `#[serde(default)]` to [`AUDIT_SCHEME_PIPE`]: an entry persisted before this field existed
    /// simply lacks the key, and an absent tag means exactly scheme 1, because that is what every
    /// such row actually is — no migration of stored data is required. `link` always writes
    /// [`AUDIT_SCHEME_LENGTH_PREFIXED`] on a FRESH entry; nothing mints scheme 1 going forward. A
    /// verifier reads this straight off the record (`ChainedRecord::framing`), so a chain mixing
    /// both eras checks each entry under the rules it actually used.
    #[serde(default = "audit_scheme_default")]
    pub scheme: u8,
    /// TRUE only for entries THIS process appended live (via `record_by` on this ring, or the seam's
    /// live emit). Seeded entries — restored from the durable store — are FALSE. `#[serde(skip)]` gives
    /// the right default (false) on the encoded/store-seeding paths; the live-append sites set it true
    /// explicitly. It carries no ring logic now that the durable rebase is retired; the boot-verify
    /// golden still asserts restored entries come back seeded (`false`).
    ///
    /// It is now WRITE-ONLY outside tests (every fill site sets it; only the boot-verify golden and the
    /// seam round-trip witness read it back), so its read is `cfg(test)`; the field is retained as the
    /// seam↔ring provenance marker those witnesses assert on.
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub recorded_here: bool,
}

/// The fields a caller supplies for one admin audit entry. `seq`, `prev_hash` and `hash` are NOT
/// here: they are the chain's own business, allocated under the ring lock and sealed by
/// [`crate::audit::seal`], so no call site can supply a sequence number or a link of its own
/// choosing.
pub struct AuditInput {
    pub ts: u64,
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub principal: String,
}

/// THE SCOPE OF THIS CHAIN: the whole log. Other chains elsewhere key their scope per PRINCIPAL or
/// per TASK, because those streams are request-rate and multi-tenant; the admin mutation log is one
/// operator-rate sequence for the whole process, so its scope is a constant and the mechanism's
/// foreign-scope check can never fire on it. Naming it anyway is what lets ONE verifier walk every
/// such chain.
const ADMIN_LOG: &str = "admin";

/// Scheme 1: pipe-separated — every entry already on disk, whether its stored tag is explicitly `1`
/// or simply absent (see [`AuditEntry::scheme`]'s `#[serde(default)]`). Nothing seals a FRESH entry
/// under this any longer; it exists so an old entry keeps verifying under the exact rules it was
/// always sealed with.
pub const AUDIT_SCHEME_PIPE: u8 = 1;

/// Scheme 2: length-prefixed — the framing that makes the split between fields unforgeable, so a
/// caller-controlled `|` inside `resource` (or any other field) can no longer move a field boundary
/// and collide two different mutations onto one digest. `link` seals every entry built fresh under
/// this scheme; it is what closes the collision [`AUDIT_SCHEME_PIPE`] admits.
pub const AUDIT_SCHEME_LENGTH_PREFIXED: u8 = 2;

/// The [`AuditEntry::scheme`] a store's silence means. A free function because `serde`'s `default`
/// attribute needs one to call, not the const directly.
fn audit_scheme_default() -> u8 {
    AUDIT_SCHEME_PIPE
}

impl ChainedRecord for AuditEntry {
    type Input = AuditInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the admin audit chain",
        scope: "log",
    };
    /// PIPE-SEPARATED: [`AUDIT_SCHEME_PIPE`]'s framing, and what an absent [`AuditEntry::scheme`] tag
    /// means — every entry already on disk, implicitly or explicitly, and the formula
    /// `busbar_api::AuditRecord`'s own doc publishes. NOT what a fresh entry seals under any longer;
    /// see `framing` below for the framing that actually governs a given instance's digest.
    const FRAMING: Framing = Framing::PipeSeparated;

    /// THE PER-RECORD OVERRIDE: read the framing straight off this entry's own
    /// [`AuditEntry::scheme`] tag rather than assume one framing for the whole stream. `FRAMING`
    /// above still names scheme 1's framing — the type's historical default, and what an absent tag
    /// reads as — but a live chain mixes scheme-1 entries already on disk with scheme-2 entries this
    /// build seals, and this is what lets `crate::audit::digest` check each one under the rules it
    /// actually used instead of the rules every OTHER entry of this type happens to use.
    fn framing(&self) -> Framing {
        if self.scheme == AUDIT_SCHEME_LENGTH_PREFIXED {
            Framing::LengthPrefixed
        } else {
            // AUDIT_SCHEME_PIPE, or a tag this build has never minted and does not recognise: fall
            // back to the framing every entry already on disk was actually sealed with, rather than
            // silently promoting an unrecognised value to a stronger framing it was never sealed
            // under -- a wrong framing here reports an intact entry as tampered, which is the safe
            // direction for a tamper-evidence surface to fail in.
            Framing::PipeSeparated
        }
    }

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
            // Reached only from `record_by`: THIS process is appending it live right now.
            recorded_here: true,
            // EVERY entry built fresh seals under the current scheme -- never caller-chosen
            // (`AuditInput` carries no scheme field), exactly like `seq`/`prev_hash`/`hash` are
            // never caller-chosen. Nothing mints scheme 1 going forward.
            scheme: AUDIT_SCHEME_LENGTH_PREFIXED,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// `sha256(prev_hash | seq | ts | action | resource | outcome | principal)` — the formula
    /// `busbar_api::AuditRecord` publishes, fed field by field instead of being formatted here.
    /// Note there is no scope field: this chain has exactly one scope, so nothing distinguishes it.
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

/// The outcome tokens this stream uses, re-exported from the ONE audit vocabulary in
/// [`crate::audit::vocab`]. They are core's, not the admin surface's: the ruling put the whole
/// vocabulary in core so a fourth stream inherits it instead of inventing a fourth spelling. The
/// re-export keeps the existing import path for the hundred-odd call sites that name them.
pub use crate::audit::vocab::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};

/// How many entries the in-memory ring retains. Bounds RAM, not history — the durable seam keeps the
/// full log. Relocated to the neutral substrate (`crate::audit::MAX_AUDIT_ENTRIES`) so the
/// admin ring and the plane audit-log ring name ONE cap; re-exported here so
/// `crate::audit_ring::MAX_AUDIT_ENTRIES` (and the test asking for "every matching row that can
/// exist") still resolves.
pub use crate::audit::MAX_AUDIT_ENTRIES;

/// The in-memory admin audit ring. `record_by` is append-only + bounded (FIFO prune of the oldest — a
/// hot cache of the recent tail); `list` returns most-recent-first. It holds NO durable state: the
/// durable path is the neutral journal seam ([`crate::plane::auditlog`]), which `record_by` feeds and
/// which serves the durable write, the `GET /audit` read, and the boot restore + verify. This ring is
/// ephemeral by construction, started fresh on every boot. Interior-mutable so it can be a shared
/// global.
pub struct AuditLog {
    entries: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
    seq: std::sync::atomic::AtomicU64,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Record one mutation attempt. Never fails (a poisoned lock is recovered — losing the audit log
    /// to a panic would be worse than proceeding). Bounded RAM ring: prunes the oldest past the cap.
    /// WITH principal attribution: every mutation, success AND failure, is attributed to WHO attempted
    /// it. Feeds the SAME mutation onto the durable journal seam — the ONE durable path.
    pub fn record_by(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        // Allocate `seq` INSIDE the entries lock so it matches insertion order: fetching it before
        // the lock let two concurrent recorders interleave (thread B takes the lock with the higher
        // seq and pushes first, thread A pushes its lower seq behind it), producing out-of-order
        // seq numbers in the ring. Under the lock, Relaxed is sufficient (the mutex is the ordering
        // point).
        // ONE clock read for this mutation, shared by the in-process ring seal below AND the journal-
        // seam emitter after the ring block. Reading the clock twice (once here, once seam-side) would
        // let the two records carry timestamps up to a second apart — a divergence a single read
        // eliminates.
        let ts = busbar_kernel::store::now();
        {
            let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Chain to the most recent entry (the back), before any prune.
            let prev_hash = q.back().map(|e| e.hash.clone()).unwrap_or_default();
            // The ring allocates the POSITION (it must, under this lock, to match insertion order);
            // `crate::audit::seal` builds and digests the record. The caller's payload and the
            // chain's position arrive through different arguments, so no call site can supply a seq
            // or a link of its own choosing.
            let entry: AuditEntry = crate::audit::seal(
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
        // THE CHOKEPOINT FEED onto the durable journal seam. `record_by` is the ONE place an admin
        // mutation is recorded, so this ONE call — with the SAME `ts` sealed above — is the durable
        // write. Fire-and-forget: it NEVER fails the mutation it records (see
        // `plane::auditlog::emit_admin_hostless`), and the seam's own seq/prev_hash/hash are minted
        // independently of this in-process ring's (both continue the same persisted chain).
        crate::plane::auditlog::emit_admin_hostless(ts, action, resource, outcome, principal);
    }

    /// Export the retained ring, oldest first. TEST-ONLY: the durable seam is production's restore
    /// source; this backs the in-process restart-simulation tests (a fresh `AuditLog` re-seeded from
    /// this process's ring) alongside `load`, and the proxy/egress audit-trail assertions.
    #[cfg(any(test, feature = "test-support"))]
    pub fn export(&self) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }

    /// Seed the ring from an in-process snapshot. TEST-ONLY: the durable seam is production's restore
    /// source (`plane::auditlog::PlaneAuditLog::restore_from_store`); this remains as the in-process
    /// restart-simulation seam the ring tests drive. Replaces the current contents and resumes the
    /// sequence AFTER the highest restored seq, so post-restart entries chain on without seq reuse.
    #[cfg(test)]
    pub fn load(&self, mut entries: Vec<AuditEntry>) {
        // `load` IS the seeding path by definition: whatever it is handed came from OUTSIDE this
        // process's live append stream, even when the `Vec` was produced by this process's OWN
        // `export()`. `#[serde(skip)]` only clears provenance on an encoded round-trip; this path
        // never encodes, so it clears it explicitly.
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

    /// Verify the tamper-evidence chain over the RETAINED entries, through the ONE verifier in
    /// [`crate::audit`]. A WINDOW, not a whole chain: the ring is bounded, so the oldest retained
    /// entry's `prev_hash` may point at a digest that has been pruned and only its self-digest can
    /// be checked. Returns `true` if intact.
    #[cfg(test)]
    pub fn verify(&self) -> bool {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let window: Vec<AuditEntry> = q.iter().cloned().collect();
        crate::audit::verify_window(&window).is_ok()
    }

    /// A page of entries newest-first, optionally filtered by exact `action` and/or `resource`:
    /// skip `offset`, then take `limit`. `None` filters match everything.
    ///
    /// NO PRODUCTION CALLER after the 1.6.0 seam read cutover: `GET /audit` reads the durable journal
    /// seam's [`crate::plane::auditlog::AUDIT_LOG`]. This in-process ring's `list_filtered`/`list`
    /// remain the direct-ring read the audit unit tests still assert on.
    #[allow(dead_code)]
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

    /// The most-recent `limit` entries, newest first (unfiltered).
    #[cfg(any(test, feature = "test-support"))]
    pub fn list(&self, limit: usize) -> Vec<AuditEntry> {
        self.list_filtered(0, limit, None, None)
    }
}

/// The process-wide admin audit log. Const-constructed, so no lazy init needed.
pub static AUDIT: AuditLog = AuditLog::new();

#[cfg(test)]
#[path = "tests/audit_ring_tests.rs"]
mod tests;
