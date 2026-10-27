// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log — every admin MUTATION is recorded, success AND failure, so a credential
//! probing the surface or an operator asking "who changed what" leaves a trail.
//!
//! ## ONE STREAM, on the CORE chain
//!
//! The hash chain here is [`crate::audit`]'s: one append, one digest, one verifier, shared with other
//! chains elsewhere in the codebase that log their own request-rate activity. This file used to own a
//! third copy of that machinery. What it owns now is the RECORD, via `impl ChainedRecord for AuditEntry`,
//! and the recording handle [`AUDIT`].
//!
//! ## Where durability lives — the ONE durable path
//!
//! Durability is the neutral journal seam's ([`crate::audit::auditlog`]): [`AuditLog::record_by`] is
//! the ONE place an admin mutation is recorded, and it feeds that mutation onto the store-backed
//! durable seam, which persists the hash-chained record into `plane_records`, seeds the read-model ring
//! `GET /audit` serves, and is restored + verified at boot. There is ONE audit path: the store-backed
//! journal seam, which is the sole write, read, boot-restore and verify path.
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
/// HASH-CHAINED for tamper-EVIDENCE: `hash` is the SHA-256 of bytes fixed by this record's own
/// `scheme` (the recipe is on `hash`), and `prev_hash` is the preceding entry's `hash`. Recomputing
/// the chain detects any altered/reordered/deleted entry (detection, not prevention; a compromised
/// host can still rewrite the whole chain; prevention is shipping the log off-box to a SIEM).
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
    /// The tamper-evidence digest: lowercase hex SHA-256 over the bytes this record's `scheme` names.
    /// Integers are written in decimal ASCII and strings as their UTF-8 bytes unless stated.
    ///
    /// Scheme 1: `prev_hash|seq|ts|action|resource|outcome|principal`, the fields joined by `|`
    /// (1.5.5's formula).
    ///
    /// Scheme 2: `prev_hash|seq` as in scheme 1, then one zero byte (0x00), then `ts`, `action`,
    /// `resource`, `outcome` and `principal`, each as its byte length (8 bytes, big-endian) followed
    /// by its bytes; `ts` is its 8-byte big-endian value, so its length is 8.
    pub hash: String,
    /// WHICH RECIPE `hash` was sealed under: 1 (the 1.5.5 pipe join) or 2 (length-prefixed fields);
    /// both are stated on `hash`. A record is sealed under 1 when its `action`, `resource` and
    /// `outcome` carry no `|`, and under 2 otherwise, so its fields always read back exactly. A
    /// record without this field is scheme 1. A verifier checks each record under its own scheme.
    //
    // `#[serde(default)]` to [`AUDIT_SCHEME_PIPE`]: an entry persisted before this field existed
    // lacks the key, and every such row was sealed under scheme 1, so no stored data migrates. The
    // durable seam picks the scheme per record (`audit::auditlog::admin_suffix`); `link` seals
    // under [`AUDIT_SCHEME_LENGTH_PREFIXED`]. `ChainedRecord::framing` and
    // `digest_fields` read the tag off the record (Q128 arch u26 #2; #82 (c): the recipe is
    // published contract a verifier reproduces without the binary).
    #[serde(default = "audit_scheme_default")]
    pub scheme: u8,
    /// TRUE only for entries THIS process appended live (the seam's live emit). Seeded entries — restored from the durable store — are FALSE. `#[serde(skip)]` gives
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
/// here: they are the chain's own business, allocated by the chain and sealed by
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

/// Scheme 1: pipe-separated, 1.5.5's formula. Every entry already on disk whose stored tag is `1` or
/// absent (see [`AuditEntry::scheme`]'s `#[serde(default)]`), and every record the durable seam
/// seals today whose `action`, `resource` and `outcome` carry no `|`
/// ([`crate::audit::auditlog::admin_suffix`]).
pub const AUDIT_SCHEME_PIPE: u8 = 1;

/// Scheme 2: length-prefixed content — the framing that makes the split between the caller-supplied
/// fields unforgeable, so a caller-controlled `|` inside `resource` (or any other field) can no
/// longer move a field boundary and collide two different mutations onto one digest. It is what
/// closes the collision [`AUDIT_SCHEME_PIPE`] admits.
///
/// THE RECIPE IS THE ONE THE DURABLE SEAM SEALS, byte for byte: the admin stream's `prev_hash|seq`
/// prelude (pipe-joined; neither field is caller text), then
/// [`crate::audit::auditlog::audit_suffix_safe`] (a marker byte, then `ts`/`action`/`resource`/
/// `outcome`/`principal` each length-prefixed). A served record that says scheme 2 recomputes under
/// exactly the bytes its `hash` was minted over (Q128 p12#1; THE DESIGN §1 "integrity (prev hash)").
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
    /// `busbar_contract::records::AuditRecord`'s own doc publishes. NOT what a fresh entry seals under any longer;
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
            // Reached only from `crate::audit::seal`: THIS process is appending it live right now.
            recorded_here: true,
            // A sealed entry is scheme 2 -- never caller-chosen (`AuditInput` carries no scheme
            // field), exactly like `seq`/`prev_hash`/`hash` are never caller-chosen. The durable
            // seam, which `GET /audit` serves, picks per record (`audit::auditlog::admin_suffix`).
            scheme: AUDIT_SCHEME_LENGTH_PREFIXED,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// Scheme 1: `sha256(prev_hash | seq | ts | action | resource | outcome | principal)` — the
    /// formula `busbar_contract::records::AuditRecord` publishes (v1.5.5
    /// `crates/busbar/src/admin/audit.rs:61-73`), fed field by field instead of being formatted here.
    /// Scheme 2: the seam's own bytes, `prev_hash|seq` then the length-prefixed safe suffix (see
    /// [`AUDIT_SCHEME_LENGTH_PREFIXED`]); fed through [`Digest::raw`], which ignores the builder's
    /// framing, so the recipe is the same whichever framing `framing` names.
    /// Note there is no scope field: this chain has exactly one scope, so nothing distinguishes it.
    fn digest_fields(&self, d: &mut Digest) {
        if self.scheme == AUDIT_SCHEME_LENGTH_PREFIXED {
            d.raw(&crate::audit::frame_prelude(
                Framing::PipeSeparated,
                &self.prev_hash,
                None,
                self.seq,
            ))
            .raw(&crate::audit::auditlog::audit_suffix_safe(
                self.ts,
                &self.action,
                &self.resource,
                &self.outcome,
                &self.principal,
            ));
            return;
        }
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

/// How many entries the read model retains. Bounds RAM, not history — the durable seam keeps the
/// full log. Relocated to the neutral substrate (`crate::audit::MAX_AUDIT_ENTRIES`); re-exported here so
/// `crate::audit_ring::MAX_AUDIT_ENTRIES` (and the test asking for "every matching row that can
/// exist") still resolves.
pub use crate::audit::MAX_AUDIT_ENTRIES;

/// The admin audit's recording handle. `record_by` is the ONE place an admin mutation is recorded:
/// it seals the mutation onto the durable journal seam ([`crate::audit::auditlog`]), which persists
/// the hash-chained record into `plane_records`, seeds the read-model ring `GET /audit` serves
/// ([`crate::audit::auditlog::AUDIT_LOG`]), and is restored + verified at boot. It holds no state of
/// its own.
pub struct AuditLog {
    _private: (),
}

impl AuditLog {
    /// Record one mutation attempt, WITH principal attribution: every mutation, success AND failure,
    /// is attributed to WHO attempted it. Never fails: the log is evidence, not admission (see
    /// `audit::auditlog::emit_admin_hostless`).
    pub fn record_by(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        crate::audit::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }
}

/// The process-wide admin audit log. Const-constructed, so no lazy init needed.
pub static AUDIT: AuditLog = AuditLog { _private: () };
