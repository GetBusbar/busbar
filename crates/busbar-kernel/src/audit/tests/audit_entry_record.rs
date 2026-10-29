// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The legacy admin-audit record, as a `ChainedRecord`. The shipped binary seals every admin
//! mutation through the durable seam ([`crate::audit::auditlog::admin_suffix`]) and never digests an
//! [`AuditEntry`] itself, so the record's own digest recipe lives here, in the test build, as the
//! independent reference the digest-oracle tests compare the seam's bytes against.

use crate::audit::{ChainLabels, ChainedRecord, Digest, Framing};
use crate::audit_ring::{AuditEntry, AUDIT_SCHEME_LENGTH_PREFIXED};

/// The scope of the admin chain: the whole log, one operator-rate sequence.
const ADMIN_LOG: &str = "admin";

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

impl ChainedRecord for AuditEntry {
    type Input = AuditInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the admin audit chain",
        scope: "log",
    };
    /// PIPE-SEPARATED: [`crate::audit_ring::AUDIT_SCHEME_PIPE`]'s framing, and what an absent [`AuditEntry::scheme`] tag
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
