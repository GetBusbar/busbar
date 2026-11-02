// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::audit::{ChainLabels, ChainedRecord, Digest, Framing};
use crate::audit_ring::{AuditEntry, AUDIT_SCHEME_LENGTH_PREFIXED};

const ADMIN_LOG: &str = "admin";

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

    const FRAMING: Framing = Framing::PipeSeparated;

    fn framing(&self) -> Framing {
        if self.scheme == AUDIT_SCHEME_LENGTH_PREFIXED {
            Framing::LengthPrefixed
        } else {
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

            recorded_here: true,

            scheme: AUDIT_SCHEME_LENGTH_PREFIXED,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

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
