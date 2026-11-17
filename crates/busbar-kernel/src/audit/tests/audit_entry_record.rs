// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::audit::{ChainLabels, ChainedRecord, Digest, Framing};
use crate::audit_ring::{
    AuditEntry, AUDIT_SCHEME_LENGTH_PREFIXED, AUDIT_SCHEME_ROW, AUDIT_SCHEME_ROW4,
};

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
        if self.scheme == AUDIT_SCHEME_LENGTH_PREFIXED
            || self.scheme == AUDIT_SCHEME_ROW
            || self.scheme == AUDIT_SCHEME_ROW4
        {
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
            ..Default::default()
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    fn digest_fields(&self, d: &mut Digest) {
        if self.scheme == AUDIT_SCHEME_ROW || self.scheme == AUDIT_SCHEME_ROW4 {
            let row = crate::audit::auditlog::AuditRowInput {
                action: self.action.clone(),
                resource: self.resource.clone(),
                outcome: self.outcome.clone(),
                principal: self.principal.clone(),
                config_generation: self.config_generation.clone(),
                sections_changed: self.sections_changed.clone(),
                request_id: self.request_id.clone(),
                idempotency_key: self.idempotency_key.clone(),
                kind: self.kind.clone(),
                instance: self.instance.clone(),
                severity: self.severity.clone(),
                message: self.message.clone(),
                data: self.data.clone(),
                client_request_id: self.client_request_id.clone(),
                trace_id: self.trace_id.clone(),
                operation_id: self.operation_id.clone(),
                unconditional: self.unconditional.unwrap_or(false),
            };
            let suffix = match self.at_ms {
                Some(at_ms) if self.scheme == AUDIT_SCHEME_ROW4 => {
                    crate::audit::auditlog::row4_suffix(at_ms, &row)
                }
                _ => crate::audit::auditlog::row_suffix(self.ts, &row),
            };
            d.raw(&crate::audit::frame_prelude(
                Framing::PipeSeparated,
                &self.prev_hash,
                None,
                self.seq,
            ))
            .raw(&suffix);
            return;
        }
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
