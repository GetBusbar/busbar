// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{RecordStoreError, RecordStoreResult};

pub const KIND_AUDIT: &str = "audit";

pub const KIND_RESIDUAL: &str = "usage_residual";

pub const KIND_DEMOTION: &str = "demotion";

pub const KIND_TRUST_DECISION: &str = "trust_decision";

pub const KERNEL_RECORD_KINDS: &[&str] = &[
    KIND_AUDIT,
    KIND_RESIDUAL,
    KIND_DEMOTION,
    KIND_TRUST_DECISION,
    crate::governance::TICKET_RECORD_KIND,
];

const PLANE_OWNED_LABEL: &str = "\u{1}plane\u{1}";

#[must_use]
pub fn plane_owned_kind(plane: &str, kind: &str) -> Option<String> {
    let fit = |s: &str| !s.is_empty() && !s.chars().any(char::is_control);
    (fit(plane) && fit(kind)).then(|| format!("{PLANE_OWNED_LABEL}{plane}\u{1}{kind}"))
}

pub fn encode<T: serde::Serialize>(row: &T) -> RecordStoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| RecordStoreError(format!("plane body encode: {e}")))
}

pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> RecordStoreResult<T> {
    serde_json::from_slice(body).map_err(|e| RecordStoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/plane_view_tests.rs"]
mod plane_view_tests;
