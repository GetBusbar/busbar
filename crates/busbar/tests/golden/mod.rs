// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PINNED GOLDEN'S CELLS, READ ONCE.
//!
//! The recorded corpus is a directory of JSON files in this repository. Every money cell in the
//! composition root's test suite asks the same question of it — what did the published 1.5.5
//! binary record for this exchange — and before this module each one answered it for itself.
//!
//! Two readers of one corpus is the defect this tree names everywhere else: two readings of one
//! `groups:` section, two deciders of one fee, two vocabularies for four token quantities. The
//! failure is the same each time. Each reader is internally consistent, neither knows the other
//! exists, and the day they drift the cells that depend on them keep passing while they disagree
//! about what the recording says.
//!
//! **AND IT IS WHAT KEEPS A DIALECT'S NAME OUT OF THE COMPOSITION ROOT.** A cell that transcribes
//! the corpus has to SPELL each recording's id, and an id in the billing families is
//! `<family>__<ingress dialect>__<upstream dialect>__request__<ending>` — two vendor names per
//! line. `fee_one_decision` carried 78 of them, which is 146 vendor words sitting in the crate
//! that composes the node, for no reason except that the corpus was typed in rather than read. A
//! fee decision does not know what a dialect is: it reads four facts about an exchange, and every
//! one of them is recorded. So the corpus is READ, the ids come off the file names, and the root
//! names no vendor to pin the money. `kind-isolation`'s `busbar × dialect` column is what measures
//! that, and the drain is this module.
//!
//! # What a cell is reduced to, and why each field is derivable
//!
//! Nothing here decides anything. Each field is a fact the recording carries, read the one way:
//!
//! * [`Recorded::status`] — the cell's own client-facing `status`.
//! * [`Recorded::usage`] — the recorded `effects.usage` delta, keyed as the oracle wrote it.
//! * [`Recorded::upstream_leg`] — whether the node ever dialled: a non-empty `effects.egress`, or
//!   a `busbar_upstream_attempts_total` metric. Two spellings of one event, because a recording
//!   that captured the attempt metric and no egress body is still a recording of a dial.
//! * [`Recorded::upstream_candidate`] — whether a destination resolved at all, which the oracle
//!   records as a `pool=` label on a metric. A unit refused at the door carries none.
//!
//! `client_origin` is NOT a field: every cell in this corpus is a caller's request, because the
//! oracle drives no provider push, and a constant is not a fact about a cell. Its readers state it
//! where they build their evidence.
//!
//! `billed` is NOT a field either, and deliberately so. The oracle's own configuration prices every
//! model and sets NO per-request fee, so a recorded `effects.usage.spend_cents` in the token-billing
//! families is token cost and only token cost: no recording there discriminates a fee count of one
//! from a fee count of zero. A reader that wants the fee 1.5.5 charged evaluates 1.5.5's own rule
//! over these facts and says so. What this module answers is [`Recorded::recorded_spend`], which is
//! the weaker and true statement: the recording carries a spend key, or it does not.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The pinned golden's cell directory.
fn cells_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// One recorded cell, reduced to the facts a money decision reads.
pub struct Recorded {
    /// The golden's own cell id — the file name without its extension, and never a literal.
    pub name: String,
    /// The recorded client-facing status.
    pub status: u16,
    /// The recorded `effects.usage` delta, keyed as the oracle wrote it.
    pub usage: BTreeMap<String, i64>,
    /// Whether the node dialled an upstream on this unit.
    pub upstream_leg: bool,
    /// Whether a destination resolved for this unit at all.
    pub upstream_candidate: bool,
}

impl Recorded {
    /// Whether the recording carries a spend at all. See this module's header on what a recorded
    /// spend does and does not say about a fee.
    #[must_use]
    pub fn recorded_spend(&self) -> bool {
        self.usage.contains_key("spend_cents")
    }

    /// The recorded request slot count. Zero where the recording carries no usage delta.
    #[must_use]
    pub fn recorded_requests(&self) -> i64 {
        self.usage.get("requests").copied().unwrap_or(0)
    }
}

/// Every cell whose id starts with `prefix`, in id order.
///
/// The prefix is a FAMILY and its trailing separator, which is the one leading segment of a cell id
/// that is not a dialect's name. It is the caller's word, never one of this module's: selecting by
/// anything narrower would be this module spelling a vendor on its callers' behalf, which is the
/// whole thing it exists to stop.
///
/// # Panics
///
/// If the pinned golden is missing or a cell is not readable JSON. Both are corpus faults and a
/// money cell that silently ran over an empty corpus would be worse than one that stopped.
#[must_use]
pub fn family(prefix: &str) -> Vec<Recorded> {
    let dir = cells_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the pinned golden's cells are checked in") {
        let path = entry.expect("a readable directory entry").path();
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(name) = file.strip_suffix(".json") else {
            continue;
        };
        // A prefix match, and the caller's prefix carries its own separator so a family cannot
        // reach a longer family's cells: an id is `<family>__…` and a sub-family is `<family>.<sub>`,
        // so the separator is what tells the two apart.
        if !name.starts_with(prefix) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a readable cell");
        let json: serde_json::Value = serde_json::from_str(&text).expect("a recorded cell is JSON");
        out.push(reduce(name.to_string(), &json));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// One recording, reduced. See this module's header for why each field reads what it reads.
fn reduce(name: String, json: &serde_json::Value) -> Recorded {
    let status = json
        .get("status")
        .and_then(serde_json::Value::as_u64)
        .map(|s| u16::try_from(s).unwrap_or(u16::MAX))
        .unwrap_or(0);
    let effects = json.get("effects");
    let mut usage = BTreeMap::new();
    if let Some(map) = effects
        .and_then(|e| e.get("usage"))
        .and_then(serde_json::Value::as_object)
    {
        for (k, v) in map {
            if let Some(n) = v.as_i64() {
                usage.insert(k.clone(), n);
            }
        }
    }
    let metric_keys: Vec<&str> = effects
        .and_then(|e| e.get("metrics"))
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let dialled = effects
        .and_then(|e| e.get("egress"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|e| !e.is_empty());
    Recorded {
        name,
        status,
        usage,
        upstream_leg: dialled
            || metric_keys
                .iter()
                .any(|k| k.starts_with("busbar_upstream_attempts_total")),
        upstream_candidate: metric_keys.iter().any(|k| k.contains("pool=")),
    }
}
