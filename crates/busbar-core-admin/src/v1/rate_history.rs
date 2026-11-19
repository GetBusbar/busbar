// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `GET /ledger/rate-history` WIRE SHAPE: the dated rate-card history as the store holds it,
//! one row per entry, so a reader holding these rows and the ledger reprices every spend figure
//! itself. One definition, which the node fills and the generated document describes.
//!
//! Every row is the stored entry, never this node's copy of it: the node reads the store's
//! history for each page, so every node answers the same rows for the same store state. Nothing
//! here writes, and nothing here takes a lock the request path takes.

use std::collections::{BTreeMap, HashMap};

use axum::response::Response;
use busbar_kernel::config::card::CardFields;
use busbar_kernel::config::RateEntryCfg;
use busbar_kernel::cost::{measurement_lane, EntryKey, HistoryView, RateCard, PLANE_LANE_SEP};
use busbar_kernel::governance::persistence::prices::{EntryAuthor, Snapshot, StoredEntry};
use serde::Serialize;

use crate::v1::contract::LIST_LIMIT_DEFAULT;
use crate::v1::json::cursor::{self, Window};

/// The operation a page cursor of this read is bound to.
pub const RATE_HISTORY_OP: &str = "ledger-rate-history";

/// `GET /ledger/rate-history`: one page of the dated rate-card history, in entry-key order.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryPage {
    /// The entries of this page, in key order: the order they were written in.
    pub items: Vec<RateHistoryEntry>,
    /// The cursor for the next page, or null after the last entry.
    pub next_cursor: Option<String>,
    /// The store generation of the rate-card history this page was read at, as decimal text. It
    /// moves with every write to the history, by any node. Pages read at different generations
    /// were read from different histories: start again from the first page to see one.
    pub generation: Option<String>,
}

/// One entry of the history: a whole card, and the instants it prices. A card prices an instant
/// from its start, inclusive, to its end, exclusive.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryEntry {
    /// The entry's identity: its key in the fleet-shared history, 40 lowercase hexadecimal digits.
    /// The same entry has the same key on every node and after every restart.
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(regex(pattern = r"^[0-9a-f]{40}$"))
    )]
    pub key: String,
    /// The id the ledger files counts priced by this entry under: the first 12 bytes of the
    /// SHA-256 of the key, 24 lowercase hexadecimal digits.
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(regex(pattern = r"^[0-9a-f]{24}$"))
    )]
    pub entry_id: String,
    /// The first instant the entry's window covers, inclusive, in milliseconds since the epoch. A
    /// configuration entry's start is the instant its activation was authorized.
    pub effective_from_ms: u64,
    /// The first instant its window does not cover, exclusive, in milliseconds since the epoch.
    /// Absent: the window is open-ended. A configuration entry is stored open-ended; the entry
    /// written after it ends it, and `in_force` says where.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_until_ms: Option<u64>,
    /// The start the writer stored with the entry, in milliseconds since the epoch, before any
    /// activation moved it. Equal to `effective_from_ms` unless an activation moved it.
    pub authored_from_ms: u64,
    /// The instants at which this entry IS the card in force, under the history's rule (of the
    /// live entries whose window covers an instant, the one with the highest key). Each span is
    /// start inclusive, end exclusive; the spans of all entries never overlap. Empty: the entry
    /// is voided or out-ranked wherever its window lies.
    pub in_force: Vec<RateHistorySpan>,
    /// The entry is VOID: it prices no instant. A voided entry's id stays known.
    pub voided: bool,
    /// How the entry was written: `configuration` (a configuration resolved a card) or
    /// `correction` (the amend verb, `POST /ledger/amend-rate-history`).
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(extend("enum" = ["configuration", "correction"]))
    )]
    pub written_as: &'static str,
    /// The stored author: `opening` (the first entry, from instant zero), `change` (a change of
    /// the configured card), `amend` (a correction) or `migrated` (copied from a node's journal).
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(extend("enum" = ["opening", "change", "amend", "migrated"]))
    )]
    pub author: &'static str,
    /// Who or what wrote the entry, exactly as stored. A correction stores the authenticated
    /// admin principal that submitted it; a configuration entry stores where it came from (`boot
    /// of node <id>`, or the text the configuration path supplied).
    pub actor: String,
    /// The durable id of the node that wrote the entry, 16 lowercase hexadecimal digits.
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(regex(pattern = r"^[0-9a-f]{16}$"))
    )]
    pub writer_node: String,
    /// When the entry was written, in milliseconds since the epoch.
    pub appended_at_ms: u64,
    /// The key of the entry this one extended, when it extended one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_key: Option<String>,
    /// The card fields that changed from the entry it extended, as stored.
    pub set_fields: Vec<String>,
    /// A correction's window and reason. Present exactly when `written_as` is `correction`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction: Option<RateHistoryCorrection>,
    /// Where a migrated entry was copied from. Present exactly when `author` is `migrated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<RateHistoryMigration>,
    /// The entry's stored correction envelope, as lowercase hexadecimal, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
    /// The card.
    pub card: RateHistoryCard,
}

/// A span of instants, start inclusive, end exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistorySpan {
    /// The first instant, inclusive, in milliseconds since the epoch.
    pub from_ms: u64,
    /// The first instant after it, exclusive, in milliseconds since the epoch. Absent: open,
    /// the card in force now and from now on until another entry is written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
}

/// A correction, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryCorrection {
    /// The corrected window's start, inclusive, in milliseconds since the epoch.
    pub from_ms: u64,
    /// The corrected window's end, exclusive, in milliseconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// The SHA-256 of the stated reason, as stored (the text itself is not kept).
    pub reason_sha256: String,
}

/// Where a migrated entry came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryMigration {
    /// The journal node, 16 lowercase hexadecimal digits.
    pub node: String,
    /// Its position on that node's chain, as decimal text.
    pub node_seq: String,
    /// Whether it was that chain's opening entry.
    pub opening: bool,
}

/// A whole card, as the entry stores it. Every money figure is an exact decimal string.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryCard {
    /// The flat per-request fee, in minor units (hundredths of the cost unit the card is priced
    /// in), as decimal text.
    pub per_request_fee_minor: String,
    /// Every rate card the entry holds: the flat card (`plane` null, the pools plane's) when one
    /// is configured, then each other plane's own card. A plane with no card here is not priced
    /// by this entry; a card here that names no lane refuses to price that lane.
    pub cards: Vec<RateHistoryPlaneCard>,
    /// Each other plane's own fees.
    pub plane_fees: Vec<RateHistoryPlaneFees>,
    /// Plugin measurement rates, by plugin kind and configured namespace.
    pub measurements: Vec<RateHistoryMeasurement>,
}

/// One plane's card.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryPlaneCard {
    /// The plane registry key; null for the flat card.
    pub plane: Option<String>,
    /// The lanes the card prices, in lane order.
    pub lanes: Vec<RateHistoryLane>,
}

/// One lane's rates.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryLane {
    /// The lane (model) as the plane's card names it.
    pub lane: String,
    /// The lane as the whole card keys it: the lane for the flat card, `<plane>` U+001F `<lane>`
    /// for another plane's (the spelling the amend verb takes).
    pub card_lane: String,
    /// Every class the lane prices. A lane with no `cache_write` row prices cache writes at its
    /// `input` rate.
    pub rates: Vec<RateHistoryRate>,
}

/// One class's rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryRate {
    /// The billable class.
    pub class: String,
    /// The rate as stored, in micro-units of the cost unit per unit of the class, as exact
    /// decimal text: it reads back to the stored figure exactly.
    pub micro_per_unit: String,
    /// The rate the card prices with, in nano-units of the cost unit per unit of the class, as
    /// decimal text. Null: the stored figure is finer than one nano-unit, so the card cannot hold
    /// it and refuses to price the class.
    pub nanos_per_unit: Option<String>,
}

/// One plane's fees, in minor units of the cost unit, as decimal text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryPlaneFees {
    /// The plane registry key.
    pub plane: String,
    /// Charged once per billable request of the plane, in minor units.
    pub per_request_minor: String,
    /// Charged once per session the plane opens, in minor units.
    pub per_session_minor: String,
}

/// One plugin measurement namespace's rates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RateHistoryMeasurement {
    /// The plugin kind.
    pub kind: String,
    /// The configured namespace.
    pub namespace: String,
    /// The measurement lane as the whole card keys it.
    pub card_lane: String,
    /// Every class the namespace prices.
    pub rates: Vec<RateHistoryRate>,
}

/// The page request: `cursor` and `limit`, refused as every other admin list refuses them.
pub fn window(query: &HashMap<String, String>) -> Result<Window, Box<Response>> {
    cursor::window(query, RATE_HISTORY_OP, "", LIST_LIMIT_DEFAULT)
}

/// One page of `snapshot`, the stored history, in key order.
#[must_use]
pub fn page(snapshot: &Snapshot, window: &Window) -> RateHistoryPage {
    let listed = cursor::keyset(
        entries(snapshot),
        window,
        RATE_HISTORY_OP,
        "",
        |entry| entry.key.clone(),
        false,
    );
    RateHistoryPage {
        items: listed.items,
        next_cursor: listed.next_cursor,
        generation: snapshot.generation.map(|generation| generation.to_string()),
    }
}

/// Every stored entry as a row, in key order, its start and voiding resolved the way the history
/// resolves them and its spans in force computed over the whole stored history.
#[must_use]
pub fn entries(snapshot: &Snapshot) -> Vec<RateHistoryEntry> {
    // The spans depend on dates, voids and keys only, never on a figure: no card is built.
    let history = snapshot.history(|_| RateCard::absent(0));
    let view = history.current();
    let mut spans = in_force(&view);
    snapshot
        .entries
        .values()
        .map(|stored| {
            let resolved = view.entry_keyed(&stored.key);
            row(
                stored,
                resolved.map_or(stored.effective_from, |entry| entry.effective_from()),
                resolved.is_some_and(|entry| entry.is_voided()),
                spans.remove(&stored.key).unwrap_or_default(),
            )
        })
        .collect()
}

/// Where each entry is the card in force: the answer of `entry_at` is constant between two
/// consecutive window boundaries, so it is asked once per boundary and runs of one owner merged.
fn in_force(view: &HistoryView<'_>) -> BTreeMap<EntryKey, Vec<RateHistorySpan>> {
    let mut bounds = vec![0u64];
    for entry in view.entries().iter().filter(|entry| !entry.is_voided()) {
        bounds.push(entry.effective_from());
        bounds.extend(entry.effective_until());
    }
    bounds.sort();
    bounds.dedup();
    let mut spans: BTreeMap<EntryKey, Vec<RateHistorySpan>> = BTreeMap::new();
    let mut run: Option<(EntryKey, u64)> = None;
    for &from in &bounds {
        let owner = view.entry_at(from).map(|entry| entry.key());
        if run.is_some_and(|(key, _)| Some(key) == owner) {
            continue;
        }
        if let Some((key, start)) = run.take() {
            spans.entry(key).or_default().push(RateHistorySpan {
                from_ms: start,
                until_ms: Some(from),
            });
        }
        run = owner.map(|key| (key, from));
    }
    if let Some((key, start)) = run {
        spans.entry(key).or_default().push(RateHistorySpan {
            from_ms: start,
            until_ms: None,
        });
    }
    spans
}

fn row(
    stored: &StoredEntry,
    effective_from_ms: u64,
    voided: bool,
    in_force: Vec<RateHistorySpan>,
) -> RateHistoryEntry {
    let correction = |reason: &str| RateHistoryCorrection {
        from_ms: stored.effective_from,
        until_ms: stored.effective_until,
        reason_sha256: reason.to_string(),
    };
    let (author, correction, migrated_from) = match &stored.author {
        EntryAuthor::Opening {} => ("opening", None, None),
        EntryAuthor::Change => ("change", None, None),
        EntryAuthor::Amend { reason } => ("amend", Some(correction(reason)), None),
        EntryAuthor::Migrated {
            node,
            node_seq,
            opening,
            reason,
        } => (
            "migrated",
            reason.as_deref().map(correction),
            Some(RateHistoryMigration {
                node: format!("{node:016x}"),
                node_seq: node_seq.to_string(),
                opening: *opening,
            }),
        ),
    };
    RateHistoryEntry {
        key: stored.key.hex(),
        entry_id: stored.key.id().hex(),
        effective_from_ms,
        effective_until_ms: stored.effective_until,
        authored_from_ms: stored.effective_from,
        in_force,
        voided,
        written_as: if correction.is_some() {
            "correction"
        } else {
            "configuration"
        },
        author,
        actor: stored.actor.clone(),
        writer_node: format!("{:016x}", stored.writer),
        appended_at_ms: stored.appended_at,
        base_key: stored.base.map(|base| base.hex()),
        set_fields: stored.set_fields.clone(),
        correction,
        migrated_from,
        envelope: stored.correction.as_deref().map(hex::encode),
        card: card(&stored.card),
    }
}

fn card(fields: &CardFields) -> RateHistoryCard {
    let flat = fields.rate_card.as_ref().map(|lanes| RateHistoryPlaneCard {
        plane: None,
        lanes: lanes
            .iter()
            .map(|(lane, rates)| lane_rates(lane, lane.clone(), rates))
            .collect(),
    });
    let planes = fields
        .plane_rate_cards
        .iter()
        .map(|(plane, lanes)| RateHistoryPlaneCard {
            plane: Some(plane.clone()),
            lanes: lanes
                .iter()
                .map(|(lane, rates)| {
                    lane_rates(lane, format!("{plane}{PLANE_LANE_SEP}{lane}"), rates)
                })
                .collect(),
        });
    RateHistoryCard {
        per_request_fee_minor: fields.per_request_fee.to_string(),
        cards: flat.into_iter().chain(planes).collect(),
        plane_fees: fields
            .plane_fees
            .iter()
            .map(|(plane, fees)| RateHistoryPlaneFees {
                plane: plane.clone(),
                per_request_minor: fees.per_request.to_string(),
                per_session_minor: fees.per_session.to_string(),
            })
            .collect(),
        measurements: fields
            .plugin_rate_cards
            .iter()
            .flat_map(|(kind, namespaces)| {
                namespaces
                    .iter()
                    .map(move |(namespace, classes)| RateHistoryMeasurement {
                        kind: kind.clone(),
                        namespace: namespace.clone(),
                        card_lane: measurement_lane(kind, namespace),
                        rates: classes
                            .iter()
                            .map(|(class, rate)| exact_rate(class, rate.nanos_per_unit()))
                            .collect(),
                    })
            })
            .collect(),
    }
}

/// A lane's rates: the four token classes as the configuration stores them (`cache_write` only
/// when configured) and every open class, each with the figure the card prices it at.
fn lane_rates(lane: &str, card_lane: String, rates: &RateEntryCfg) -> RateHistoryLane {
    let priced = rates.raw_tier_rates();
    let tiers = [
        ("input", Some(rates.input_utok), priced.input),
        ("output", Some(rates.output_utok), priced.output),
        ("cache_read", Some(rates.cache_read_utok), priced.cache_read),
        ("cache_write", rates.cache_write_utok, priced.cache_write),
    ];
    let mut out: Vec<RateHistoryRate> = tiers
        .into_iter()
        .filter_map(|(class, stored, nanos)| {
            stored.map(|micro| RateHistoryRate {
                class: class.to_string(),
                // Rust spells a double as its shortest decimal that reads back to the same bits,
                // and never with an exponent: exact text for the stored figure.
                micro_per_unit: micro.to_string(),
                nanos_per_unit: nanos.map(|nanos| nanos.to_string()),
            })
        })
        .collect();
    out.extend(
        rates
            .units
            .iter()
            .map(|(class, rate)| exact_rate(class, rate.nanos_per_unit())),
    );
    RateHistoryLane {
        lane: lane.to_string(),
        card_lane,
        rates: out,
    }
}

/// A rate the card holds as whole nano-units: its micro-unit text is exact by construction.
fn exact_rate(class: &str, nanos: u64) -> RateHistoryRate {
    RateHistoryRate {
        class: class.to_string(),
        micro_per_unit: micro_text(nanos),
        nanos_per_unit: Some(nanos.to_string()),
    }
}

/// `nanos` nano-units as exact micro-unit decimal text: no trailing zero, no point for a whole.
fn micro_text(nanos: u64) -> String {
    let (whole, frac) = (nanos / 1000, nanos % 1000);
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{frac:03}")
            .trim_end_matches('0')
            .to_string()
    }
}

#[cfg(test)]
#[path = "tests/rate_history_tests.rs"]
mod tests;
