// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Root wiring and historical node-journal input conversion. Price persistence,
//! pending ownership, publication and recovery live in kernel governance.
use busbar_kernel::config::card::CardFields;
pub use busbar_kernel::governance::persistence::prices::runtime::CardStore;
use busbar_kernel::governance::persistence::prices::{EntryAuthor, StoredEntry};
use busbar_kernel_ledger::cost::{Author, EntryKey, History};
use std::collections::{BTreeMap, BTreeSet};
pub fn digest_hex(card: &CardFields) -> String {
    hex::encode(card.digest())
}
pub fn rate_card_of(card: &CardFields) -> busbar_kernel_ledger::cost::RateCard {
    let rates = card.rates();
    crate::root::kernel::register_classes(&rates.raw());
    crate::root::kernel::card_from_raw(&rates.raw())
}
pub type Chain = (u64, Vec<busbar_kernel_wal::JournalRecord>);

/// Convert historical cards without changing their timestamp/node/sequence keys.
///
/// Refuses the whole conversion if a card's journal sequence cannot fit the
/// key's 32-bit counter. Truncating or saturating it can collide with another
/// card and silently replace financial history when entries are persisted.
/// No partial history is returned on failure.
pub fn migrated(chains: &[Chain], writer: u64) -> Result<Vec<StoredEntry>, String> {
    use crate::root::kernel::JournalledCard;
    let mut out: Vec<StoredEntry> = Vec::new();
    for (node, records) in chains {
        let mut opening = None;
        let mut rest = Vec::new();
        for (seq, body, card) in crate::root::kernel::journalled_cards_at(records) {
            match card {
                JournalledCard::Applied(applied)
                    if applied.effective_from == 0 && opening.is_none() =>
                {
                    opening = Some((seq, body, JournalledCard::Applied(applied)));
                }
                other => rest.push((seq, body, other)),
            }
        }
        let has_opening = opening.is_some();
        let mut history = History::new();

        let mut cards: BTreeMap<EntryKey, CardFields> = BTreeMap::new();
        let mut original_keys = Vec::new();
        for (index, (seq, body, card)) in opening.into_iter().chain(rest).enumerate() {
            let migrated = |reason: Option<String>| EntryAuthor::Migrated {
                node: *node,
                node_seq: seq,
                opening: has_opening && index == 0 && reason.is_none(),
                reason,
            };
            let (draft, fields, reason) = match card {
                JournalledCard::Applied(applied) => {
                    (applied.draft(), applied.form.to_fields(), None)
                }
                JournalledCard::Corrected(correction, sealed_over) => {
                    let (base_key, draft) = match correction.rebuild_from_original_chain(
                        &history,
                        sealed_over,
                        &original_keys,
                    ) {
                        Ok(resolved) => resolved,
                        Err(cause) => {
                            tracing::warn!(
                                node,
                                node_seq = seq,
                                ?cause,
                                "a journalled rate correction its chain's rebuild refuses is not \
                                 migrated (it never priced an instant)"
                            );
                            original_keys.push(None);
                            continue;
                        }
                    };
                    let Some(base) = cards.get(&base_key) else {
                        original_keys.push(None);
                        continue;
                    };
                    let cells: Vec<(String, String, u64)> = correction
                        .cells
                        .iter()
                        .map(|(cell, nanos)| (cell.lane.clone(), cell.class.clone(), *nanos))
                        .collect();
                    let fields = crate::root::kernel::cells_onto(base, &cells, correction.fee);
                    let reason = match &draft.author {
                        Author::Amend { reason_hash } => Some(hex::encode(reason_hash)),
                        _ => Some(String::new()),
                    };
                    (draft, fields, reason)
                }
                JournalledCard::Amended(draft) => {
                    let fields = amended_fields(&body);
                    let reason = match &draft.author {
                        Author::Amend { reason_hash } => Some(hex::encode(reason_hash)),
                        _ => Some(String::new()),
                    };
                    (draft, fields, reason)
                }
            };
            let counter = u32::try_from(seq).map_err(|_| {
                format!(
                    "cannot migrate rate-card history: node {node} journal sequence {seq} exceeds \
                     the entry key's 32-bit counter; no history was converted"
                )
            })?;
            history.append(draft.clone());
            let entry_key = history.head_key();
            original_keys.push(entry_key);
            if let Some(key) = entry_key {
                cards.insert(key, fields.clone());
            }
            out.push(StoredEntry {
                key: EntryKey::new(draft.appended_at, node.to_be_bytes(), counter),
                effective_from: draft.effective_from,
                effective_until: draft.effective_until,
                appended_at: draft.appended_at,
                author: migrated(reason),
                actor: format!("migrated from node {node}'s journal"),
                base: None,
                writer,
                set_fields: Vec::new(),
                card: fields,
                correction: None,
            });
        }
    }

    out.sort_by_key(|e| e.key);
    let mut seen: BTreeSet<(String, u64, Option<u64>)> = BTreeSet::new();
    let mut opened = false;
    out.retain(|e| {
        if matches!(e.author, EntryAuthor::Migrated { opening: true, .. }) {
            if opened {
                return false;
            }
            opened = true;
        }
        seen.insert((digest_hex(&e.card), e.effective_from, e.effective_until))
    });
    Ok(out)
}

#[cfg(feature = "root-admin")]
fn amended_fields(body: &[u8]) -> CardFields {
    let Some(amendment) = crate::root::units_admin::amendment_from_body(body) else {
        return CardFields::default();
    };
    let cells: Vec<(String, String, u64)> = amendment
        .rates
        .iter()
        .filter_map(|(l, c, n)| n.map(|n| (l.clone(), c.clone(), n)))
        .collect();
    crate::root::kernel::cells_onto(
        &CardFields {
            rate_card: Some(BTreeMap::new()),
            ..CardFields::default()
        },
        &cells,
        Some(amendment.sealed_fee),
    )
}

#[cfg(not(feature = "root-admin"))]
fn amended_fields(_body: &[u8]) -> CardFields {
    CardFields::default()
}

#[cfg(test)]
#[path = "tests/card_history.rs"]
mod tests;
