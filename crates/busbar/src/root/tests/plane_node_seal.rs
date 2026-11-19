// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn pinned(
    entries: Vec<(u64, busbar_kernel_ledger::cost::Author)>,
) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    let mut head = busbar_kernel_ledger::cost::HistorySeq::OPENING;
    for (effective_from, author) in entries {
        head = history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from,
            effective_until: None,
            card: crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                false,
            ),
            appended_at: effective_from,
            author,
        });
    }
    crate::root::kernel::PinnedHistory::for_test(Arc::new(history), head)
}

fn configured(policy_epoch: u64) -> busbar_kernel_ledger::cost::Author {
    busbar_kernel_ledger::cost::Author::Config { policy_epoch }
}

#[test]
fn audit_rate_card_provenance_keeps_the_actual_key_across_peer_insertion() {
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, History};
    let card = crate::root::kernel::card_from_config(
        std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
        0,
        false,
    );
    let draft = |at| CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: card.clone(),
        appended_at: at,
        author: Author::Opening,
    };
    let original = EntryKey::new(300, [3; 8], 1);
    let mut history = History::new();
    history.insert(EntryKey::new(100, [1; 8], 0), draft(100));
    history.insert(original, draft(300));
    let before = crate::root::kernel::PinnedHistory::for_test(
        Arc::new(history.clone()),
        history.head().unwrap(),
    );
    assert_eq!(card_in_force(Some(&before), 0), Some(original.0));
    history.insert(EntryKey::new(200, [2; 8], 0), draft(200));
    assert_eq!(history.entry(&original).unwrap().seq().get(), 2);
    let after = crate::root::kernel::PinnedHistory::for_test(
        Arc::new(history.clone()),
        history.head().unwrap(),
    );
    assert_eq!(card_in_force(Some(&after), 0), Some(original.0));
    assert_eq!(card_in_force(None, 0), None);
    let zero = pinned(vec![(0, configured(1))]);
    assert_eq!(card_in_force(Some(&zero), 0), Some([0; 20]));
}
