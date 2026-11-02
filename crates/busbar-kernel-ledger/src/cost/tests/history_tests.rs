// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated history and the lookup over it: appending never rewrites, the resolution rule takes

use super::*;
use crate::cost::{Author, CardEntryDraft, History, HistorySeq, LaneClass, RateCard};

/// A card pricing one class on one lane at a named rate.
fn card_at(micro: f64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", INPUT), micro)], 0)
}

/// A history with three entries: the opening one, an ordinary edit, and a back-dated amendment that
fn overlapping_history() -> History {
    let mut history = History::opening(card_at(1.0), 0);
    history.append(CardEntryDraft {
        effective_from: 100,
        effective_until: None,
        card: card_at(2.0),
        appended_at: 100,
        author: Author::Config { policy_epoch: 1 },
    });
    history.append(CardEntryDraft {
        effective_from: 50,
        effective_until: Some(150),
        card: card_at(3.0),
        appended_at: 900,
        author: Author::Amend {
            reason_hash: [7u8; 32],
        },
    });
    history
}

/// **THE RESOLUTION RULE.** Among the entries a snapshot can see whose interval covers an instant,
#[test]
fn card_at_resolves_overlap_by_the_highest_covering_seq() {
    let history = overlapping_history();
    let view = history.current();

    assert_eq!(view.card_at(10).expect("covered").0, HistorySeq(0));

    assert_eq!(view.card_at(60).expect("covered").0, HistorySeq(2));

    assert_eq!(view.card_at(120).expect("covered").0, HistorySeq(2));

    assert_eq!(view.card_at(150).expect("covered").0, HistorySeq(1));
    assert_eq!(view.card_at(1_000_000).expect("covered").0, HistorySeq(1));

    assert_eq!(view.card_at(49).expect("covered").0, HistorySeq(0));
    assert_eq!(view.card_at(50).expect("covered").0, HistorySeq(2));
    assert_eq!(view.card_at(149).expect("covered").0, HistorySeq(2));
}

/// The opening entry is effective from instant ZERO, which is what makes a hole impossible for a
#[test]
fn the_opening_entry_covers_every_instant_including_zero() {
    let history = History::opening(card_at(1.0), 1_700_000_000_000);
    let view = history.current();
    for t in [0u64, 1, 1_700_000_000_000, u64::MAX] {
        assert_eq!(
            view.card_at(t).expect("the opening entry is open-ended").0,
            HistorySeq(0),
            "instant {t} is covered"
        );
    }
    assert_eq!(history.entries()[0].author(), &Author::Opening);
    assert_eq!(
        history.entries()[0].appended_at(),
        1_700_000_000_000,
        "the seal's wall clock, which is NOT the effective instant"
    );
    assert_eq!(history.entries()[0].effective_from(), 0);
}

/// A back-dated amendment is visible AS a back-date, because the instant it prices from and the
#[test]
fn a_back_dated_entry_is_visible_as_one() {
    let history = overlapping_history();
    let config = &history.entries()[1];
    let amend = &history.entries()[2];
    assert_eq!(config.effective_from(), config.appended_at());
    assert!(amend.appended_at() > amend.effective_from());
    match amend.author() {
        Author::Amend { reason_hash } => {
            assert_eq!(reason_hash, &[7u8; 32]);
        }
        other => panic!("the amendment's author is an amendment, not {other:?}"),
    }
}

/// A snapshot above the head sees the whole history rather than refusing: the refusal for a seq
#[test]
fn a_snapshot_above_the_head_sees_the_whole_history() {
    let history = overlapping_history();
    let above = history.snapshot(HistorySeq(99));
    assert_eq!(above.entries().len(), 3);
    assert_eq!(above.card_at(120).expect("covered").0, HistorySeq(2));
}

/// The current view of a history nothing has been appended to names no snapshot. Zero is the seq of
#[test]
fn the_current_view_of_an_empty_history_names_no_snapshot() {
    let empty = History::new();
    assert_eq!(empty.current().seq(), None);
    assert!(empty.current().is_empty());

    let opened = History::opening(card_at(1.0), 0);
    assert_eq!(opened.current().seq(), Some(HistorySeq::OPENING));
    assert_eq!(
        overlapping_history().current().seq(),
        Some(HistorySeq(2)),
        "the current view is the head's snapshot"
    );
    assert_eq!(
        overlapping_history().snapshot(HistorySeq(1)).seq(),
        Some(HistorySeq(1)),
        "a named snapshot keeps the seq it was named at"
    );
}

/// **THE ONE CARD A CORRECTION'S WINDOW RESOLVES TO** (#79): the entry pricing every
#[test]
fn sole_entry_over_names_the_one_entry_pricing_a_whole_window() {
    let mut history = History::opening(card_at(2.0), 0);
    history.append(CardEntryDraft {
        effective_from: 6_000,
        effective_until: None,
        card: card_at(3.0),
        appended_at: 6_000,
        author: Author::Config { policy_epoch: 1 },
    });
    history.append(CardEntryDraft {
        effective_from: 10_000,
        effective_until: Some(12_000),
        card: card_at(4.0),
        appended_at: 20_000,
        author: Author::Amend {
            reason_hash: [0; 32],
        },
    });
    let view = history.current();
    let seq = |from, until| view.sole_entry_over(from, until).map(|e| e.seq());
    assert_eq!(seq(1_000, Some(6_000)), Some(HistorySeq(0)));
    assert_eq!(
        seq(1_000, Some(6_001)),
        None,
        "the edit at 6,000 prices part of it"
    );
    assert_eq!(seq(6_000, Some(10_000)), Some(HistorySeq(1)));
    assert_eq!(
        seq(6_000, None),
        None,
        "the amendment prices part of an open window"
    );
    assert_eq!(seq(10_000, Some(12_000)), Some(HistorySeq(2)));
    assert_eq!(
        seq(11_000, Some(12_001)),
        None,
        "runs past the amendment's end"
    );
    assert_eq!(seq(12_000, None), Some(HistorySeq(1)));
    assert_eq!(
        History::new()
            .current()
            .sole_entry_over(0, None)
            .map(|e| e.seq()),
        None
    );
}

/// **WHERE A CORRECTION WOULD CUT INSIDE A ROW** (OWNER ruling #32, 2026-09-29). Rows are
#[test]
fn correction_cut_names_a_boundary_inside_a_row() {
    let mut history = History::opening(card_at(2.0), 0);
    history.append(CardEntryDraft {
        effective_from: 2_500,
        effective_until: None,
        card: card_at(3.0),
        appended_at: 2_500,
        author: Author::Config { policy_epoch: 1 },
    });
    history.append(CardEntryDraft {
        effective_from: 3_200,
        effective_until: Some(3_600),
        card: card_at(4.0),
        appended_at: 4_000,
        author: Author::Amend {
            reason_hash: [0; 32],
        },
    });
    let view = history.current();
    let cut = |from, until| view.correction_cut(from, until, 5_000, 1_000);

    assert_eq!(cut(1_000, Some(2_000)), None);
    assert_eq!(cut(2_500, Some(3_000)), Some(2_500));
    assert_eq!(cut(0, None), None);

    assert_eq!(cut(1_500, Some(2_000)), Some(1_500));
    assert_eq!(cut(1_000, Some(1_500)), Some(1_500));
    assert_eq!(cut(2_700, None), Some(2_700));

    assert_eq!(cut(3_200, Some(4_000)), Some(3_200));

    assert_eq!(cut(5_200, Some(5_800)), Some(5_200));
    assert_eq!(cut(5_000, Some(6_300)), Some(6_300));
    assert_eq!(cut(5_000, Some(6_000)), None);
}

/// **AN ENTRY IS NAMED BY ITS KEY'S ID.** The id is the first 12 bytes of SHA-256 of the key, spelled
#[test]
fn entries_are_named_by_the_id_of_their_key() {
    use crate::cost::{EntryId, EntryKey};
    let key = EntryKey::new(0x0102_0304_0506_0708, [9; 8], 3);
    assert_eq!(key.t_ms(), 0x0102_0304_0506_0708);
    assert_eq!(EntryKey::parse_hex(&key.hex()), Some(key));
    let id = key.id();
    assert_eq!(id.hex().len(), 24);
    assert_eq!(EntryId::parse_hex(&id.hex()), Some(id));
    let prefix = id.pseudo_prefix();
    assert_eq!(prefix.len(), 25);
    assert_eq!(
        EntryId::split_pseudo(&format!("{prefix}gpt-4o")),
        Some((id, "gpt-4o"))
    );
    assert_eq!(EntryId::split_pseudo(&prefix), Some((id, "")));
    assert_eq!(EntryId::split_pseudo("gpt-4o"), None);

    let history = overlapping_history();
    let keys: Vec<_> = history.entries().iter().map(|e| e.key()).collect();
    assert!(
        keys.windows(2).all(|w| w[0] < w[1]),
        "key order is append order"
    );
    let (at_120, card) = history.entry_at(120).expect("covered");
    assert_eq!(at_120, history.entries()[2].id());
    assert_eq!(card, &card_at(3.0));
    assert_eq!(
        history.card_of(&history.entries()[0].id()),
        Some(&card_at(1.0))
    );
    assert_eq!(history.card_of(&EntryKey::new(1, [0; 8], 0).id()), None);
}

#[test]
fn serving_entry_survives_later_config_but_accepts_a_wall_scoped_amendment() {
    use crate::cost::RawRateEra;

    let mut history = overlapping_history();
    let opening = history.entries()[0].id();
    let config = history.entries()[1].id();
    let amendment = history.entries()[2].key();
    let view = history.current();
    let seq = |id, wall_at| view.card_for_entry_era(id, wall_at).map(|(seq, _)| seq);

    assert_eq!(seq(opening, 150), Some(HistorySeq::OPENING));
    assert_eq!(seq(config, 150), Some(HistorySeq(1)));
    assert_eq!(seq(opening, 49), Some(HistorySeq::OPENING));
    assert_eq!(seq(opening, 50), Some(HistorySeq(2)));
    assert_eq!(seq(opening, 149), Some(HistorySeq(2)));
    assert_eq!(seq(config, 120), Some(HistorySeq(2)));

    assert_eq!(
        view.card_for_raw_era(RawRateEra::legacy(0), 150)
            .map(|(seq, _)| seq),
        Some(HistorySeq(1)),
        "an undated legacy zero proves no opening identity"
    );
    assert_eq!(
        view.card_for_raw_era(RawRateEra::entry(0, opening), 150)
            .map(|(seq, _)| seq),
        Some(HistorySeq::OPENING)
    );
    assert!(view
        .card_for_raw_era(RawRateEra::entry(100, opening), 150)
        .is_none());
    assert_eq!(
        history
            .snapshot(HistorySeq(1))
            .card_for_entry_era(opening, 120)
            .map(|(seq, _)| seq),
        Some(HistorySeq::OPENING),
        "a prior snapshot cannot see the later amendment"
    );
    assert!(history
        .snapshot(HistorySeq::OPENING)
        .card_for_entry_era(config, 150)
        .is_none());

    history.void(&amendment);
    assert_eq!(
        history
            .current()
            .card_for_entry_era(opening, 120)
            .map(|(seq, _)| seq),
        Some(HistorySeq::OPENING),
        "a voided amendment no longer corrects counts"
    );
    let config_key = history.entries()[1].key();
    history.void(&config_key);
    assert_eq!(
        history
            .current()
            .card_for_entry_era(config, 150)
            .map(|(seq, _)| seq),
        Some(HistorySeq(1)),
        "voiding a configuration keeps the card already-served counts name"
    );
}

#[test]
fn timestamp_eras_refuse_missing_or_ambiguous_original_entries() {
    use crate::cost::{EntryKey, RawRateEra};

    let mut history = overlapping_history();
    let original = history.entries()[1].id();
    assert!(history.current().card_for_config_era(99, 1_000).is_none());
    assert!(history
        .current()
        .card_for_entry_era(EntryKey::new(42, [1; 8], 0).id(), 1_000)
        .is_none());
    history.append(CardEntryDraft {
        effective_from: 100,
        effective_until: None,
        card: card_at(4.0),
        appended_at: 1_000,
        author: Author::Config { policy_epoch: 2 },
    });
    let view = history.current();
    assert!(view.card_for_config_era(100, 1_000).is_none());
    assert_eq!(
        view.card_for_entry_era(original, 120).map(|(seq, _)| seq),
        Some(HistorySeq(2)),
        "a later configuration does not erase an amendment of old-entry counts"
    );
    let later = history.entries()[3].id();
    assert_eq!(
        view.card_for_entry_era(later, 120).map(|(seq, _)| seq),
        Some(HistorySeq(3)),
        "an earlier amendment does not replace a later serving configuration"
    );
    assert_eq!(
        view.card_for_raw_era(RawRateEra::entry(100, original), 1_000)
            .map(|(seq, _)| seq),
        Some(HistorySeq(1)),
        "the recorded identity disambiguates equal configuration timestamps"
    );
}

#[test]
fn metering_identity_codec_preserves_legacy_names_and_refuses_malformed_new_names() {
    use crate::cost::{EntryId, EntryKey};

    let id = EntryKey::new(42, [1; 8], 0).id();
    assert_eq!(
        EntryId::parse_metering_version(&id.metering_version()),
        Some(Some(id))
    );
    for legacy in ["", "v1", "historical-card", "historical-version"] {
        assert_eq!(EntryId::parse_metering_version(legacy), None);
    }
    assert_eq!(
        EntryId::parse_metering_version(EntryId::METERING_VERSION_PREFIX),
        Some(None)
    );
    assert_eq!(
        EntryId::parse_metering_version(&format!("{}bad", EntryId::METERING_VERSION_PREFIX)),
        Some(None)
    );
}
