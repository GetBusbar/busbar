// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /ledger/rate-history`: the stored history, one row per entry, and a reader's lookup of
//! "the card in force at t" from those rows agrees with the engine's own.

use std::collections::{BTreeMap, HashMap};

use busbar_kernel::governance::persistence::prices::{Activation, VoidRecord};

use super::*;

fn key(t_ms: u64, counter: u32) -> EntryKey {
    EntryKey::new(t_ms, [7; 8], counter)
}

fn fee_card(fee: i64) -> CardFields {
    CardFields {
        per_request_fee: fee,
        ..CardFields::default()
    }
}

fn stored(
    key: EntryKey,
    author: EntryAuthor,
    from: u64,
    until: Option<u64>,
    card: CardFields,
) -> StoredEntry {
    StoredEntry {
        key,
        effective_from: from,
        effective_until: until,
        appended_at: key.t_ms(),
        author,
        actor: "boot of node 42".into(),
        base: None,
        writer: 42,
        set_fields: Vec::new(),
        card,
        correction: None,
    }
}

fn snapshot_of(entries: Vec<StoredEntry>) -> Snapshot {
    let head = entries.iter().map(|e| e.key).max();
    Snapshot {
        entries: entries.into_iter().map(|e| (e.key, e)).collect(),
        head,
        generation: Some(9),
        ..Snapshot::default()
    }
}

fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn whole(snapshot: &Snapshot) -> RateHistoryPage {
    page(snapshot, &window(&q(&[("limit", "1000")])).ok().unwrap())
}

fn span(from_ms: u64, until_ms: Option<u64>) -> RateHistorySpan {
    RateHistorySpan { from_ms, until_ms }
}

async fn refusal(resp: Response) -> (u16, String) {
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[test]
fn an_empty_history_is_an_empty_page_with_no_cursor() {
    let page = whole(&Snapshot {
        generation: Some(3),
        ..Snapshot::default()
    });
    assert!(page.items.is_empty());
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.generation.as_deref(), Some("3"));
    assert_eq!(
        wire(&page),
        r#"{"items":[],"next_cursor":null,"generation":"3"}"#
    );
}

/// The page as the node writes it.
fn wire(page: &RateHistoryPage) -> String {
    String::from_utf8(busbar_contract::json::to_vec(page).unwrap()).unwrap()
}

/// What follows each `"name":` in `text`, up to its first byte.
fn first_bytes_after(text: &str, name: &str) -> Vec<char> {
    let needle = format!("\"{name}\":");
    text.match_indices(&needle)
        .filter_map(|(at, _)| text[at + needle.len()..].chars().next())
        .collect()
}

#[test]
fn one_configuration_entry_is_one_open_row_in_force_from_instant_zero() {
    let opening = key(1_000, 0);
    let page = whole(&snapshot_of(vec![stored(
        opening,
        EntryAuthor::Opening {},
        0,
        None,
        fee_card(7),
    )]));
    assert_eq!(page.items.len(), 1);
    let row = &page.items[0];
    assert_eq!(row.key, opening.hex());
    assert_eq!(row.key.len(), 40);
    assert_eq!(row.entry_id, opening.id().hex());
    assert_eq!(row.effective_from_ms, 0);
    assert_eq!(row.effective_until_ms, None);
    assert_eq!(row.in_force, vec![span(0, None)]);
    assert!(!row.voided);
    assert_eq!(row.written_as, "configuration");
    assert_eq!(row.author, "opening");
    assert_eq!(row.actor, "boot of node 42");
    assert_eq!(row.writer_node, "000000000000002a");
    assert_eq!(row.appended_at_ms, 1_000);
    assert_eq!(row.correction, None);
    assert_eq!(row.card.per_request_fee_minor, "7");
    assert!(row.card.cards.is_empty(), "no rate_card is configured");

    let text = wire(&page);
    assert!(
        !text.contains("\"effective_until_ms\""),
        "an open entry has no end: {text}"
    );
    assert!(
        !text.contains("\"until_ms\""),
        "an open span has no end: {text}"
    );
    assert!(text.contains("\"in_force\":[{\"from_ms\":0}]"), "{text}");
    assert!(text.contains("\"per_request_fee_minor\":\"7\""), "{text}");
}

#[test]
fn a_configuration_change_closes_the_first_entry_at_exactly_the_seconds_start() {
    let opening = key(1_000, 0);
    let change = key(5_000, 1);
    let mut second = stored(change, EntryAuthor::Change, 4_990, None, fee_card(9));
    second.base = Some(opening);
    second.actor = "a configuration change".into();
    second.set_fields = vec!["per_request_fee".into()];
    let mut snapshot = snapshot_of(vec![
        stored(opening, EntryAuthor::Opening {}, 0, None, fee_card(7)),
        second,
    ]);
    // The activation, not the authored start, is when the change took effect.
    snapshot.activations.insert(
        change,
        Activation {
            effective_from: 5_000,
        },
    );
    let page = whole(&snapshot);
    let [first, next] = page.items.as_slice() else {
        panic!("two rows: {:?}", page.items);
    };
    assert_eq!(first.in_force, vec![span(0, Some(5_000))]);
    assert_eq!(next.in_force, vec![span(5_000, None)]);
    assert_eq!(next.effective_from_ms, 5_000);
    assert_eq!(next.authored_from_ms, 4_990);
    assert_eq!(
        first.effective_until_ms, None,
        "stored open; the change ends it"
    );
    assert_eq!(next.written_as, "configuration");
    assert_eq!(next.author, "change");
    assert_eq!(next.base_key.as_deref(), Some(opening.hex().as_str()));
    assert_eq!(next.set_fields, vec!["per_request_fee".to_string()]);

    let history = snapshot.history(|_| RateCard::absent(0));
    for (t, owner) in [(4_999, opening), (5_000, change), (5_001, change)] {
        assert_eq!(history.current().entry_at(t).unwrap().key(), owner, "{t}");
        assert_eq!(in_force_at(&page.items, t), Some(owner.hex()), "{t}");
    }
}

#[test]
fn a_signed_correction_carries_its_window_and_reason_and_outranks_inside_it() {
    let opening = key(1_000, 0);
    let amend = key(9_000, 1);
    let reason = "ab".repeat(32);
    let mut correction = stored(
        amend,
        EntryAuthor::Amend {
            reason: reason.clone(),
        },
        2_000,
        Some(4_000),
        fee_card(5),
    );
    correction.actor = "key:vk_operator".into();
    correction.base = Some(opening);
    let page = whole(&snapshot_of(vec![
        stored(opening, EntryAuthor::Opening {}, 0, None, fee_card(7)),
        correction,
    ]));
    let [first, fix] = page.items.as_slice() else {
        panic!("two rows: {:?}", page.items);
    };
    assert_eq!(fix.written_as, "correction");
    assert_eq!(fix.author, "amend");
    assert_eq!(fix.actor, "key:vk_operator");
    assert_eq!(
        fix.correction,
        Some(RateHistoryCorrection {
            from_ms: 2_000,
            until_ms: Some(4_000),
            reason_sha256: reason,
        })
    );
    assert_eq!(fix.envelope, None, "this build stores no signature");
    assert_eq!(fix.effective_until_ms, Some(4_000));
    assert_eq!(fix.in_force, vec![span(2_000, Some(4_000))]);
    assert_eq!(
        first.in_force,
        vec![span(0, Some(2_000)), span(4_000, None)]
    );
    assert_eq!(first.correction, None);
}

#[test]
fn a_stored_envelope_is_served_as_stored() {
    let mut entry = stored(key(1, 0), EntryAuthor::Opening {}, 0, None, fee_card(1));
    entry.correction = Some(vec![0, 128, 255, 1]);
    let page = whole(&snapshot_of(vec![entry]));
    assert_eq!(page.items[0].envelope.as_deref(), Some("0080ff01"));
}

#[test]
fn a_voided_entry_and_a_losing_opening_price_nothing() {
    let opening = key(1_000, 0);
    let rival = key(2_000, 1);
    let future = key(3_000, 2);
    let mut snapshot = snapshot_of(vec![
        stored(opening, EntryAuthor::Opening {}, 0, None, fee_card(1)),
        stored(rival, EntryAuthor::Opening {}, 0, None, fee_card(2)),
        stored(future, EntryAuthor::Change, 10_000, None, fee_card(3)),
    ]);
    snapshot.voids.push(VoidRecord {
        voided: future.hex(),
        voider: 42,
        at_ms: 3_500,
        actor: "admin".into(),
        why: "void".into(),
    });
    let page = whole(&snapshot);
    let rows: BTreeMap<&str, &RateHistoryEntry> =
        page.items.iter().map(|r| (r.key.as_str(), r)).collect();
    assert!(!rows[opening.hex().as_str()].voided);
    assert_eq!(rows[opening.hex().as_str()].in_force, vec![span(0, None)]);
    for lost in [rival, future] {
        let row = rows[lost.hex().as_str()];
        assert!(row.voided, "{lost}");
        assert!(row.in_force.is_empty(), "{lost}");
    }
}

#[tokio::test]
async fn pages_cross_a_boundary_without_skipping_or_repeating_and_refuse_foreign_cursors() {
    let entries: Vec<StoredEntry> = (0..5u32)
        .map(|i| {
            let t = 1_000 * (u64::from(i) + 1);
            let author = if i == 0 {
                EntryAuthor::Opening {}
            } else {
                EntryAuthor::Change
            };
            let from = if i == 0 { 0 } else { t };
            stored(key(t, i), author, from, None, fee_card(i64::from(i)))
        })
        .collect();
    let snapshot = snapshot_of(entries.clone());
    let everything = whole(&snapshot).items;

    let mut seen = Vec::new();
    let mut query = q(&[("limit", "2")]);
    let mut sizes = Vec::new();
    loop {
        let page = page(&snapshot, &window(&query).ok().unwrap());
        sizes.push(page.items.len());
        seen.extend(page.items);
        match page.next_cursor {
            Some(next) => {
                query = q(&[("limit", "2"), ("cursor", next.as_str())]);
            }
            None => break,
        }
    }
    assert_eq!(sizes, vec![2, 2, 1]);
    assert_eq!(
        seen, everything,
        "the pages are the whole history, in key order"
    );
    let keys: Vec<String> = entries.iter().map(|e| e.key.hex()).collect();
    assert_eq!(seen.iter().map(|r| r.key.clone()).collect::<Vec<_>>(), keys);

    // A row written between pages is not skipped and an earlier one is not repeated.
    let first = page(&snapshot, &window(&q(&[("limit", "2")])).ok().unwrap());
    let next = first.next_cursor.unwrap();
    let mut grown = entries;
    grown.push(stored(
        key(9_000, 9),
        EntryAuthor::Change,
        9_000,
        None,
        fee_card(9),
    ));
    let grown = snapshot_of(grown);
    let rest = page(
        &grown,
        &window(&q(&[("limit", "10"), ("cursor", next.as_str())]))
            .ok()
            .unwrap(),
    );
    assert_eq!(rest.items.len(), 4);
    assert_eq!(rest.items[0].key, keys[2]);
    assert_eq!(rest.next_cursor, None);

    let foreign = cursor::encode("audit-keys", "", &keys[0]);
    let (status, body) = refusal(*window(&q(&[("cursor", foreign.as_str())])).err().unwrap()).await;
    assert_eq!(status, 400);
    assert!(body.contains("cursor_mismatch"), "{body}");
    for bad in ["o:2", "k1", "k1.ledger-rate-history..zz", "garbage"] {
        let (status, body) = refusal(*window(&q(&[("cursor", bad)])).err().unwrap()).await;
        assert_eq!(status, 400, "{bad}");
        assert!(body.contains("malformed_cursor"), "{bad}: {body}");
    }
}

/// Reads `text` (a decimal with at most three places) as exact nano-units.
fn nanos_of_micro_text(text: &str) -> u64 {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    assert!(frac.len() <= 3, "{text}");
    let digits = format!("{whole}{frac:0<3}");
    digits.parse().unwrap()
}

#[test]
fn every_rate_and_fee_is_exact_decimal_text_that_reads_back_to_the_stored_figure() {
    let stored_card = br#"{
        "rate_card": {
            "smart": {"input_utok": 0.1, "output_utok": 3.0, "cache_read_utok": 1.234,
                      "cache_write_utok": 0.0005, "units": {"search_units": "1.5"}},
            "big": {"input_utok": 123456789.123, "output_utok": 0.3, "cache_read_utok": 0.0}
        },
        "per_request_fee": 9007199254740993,
        "planes": {"voice": {"rate_card": {"realtime": {"input_utok": 2.5, "output_utok": 7.0,
                                                         "cache_read_utok": 0.0}},
                             "fees": {"per_request": 3, "per_session": 11}}}
    }"#;
    let fields = CardFields::from_bytes(stored_card).unwrap();
    let page = whole(&snapshot_of(vec![stored(
        key(1, 0),
        EntryAuthor::Opening {},
        0,
        None,
        fields.clone(),
    )]));
    let card = &page.items[0].card;
    assert_eq!(card.per_request_fee_minor, "9007199254740993");
    assert_eq!(
        card.per_request_fee_minor.parse::<i64>().unwrap(),
        fields.per_request_fee
    );

    let flat = card.cards.iter().find(|c| c.plane.is_none()).unwrap();
    let voice = card
        .cards
        .iter()
        .find(|c| c.plane.as_deref() == Some("voice"))
        .unwrap();
    assert_eq!(voice.lanes[0].card_lane, "voice\u{1f}realtime");
    assert_eq!(
        flat.lanes
            .iter()
            .map(|l| l.lane.as_str())
            .collect::<Vec<_>>(),
        ["big", "smart"]
    );

    let configured = fields.rate_card.as_ref().unwrap();
    let mut checked = 0;
    for (lanes, cfg) in [
        (&flat.lanes, configured),
        (&voice.lanes, &fields.plane_rate_cards["voice"]),
    ] {
        for lane in lanes.iter() {
            let entry = &cfg[&lane.lane];
            let priced = entry.raw_tier_rates();
            for rate in &lane.rates {
                let (stored, nanos) = match rate.class.as_str() {
                    "input" => (Some(entry.input_utok), priced.input),
                    "output" => (Some(entry.output_utok), priced.output),
                    "cache_read" => (Some(entry.cache_read_utok), priced.cache_read),
                    "cache_write" => (entry.cache_write_utok, priced.cache_write),
                    class => {
                        let unit = entry.units[class].nanos_per_unit();
                        assert_eq!(rate.nanos_per_unit, Some(unit.to_string()));
                        assert_eq!(nanos_of_micro_text(&rate.micro_per_unit), unit);
                        checked += 1;
                        continue;
                    }
                };
                let stored = stored.expect("a served class is a stored class");
                // Bit for bit: the text reads back to exactly the stored double.
                assert_eq!(
                    rate.micro_per_unit.parse::<f64>().unwrap().to_bits(),
                    stored.to_bits(),
                    "{} {}",
                    lane.lane,
                    rate.class
                );
                assert!(
                    !rate.micro_per_unit.contains(['e', 'E']),
                    "{}",
                    rate.micro_per_unit
                );
                assert_eq!(rate.nanos_per_unit, nanos.map(|n| n.to_string()));
                if let Some(n) = nanos {
                    assert_eq!(nanos_of_micro_text(&rate.micro_per_unit), n);
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 4 + 1 + 3 + 3);

    let smart = flat.lanes.iter().find(|l| l.lane == "smart").unwrap();
    let rates: BTreeMap<&str, (&str, Option<&str>)> = smart
        .rates
        .iter()
        .map(|r| {
            (
                r.class.as_str(),
                (r.micro_per_unit.as_str(), r.nanos_per_unit.as_deref()),
            )
        })
        .collect();
    assert_eq!(rates["input"], ("0.1", Some("100")));
    assert_eq!(rates["output"], ("3", Some("3000")));
    assert_eq!(rates["cache_read"], ("1.234", Some("1234")));
    assert_eq!(
        rates["cache_write"],
        ("0.0005", None),
        "finer than a nano-unit: unpriced"
    );
    assert_eq!(rates["search_units"], ("1.5", Some("1500")));
    let big = flat.lanes.iter().find(|l| l.lane == "big").unwrap();
    assert!(
        big.rates.iter().all(|r| r.class != "cache_write"),
        "an unconfigured cache_write is not invented"
    );
    assert_eq!(big.rates[0].nanos_per_unit.as_deref(), Some("123456789123"));
    assert_eq!(
        card.plane_fees,
        vec![RateHistoryPlaneFees {
            plane: "voice".into(),
            per_request_minor: "3".into(),
            per_session_minor: "11".into(),
        }]
    );

    // Through the wire: every figure is a JSON string, never a number.
    let text = wire(&page);
    assert!(
        text.contains("\"per_request_fee_minor\":\"9007199254740993\""),
        "{text}"
    );
    let micros = first_bytes_after(&text, "micro_per_unit");
    assert_eq!(micros.len(), checked);
    assert!(micros.iter().all(|c| *c == '"'), "{text}");
    let nanos = first_bytes_after(&text, "nanos_per_unit");
    assert_eq!(nanos.len(), checked);
    assert!(nanos.iter().all(|c| *c == '"' || *c == 'n'), "{text}");
    for name in ["per_request_minor", "per_session_minor"] {
        assert!(first_bytes_after(&text, name).iter().all(|c| *c == '"'));
    }
}

#[test]
fn whole_nano_rates_spell_exactly() {
    for (nanos, text) in [
        (0, "0"),
        (1, "0.001"),
        (10, "0.01"),
        (1_000, "1"),
        (1_500, "1.5"),
        (u64::MAX, "18446744073709551.615"),
    ] {
        assert_eq!(micro_text(nanos), text);
        assert_eq!(nanos_of_micro_text(text), nanos);
    }
}

/// The key of the row whose `in_force` holds `t`, asserting that at most one does.
fn in_force_at(rows: &[RateHistoryEntry], t: u64) -> Option<String> {
    let mut owners = rows.iter().filter(|row| {
        row.in_force
            .iter()
            .any(|s| s.from_ms <= t && s.until_ms.is_none_or(|until| t < until))
    });
    let owner = owners.next().map(|row| row.key.clone());
    assert!(owners.next().is_none(), "two rows are in force at {t}");
    owner
}

/// A reader's rule from the rows alone: of the live rows whose window covers `t` (start
/// inclusive, end exclusive), the one with the highest key.
fn window_rule_at(rows: &[RateHistoryEntry], t: u64) -> Option<String> {
    rows.iter()
        .filter(|row| {
            !row.voided
                && row.effective_from_ms <= t
                && row.effective_until_ms.is_none_or(|until| t < until)
        })
        .map(|row| row.key.clone())
        .max()
}

/// A small deterministic generator (xorshift64), so a failure names its seed.
struct Gen(u64);
impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn generated(seed: u64) -> Snapshot {
    let mut gen = Gen(seed);
    let count = 1 + gen.below(12);
    let mut entries = Vec::new();
    let mut activations = Vec::new();
    let mut voids = Vec::new();
    let mut t = 0u64;
    for i in 0..count {
        t += 1 + gen.below(5_000);
        let key = key(t, u32::try_from(i).unwrap());
        let (author, from, until) = match gen.below(5) {
            0 => (EntryAuthor::Opening {}, 0, None),
            1 | 2 => (EntryAuthor::Change, t.saturating_sub(gen.below(50)), None),
            _ => {
                let from = gen.below(t + 1);
                let until = from + 1 + gen.below(10_000);
                (
                    EntryAuthor::Amend {
                        reason: "cd".repeat(32),
                    },
                    from,
                    Some(until),
                )
            }
        };
        if matches!(author, EntryAuthor::Change) && gen.below(2) == 0 {
            activations.push((
                key,
                Activation {
                    effective_from: from + gen.below(20),
                },
            ));
        }
        if !matches!(author, EntryAuthor::Opening {}) && gen.below(6) == 0 {
            voids.push(VoidRecord {
                voided: key.hex(),
                voider: 42,
                at_ms: t,
                actor: "admin".into(),
                why: "void".into(),
            });
        }
        entries.push(stored(
            key,
            author,
            from,
            until,
            fee_card(i64::try_from(i).unwrap()),
        ));
    }
    let mut snapshot = snapshot_of(entries);
    snapshot.activations.extend(activations);
    snapshot.voids = voids;
    snapshot
}

#[test]
fn the_entry_in_force_from_the_rows_is_the_engines_entry_at_on_and_around_every_boundary() {
    let mut instants_checked = 0usize;
    for seed in 1..=400u64 {
        let snapshot = generated(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let rows = whole(&snapshot).items;
        let history = snapshot.history(|_| RateCard::absent(0));
        let mut instants = vec![0u64];
        for row in &rows {
            for boundary in [Some(row.effective_from_ms), row.effective_until_ms]
                .into_iter()
                .flatten()
            {
                instants.extend([boundary.saturating_sub(1), boundary, boundary + 1]);
            }
        }
        for t in instants {
            let engine = history.current().entry_at(t).map(|entry| entry.key().hex());
            let engine_id = history.entry_at(t).map(|(id, _)| id.hex());
            assert_eq!(
                engine_id,
                engine
                    .as_ref()
                    .and_then(|hex| rows.iter().find(|row| &row.key == hex))
                    .map(|row| row.entry_id.clone()),
                "seed {seed} t {t}: the row's entry id is the id the engine prices with"
            );
            assert_eq!(in_force_at(&rows, t), engine, "seed {seed} t {t}: in_force");
            assert_eq!(
                window_rule_at(&rows, t),
                engine,
                "seed {seed} t {t}: window rule"
            );
            instants_checked += 1;
        }
    }
    assert!(instants_checked > 4_000, "{instants_checked}");
}
