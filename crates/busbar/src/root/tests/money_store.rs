// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the two money verbs actually do to the books.
//!
//! Every assertion below reads the BOOK after the call, not just the answer. An answer is a claim
//! about a mutation; the book is the mutation. A view rendered from figures the ledger never took
//! would satisfy any test that only read the response, and that is precisely the failure a money
//! verb must not be able to have.

use std::sync::{Arc, Mutex};

use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};
use busbar_unit_verbs::store::{Store, StoreError};

use super::MoneyStore;
use crate::root::durability::Durability;
use crate::root::units_admin::AdminAnswer;

const WINDOW: u64 = 1_700_000_000;
const OLDER_WINDOW: u64 = 1_600_000_000;

fn key() -> TotalsKey {
    TotalsKey::new(
        BucketId::new("key-1"),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// A node whose book already holds one balance, in one window, with figures to move.
fn a_node(unreconciled: i128) -> (MoneyStore, Arc<Mutex<Durability>>) {
    let durability = Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::default()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ));
    {
        let mut guard = durability.lock().unwrap();
        let figures = guard.ledger.book_mut().entry(key(), WINDOW);
        figures.settled = 10_000;
        figures.drawn = 10_000;
        figures.unreconciled = unreconciled;
    }
    (
        MoneyStore::new(
            Arc::new(crate::root::kernel::RefusingStore),
            Arc::clone(&durability),
        ),
        durability,
    )
}

fn admin() -> busbar_caps::AdminToken {
    crate::root::kernel::new_kernel().admin_token()
}

/// The JSON the loop would send, out of the packed answer the seam returns.
///
/// The seam answers PACKED bytes because that is what the admin loop unpacks; reading the JSON
/// through the same unpack the loop uses is what makes these assertions about what a client sees
/// rather than about an intermediate form.
fn json_of(packed: &[u8]) -> String {
    let answer = AdminAnswer::unpack(packed).expect("the money verb packs an answer");
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
    String::from_utf8(answer.body).expect("utf8")
}

fn body(fields: &str) -> Vec<u8> {
    format!(
        "{{\"bucket\":\"key-1\",\"dimension\":\"nano_units\",\"scope\":\"all\",\
         \"window_start\":\"{WINDOW}\"{fields}}}"
    )
    .into_bytes()
}

/// An adjustment in the OPEN window moves the adjustments column and releases headroom.
#[test]
fn an_adjustment_in_the_open_window_releases_headroom() {
    let (store, durability) = a_node(0);
    let answer = store
        .adjust(
            &admin(),
            &body(",\"amount_nanos\":\"250\",\"reason\":\"an audit\""),
        )
        .expect("the adjustment lands");

    let figures = durability.lock().unwrap().ledger.book().get(&key(), WINDOW);
    assert_eq!(figures.adjustments, 250, "the correction is in the books");
    assert_eq!(figures.settled, 9_750, "and came out of settled");
    assert_eq!(figures.released, 250, "the open window gave headroom back");

    let text = json_of(&answer);
    assert!(text.contains(r#""amount_nanos":"250""#), "{text}");
    assert!(
        text.contains(r#""headroom_released_nanos":"250""#),
        "{text}"
    );
    assert!(text.contains(r#""pure_reversal":false"#), "{text}");
}

/// The same call against an OLDER window is a pure reversal: no headroom goes back.
///
/// The rule is the ledger unit's own — "a closed window's budget has already been reported, so
/// handing headroom back to it would change a figure somebody has already read" — and this is the
/// half of it that would be silently wrong if the open-window test above were the only one.
#[test]
fn an_adjustment_in_a_closed_window_is_a_pure_reversal() {
    let (store, durability) = a_node(0);
    {
        // Give the key an older window too, so the newest is unambiguous and the request names the
        // one that is NOT it.
        let mut guard = durability.lock().unwrap();
        guard.ledger.book_mut().entry(key(), OLDER_WINDOW).settled = 5_000;
    }
    let request = format!(
        "{{\"bucket\":\"key-1\",\"dimension\":\"nano_units\",\"scope\":\"all\",\
         \"window_start\":\"{OLDER_WINDOW}\",\"amount_nanos\":\"100\",\"reason\":\"late\"}}"
    );
    let answer = store
        .adjust(&admin(), request.as_bytes())
        .expect("the adjustment lands");

    let figures = durability
        .lock()
        .unwrap()
        .ledger
        .book()
        .get(&key(), OLDER_WINDOW);
    assert_eq!(figures.adjustments, 100);
    assert_eq!(figures.released, 0, "a closed window releases nothing");

    let text = json_of(&answer);
    assert!(text.contains(r#""pure_reversal":true"#), "{text}");
    assert!(text.contains(r#""headroom_released_nanos":"0""#), "{text}");
}

/// A correction with no reason is refused, before anything moves.
#[test]
fn an_adjustment_with_no_reason_moves_nothing() {
    let (store, durability) = a_node(0);
    assert!(store
        .adjust(&admin(), &body(",\"amount_nanos\":\"250\""))
        .is_err());
    assert!(store
        .adjust(
            &admin(),
            &body(",\"amount_nanos\":\"250\",\"reason\":\"   \"")
        )
        .is_err());
    let figures = durability.lock().unwrap().ledger.book().get(&key(), WINDOW);
    assert_eq!(figures.adjustments, 0, "a refused adjustment moved money");
    assert_eq!(figures.settled, 10_000);
}

/// An amount that is not a decimal string is refused rather than rounded.
#[test]
fn an_adjustment_naming_no_balance_or_no_amount_is_refused() {
    let (store, _) = a_node(0);
    assert!(store.adjust(&admin(), b"{}").is_err(), "no balance at all");
    assert!(
        store
            .adjust(&admin(), &body(",\"reason\":\"why\""))
            .is_err(),
        "no amount"
    );
    assert!(
        store
            .adjust(
                &admin(),
                &body(",\"amount_nanos\":\"1.5\",\"reason\":\"why\"")
            )
            .is_err(),
        "a decimal point is not a nano-unit amount"
    );
}

/// Resolving a slice moves the value out of unreconciled and reports all three figures.
#[test]
fn resolving_a_slice_posts_the_value_back_and_reports_what_is_left() {
    let (store, durability) = a_node(400);
    let answer = store
        .resolve_slice(
            &admin(),
            &body(",\"node\":\"7\",\"verdict\":\"post\",\"amount_nanos\":\"300\""),
        )
        .expect("the slice resolves");

    let figures = durability.lock().unwrap().ledger.book().get(&key(), WINDOW);
    assert_eq!(figures.unreconciled, 100, "only what was asked for moved");
    assert_eq!(
        figures.settled, 10_300,
        "a posted slice stands as settled value"
    );

    let text = json_of(&answer);
    assert!(text.contains(r#""unreconciled_nanos":"400""#), "{text}");
    assert!(text.contains(r#""resolved_nanos":"300""#), "{text}");
    assert!(text.contains(r#""remaining_nanos":"100""#), "{text}");
    assert!(text.contains(r#""written_off":false"#), "{text}");
    assert!(text.contains(r#""node":7"#), "{text}");
}

/// A write-off does not leave the value sitting in settled.
///
/// This is the difference between the two verdicts, and it is the one that shows up on an invoice.
#[test]
fn writing_a_slice_off_leaves_the_value_in_adjustments_not_in_settled() {
    let (store, durability) = a_node(400);
    store
        .resolve_slice(
            &admin(),
            &body(",\"node\":\"7\",\"verdict\":\"write-off\",\"amount_nanos\":\"400\""),
        )
        .expect("the slice resolves");

    let figures = durability.lock().unwrap().ledger.book().get(&key(), WINDOW);
    assert_eq!(figures.unreconciled, 0);
    assert_eq!(
        figures.settled, 10_000,
        "a written-off slice does not become settled value"
    );
    assert_eq!(
        figures.adjustments, 400,
        "it is in the adjustments column, where an auditor can find it"
    );
}

/// A request naming more than is stranded resolves only what is stranded.
///
/// Without the clamp the column would go negative and the node would report settled value it never
/// took — an invented figure, which is worse than a refusal.
#[test]
fn resolving_more_than_is_stranded_moves_only_what_is_there() {
    let (store, durability) = a_node(100);
    let answer = store
        .resolve_slice(
            &admin(),
            &body(",\"node\":\"7\",\"verdict\":\"post\",\"amount_nanos\":\"999999\""),
        )
        .expect("the slice resolves");

    let figures = durability.lock().unwrap().ledger.book().get(&key(), WINDOW);
    assert_eq!(figures.unreconciled, 0);
    assert_eq!(figures.settled, 10_100, "only the stranded 100 moved");
    assert!(json_of(&answer).contains(r#""resolved_nanos":"100""#));
}

/// A verdict this verb does not have is refused rather than guessed.
#[test]
fn an_unknown_verdict_moves_nothing() {
    let (store, durability) = a_node(400);
    assert!(store
        .resolve_slice(
            &admin(),
            &body(",\"node\":\"7\",\"verdict\":\"maybe\",\"amount_nanos\":\"400\"")
        )
        .is_err());
    assert_eq!(
        durability
            .lock()
            .unwrap()
            .ledger
            .book()
            .get(&key(), WINDOW)
            .unreconciled,
        400
    );
}

/// Everything this type does not implement is the wrapped store's, unchanged.
#[test]
fn every_other_primitive_is_delegated() {
    let (store, _) = a_node(0);
    // `RefusingStore` fails all three, which is what says the call reached it rather than being
    // answered here.
    assert!(matches!(
        store.chain_break(&admin()),
        Err(StoreError::Failed)
    ));
    assert!(matches!(
        store.store_restore(&admin(), "backup-1"),
        Err(StoreError::Failed)
    ));
    assert!(matches!(
        store.reseal_epoch_floor(&admin()),
        Err(StoreError::Failed)
    ));
}
