// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE CARD IS JOURNALLED BEFORE THE CONFIG CHANGE IS SAVED (MONEY-AUDIT D-6, ARCHITECT ruling
//! 2026-10-02).
//!
//! The seam's holder journals the applied card. Raised only at the commit, after the change was
//! persisted and swapped, a journal that refused the card left the live configuration on the new
//! rates and the dated card history on the old ones. So the build STAGES the card with the holder
//! as its last fallible step: a holder that cannot make it durable refuses the whole change —
//! nothing persisted, nothing swapped — and a change that stages and then never commits withdraws
//! what it staged.
//!
//! A test BINARY of its own, because the rate holder is a process-wide `OnceLock` this file installs.

mod linked;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_kernel::config::transaction::{config_transaction, Outcome, TxnError};
use busbar_kernel::rate_apply::{install_rate_apply, RateApply, RawRates};

/// The flat figure whose card the holder's journal refuses.
const REFUSED: i64 = 666_001;

/// What the holder heard, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Heard {
    Staged(i64),
    Withdrawn,
    Applied(i64),
}

/// A holder whose journal refuses one card and takes every other.
struct Journal(Mutex<Vec<Heard>>);

impl RateApply for Journal {
    fn rates_staged(&self, rates: &RawRates<'_>) -> Result<(), String> {
        if rates.flat_minor == REFUSED {
            return Err("the journal refused the append".to_string());
        }
        self.0.lock().unwrap().push(Heard::Staged(rates.flat_minor));
        Ok(())
    }

    fn rates_withdrawn(&self) {
        self.0.lock().unwrap().push(Heard::Withdrawn);
    }

    fn rates_applied(&self, rates: &RawRates<'_>) {
        self.0
            .lock()
            .unwrap()
            .push(Heard::Applied(rates.flat_minor));
    }
}

fn cfg(per_request_fee: i64) -> busbar_kernel::config::RootCfg {
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(
        busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_RATE_APPLY_JOURNAL_FIRST"),
    );
    cfg.per_request_fee = per_request_fee;
    cfg
}

fn build(
    per_request_fee: i64,
) -> Result<
    (
        busbar_kernel::state::App,
        Option<busbar_kernel::GovCredentialRotation>,
        busbar_kernel::InstalledLimits,
    ),
    String,
> {
    busbar_kernel::build_app_from_config(
        cfg(per_request_fee),
        busbar_kernel::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
    )
}

/// One config change at `per_request_fee` through the one config door, whose persist answers
/// `persist_ok`. Answers whether the persist ran, and the transaction's answer.
async fn change(
    handle: &Arc<busbar_kernel::state::AppHandle>,
    per_request_fee: i64,
    persist_ok: bool,
) -> (bool, Result<(), TxnError>) {
    let persisted = Arc::new(AtomicBool::new(false));
    let ran = Arc::clone(&persisted);
    let answer = config_transaction(handle, move |_txn| {
        let (next, _rotate, limits) = build(per_request_fee).map_err(TxnError::Validation)?;
        Ok(Outcome::commit_then(
            Arc::new(next),
            move || {
                ran.store(true, Ordering::SeqCst);
                if persist_ok {
                    Ok(())
                } else {
                    Err("the overlay could not be written".to_string())
                }
            },
            move || {
                limits.keep();
                Ok(Outcome::Value(()))
            },
        ))
    })
    .await;
    (persisted.load(Ordering::SeqCst), answer)
}

/// A CONFIG CHANGE WHOSE CARD THE JOURNAL REFUSES LEAVES THE CONFIG UNCHANGED: nothing is persisted,
/// nothing is swapped, and the holder publishes nothing. A change that stages and then fails its
/// persist withdraws the staged card; a change that commits publishes it, once. RED arm: the build
/// staged nothing, so the refused card's change was persisted and swapped and only its card was
/// refused, at the commit — the live configuration and the dated card history disagreed.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_change_whose_card_the_journal_refuses_leaves_the_config_unchanged() {
    busbar_kernel::snapshot::init();
    linked::install();
    let journal: &'static Journal = Box::leak(Box::new(Journal(Mutex::new(Vec::new()))));
    install_rate_apply(journal);

    let (first, _rotate, limits) = build(1).expect("the boot config builds");
    limits.keep();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(first)));
    let before = handle.load();
    journal.0.lock().unwrap().clear();

    // THE JOURNAL REFUSES THE CARD: the whole change is refused.
    let (persisted, answer) = change(&handle, REFUSED, true).await;
    assert!(answer.is_err(), "the change was not refused");
    assert!(!persisted, "the refused change was saved");
    assert!(
        Arc::ptr_eq(&before, &handle.load()),
        "the refused change was swapped live"
    );
    assert_eq!(
        *journal.0.lock().unwrap(),
        Vec::<Heard>::new(),
        "the refused card was published"
    );

    // THE CARD IS STAGED BUT THE PERSIST FAILS: the staged card is withdrawn, nothing published.
    let (persisted, answer) = change(&handle, 2, false).await;
    assert!(answer.is_err() && persisted);
    assert!(Arc::ptr_eq(&before, &handle.load()));
    assert_eq!(
        *journal.0.lock().unwrap(),
        vec![Heard::Staged(2), Heard::Withdrawn]
    );
    journal.0.lock().unwrap().clear();

    // THE CHANGE COMMITS: staged before the save, published at the commit, once.
    let (persisted, answer) = change(&handle, 3, true).await;
    assert!(answer.is_ok() && persisted);
    assert!(!Arc::ptr_eq(&before, &handle.load()));
    assert_eq!(
        *journal.0.lock().unwrap(),
        vec![Heard::Staged(3), Heard::Applied(3)]
    );
}
