// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE-APPLY SEAM IS RAISED AT THE COMMIT, NEVER DURING THE BUILD (#79).
//!
//! The seam's holder appends the applied rates to the dated rate-card history and journals them.
//! An admin apply builds the next `App` first and persists after; a persist that fails aborts the
//! transaction with "nothing was changed", and the build's uncommitted handle is dropped. Raised
//! during the build, the rates of that rejected apply had already entered the history and the
//! journal. So the seam rides the same commit the process-wide limits do: `InstalledLimits::keep`.
//!
//! A test BINARY of its own, because the rate holder is a process-wide `OnceLock` this file installs.

use std::sync::Mutex;

use busbar_kernel::rate_apply::{install_rate_apply, RateApply, RawRates};

/// The holder, writing down the flat figure of every apply it hears — the only writer of the dated
/// history and of the journal, so what it never hears neither of them holds.
struct Recorder(Mutex<Vec<i64>>);

impl RateApply for Recorder {
    fn rates_applied(&self, rates: &RawRates<'_>) {
        self.0.lock().unwrap().push(rates.flat_minor);
    }
}

fn build(
    per_request_fee: i64,
) -> (
    busbar_kernel::state::App,
    Option<busbar_kernel::GovCredentialRotation>,
    busbar_kernel::InstalledLimits,
) {
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(
        busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_RATE_APPLY_COMMIT"),
    );
    cfg.per_request_fee = per_request_fee;
    busbar_kernel::build_app_from_config(
        cfg,
        busbar_kernel::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
    )
    .expect("the app builds")
}

/// An apply whose persist fails drops the build's handle unkept: the holder hears nothing, so the
/// dated history and the journal are exactly as they were. The apply that commits is heard once,
/// at its commit, with its own figures.
#[test]
fn an_apply_that_never_commits_raises_no_rates_and_one_that_commits_raises_them_once() {
    busbar_kernel::metrics::init();
    busbar_llm::testkit::install_test_seams();
    let recorder: &'static Recorder = Box::leak(Box::new(Recorder(Mutex::new(Vec::new()))));
    install_rate_apply(recorder);

    // THE PERSIST FAILED: the transaction never reaches its commit and the handle falls out of scope.
    let (_app, _rotate, limits) = build(424_242);
    drop(limits);
    assert_eq!(
        *recorder.0.lock().unwrap(),
        Vec::<i64>::new(),
        "an apply that never committed entered the dated history and the journal"
    );

    // THE APPLY LANDED: persist and swap both `Ok`, and the commit keeps it.
    let (_app, _rotate, limits) = build(515_151);
    assert_eq!(
        *recorder.0.lock().unwrap(),
        Vec::<i64>::new(),
        "the build alone raised the seam before the transaction committed"
    );
    limits.keep();
    assert_eq!(
        *recorder.0.lock().unwrap(),
        vec![515_151],
        "the committed apply's rates, heard once, at the commit"
    );
}
