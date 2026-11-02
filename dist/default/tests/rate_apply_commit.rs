// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use std::sync::Mutex;

use busbar_kernel::rate_apply::{RateApply, RawRates};
use busbar_kernel_testkit::test_support::rate_holders::install_rate_apply;

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
    let mut cfg = busbar_kernel_testkit::test_support::cfg_with_provider_api_key(
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
        &(std::sync::Arc::new(busbar_kernel::appbuild::AcceptAll)
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>),
    )
    .expect("the app builds")
}

#[test]
fn an_apply_that_never_commits_raises_no_rates_and_one_that_commits_raises_them_once() {
    busbar_kernel_testkit::test_support::metrics::init();
    linked::install();
    let recorder: &'static Recorder = Box::leak(Box::new(Recorder(Mutex::new(Vec::new()))));
    install_rate_apply(recorder);

    let (_app, _rotate, limits) = build(424_242);
    drop(limits);
    assert_eq!(
        *recorder.0.lock().unwrap(),
        Vec::<i64>::new(),
        "an apply that never committed entered the dated history and the journal"
    );

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
