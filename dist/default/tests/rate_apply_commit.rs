// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;

use busbar_kernel::rate_apply::{PreparedRates, RateApply, RateCommit, RawRates};

struct Recorder(Arc<Mutex<Vec<i64>>>);

struct PendingRate {
    seen: Arc<Mutex<Vec<i64>>>,
    flat_minor: i64,
}

impl PreparedRates for PendingRate {
    fn confirm_activation(self: Box<Self>) -> Result<Box<dyn RateCommit>, String> {
        Ok(self)
    }
}

impl RateCommit for PendingRate {
    fn commit(self: Box<Self>) {
        self.seen.lock().unwrap().push(self.flat_minor);
    }
}

impl RateApply for Recorder {
    fn prepare(
        &self,
        _: &busbar_kernel::config::card::CardFields,
        rates: &RawRates<'_>,
        _: &str,
    ) -> Result<Box<dyn PreparedRates>, String> {
        Ok(Box::new(PendingRate {
            seen: Arc::clone(&self.0),
            flat_minor: rates.flat_minor,
        }))
    }

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
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "rates-commit-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    config.per_request_fee = per_request_fee;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;

    busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the app builds")
}

#[test]
fn an_apply_that_never_commits_raises_no_rates_and_one_that_commits_raises_them_once() {
    const CHILD: &str = "BUSBAR_RATE_APPLY_COMMIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let module = module_path!()
            .split_once("::")
            .expect("a mounted test module")
            .1;
        let test = format!(
            "{module}::an_apply_that_never_commits_raises_no_rates_and_one_that_commits_raises_them_once"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("the rate-holder assertion runs in its own product process");
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains(&test),
            "isolated rate-holder assertion failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }
    crate::dist_root_install::install();
    let recorder: &'static Recorder =
        Box::leak(Box::new(Recorder(Arc::new(Mutex::new(Vec::new())))));
    busbar_kernel::preflight::publish_root_rows(busbar_kernel::preflight::RootInstall {
        rate_apply: Some(recorder),
        ..busbar_kernel::preflight::root_rows()
    });

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
    limits
        .keep()
        .expect("the committed apply activates its rates");
    assert_eq!(
        *recorder.0.lock().unwrap(),
        vec![515_151],
        "the committed apply's rates, heard once, at the commit"
    );
}
