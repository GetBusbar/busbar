// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::snapshot_fields;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CHILD: &str = "BUSBAR_APP_PARTS_ASSEMBLY_CHILD";
const SELECTOR: &str =
    "state::app_parts_tests::public_parts_assemble_without_boot_effects_or_journal_subscription";
static ROOT_EFFECTS: AtomicUsize = AtomicUsize::new(0);

struct UncalledRules;

impl crate::appbuild::RootRules for UncalledRules {
    fn check(&self, _: &crate::config::RootCfg) -> Result<(), String> {
        ROOT_EFFECTS.fetch_add(1, Ordering::SeqCst);
        panic!("pure snapshot ownership cannot validate a configuration")
    }
    fn check_built(&self, _: &crate::state::App) -> Result<(), String> {
        ROOT_EFFECTS.fetch_add(1, Ordering::SeqCst);
        panic!("pure snapshot ownership cannot invoke a root observer")
    }
    fn mounted_plugin_paths(
        &self,
        _: &crate::state::App,
    ) -> Option<std::collections::HashSet<String>> {
        ROOT_EFFECTS.fetch_add(1, Ordering::SeqCst);
        panic!("pure snapshot ownership cannot ask the root for routes")
    }
    fn planes_awaiting_restart(&self, _: &crate::config::RootCfg) -> Vec<&'static str> {
        ROOT_EFFECTS.fetch_add(1, Ordering::SeqCst);
        panic!("pure snapshot ownership cannot invoke plane selection")
    }
    fn destinations_applied(&self, _: &crate::config::Destinations) {
        ROOT_EFFECTS.fetch_add(1, Ordering::SeqCst);
        panic!("pure snapshot ownership cannot publish destinations")
    }
}

#[test]
fn public_parts_assemble_without_boot_effects_or_journal_subscription() {
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", SELECTOR, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .expect("run the isolated assembly control");
        assert!(
            output.status.success(),
            "assembly control failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
        return;
    }
    let rules = Arc::new(UncalledRules) as Arc<dyn crate::appbuild::RootRules>;
    let amendments = Arc::new(crate::audit::amend::NodeAmendments::new());
    let journal = Arc::clone(&amendments);
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(777));
    let before = Arc::strong_count(&journal);
    let assembled = snapshot_fields(
        rules.clone(),
        amendments,
        counter.clone(),
        41,
        Some("https://assembly.example".into()),
        Arc::new(crate::auth::login::LoginMethods::empty()),
        Default::default(),
    );
    assert_eq!(ROOT_EFFECTS.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&journal), before, "no sink subscribed");
    assert!(Arc::ptr_eq(&assembled.amendments, &journal));
    assert!(Arc::ptr_eq(&assembled.root_rules, &rules));
    assert!(Arc::ptr_eq(&assembled.request_id_counter, &counter));
    assert_eq!(assembled.request_id_counter.load(Ordering::SeqCst), 777);
    assert_eq!(assembled.config_version, 41);
    assert_eq!(
        assembled.public_url.as_deref(),
        Some("https://assembly.example")
    );
    assert!(assembled.login_methods.methods.is_empty());
    assert_eq!(assembled.export_projections, Default::default());

    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rules.destinations_applied(&crate::config::Destinations::default());
    }));
    assert!(observed.is_err(), "the no-root-effects guard must be live");
    assert_eq!(ROOT_EFFECTS.load(Ordering::SeqCst), 1);
}
