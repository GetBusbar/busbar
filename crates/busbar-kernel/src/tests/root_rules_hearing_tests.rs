// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's destination guard hears a committed configuration through the root's rules, which
//! every build is handed and every generation keeps.

use std::sync::{Arc, Mutex};

use crate::appbuild::RootRules;
use crate::config::Destinations;

/// Rules that record every commit raised to them.
#[derive(Default)]
struct Hearing(Mutex<Vec<Destinations>>);

impl RootRules for Hearing {
    fn check(&self, _cfg: &crate::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn destinations_applied(&self, destinations: &Destinations) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(destinations.clone());
    }
}

impl Hearing {
    fn heard(&self) -> Vec<Destinations> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[test]
fn boot_builds_a_pool_of_nine_unbounded_lanes_without_overflowing_its_banner() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let mut cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef::none());
    let members: Vec<_> = (0..9).map(|index| format!("unbounded-{index}")).collect();
    for name in &members {
        let model: crate::config::ModelCfg =
            serde_json::from_value(serde_json::json!({"provider":"acme"})).unwrap();
        assert_eq!(
            model.max_concurrent, None,
            "the ordinary omitted concurrency limit"
        );
        cfg.models.insert(name.clone(), model);
    }
    cfg.pools.insert(
        "wide".into(),
        serde_json::from_value(serde_json::json!({"members":members})).unwrap(),
    );
    let rules: Arc<dyn RootRules> = Arc::new(crate::appbuild::AcceptAll);
    let app = crate::test_support::build_once_under(cfg, None, &rules)
        .expect("an aggregate display wider than usize must not prevent boot");
    assert_eq!(app.engine_tables_view().lane_count(), 9);
    assert_eq!(app.engine_tables_view().pool_members("wide").len(), 9);
}

#[test]
fn a_completed_candidate_refusal_is_returned_before_a_reload_can_replace_the_old_app() {
    struct RefuseBuilt(std::sync::atomic::AtomicUsize);
    impl RootRules for RefuseBuilt {
        fn check(&self, _: &crate::config::RootCfg) -> Result<(), String> {
            Ok(())
        }
        fn check_built(&self, candidate: &crate::state::App) -> Result<(), String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                candidate.config_version, 1,
                "the rule receives the rebuilt candidate, not the old App"
            );
            Err("candidate listener has no compatible auth point".into())
        }
    }
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let cfg = || {
        let mut cfg = crate::test_support::cfg_with_provider_api_key(
            crate::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_BUILT_LISTENER"),
        );
        cfg.allow_all_metadata = true;
        cfg
    };
    let prior = crate::test_support::build_once_under(
        cfg(),
        None,
        &(Arc::new(crate::appbuild::AcceptAll) as Arc<dyn RootRules>),
    )
    .expect("the original generation builds");
    let prior_version = prior.config_version;
    let reject = Arc::new(RefuseBuilt(std::sync::atomic::AtomicUsize::new(0)));
    let rules: Arc<dyn RootRules> = reject.clone();
    let result = crate::test_support::build_once_under(cfg(), Some(&prior), &rules);
    let refusal = match result {
        Err(refusal) => refusal,
        Ok(_) => panic!("the completed candidate escaped its listener refusal"),
    };
    assert_eq!(refusal, "candidate listener has no compatible auth point");
    assert_eq!(reject.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(prior.config_version, prior_version);
}

/// THE COMMIT REACHES THE GUARD THROUGH THE ROOT'S RULES, as it reached it through the installed
/// capability: a build dropped unkept (an apply whose persist or swap failed) raises nothing, and a
/// kept build raises exactly the destinations its configuration states, once.
#[test]
fn a_kept_build_raises_its_destinations_to_the_rules_it_was_judged_by() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let cfg = || {
        let mut cfg = crate::test_support::cfg_with_provider_api_key(
            crate::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_COMMIT_GUARD"),
        );
        cfg.allow_all_metadata = true;
        cfg
    };
    let expected = cfg().destinations();
    assert!(
        expected.allow_all_metadata,
        "the configuration states a destination fact"
    );
    let hearing = Arc::new(Hearing::default());
    let rules: Arc<dyn RootRules> = hearing.clone();

    let (_app, _, unkept) = crate::build_app_from_config(
        cfg(),
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the configuration builds");
    drop(unkept);
    assert!(
        hearing.heard().is_empty(),
        "a build dropped unkept raises nothing"
    );

    crate::test_support::build_once_under(cfg(), None, &rules).expect("the configuration builds");
    assert_eq!(
        hearing.heard(),
        vec![expected],
        "the kept build raises its configuration's destinations, once"
    );
}
