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
