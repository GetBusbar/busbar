// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::settings_public::PublicSettings as _;

#[test]
fn a_plugins_public_settings_are_found_under_its_words_alone() {
    let t = Table(vec![Row {
        words: vec!["stub-alias".into(), "stub-public".into()],
        public: ["url".to_string()].into_iter().collect(),
    }]);
    assert_eq!(
        t.public("stub-alias").into_iter().collect::<Vec<_>>(),
        ["url"]
    );
    assert_eq!(
        t.public("stub-public").into_iter().collect::<Vec<_>>(),
        ["url"]
    );
    assert!(
        t.public("elsewhere").is_empty(),
        "undeclared: every setting sensitive"
    );
}
