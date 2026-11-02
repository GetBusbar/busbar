// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::{Registration, MAX_VOCABULARY};

#[test]
fn interning_stops_at_the_ceiling_rather_than_growing_with_traffic() {
    let mut reg = Registration::new();
    for i in 0..MAX_VOCABULARY {
        assert!(
            reg.key(&format!("key-{i}")).is_some(),
            "the ceiling is a ceiling on distinct keys, and this is the {i}th"
        );
    }
    assert_eq!(Registration::interned(), MAX_VOCABULARY);

    assert_eq!(reg.key("one-past-the-ceiling"), None);
    assert_eq!(reg.lane("one-past-the-ceiling"), None);
    assert_eq!(Registration::interned(), MAX_VOCABULARY);

    assert!(reg.key("key-0").is_some());
}
