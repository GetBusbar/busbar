// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn both_abi_lanes_ask_the_same_metric_name_question() {
    assert!(crate::snapshot::observe::admits_metric_name(
        "plane_host_test"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name(
        "busbar_anything"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name("Bad-Name"));
    assert!(!crate::snapshot::observe::admits_metric_name(""));
}
