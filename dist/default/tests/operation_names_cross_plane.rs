// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel::operation::OpVerb;

fn register_planes() {
    linked::install();
}

#[test]
fn no_verb_name_carries_a_plane_key_or_a_protocol_name() {
    register_planes();

    let plane_keys: Vec<&'static str> =
        busbar_kernel::plane_driver::dispatch::plane_keys().collect();
    assert!(
        plane_keys.len() >= 3,
        "the registered roster declares at least three plane keys: {plane_keys:?}"
    );
    let mut identities: Vec<&'static str> = plane_keys.clone();
    identities.extend(
        busbar_kernel::ingress::protocols::registry()
            .decls()
            .iter()
            .map(|d| d.name),
    );
    let verbs: Vec<OpVerb> = OpVerb::ALL
        .iter()
        .copied()
        .chain(
            busbar_kernel_testkit::test_support::protocols::declared_verbs()
                .iter()
                .copied(),
        )
        .collect();
    assert!(
        verbs.len() > OpVerb::ALL.len(),
        "the declared verbs folded in: {} verbs",
        verbs.len()
    );
    for verb in verbs {
        let name = verb.name();
        for forbidden in &identities {
            assert!(
                !name.contains(forbidden),
                "`{name}` names the `{forbidden}` plane or protocol; verbs are shapes plus neutral words"
            );
        }
    }
}
