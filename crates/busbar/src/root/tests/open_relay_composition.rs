// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_SIGNED_INGRESS, CLAIM_TICKET};
use busbar_kernel::guest::LineAuth;

#[test]
fn explicit_operator_open_is_distinct_from_an_empty_credential_requirement() {
    assert_eq!(
        inherited_data_auth(&[], DataChainMode::OpenRelay),
        LineAuth::None
    );
    assert_eq!(
        inherited_data_auth(&[], DataChainMode::Credentialed),
        LineAuth::Chain(Vec::new(), AuthPoints::EMPTY)
    );
    assert_eq!(
        line_auth(CLAIM_EXACT, &[]),
        LineAuth::Chain(Vec::new(), AuthPoints::EMPTY),
        "a raw credentialed claim never infers operator openness"
    );
}

#[test]
fn a_current_nonempty_chain_cannot_retain_an_old_open_policy() {
    let closed = vec![("keys".to_string(), AuthPoints::HEAD)];
    for mode in [DataChainMode::OpenRelay, DataChainMode::Credentialed] {
        assert_eq!(
            inherited_data_auth(&closed, mode),
            LineAuth::Chain(vec!["keys".to_string()], AuthPoints::HEAD)
        );
    }
    assert_eq!(
        inherited_data_auth(&[], DataChainMode::OpenRelay),
        LineAuth::None,
        "removing the configured chain restores the operator's open policy"
    );
}

#[test]
fn only_the_pools_claim_inherits_open_relay_without_a_dedicated_auth_mechanism() {
    let pools = busbar_contract::section::RESERVED_POOLS_KEY;
    assert!(operator_open_claim(
        DataChainMode::OpenRelay,
        pools,
        CLAIM_EXACT
    ));
    assert!(!operator_open_claim(
        DataChainMode::Credentialed,
        pools,
        CLAIM_EXACT
    ));
    for section in ["tools", "agents", "streaming", "unrelated"] {
        assert!(!operator_open_claim(
            DataChainMode::OpenRelay,
            section,
            CLAIM_EXACT
        ));
    }
    for mechanism in [
        CLAIM_TICKET,
        CLAIM_SIGNED_INGRESS,
        CLAIM_TICKET | CLAIM_SIGNED_INGRESS,
    ] {
        assert!(!operator_open_claim(
            DataChainMode::OpenRelay,
            pools,
            CLAIM_EXACT | mechanism
        ));
    }
}
