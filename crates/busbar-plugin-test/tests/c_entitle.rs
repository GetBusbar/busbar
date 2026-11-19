// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ENTITLE (ABI-MIN3-INTERFACE §14): FROM_CORE results arrive in the §8.6 order, before any other call (K10
//! lands the results; plane serving delivers them).
//!
//! W1-K10: one plane answer stating CONNECT, SIGN, MINT, ENTITLE and LOOKUP (reverse order) is resolved by the
//! production intent host over K10's services; the pieces come back P_LOOKUP, P_ENTITLE, P_MINTED, P_SIGNED,
//! P_CONNECT, and P_ENTITLE carries the verified principal's grant.

use busbar_plugin_abi::plane::{tag, EntitleAns, CONNECT_STATUS, P_ENTITLE};

use crate::k10_rig::{if_order, order, piece, records_of, resolve, runtime, Deployment};

#[test]
fn entitle_results_arrive_first_in_order() {
    let rt = runtime();
    let deployment = rt.block_on(Deployment::new());
    let host = deployment.intents(std::sync::Arc::new(deployment.connections()));
    let pieces = resolve(&rt, &host, CONNECT_STATUS);
    assert_eq!(order(&pieces), if_order());
    let answers = records_of::<EntitleAns>(piece(&pieces, P_ENTITLE), tag::ENTITLE_ANS);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].0.check, 2);
    assert_eq!(answers[0].0.granted, 1, "the principal holds `chat`");
}
