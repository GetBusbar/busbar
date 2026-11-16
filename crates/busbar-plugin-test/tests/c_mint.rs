// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MINT (ABI-MIN3-INTERFACE §14): FROM_CORE results arrive in the §8.6 order, before any other call (K10 lands
//! the results; plane serving delivers them).
//!
//! W1-K10: the MINT of a mixed answer comes back as P_MINTED in the §8.6 position, a sealed ticket with the
//! plane's prefix and core's marker, admitted once (MINT_ONCE) by the same host.

use busbar_kernel::plane_grants::TICKET_MARKER;
use busbar_plugin_abi::plane::{tag, MintedRec, CONNECT_STATUS, P_MINTED};

use crate::k10_rig::{if_order, order, piece, records_of, resolve, runtime, Deployment};

#[test]
fn mint_results_arrive_first_in_order() {
    let rt = runtime();
    let deployment = rt.block_on(Deployment::new());
    let host = deployment.intents(&rt, std::sync::Arc::new(deployment.connections()));
    let pieces = resolve(&host, CONNECT_STATUS);
    assert_eq!(order(&pieces), if_order());
    let minted = records_of::<MintedRec>(piece(&pieces, P_MINTED), tag::MINTED);
    assert_eq!(minted.len(), 1);
    let (rec, ticket) = &minted[0];
    assert_eq!((rec.check, rec.status), (3, 0));
    assert!(rec.expires_at_s > busbar_kernel::store::now());
    let ticket = std::str::from_utf8(ticket).expect("ticket text");
    assert!(
        ticket.starts_with(&format!("ek_{TICKET_MARKER}")),
        "MT_PREFIX then core's marker: {ticket}"
    );
}
