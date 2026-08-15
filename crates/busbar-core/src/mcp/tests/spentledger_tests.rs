// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE APPROVAL, REDEEMED ONCE — across a restart, and across a fleet.
//!
//! ## The two shapes an in-process ledger cannot refuse
//!
//! Everything about a sealed `requestState` except single use rides inside the blob: who it was
//! minted for, which request, which round, until when. Single use cannot, because the second
//! presentation of a redeemed approval is byte-identical to the first and is perfectly valid. Only a
//! RECORD THAT THE FIRST HAPPENED tells them apart, and where that record lives decides which
//! double-redemptions it can refuse:
//!
//! * **A RESTART.** The record was in process memory, so a restart lost it while the approval —
//!   which has its own, longer, life — was still openable.
//! * **A FLEET.** Two nodes of one deployment share `auth.signing_key`, because that is what lets
//!   one logical exchange span requests different nodes serve. Sharing the key shares the SEAL. With
//!   the ledger unshared, one approval was redeemable once PER NODE, and the second redemption is
//!   not a race or a timing trick — it is an ordinary sequential request that a load balancer sends
//!   somewhere else. On a tool an operator gated because it moves money, that is the defect the gate
//!   exists to stop, multiplied by the size of the fleet.
//!
//! ## Judged through the real decision, and through the real plugin
//!
//! Every case below drives `callerask::decide` — the gate itself, the one production call site's
//! only decision function — rather than calling `SpentAskStates::spend`. A test against `spend`
//! would prove the ledger and say nothing about whether the gate consults it, which is exactly the
//! shape of "a complete subsystem with no production caller" this tree has already paid for once.
//!
//! And the shared ledger is the genuine `busbar-store-example-plugin` cdylib in its durable mode,
//! `dlopen`ed once PER NODE through `busbar_plugin_loader::load_store`. Two `dlopen`s of one file is
//! what two nodes of a fleet are; a `dlopen`, a drop, and a second `dlopen` is what a restart is. An
//! in-process `Store` double would be green against an ABI that carried no variant for this method
//! at all, which is precisely how ten store methods were dropped at this seam earlier in the same
//! release.

use crate::mcp::askstate::{Sealer, SpentAskStates};
use crate::mcp::callerask::{decide, Approvals, AskDecision, Bind, Refusal, Retry};
use crate::mcp::config::{AskEntryCfg, AskRoundCfg};
use crate::test_support::plugin_store::{durable_cfg, open_plugin};

/// THE FLEET-SHARED SECRET. One key for every node below — that is the premise, not a shortcut: it
/// is what makes an approval minted on one node openable on another, and therefore what makes the
/// unshared ledger a defect rather than a curiosity.
const KEY: [u8; 32] = [11u8; 32];
const NOW: u64 = 1_700_000_000;
const PRINCIPAL: &str = "vk_treasury_ops";
const CAP: &str = "bank_transfer";
const DIGEST: &str = "args-digest-of-the-transfer";

fn sealer() -> Sealer {
    Sealer::derive(&KEY)
}

fn bind() -> Bind<'static> {
    Bind {
        principal: PRINCIPAL,
        method: "tools/call",
        capability: CAP,
        generation: 1,
        now: NOW,
        // The live roots epoch. Zero is a principal that has never announced a change, which is
        // this battery's fixture; the epoch's own behaviour is judged in `roots_changed_tests.rs`.
        roots_epoch: 0,
    }
}

/// ONE ROUND: the operator gating a money-moving tool behind a confirmation. This is the whole
/// scenario the single-use property exists for.
fn confirm_round() -> Vec<AskRoundCfg> {
    let mut m = AskRoundCfg::new();
    m.insert(
        "confirm".to_string(),
        AskEntryCfg {
            method: "elicitation/create".to_string(),
            params: Some(serde_json::json!({ "message": "Confirm the transfer" })),
        },
    );
    vec![m]
}

fn all_capabilities() -> serde_json::Value {
    serde_json::json!({ "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } })
}

/// ONE NODE of a deployment: its own in-process ledger, and its own `dlopen` of the shared store
/// when there is one. `None` is a node that configures no durable store.
fn node(cfg: Option<&str>) -> SpentAskStates {
    let spent = SpentAskStates::new();
    if let Some(cfg) = cfg {
        spent.set_sink(open_plugin(cfg));
    }
    spent
}

/// Ask this node for an approval — the opening round, which mints the sealed state.
fn ask(spent: &SpentAskStates) -> String {
    let rounds = confirm_round();
    match decide(
        &rounds,
        3,
        &all_capabilities(),
        Retry::default(),
        bind(),
        DIGEST,
        Approvals {
            sealer: Some(&sealer()),
            spent,
        },
    ) {
        AskDecision::Ask { request_state, .. } => request_state,
        other => panic!("the opening round must ask: {other:?}"),
    }
}

/// Present `state` to this node as the answered confirmation — the redemption.
fn redeem(spent: &SpentAskStates, state: &str) -> AskDecision {
    let rounds = confirm_round();
    let responses = serde_json::json!({ "confirm": { "action": "accept", "content": {} } });
    decide(
        &rounds,
        3,
        &all_capabilities(),
        Retry {
            responses: Some(&responses),
            state: Some(state),
        },
        bind(),
        DIGEST,
        Approvals {
            sealer: Some(&sealer()),
            spent,
        },
    )
}

/// `true` when the decision was the already-spent refusal specifically, not merely any refusal. A
/// looser assertion would be satisfied by a gate that refused the SECOND redemption for the wrong
/// reason — a lapsed clock, a generation bump — and would go on passing if the ledger were removed.
fn refused_as_spent(d: &AskDecision) -> bool {
    matches!(
        d,
        AskDecision::Refuse(Refusal::StateRejected(
            crate::mcp::askstate::Rejected::AlreadySpent
        ))
    )
}

/// THE FLEET CASE. Node A mints and redeems; node B — same signing key, same shared store, its own
/// process state — must refuse the same approval.
#[test]
fn a_second_fleet_node_cannot_redeem_an_approval_the_first_already_spent() {
    let (file, cfg) = durable_cfg("askstate-fleet");
    let node_a = node(Some(&cfg));
    let node_b = node(Some(&cfg));

    let state = ask(&node_a);
    assert_eq!(
        redeem(&node_a, &state),
        AskDecision::Proceed,
        "the FIRST redemption must dispatch, or nothing below is about single use"
    );

    // The seal is the deployment's, not the node's: node B opens it and every field verifies. That
    // is the premise of the fleet, and it is why the ledger is the only thing standing between one
    // approval and a second execution.
    let second = redeem(&node_b, &state);
    assert!(
        refused_as_spent(&second),
        "a second node of the same deployment redeemed an approval that was already spent. The \
         nodes share the signing key, so they share the seal — every check but this one passes on \
         both — which means one operator confirmation executed the tool once per node. On a tool \
         gated because it moves money that is the whole defect the gate exists to stop. Got \
         {second:?}; the shared ledger at {} holds: {}",
        file.display(),
        std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
    );

    // The BYTES the shared ledger actually kept, so a release report can quote evidence rather than
    // quote an assertion that passed.
    eprintln!(
        "SHARED SPENT-APPROVAL LEDGER {}:\n{}",
        file.display(),
        std::fs::read_to_string(&file).expect("the plugin's on-disk state")
    );
}

/// THE RESTART CASE. The node that spent the approval is gone — its ledger and its store handle both
/// — and a fresh one comes up on the same store while the approval is still inside its own window.
#[test]
fn a_restarted_node_cannot_redeem_an_approval_the_previous_process_spent() {
    let (_file, cfg) = durable_cfg("askstate-restart");

    let state = {
        let before = node(Some(&cfg));
        let state = ask(&before);
        assert_eq!(
            redeem(&before, &state),
            AskDecision::Proceed,
            "the first redemption must dispatch"
        );
        state
        // `before` is dropped here, which drops the store handle and unloads the library — so the
        // read below cannot be answered out of anything the plugin kept in RAM.
    };

    let after = node(Some(&cfg));
    let second = redeem(&after, &state);
    assert!(
        refused_as_spent(&second),
        "a restart handed a spent approval back. The state has not lapsed — it outlives a process \
         restart by design, and being openable is exactly the point — so the only thing that \
         changed is that the process that recorded the redemption is no longer running: {second:?}"
    );
}

/// THE CONTROL, and it is load-bearing: a DIFFERENT approval, on a node that has already spent one,
/// still dispatches. A ledger that refused everything would satisfy both cases above and would have
/// deleted the feature.
#[test]
fn a_fresh_approval_is_not_refused_by_a_ledger_holding_another() {
    let (_file, cfg) = durable_cfg("askstate-distinct");
    let node_a = node(Some(&cfg));
    let node_b = node(Some(&cfg));

    let first = ask(&node_a);
    assert_eq!(redeem(&node_a, &first), AskDecision::Proceed);

    let second = ask(&node_a);
    assert_ne!(
        first, second,
        "two mints must differ, or this case is re-presenting the same approval"
    );
    assert_eq!(
        redeem(&node_b, &second),
        AskDecision::Proceed,
        "a second, freshly minted approval is not the one that was spent, and refusing it would \
         mean the shared ledger had become a blanket refusal of every confirmation after the first"
    );
}

/// AND ONE NODE STILL REFUSES ITS OWN REPLAY WITHOUT ASKING THE STORE. The local half is not
/// decoration: it is what keeps the obvious replay off the store's round trip, and it is the whole
/// gate for a deployment that configures no store at all.
#[test]
fn a_node_refuses_its_own_replay_with_no_durable_store_configured() {
    let solo = node(None);
    let state = ask(&solo);
    assert_eq!(redeem(&solo, &state), AskDecision::Proceed);
    let second = redeem(&solo, &state);
    assert!(
        refused_as_spent(&second),
        "single use per node, for the life of the process, is the pre-existing property and must \
         survive the change that shares it: {second:?}"
    );
}

/// THE PERMANENT NEGATIVE. Two nodes that share the signing key and share NO store DO both redeem —
/// which is the documented `store: memory` posture stated out loud rather than discovered.
///
/// This case exists because without it every case above is equally consistent with a gate that
/// refuses a second redemption for some reason that has nothing to do with the shared ledger. It is
/// the one arrangement in which the ledger is provably the thing doing the work: change nothing but
/// whether the two nodes share a store, and the answer changes.
///
/// It is not a defect being enshrined. A deployment with no durable store has no shared anything,
/// and the honest thing for a gateway to do about a property it cannot provide is to say so where an
/// operator will find it.
#[test]
fn two_nodes_sharing_no_store_each_redeem_once_which_is_the_documented_ram_posture() {
    let node_a = node(None);
    let node_b = node(None);
    let state = ask(&node_a);
    assert_eq!(redeem(&node_a, &state), AskDecision::Proceed);
    assert_eq!(
        redeem(&node_b, &state),
        AskDecision::Proceed,
        "with no shared ledger there is nothing for node B to consult, and this is the behaviour \
         the durable ledger exists to change — a durability test that has never seen the \
         NON-durable arrangement has proven nothing about which half is doing the work"
    );
}

/// AND THE RAM DEFAULT IS THE SAME ARRANGEMENT. `busbar-store-memory` implements none of this, so
/// attaching it is indistinguishable from attaching nothing — which is also the exact shape of every
/// already-signed store plugin built before this method existed.
#[test]
fn the_memory_store_shares_no_ledger_which_is_the_documented_contract() {
    let node_a = SpentAskStates::new();
    node_a.set_sink(std::sync::Arc::new(busbar_store_memory::MemoryStore::new()));
    let node_b = SpentAskStates::new();
    node_b.set_sink(std::sync::Arc::new(busbar_store_memory::MemoryStore::new()));

    let state = ask(&node_a);
    assert_eq!(redeem(&node_a, &state), AskDecision::Proceed);
    assert_eq!(
        redeem(&node_b, &state),
        AskDecision::Proceed,
        "the RAM default accepts the redemption and keeps nothing, which is why a deployment that \
         wants this property across a fleet has to configure a durable store"
    );
}
