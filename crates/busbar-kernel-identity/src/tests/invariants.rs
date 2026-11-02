// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The security invariants of the authenticate step, stated over every shape rather than sampled.

use super::{entry, Canned, OneKey};
use crate::chain::{AuthChain, ChainEntry, ChainVerdict};
use crate::module::{AuthModule, AuthOutcome};
use crate::principal::Principal;

/// A module that identifies, for the positions after the rejecting one.
fn identifies(name: &'static str) -> Box<dyn AuthModule> {
    Box::new(Canned::new(
        name,
        AuthOutcome::Identify(Principal::from_id("alice")),
    ))
}

/// The three answers, as a chain position.
fn answering(name: &'static str, outcome: AuthOutcome) -> Box<dyn AuthModule> {
    Box::new(Canned::new(name, outcome))
}

/// A `Reject` ANYWHERE in the chain denies, whatever is behind it.

#[test]
fn a_reject_at_any_position_denies_whatever_would_have_admitted_behind_it() {
    const TOKEN: &str = "the-token";
    for len in 1..=4usize {
        for reject_at in 0..len {
            for keys_behind in [false, true] {
                let names = ["m0", "m1", "m2", "m3"];
                let mut chain: Vec<ChainEntry> = Vec::new();
                for (i, name) in names.iter().take(len).enumerate() {
                    let m = if i == reject_at {
                        answering(name, AuthOutcome::Reject)
                    } else if i > reject_at {
                        identifies(name)
                    } else {
                        answering(name, AuthOutcome::Pass)
                    };
                    chain.push(entry(name, m));
                }
                let c = AuthChain::new(chain, keys_behind);
                let keys = OneKey {
                    token: TOKEN,
                    aud: None,
                };
                let verdict = c.run_chain_with(Some(TOKEN), Some(&keys), 1000, None);
                assert_eq!(
                    verdict,
                    ChainVerdict::Denied,
                    "len={len} reject_at={reject_at} keys_behind={keys_behind}: \
                     a recognised-and-refused credential was admitted by something behind it"
                );
            }
        }
    }
}

/// A `Reject` is re-asked every time: an invalid credential re-runs its module on every call, so

#[test]
fn a_rejection_is_re_asked_every_time() {
    let rejecting = Canned::new("m", AuthOutcome::Reject);
    let calls = rejecting.calls.clone();
    let c = AuthChain::new(vec![entry("m", Box::new(rejecting))], false);

    for i in 1..=5 {
        assert_eq!(
            c.run_chain_with(Some("bad"), None, 1000, None),
            ChainVerdict::Denied
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            i,
            "the module is asked every time"
        );
    }
}

/// A chain that only ever passes ends DENIED, never open.

#[test]
fn an_all_pass_chain_denies_and_only_an_unconfigured_chain_opens() {
    for len in 1..=4usize {
        let names = ["m0", "m1", "m2", "m3"];
        let chain: Vec<ChainEntry> = names
            .iter()
            .take(len)
            .map(|n| entry(n, answering(n, AuthOutcome::Pass)))
            .collect();
        let c = AuthChain::new(chain, false);
        assert!(!c.is_open(), "len={len}");
        assert_eq!(
            c.run_chain_with(Some("cred"), None, 1000, None),
            ChainVerdict::Denied,
            "len={len}: every module said 'not mine', which is not an admission"
        );
    }

    let arm_only = AuthChain::new(Vec::new(), true);
    assert!(!arm_only.is_open());
    assert_eq!(
        arm_only.run_chain_with(Some("cred"), None, 1000, None),
        ChainVerdict::Denied
    );

    let unconfigured = AuthChain::new(Vec::new(), false);
    assert!(unconfigured.is_open());
    assert_eq!(
        unconfigured.run_chain_with(Some("cred"), None, 1000, None),
        ChainVerdict::Open
    );
}
