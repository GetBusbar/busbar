// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain walk's ordering rules, pinned on the production chain (`AuthMiddleware`): config
//! order, the first identification wins, a rejection stops the walk and is re-asked every time, an
//! all-pass chain denies, only an unconfigured chain opens, and the keys arm runs last.

use super::*;
use busbar_contract::auth_calls::{VerifiedIdentity, Verifying};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A module with a canned verdict that counts how often the walk consulted it.
struct Canned {
    verdict: Verified,
    asked: AtomicUsize,
}

fn identifies(subject: &str) -> Arc<Canned> {
    canned(Verified::Identity(VerifiedIdentity {
        subject: subject.to_string(),
        ..VerifiedIdentity::default()
    }))
}

fn canned(verdict: Verified) -> Arc<Canned> {
    Arc::new(Canned {
        verdict,
        asked: AtomicUsize::new(0),
    })
}

impl Canned {
    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

struct Ready(Option<VerifyAnswer>);

impl std::future::Future for Ready {
    type Output = VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<VerifyAnswer> {
        std::task::Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl Verifying for Ready {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

impl AuthCalls for Canned {
    fn name(&self) -> &str {
        "canned"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Some(VerifyAnswer::from(self.verdict.clone()))
    }
    fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Box::new(Ready(Some(VerifyAnswer::from(self.verdict.clone()))))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

fn chain(modules: &[(&str, &Arc<Canned>)], keys_in_chain: bool) -> AuthMiddleware {
    AuthMiddleware {
        keys_in_chain,
        chain: modules
            .iter()
            .map(|(provider, calls)| ChainEntry {
                provider: (*provider).into(),
                calls: Arc::clone(calls) as Arc<dyn AuthCalls>,
                name: (*provider).to_string(),
            })
            .collect(),
        readers: Vec::new(),
        reader_by_carrier: foldhash::HashMap::default(),
        carriers: Vec::new(),
        issued: None,
    }
}

fn identified_by(verdict: &ChainVerdict) -> Option<(&str, &str)> {
    match verdict {
        ChainVerdict::Identified {
            module, principal, ..
        } => Some((module.as_str(), principal.id.as_str())),
        _ => None,
    }
}

#[test]
fn a_reject_stops_the_walk_before_a_later_module_is_asked() {
    let reject = canned(Verified::Reject);
    let behind = identifies("would-admit");
    let c = chain(&[("a", &reject), ("b", &behind)], true);
    assert_eq!(c.run_chain(Some("cred")), ChainVerdict::Denied);
    assert_eq!(behind.asked(), 0, "nothing behind a reject is consulted");
}

#[test]
fn a_reject_at_any_position_denies_whatever_would_have_admitted_behind_it() {
    for at in 0..3 {
        let modules: Vec<Arc<Canned>> = (0..3)
            .map(|i| {
                if i == at {
                    canned(Verified::Reject)
                } else if i < at {
                    canned(Verified::Pass)
                } else {
                    identifies("behind")
                }
            })
            .collect();
        let named: Vec<(&str, &Arc<Canned>)> = ["a", "b", "c"].into_iter().zip(&modules).collect();
        assert_eq!(
            chain(&named, false).run_chain(Some("cred")),
            ChainVerdict::Denied,
            "a reject at position {at} must deny"
        );
    }
}

#[test]
fn the_first_identification_wins_among_two_that_would_both_identify() {
    let first = identifies("first");
    let second = identifies("second");
    let c = chain(&[("one", &first), ("two", &second)], false);
    let verdict = c.run_chain(Some("cred"));
    assert_eq!(identified_by(&verdict), Some(("one", "first")));
    assert_eq!(
        second.asked(),
        0,
        "the walk ends at the first identification"
    );
}

#[test]
fn a_rejection_is_re_asked_every_time() {
    let reject = canned(Verified::Reject);
    let c = chain(&[("a", &reject)], false);
    for _ in 0..3 {
        assert_eq!(c.run_chain(Some("cred")), ChainVerdict::Denied);
    }
    assert_eq!(reject.asked(), 3, "no verdict is answered from a cache");
}

#[test]
fn an_all_pass_chain_denies_and_only_an_unconfigured_chain_opens() {
    let pass = canned(Verified::Pass);
    assert_eq!(
        chain(&[("a", &pass)], false).run_chain(Some("cred")),
        ChainVerdict::Denied
    );
    assert_eq!(chain(&[], false).run_chain(None), ChainVerdict::Open);
    assert_eq!(
        chain(&[], true).run_chain(Some("cred")),
        ChainVerdict::Denied,
        "a keys-only chain is configured, not open"
    );
}

#[test]
fn the_keys_arm_runs_only_after_every_module_passed() {
    let pass = canned(Verified::Pass);
    let identify = identifies("module-subject");
    let c = chain(&[("a", &pass), ("b", &identify)], true);
    let verdict = c.run_chain(Some("cred"));
    assert_eq!(
        identified_by(&verdict),
        Some(("b", "module-subject")),
        "a module identification ends the walk before the keys arm"
    );
    let c = chain(&[("a", &pass)], true);
    assert_eq!(
        c.run_chain(Some("cred")),
        ChainVerdict::Denied,
        "the keys arm without a key store denies"
    );
    assert_eq!(pass.asked(), 2, "every module is asked before the keys arm");
}

#[test]
fn the_keys_arm_refuses_an_empty_or_unverifiable_credential() {
    assert_eq!(
        keys_arm_verdict(None, Some(""), 1_000, None),
        ChainVerdict::Denied
    );
    assert_eq!(
        keys_arm_verdict(None, None, 1_000, None),
        ChainVerdict::Denied
    );
    assert_eq!(
        keys_arm_verdict(None, Some("vk-token"), 1_000, None),
        ChainVerdict::Denied,
        "no key store, no verified key"
    );
}

#[test]
fn validate_token_is_admit_or_deny() {
    assert!(chain(&[], false).validate_token(None));
    let pass = canned(Verified::Pass);
    assert!(!chain(&[("a", &pass)], false).validate_token(Some("cred")));
}
