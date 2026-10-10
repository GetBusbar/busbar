// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The security invariants of the authenticate step, stated over every shape rather than sampled.
//!
//! Each of these is a property the ported suite checks one instance of. One instance is what a
//! reader believes; every instance is what a change has to survive. They are written as exhaustive
//! walks over the chain shapes the configuration can produce, so a change that keeps the sampled
//! case working and breaks a neighbouring one has nowhere to land.

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

// ---------------------------------------------------------------------------------------------
// A Reject is never a Pass.
// ---------------------------------------------------------------------------------------------

/// A `Reject` ANYWHERE in the chain denies, whatever is behind it.
///
/// The three answers are not interchangeable and only one of them is a refusal: `Reject` means this
/// module recognised the credential and refuses it, and `Pass` means it is not this module's
/// credential at all. Turning the first into the second is the whole failure mode this chain shape
/// exists to prevent — the module that KNOWS the credential is bad steps aside, and the next module,
/// or the keys arm, admits it. The suite checks one two-module chain. This checks every position in
/// chains of every length up to four, with something behind the rejection that would have admitted:
/// a module that identifies, the built-in keys arm holding a valid token, and both.
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
                        // Behind the rejection: a module that WOULD identify.
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

/// A chain that only ever passes ends DENIED, never open.
///
/// The open door is one condition and one only: no boxed module and no keys arm. A chain that has
/// modules, all of which say "not mine", has not authenticated anybody — collapsing that into the
/// anonymous admit would turn "no module recognised this credential" into "no module was
/// configured", which is the operator's most consequential posture decided by accident.
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
    // The keys arm alone keeps the door shut too: it runs, and with no verifier it denies.
    let arm_only = AuthChain::new(Vec::new(), true);
    assert!(!arm_only.is_open());
    assert_eq!(
        arm_only.run_chain_with(Some("cred"), None, 1000, None),
        ChainVerdict::Denied
    );
    // And the one shape that opens.
    let unconfigured = AuthChain::new(Vec::new(), false);
    assert!(unconfigured.is_open());
    assert_eq!(
        unconfigured.run_chain_with(Some("cred"), None, 1000, None),
        ChainVerdict::Open
    );
}

// ---------------------------------------------------------------------------------------------
// One authenticate path.
// ---------------------------------------------------------------------------------------------

/// The `.rs` files under `dir`, skipping the `tests` directory.
fn non_test_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("source dir reads") {
        let path = e.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "tests") {
                non_test_sources(&path, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

fn is_ident(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// The kernel's one chain is the only authenticate path (BUSBAR-1.6.0.md R3; l.1932-1935, "a built
/// type or verb with no production construction site is either wired or deleted").
///
/// `Auth::resolve` and its satellites — the new-unit revocation walk, the bounded challenge, the
/// admin-grant lattice, the browser exchange dispatch — had no production caller, and the root's
/// `ProductionUnits` only built an `Auth` nobody read. A second authenticate implementation that
/// never runs still ships, and drifts from the one that does.
#[test]
fn the_unreached_authenticate_unit_is_gone() {
    const GONE: &[&str] = &[
        "pub fn resolve(",
        "pub struct AuthRequest",
        "fn run_chain_for_new_unit",
        "pub mod challenge",
        "pub mod admin",
        "pub mod exchange",
        "Auth::new(",
        "with_auth_chain",
    ];
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    non_test_sources(&crate_dir.join("src"), &mut files);
    files.push(crate_dir.join("../busbar/src/root/kernel.rs"));
    files.sort();

    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("source reads");
        for (n, line) in text.lines().enumerate() {
            for needle in GONE {
                for (at, _) in line.match_indices(needle) {
                    // A whole token only: `InProcessAuth::new(` is not `Auth::new(`, and
                    // `pub mod admin_verbs` is not `pub mod admin`.
                    let before = line[..at].chars().next_back();
                    let after = line[at + needle.len()..].chars().next();
                    if is_ident(before)
                        || (needle.ends_with(char::is_alphanumeric) && is_ident(after))
                    {
                        continue;
                    }
                    hits.push(format!("{}:{}: {needle}", file.display(), n + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the unreached authenticate unit is still in non-test source:\n{}",
        hits.join("\n")
    );
}
