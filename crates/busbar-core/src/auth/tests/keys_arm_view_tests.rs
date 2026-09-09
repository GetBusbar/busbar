// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What `GET /api/v1/admin/auth` says about a chain that names the built-in `keys` verifier.
//!
//! ## The defect these pin
//!
//! `keys` is not a boxed module: `AuthMiddleware::new` recognises it, sets `keys_in_chain`, and does
//! NOT push anything onto `self.chain`. Everything on the request path already knows that and
//! compensates — the admission check is `self.chain.is_empty() && !self.keys_in_chain`, and so is
//! the open-relay boot warning. Two REPORTING paths did not:
//!
//! - `chain_names()` walks the boxed modules, so an operator who configured `auth.chain: [keys]`
//!   was told `chain: []`.
//! - `is_open()` tested `self.chain.is_empty()` alone, so the same operator was told
//!   `open: true` — the front door admits everything — about a node whose front door is CLOSED and
//!   runs the keys arm on every request.
//!
//! The second is the one with teeth. `open` is the field an operator greps for to answer "is this
//! node exposed", and it was answering yes about a node that is not.

use crate::auth::AuthMiddleware;
use crate::config::AuthCfg;

fn chain_of(modules: &[&str]) -> AuthCfg {
    let mut cfg = AuthCfg::default_none();
    cfg.chain = modules
        .iter()
        .map(|m| crate::config::AuthChainEntry::bare(*m))
        .collect();
    cfg
}

/// A chain that names only `keys` reports the arm, and reports the door as closed.
#[test]
fn a_keys_only_chain_reports_the_arm_and_a_closed_door() {
    let mw = AuthMiddleware::new_builtin(&chain_of(&["keys"]));

    assert_eq!(
        mw.chain_names(),
        vec!["keys"],
        "the configured arm is not reported"
    );
    assert!(
        !mw.is_open(),
        "a keys chain was reported as an open front door; the request path keeps it closed"
    );
}

/// The reported door agrees with the rule the request path actually admits by.
///
/// Written as an agreement rather than as two literals, because the pair drifting apart is the
/// whole defect: the request path was right and the report was wrong, and only a test that reads
/// both would have said so.
#[test]
fn the_reported_door_agrees_with_the_admission_rule() {
    for modules in [
        vec![],
        vec!["keys"],
        vec!["test-groups-module"],
        vec!["keys", "test-groups-module"],
    ] {
        let mw = AuthMiddleware::new_builtin(&chain_of(&modules));
        let admits_anonymously = matches!(mw.run_chain(None), crate::auth::ChainVerdict::Open);
        assert_eq!(
            mw.is_open(),
            admits_anonymously,
            "{modules:?}: the reported `open` disagrees with what the chain actually does"
        );
    }
}

/// `keys` is reported in the position the operator wrote it, among the boxed modules.
///
/// Order is the chain's meaning — the first module to identify admits — so a report that listed the
/// arms in a different order would describe a different door.
#[test]
fn the_keys_arm_is_reported_in_its_configured_position() {
    assert_eq!(
        AuthMiddleware::new_builtin(&chain_of(&["keys", "test-groups-module"])).chain_names(),
        vec!["keys", "test-groups-module"]
    );
    assert_eq!(
        AuthMiddleware::new_builtin(&chain_of(&["test-groups-module", "keys"])).chain_names(),
        vec!["test-groups-module", "keys"]
    );
}

/// An empty chain still reports an empty chain and an open door.
///
/// The control: the fix must not make every node look closed.
#[test]
fn an_empty_chain_is_still_an_open_front_door() {
    let mw = AuthMiddleware::new_builtin(&chain_of(&[]));
    assert!(mw.chain_names().is_empty());
    assert!(mw.is_open());
}
