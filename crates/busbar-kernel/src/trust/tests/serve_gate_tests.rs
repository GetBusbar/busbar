// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE OWNER FOR "MAY THIS ITEM SERVE?" (choke point I, ARCHITECT Q3): the kernel's Approve.
//!
//! A plane states its trust facts and the kernel decides: the registration's configured item
//! approvals arrive through the plane's declared item-approvals trust key
//! (`abi::plane::TRUST_ITEM_APPROVALS`), parsed by the kernel ([`parse_entry`]); the plane sights
//! what each item is offered at (`trust.sight_item`); the route leg asks `trust.serves`, which is
//! [`TrustBook::judge`]. No plane re-derives the answer from its raw registration fields.
//!
//! This is the class test the deleted engine's inline decision was held to (`trust_gate_tests.rs`,
//! `the_routed_gate_answers_exactly_what_the_deleted_inline_decision_answered`), ported to the
//! kernel against a neutral double of a plane's declared facts: the deleted decision is restated
//! as an ORACLE and the whole `(approved digest × offered digest)` space is driven through both,
//! asserted on the full answer, the reason included.

use std::sync::Arc;

use busbar_contract::plane::{TrustKeyDecl, TrustRole};

use super::*;
use crate::trust::section::parse_entry;

/// A NEUTRAL DOUBLE of a plane's declared trust keys: its registrations' items under `items`, each
/// approved at the digest its `digest` field holds. Kernel tests name no plane.
const KEYS: &[TrustKeyDecl] = &[TrustKeyDecl {
    key: "items",
    role: TrustRole::ItemApprovals,
    fingerprint: false,
    default: Some("digest"),
    mechanisms: &[],
}];

/// Every shape an approved digest can take in config: absent, present, empty and whitespace. The
/// last two are where "is a digest configured" and "does the digest match" could disagree; both
/// approve nothing.
const APPROVED: &[Option<&str>] = &[None, Some("sha256:approved"), Some(""), Some("   ")];

/// What the item is offered at when the plane sights it.
const OFFERED: &[&str] = &["sha256:approved", "sha256:other"];

/// One registration `cp` declaring item `t` at `approved`, admitted for instance `inst`.
fn admitted(approved: Option<&str>) -> (TrustBook, Arc<str>) {
    let written = match approved {
        Some(d) => format!("items: {{ t: {{ digest: \"{d}\" }} }}"),
        None => "items: { t: {} }".to_string(),
    };
    let doc: serde_yaml::Value = serde_yaml::from_str(&written).expect("yaml");
    let entry = parse_entry("`section.cp`", &doc, KEYS).expect("the declared keys parse");
    let book = TrustBook::default();
    let inst: Arc<str> = Arc::from("inst");
    book.admit(&inst, [("cp".to_string(), entry)], []);
    (book, inst)
}

/// THE ORACLE: the deleted inline decision, restated. A blank digest approved nothing (`pending`,
/// not served); an approved item serves at exactly its approved digest; offered at any other, it
/// is the rug-pull and refuses.
fn deleted_inline_decision(approved: Option<&str>, offered: &str) -> Result<(), Distrust> {
    match approved.map(str::trim).filter(|d| !d.is_empty()) {
        None => Err(Distrust::NotApproved),
        Some(d) if d == offered => Ok(()),
        Some(_) => Err(Distrust::Changed),
    }
}

/// THE EQUIVALENCE MATRIX: every approved shape × every offered digest, through the kernel's
/// Approve and through the oracle, on the full answer.
#[test]
fn the_kernels_approve_answers_exactly_what_the_deleted_inline_decision_answered() {
    let (mut cases, mut served, mut refused) = (0usize, 0usize, 0usize);
    for &approved in APPROVED {
        for &offered in OFFERED {
            cases += 1;
            let (book, inst) = admitted(approved);
            book.sight_item(&inst, "cp", "t", offered)
                .expect("a declared counterparty sights");
            let facts = TrustFacts {
                counterparty: "cp",
                item: Some("t"),
                digest: None,
            };
            let got = book.judge(&inst, &facts);
            let oracle = deleted_inline_decision(approved, offered);
            assert_eq!(
                got, oracle,
                "approved {approved:?}, offered {offered:?}: the kernel said {got:?}, the deleted \
                 decision said {oracle:?}"
            );
            if got.is_ok() {
                served += 1;
            } else {
                refused += 1;
            }
        }
    }
    // Not vacuous: the matrix both serves and refuses.
    assert_eq!(cases, APPROVED.len() * OFFERED.len());
    assert_eq!((served, refused), (1, cases - 1));
}

/// An item the plane never sighted and the registration never names is UNKNOWN (a 404's case),
/// not merely unapproved: the kernel tells the two apart, the deleted decision could not.
#[test]
fn an_item_never_sighted_or_declared_is_unknown_not_unapproved() {
    let (book, inst) = admitted(Some("sha256:approved"));
    let facts = TrustFacts {
        counterparty: "cp",
        item: Some("never"),
        digest: None,
    };
    assert_eq!(book.judge(&inst, &facts), Err(Distrust::UnknownItem));
}
