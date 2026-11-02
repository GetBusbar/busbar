// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::plane::{TrustKeyDecl, TrustRole};

use super::*;
use crate::trust::section::parse_entry;

const KEYS: &[TrustKeyDecl] = &[TrustKeyDecl {
    key: "items",
    role: TrustRole::ItemApprovals,
    fingerprint: false,
    default: Some("digest"),
    mechanisms: &[],
}];

const APPROVED: &[Option<&str>] = &[None, Some("sha256:approved"), Some(""), Some("   ")];

const OFFERED: &[&str] = &["sha256:approved", "sha256:other"];

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

fn deleted_inline_decision(approved: Option<&str>, offered: &str) -> Result<(), Distrust> {
    match approved.map(str::trim).filter(|d| !d.is_empty()) {
        None => Err(Distrust::NotApproved),
        Some(d) if d == offered => Ok(()),
        Some(_) => Err(Distrust::Changed),
    }
}

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

    assert_eq!(cases, APPROVED.len() * OFFERED.len());
    assert_eq!((served, refused), (1, cases - 1));
}

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
