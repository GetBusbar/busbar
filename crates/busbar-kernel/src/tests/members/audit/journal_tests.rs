// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed record survives the journal: `audit.v4` keeps the whole record, and reading it back
//! gives the record that was sealed — the same digest, the same signature, still verifying.

use busbar_contract::caps::{Audit as AuditStep, KernelSeal, MeterClassId, Pass};

use busbar_kernel_audit::journal::{from_journal_body, journal_body, JOURNAL_TAG};
use busbar_kernel_audit::record::{AuditBreakKind, AuditChain};
use busbar_kernel_audit::sign::AuditSigningKey;

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// The classes the fixture's lines name, as a node's registered vocabulary would resolve them.
fn declared(name: &str) -> Option<MeterClassId> {
    ["tokens_in", "tokens_out"]
        .into_iter()
        .find(|c| *c == name)
        .map(MeterClassId::new)
}

fn sealed(n: u64) -> Vec<busbar_kernel_audit::record::AuditRecord> {
    let key = AuditSigningKey::from_hex_seed(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .expect("the test seed is 64 lowercase hex");
    let mut chain = AuditChain::new().signing_with(key);
    (1..=n)
        .map(|unit| {
            let mut inputs = super::sign_tests::rich_inputs(unit);
            inputs.what.incarnation = 3;
            busbar_kernel_audit::record::Audit::seal(&mut chain, inputs, &token())
        })
        .collect()
}

#[test]
fn a_signed_record_round_trips_through_its_journal_body() {
    for record in sealed(3) {
        let back = from_journal_body(&journal_body(&record), &declared)
            .expect("the body decodes")
            .expect("the body is an audit record");
        assert_eq!(back, record, "the journal lost or changed a field");
        assert_eq!(AuditChain::digest_of(&back), record.hash);
    }
    let back: Vec<_> = sealed(3)
        .iter()
        .map(|r| {
            from_journal_body(&journal_body(r), &declared)
                .unwrap()
                .unwrap()
        })
        .collect();
    assert!(
        AuditChain::verify_chain(&back).is_ok(),
        "the decoded run walks from genesis"
    );
}

#[test]
fn a_body_that_is_not_an_audit_record_is_none_and_a_torn_one_is_an_error() {
    assert_eq!(from_journal_body(b"posting/counts", &declared), Ok(None));
    let body = journal_body(&sealed(1)[0]);
    assert!(body.starts_with(&(JOURNAL_TAG.len() as u32).to_be_bytes()));
    assert!(from_journal_body(&body[..body.len() - 1], &declared).is_err());
    let mut longer = body.clone();
    longer.push(0);
    assert!(from_journal_body(&longer, &declared).is_err());
}

/// A CLASS THE VOCABULARY DOES NOT HOLD IS AN ERROR, never a line dropped: the reader names it.
#[test]
fn a_class_nobody_declares_here_is_an_error_naming_it() {
    let body = journal_body(&sealed(1)[0]);
    let err = from_journal_body(&body, &|_| None).expect_err("no class resolves");
    assert!(err.contains("tokens_out"), "{err}");
}

/// AN EDIT TO A RECORD ON DISK decodes to a record whose digest no longer matches: the chain walk
/// names it.
#[test]
fn an_edited_journal_body_decodes_to_a_record_the_chain_walk_refuses() {
    let records = sealed(1);
    let mut body = journal_body(&records[0]);
    // The first usage line's quantity (120) is a big-endian u64 somewhere in the body; edit it.
    let needle = 120u64.to_be_bytes();
    let at = body
        .windows(8)
        .position(|w| w == needle)
        .expect("the quantity is in the body");
    body[at + 7] = 121;
    let tampered = from_journal_body(&body, &declared).unwrap().unwrap();
    assert_eq!(tampered.usage.lines[0].quantity, 121);
    assert_eq!(
        AuditChain::verify_chain(std::slice::from_ref(&tampered)).map_err(|b| b.kind),
        Err(AuditBreakKind::DigestMismatch)
    );
}
