// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE SUBJECT DECODER: a sealed body's subject is read back by the same round-tripping rule the
//! amendment journal reads its subjects with.

use busbar_contract::caps::{Audit as AuditStep, KernelSeal, MeterClassId, Pass};

use busbar_kernel_audit::journal::{from_journal_body, journal_body};
use busbar_kernel_audit::record::AuditChain;
use busbar_kernel_audit::sign::AuditSigningKey;

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// The classes the fixture's lines name.
fn declared(name: &str) -> Option<MeterClassId> {
    ["tokens_in", "tokens_out"]
        .into_iter()
        .find(|c| *c == name)
        .map(MeterClassId::new)
}

/// A SUBJECT PAIR THAT DOES NOT RE-RENDER IS REFUSED, never read as a different spelling of the
/// same subject. The journal decodes a sealed subject through the one decoder the amendment journal
/// uses, which accepts `("node", v)` only when `v` is exactly how node `n` renders. A body that
/// carries `"007"` where the record sealed `"7"` would otherwise decode as node 7 and re-digest
/// cleanly, because the digest re-renders the canonical `"7"` — so the decoder is the only place a
/// rewritten spelling can be caught.
#[test]
fn a_subject_value_that_does_not_re_render_is_refused_in_a_sealed_body() {
    let key = AuditSigningKey::from_hex_seed(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .expect("the test seed is 64 lowercase hex");
    let mut chain = AuditChain::new().signing_with(key);
    let mut inputs = super::sign_tests::rich_inputs(1);
    inputs.subject = busbar_kernel_audit::record::Subject::Node(7);
    let record = busbar_kernel_audit::record::Audit::seal(&mut chain, inputs, &token());
    let body = journal_body(&record);
    assert_eq!(
        from_journal_body(&body, &declared)
            .expect("the sealed body decodes")
            .expect("it is an audit record"),
        record
    );

    let framed = |s: &str| {
        let mut out = (s.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(s.as_bytes());
        out
    };
    let sealed_pair = [framed("node"), framed("7")].concat();
    let at = body
        .windows(sealed_pair.len())
        .position(|w| w == sealed_pair.as_slice())
        .expect("the subject pair is in the body");
    let mut forged = body[..at].to_vec();
    forged.extend_from_slice(&[framed("node"), framed("007")].concat());
    forged.extend_from_slice(&body[at + sealed_pair.len()..]);
    assert!(
        from_journal_body(&forged, &declared).is_err(),
        "a body naming node \"007\" decoded as node 7"
    );
}
