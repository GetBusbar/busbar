// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-AU6: the caller's verified secret is copied into kernel custody once, at
//! `CallerCredential::verified`; the unit's transport-custody `Secret<String>` moves into the
//! claimed request instead of being copied, and every later holder shares the one zeroising
//! buffer, through the far end's lend to the passthrough member's auth binding. Counted by the
//! dev-only stage probe (`Derive::SecretCopy`) on the actual inbound host and the actual far end.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

const ROLE: &str = "caller-secret-role";

/// Claim one request whose body provider verified the caller's `secret`, under a binding that
/// admits it, and complete its admitted context the way the data plane does.
async fn admitted(secret: &str) -> (Kit, UnitRef, crate::auth::AdmittedContext) {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        Verified::Identity(VerifiedIdentity {
            subject: "body".to_string(),
            credential: Some(Secret::new(secret.to_string())),
            groups: vec![ROLE.to_string()],
            ..VerifiedIdentity::default()
        }),
        &seen,
    );
    let bindings = crate::config::RoleBindings::from([(
        "body".to_string(),
        std::collections::BTreeMap::from([(
            ROLE.to_string(),
            crate::config::RoleBindingCfg::default(),
        )]),
    )]);
    let k = mixed_bound(reader, &[head, body], bindings);
    let answer = two_points(&k, &seen).await;
    assert_eq!(
        answer.flow, FLOW_CONTINUE,
        "the body provider admits the caller"
    );
    let head = signed_head().stripped_for_test(&answer.strips).unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, head.clone()).0,
        FLOW_CONTINUE
    );
    let request = k.inbound.claim_request(OWNER, 1, 1, &head).unwrap();
    let context = crate::auth::admitted_context(&request)
        .await
        .expect("the bound caller is admitted");
    (k, answer.unit, context)
}

#[tokio::test(flavor = "current_thread")]
async fn caller_secret_has_one_plaintext_buffer() {
    let scope = Scope::open();
    let (k, unit, context) = admitted("sk-caller-secret").await;

    assert!(
        context.consumed.caller.is_some(),
        "the claim verified the caller's credential"
    );
    assert_eq!(
        scope.count(Derive::SecretCopy),
        1,
        "from the claim to the host context the caller secret is copied once, into the kernel's \
         one zeroising buffer"
    );
    assert!(
        k.inbound.with_credential(unit.id, |_| ()).is_none(),
        "the claim takes the unit's credential into the claimed request; no copy stays behind"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn caller_secret_lent_to_plugin_without_copy() {
    let scope = Scope::open();
    let (_k, _unit, context) = admitted("sk-caller-secret").await;

    let lent = crate::plane_driver::lent_on_egress(context.consumed.caller).await;
    assert_eq!(
        lent,
        vec![Some(b"sk-caller-secret".to_vec())],
        "the passthrough member's auth binding is lent the caller's credential"
    );
    assert_eq!(
        scope.count(Derive::SecretCopy),
        1,
        "from verify to the plugin lend the caller secret is copied once: the far end lends the \
         one buffer, never a copy of it"
    );
}
