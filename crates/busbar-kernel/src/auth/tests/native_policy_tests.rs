// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use busbar_ports::auth::{decode_verify_ok, VerifyOk};

fn identity(subject: &str, groups: &[&str]) -> Identity {
    let mut records = Reply::new();
    records.put_text(tag::ID_SUBJECT, subject).unwrap();
    for group in groups {
        records.put_text(tag::ID_GROUP, group).unwrap();
    }
    let VerifyOk::Identity(identity) = decode_verify_ok(Records::new(records.as_bytes())).unwrap()
    else {
        panic!("identity records");
    };
    identity
}

fn request<'a>(method: &'a str, path: &'a str) -> AuthIn<'a> {
    AuthIn {
        method,
        path,
        query: "",
        authority: "busbar.example",
        headers: &[],
        peer: "127.0.0.1",
        tls_peer_cert: &[],
        body: &[],
        now_s: 100,
    }
}

fn policy(surface: Surface) -> BindingsPolicy {
    let bindings = crate::config::RoleBindings::from([(
        "directory".into(),
        std::collections::BTreeMap::from([(
            "reader".into(),
            crate::config::RoleBindingCfg {
                allowed_pools: Some(vec!["chat".into()]),
                group: None,
                admin_scope: Some("read-only".into()),
                verbs: None,
                plane_grants: Default::default(),
            },
        )]),
    )]);
    BindingsPolicy {
        instance: 41,
        provider: "directory".into(),
        epoch: 7,
        current_epoch: Arc::new(AtomicU64::new(7)),
        bindings,
        surface,
    }
}

#[test]
fn native_data_policy_requires_its_provider_binding_and_current_instance_generation() {
    let mut policy = policy(Surface::Data);
    let req = request("POST", "/v1/chat/completions");
    let alice = identity("alice", &["reader"]);
    assert_eq!(policy.authorize(41, &alice, &req), Ok(()));
    assert_eq!(policy.authorize(42, &alice, &req), Err(R_POLICY));
    policy.provider = "other-provider".into();
    assert_eq!(policy.authorize(41, &alice, &req), Err(R_POLICY));
    policy.provider = "directory".into();
    policy.current_epoch.store(8, Ordering::Release);
    assert_eq!(policy.authorize(41, &alice, &req), Err(R_POLICY));
}

#[test]
fn native_operator_policy_reuses_scopes_and_refuses_an_external_operator_subject() {
    let policy = policy(Surface::Operator {
        chain: Arc::new(super::super::AdminAuthChain {
            modules: Default::default(),
            operator: super::super::Operator::new("operator-provider"),
        }),
        principal: "operator:local".into(),
        cap: Some(busbar_contract::authz::Scope::ReadOnly),
    });
    let alice = identity("alice", &["reader"]);
    assert_eq!(
        policy.authorize(41, &alice, &request("GET", "/api/v1/config")),
        Ok(())
    );
    assert_eq!(
        policy.authorize(41, &alice, &request("DELETE", "/api/v1/config")),
        Err(R_POLICY)
    );
    assert_eq!(
        policy.authorize(
            41,
            &identity("operator:local", &[]),
            &request("GET", "/api/v1/config")
        ),
        Err(R_POLICY),
        "an external provider cannot manufacture the operator principal"
    );
}

#[test]
fn frozen_chain_policy_never_borrows_another_instance_or_generation() {
    let req = request("GET", "/resource");
    let alice = identity("alice", &["reader"]);
    let admitted = policy(Surface::Data);
    let current = Arc::clone(&admitted.current_epoch);
    let chain = ChainPolicy::new(7, vec![admitted]);
    assert_eq!(chain.authorize(41, &alice, &req), Ok(()));
    assert_eq!(chain.authorize(42, &alice, &req), Err(R_POLICY));
    current.store(8, Ordering::Release);
    assert_eq!(chain.authorize(41, &alice, &req), Err(R_POLICY));
    let mismatched = ChainPolicy::new(8, vec![policy(Surface::Data)]);
    assert_eq!(mismatched.authorize(41, &alice, &req), Err(R_POLICY));
}
