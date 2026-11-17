// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #408: a selected resource label cannot authorize another actual effect.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::caps::KernelSeal;
use busbar_contract::records::{ScopeRef, VirtualKey};
use busbar_contract::services::Caller;
use busbar_kernel::plane_driver::port_egress::{MemberTarget, Targets};
use busbar_kernel::plane_driver::port_session::UpExchange;
use busbar_kernel::resource_admission::{
    ForwardFact, FrozenRequest, ResourceError, ResourceFact, ResourceInventory,
};
use busbar_kernel::state::InvocationId;
use busbar_kernel::upstreams::{ConfiguredUpstreams, UpstreamDef, UpstreamTls, Upstreams};
use busbar_plugin_abi::plane::{CARRIER_HTTP, OUTBOUND_DEFAULT};

fn caller() -> Caller {
    Caller::issue(
        &KernelSeal::acquire_for_kernel(),
        Arc::from("plane/test"),
        KindCode::Plane,
    )
}

fn upstream() -> Arc<UpstreamDef> {
    Arc::new(UpstreamDef {
        name: "shared".into(),
        allow_private: false,
        url: Some("https://example.invalid/".into()),
        command: None,
        tls: UpstreamTls {
            pin_spki: vec![],
            client_identity: None,
            trust: None,
        },
        auth: None,
    })
}

fn fact(value: &str, descriptor: u32) -> ResourceFact {
    ResourceFact {
        scope: ScopeRef {
            kind: "pool".into(),
            value: value.into(),
        },
        forwards: vec![ForwardFact {
            descriptor,
            upstream: "shared".into(),
            dialect: "fixture".into(),
            model: value.into(),
            method: "POST".into(),
            target: "/generate".into(),
        }],
    }
}

fn build(
    owner: &Caller,
    facts: Vec<ResourceFact>,
) -> Result<Arc<ResourceInventory>, ResourceError> {
    let upstreams: Arc<dyn Upstreams> = Arc::new(ConfiguredUpstreams::from_definitions(
        BTreeMap::from([("shared".into(), upstream())]),
    ));
    let targets: Targets = Arc::new(|name| (name == "shared").then(MemberTarget::bare));
    ResourceInventory::build(
        owner,
        7,
        vec!["pool".into()],
        facts,
        upstreams,
        targets,
        1 << 20,
    )
}

fn request(n: u64) -> FrozenRequest {
    FrozenRequest::new(
        InvocationId::from_request_id(NonZeroU64::new(n).unwrap()),
        3,
        "POST".into(),
        "/requests".into(),
        "".into(),
        vec![],
        b"request".to_vec(),
    )
}

fn exchange() -> UpExchange {
    UpExchange {
        carrier: CARRIER_HTTP,
        outbound: OUTBOUND_DEFAULT,
        method: Some("POST".into()),
        path: Some("/generate".into()),
        ..UpExchange::default()
    }
}

#[test]
fn valid_chat_reference_cannot_authorize_secret_at_the_same_endpoint() {
    let owner = caller();
    let inventory = build(&owner, vec![fact("chat", 1), fact("secret", 2)]).unwrap();
    let selected = inventory
        .select(request(1), &[ScopeRef::pool("chat")])
        .unwrap();
    let chat = selected.forward(1).unwrap();
    assert!(matches!(
        selected.forward(2),
        Err(ResourceError::NotSelected)
    ));
    let secret = inventory.descriptor(2).unwrap();
    let candidate = secret.candidate();
    assert!(matches!(
        chat.validate(
            chat.echo(),
            &candidate,
            secret.dialect(),
            secret.model(),
            secret.upstream(),
            exchange(),
        ),
        Err(ResourceError::Operands)
    ));
}

#[test]
fn permitted_descriptor_moves_exact_exchange_into_validated_custody() {
    let owner = caller();
    let inventory = build(&owner, vec![fact("chat", 1)]).unwrap();
    let selected = inventory
        .select(request(2), &[ScopeRef::pool("chat")])
        .unwrap();
    let forward = selected.forward(1).unwrap();
    let descriptor = forward.descriptor();
    let candidate = descriptor.candidate();
    let validated = forward
        .validate(
            forward.echo(),
            &candidate,
            descriptor.dialect(),
            descriptor.model(),
            descriptor.upstream(),
            exchange(),
        )
        .unwrap();
    assert_eq!(validated.exchange().path.as_deref(), Some("/generate"));
    assert_eq!(validated.descriptor().scope(), &ScopeRef::pool("chat"));
}

#[test]
fn echo_is_bound_to_invocation_and_inventory_not_just_numeric_descriptor() {
    let owner = caller();
    let inventory = build(&owner, vec![fact("chat", 1)]).unwrap();
    let first = inventory
        .select(request(3), &[ScopeRef::pool("chat")])
        .unwrap();
    let other = inventory
        .select(request(4), &[ScopeRef::pool("chat")])
        .unwrap();
    let forward = first.forward(1).unwrap();
    let descriptor = forward.descriptor();
    assert!(matches!(
        forward.validate(
            other.forward(1).unwrap().echo(),
            &descriptor.candidate(),
            descriptor.dialect(),
            descriptor.model(),
            descriptor.upstream(),
            exchange(),
        ),
        Err(ResourceError::Binding)
    ));
}

#[test]
fn actual_method_path_upstream_or_secondary_exchange_cannot_override_descriptor() {
    let owner = caller();
    let inventory = build(&owner, vec![fact("chat", 1)]).unwrap();
    let selected = inventory
        .select(request(5), &[ScopeRef::pool("chat")])
        .unwrap();
    let forward = selected.forward(1).unwrap();
    let descriptor = forward.descriptor();
    for changed in [
        UpExchange {
            method: Some("DELETE".into()),
            ..exchange()
        },
        UpExchange {
            path: Some("/private".into()),
            ..exchange()
        },
        UpExchange {
            id: 1,
            ..exchange()
        },
        UpExchange {
            scope: Some("other-credential".into()),
            ..exchange()
        },
    ] {
        assert!(matches!(
            forward.validate(
                forward.echo(),
                &descriptor.candidate(),
                descriptor.dialect(),
                descriptor.model(),
                descriptor.upstream(),
                changed,
            ),
            Err(ResourceError::Operands)
        ));
    }
    assert!(
        matches!(
            forward.validate(
                forward.echo(),
                &descriptor.candidate(),
                descriptor.dialect(),
                descriptor.model(),
                &upstream(),
                exchange(),
            ),
            Err(ResourceError::Binding)
        ),
        "equal endpoint text is not the retained upstream object"
    );
}

#[test]
fn exact_all_of_scopes_keep_empty_grants_and_kind_collisions_closed() {
    let owner = caller();
    let inventory = build(&owner, vec![fact("chat", 1), fact("secret", 2)]).unwrap();
    let selected = inventory
        .select(
            request(6),
            &[ScopeRef::pool("chat"), ScopeRef::pool("secret")],
        )
        .unwrap();
    let mut key = VirtualKey::default();
    key.allowed_scopes = Some(vec![ScopeRef::pool("chat")]);
    assert!(!selected.scope_allowed(&key));
    key.allowed_scopes = Some(vec![ScopeRef {
        kind: "agent".into(),
        value: "chat".into(),
    }]);
    assert!(!selected.scope_allowed(&key));
    key.allowed_scopes = Some(vec![]);
    assert!(!selected.scope_allowed(&key));
    key.allowed_scopes = None;
    assert!(selected.scope_allowed(&key));
    assert!(matches!(
        inventory.select(request(7), &[]),
        Err(ResourceError::Selection)
    ));
}

#[test]
fn unknown_upstreams_duplicate_descriptors_and_undeclared_kinds_refuse_inventory() {
    let owner = caller();
    assert!(matches!(
        build(&owner, vec![fact("chat", 1), fact("secret", 1)]),
        Err(ResourceError::Duplicate)
    ));
    let mut unknown = fact("chat", 1);
    unknown.forwards[0].upstream = "missing".into();
    assert!(matches!(
        build(&owner, vec![unknown]),
        Err(ResourceError::Upstream)
    ));
    let mut wrong_kind = fact("chat", 1);
    wrong_kind.scope.kind = "agent".into();
    assert!(matches!(
        build(&owner, vec![wrong_kind]),
        Err(ResourceError::Kind)
    ));
}
