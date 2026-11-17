use super::{Binder, ConfigBinder};
use std::sync::Arc;
fn binder(_: &str) -> Binder {
    Binder::new(
        Arc::new(busbar_contract::secret_ref::Sugars::default()),
        Vec::new(),
    )
}
use busbar_plugin_abi::need::{egress, need_flag, op};
use busbar_ports::binder::NetworkEndpoint;

fn endpoint(op: u32, tls: u32, class: u32, dest: &str) -> NetworkEndpoint {
    NetworkEndpoint::new(op, tls | (class << 16), dest).expect("valid endpoint")
}

#[test]
fn direct_network_authority_is_frozen_for_one_instance_and_operation() {
    let b = binder("unused");
    for id in [7, 8] {
        b.bind(id, b"{}", &[], &[], &[], &[]).unwrap();
    }
    let e = endpoint(
        op::OPEN,
        need_flag::TLS_REQUIRED,
        egress::OPERATOR_INFRASTRUCTURE,
        "DB.internal:5432",
    );
    assert!(
        b.admit_network(7, &e).is_none(),
        "binding alone grants no network authority"
    );
    b.freeze_network(7, &[e.clone()]).unwrap();
    b.freeze_network(8, &[]).unwrap();
    let permit = b.admit_network(7, &e).expect("exact bound endpoint");
    assert_eq!(
        (permit.instance, permit.registration, permit.class()),
        (7, 1, egress::OPERATOR_INFRASTRUCTURE)
    );
    assert_eq!(permit.endpoint.dest.as_ref(), "db.internal:5432");
    assert!(
        b.admit_network(8, &e).is_none(),
        "another instance cannot borrow the same host"
    );
    assert!(b.admit_network(99, &e).is_none(), "unknown instance");
    assert!(
        b.freeze_network(7, &[]).is_err(),
        "the active set is immutable"
    );
    for forged in [
        endpoint(
            op::OPEN,
            need_flag::TLS_NONE,
            egress::OPERATOR_INFRASTRUCTURE,
            "db.internal:5432",
        ),
        endpoint(
            op::OPEN,
            need_flag::TLS_REQUIRED,
            egress::LOOPBACK_ALLOWED,
            "db.internal:5432",
        ),
        endpoint(
            op::FETCH,
            need_flag::TLS_REQUIRED,
            egress::OPERATOR_INFRASTRUCTURE,
            "https://db.internal:5432/path",
        ),
        endpoint(
            op::OPEN,
            need_flag::TLS_REQUIRED,
            egress::OPERATOR_INFRASTRUCTURE,
            "other.internal:5432",
        ),
    ] {
        assert!(
            b.admit_network(7, &forged).is_none(),
            "no operation/TLS/class/origin expansion"
        );
    }
    b.unbind(7);
    assert!(
        !permit.lease.live(),
        "retirement reaches held operation authority"
    );
    assert!(b.admit_network(7, &e).is_none(), "retired generation");
}

#[test]
fn network_endpoint_canonicalization_preserves_origin_and_tls_boundaries() {
    assert_eq!(
        endpoint(
            op::OPEN,
            need_flag::TLS_REQUIRED,
            egress::OPERATOR_INFRASTRUCTURE,
            "bücher.example:443"
        )
        .dest
        .as_ref(),
        "xn--bcher-kva.example:443"
    );
    let a = endpoint(
        op::FETCH,
        need_flag::TLS_REQUIRED,
        egress::OPERATOR_INFRASTRUCTURE,
        "https://EXAMPLE.org/path?query",
    );
    let b = endpoint(
        op::FETCH,
        need_flag::TLS_REQUIRED,
        egress::OPERATOR_INFRASTRUCTURE,
        "https://example.org:443/other",
    );
    assert_eq!(a, b, "FETCH authority is an origin, not a URL path");
    assert_eq!(
        endpoint(
            op::OPEN,
            need_flag::TLS_REQUIRED,
            egress::OPERATOR_INFRASTRUCTURE,
            "[2001:db8::1]:5432"
        )
        .dest
        .as_ref(),
        "[2001:db8::1]:5432"
    );
    for (op, tls, dest) in [
        (op::OPEN, need_flag::TLS_REQUIRED, "db.internal"),
        (op::OPEN, need_flag::TLS_REQUIRED, "127.1:5432"),
        (op::OPEN, need_flag::TLS_REQUIRED, "db.internal:0"),
        (
            op::FETCH,
            need_flag::TLS_REQUIRED,
            "https://user@example.org/",
        ),
        (
            op::FETCH,
            need_flag::TLS_REQUIRED,
            "https://example.org/#fragment",
        ),
        (op::FETCH, need_flag::TLS_REQUIRED, "http://example.org/"),
        (op::FETCH, need_flag::TLS_INBAND, "https://example.org/"),
    ] {
        assert!(
            NetworkEndpoint::new(op, tls | (egress::OPERATOR_INFRASTRUCTURE << 16), dest).is_none(),
            "refuse {dest}"
        );
    }
}

#[test]
fn conflicting_endpoint_constraints_refuse_the_whole_candidate() {
    let b = binder("unused");
    b.bind(7, b"{}", &[], &[], &[], &[]).unwrap();
    let a = endpoint(
        op::OPEN,
        need_flag::TLS_REQUIRED,
        egress::OPERATOR_INFRASTRUCTURE,
        "db.internal:5432",
    );
    let mut other = a.clone();
    other.flags = need_flag::TLS_NONE | (egress::OPERATOR_INFRASTRUCTURE << 16);
    assert!(b.freeze_network(7, &[a.clone(), other]).is_err());
    assert!(
        b.admit_network(7, &a).is_none(),
        "failure publishes no partial grants"
    );
    b.freeze_network(7, &[a.clone(), a.clone()]).unwrap();
    assert_eq!(
        b.admit_network(7, &a).unwrap().registration,
        1,
        "identical duplicates collapse"
    );
}
