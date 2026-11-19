// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The config binder (IF §12.7): binding, the stray rule, D_REF_PATH resolution and its round trip, `bind_any`,
//! dests, trust anchors, `unix_paths` and the binding bound.

use std::sync::Arc;

use busbar_contract::json::{json, Value};
use busbar_contract::plugin_settings::sugar_words::REWRITE_SUGAR;
use busbar_contract::secret_ref::{SecretRef, Sugars};
use busbar_contract::secure::SecureVec;

use super::{BindError, Binder, BoxFut, ConfigBinder, RefSource, MAX_BINDINGS};

/// Resolves every reference to one fixed value (custody's part, §12.2, is K2's).
struct Fixed(&'static str);
impl RefSource for Fixed {
    fn resolve<'a>(
        &'a self,
        _: u64,
        _: u32,
        _: u32,
        _: &'a SecretRef,
    ) -> BoxFut<'a, Option<SecureVec>> {
        let v = self.0;
        Box::pin(async move { Some(SecureVec::from(v.as_bytes())) })
    }
}

fn sugars() -> Arc<Sugars> {
    let mut s = Sugars::default();
    s.declare(
        "busbar-secret-env",
        &[(REWRITE_SUGAR, "env".into(), "name".into())],
    )
    .expect("one shorthand");
    Arc::new(s)
}

fn binder(_value: &'static str) -> Binder {
    Binder::new(sugars(), Vec::new())
}

fn bytes(v: &Value) -> Vec<u8> {
    busbar_contract::json::to_vec(v).expect("json")
}

fn read(b: &[u8]) -> Value {
    busbar_contract::json::parse_value(b).expect("json")
}

fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(f)
}

#[test]
fn a_declared_secret_becomes_a_handle_and_custody_finds_it() {
    let b = binder("unused");
    let cfg = json!({"addr": "https://vault:8200", "token": {"env": "VAULT_TOKEN"}});
    let out = read(
        &b.bind(7, &bytes(&cfg), &["/token"], &[], &[], &[])
            .expect("binds"),
    );
    assert_eq!(
        out,
        json!({"addr": "https://vault:8200", "token": {"$secret": 1}})
    );
    assert!(
        matches!(b.secret(7, 1), Some(SecretRef::Source(s)) if s.module == "busbar-secret-env")
    );
    assert!(b.secret(7, 0).is_none(), "handle 0 is none");
    assert!(b.secret(7, 2).is_none(), "out of range");
    assert!(b.secret(8, 1).is_none(), "unknown instance");
    b.unbind(7);
    assert!(b.secret(7, 1).is_none(), "unbind drops the bindings");
}

#[test]
fn a_star_pointer_binds_each_array_index_in_order() {
    let b = binder("unused");
    let cfg = json!({"keys": [{"k": {"env": "A"}}, {"k": {"env": "B"}}]});
    let out = read(
        &b.bind(1, &bytes(&cfg), &["/keys/*/k"], &[], &[], &[])
            .expect("binds"),
    );
    assert_eq!(
        out,
        json!({"keys": [{"k": {"$secret": 1}}, {"k": {"$secret": 2}}]})
    );
}

#[test]
fn a_reference_or_a_marker_outside_a_declared_path_is_stray() {
    let b = binder("unused");
    let stray = json!({"other": {"env": "X"}});
    assert!(matches!(
        b.bind(1, &bytes(&stray), &["/token"], &[], &[], &[]),
        Err(BindError::StraySecret { pointer }) if &*pointer == "/other"
    ));
    let canonical = json!({"deep": [{"module": "vault", "settings": {"path": "kv/x"}}]});
    assert!(matches!(
        b.bind(1, &bytes(&canonical), &[], &[], &[], &[]),
        Err(BindError::StraySecret { pointer }) if &*pointer == "/deep/0"
    ));
    let forged = json!({"x": {"$secret": 1}});
    assert!(matches!(
        b.bind(1, &bytes(&forged), &[], &[], &[], &[]),
        Err(BindError::StraySecret { .. })
    ));
    assert!(b.secret(1, 1).is_none(), "a refused bind stores nothing");
}

#[test]
fn a_plain_value_at_a_secret_path_is_not_a_reference() {
    let b = binder("unused");
    let cfg = json!({"token": "s3cr3t-literal"});
    assert!(matches!(
        b.bind(1, &bytes(&cfg), &["/token"], &[], &[], &[]),
        Err(BindError::NotAReference { pointer }) if &*pointer == "/token"
    ));
}

#[test]
fn a_ref_path_reference_resolves_before_open_and_unbinds_to_its_text() {
    let b = binder("/tmp/x.db");
    let cfg = json!({"db_path": {"env": "DB"}, "busy_timeout_ms": 5000});
    let bound = b
        .bind(3, &bytes(&cfg), &[], &[], &[], &["/db_path"])
        .expect("binds");
    assert_eq!(
        read(&bound),
        cfg,
        "the reference stays in place until resolve_refs"
    );
    let resolved = run(b.resolve_refs(3, 0, bound, &Fixed("/tmp/x.db"))).expect("resolves");
    assert_eq!(
        read(resolved.as_slice()),
        json!({"db_path": "/tmp/x.db", "busy_timeout_ms": 5000})
    );
    let settled = json!({"db_path": "/tmp/x.db", "busy_timeout_ms": 5000, "v": 2});
    let back = read(&b.unbind_refs(3, &bytes(&settled)).expect("unbinds"));
    assert_eq!(
        back,
        json!({"db_path": {"env": "DB"}, "busy_timeout_ms": 5000, "v": 2})
    );
    let leaked = json!({"db_path": "/tmp/x.db", "copy": "/tmp/x.db"});
    assert!(matches!(
        b.unbind_refs(3, &bytes(&leaked)),
        Err(BindError::NotAReference { pointer }) if &*pointer == "/copy"
    ));
}

#[test]
fn a_plain_string_at_a_ref_path_is_left_and_no_refs_means_no_io() {
    let b = binder("never");
    let cfg = json!({"url": "postgres://db/busbar"});
    let bound = b
        .bind(4, &bytes(&cfg), &[], &[], &[], &["/url"])
        .expect("binds");
    let resolved = run(b.resolve_refs(4, 0, bound.clone(), &Fixed("never"))).expect("no refs");
    assert_eq!(resolved.as_slice(), bound.as_slice());
}

#[test]
fn an_undeclared_shorthand_at_a_ref_path_refuses() {
    let b = binder("unused");
    let cfg = json!({"url": {"envx": "U"}});
    assert!(matches!(
        b.bind(1, &bytes(&cfg), &[], &[], &[], &["/url"]),
        Err(BindError::NotAReference { pointer }) if &*pointer == "/url"
    ));
}

#[test]
fn a_reference_failing_its_secret_instances_ref_schema_is_bad_reference() {
    let b = Binder::new(
        sugars(),
        vec![(
            Arc::from("env"),
            Box::from(
                r#"{"type":"object","properties":{"name":{"type":"string","pattern":"^[A-Z_]+$"}},"required":["name"]}"#,
            ),
        )],
    );
    let good = json!({"token": {"env": "TOKEN"}});
    assert!(b.bind(1, &bytes(&good), &["/token"], &[], &[], &[]).is_ok());
    let bad = json!({"token": {"env": "lower"}});
    match b.bind(1, &bytes(&bad), &["/token"], &[], &[], &[]) {
        Err(BindError::BadReference { pointer, text }) => {
            assert_eq!(&*pointer, "/token");
            assert!(
                !text.contains("lower"),
                "core text never echoes the value: {text}"
            );
        }
        other => panic!("expected BadReference, got {other:?}"),
    }
}

#[test]
fn bind_any_binds_references_anywhere_and_leaves_literals() {
    let b = binder("unused");
    let cfg = json!({"old": {"nested": {"env": "K"}}, "token": "1x-literal"});
    let out = read(
        &b.bind_any(9, &bytes(&cfg), &["/token"], &[], &[], &[])
            .expect("binds"),
    );
    assert_eq!(
        out,
        json!({"old": {"nested": {"$secret": 1}}, "token": "1x-literal"})
    );
    let back = read(&b.unbind_refs(9, &bytes(&out)).expect("unbinds"));
    assert_eq!(back, cfg, "the shorthand stays a shorthand");
}

#[test]
fn an_invented_handle_is_not_a_reference() {
    let b = binder("unused");
    let cfg = json!({"token": {"env": "K"}});
    b.bind(2, &bytes(&cfg), &["/token"], &[], &[], &[])
        .expect("binds");
    let invented = json!({"token": {"$secret": 1}, "more": {"$secret": 2}});
    assert!(matches!(
        b.unbind_refs(2, &bytes(&invented)),
        Err(BindError::NotAReference { pointer }) if &*pointer == "/more"
    ));
}

#[test]
fn a_dest_binds_with_its_defaults_and_keep_is_bounded() {
    let b = binder("unused");
    let cfg = json!({"path": "/var/log/busbar/requests.jsonl"});
    let out = read(
        &b.bind(5, &bytes(&cfg), &[], &[], &[""], &[])
            .expect("binds"),
    );
    assert_eq!(out, json!({"$dest": 1}));
    let d = b.dest(5, 1).expect("bound");
    assert_eq!(
        (&*d.path, d.rotate_mb, d.keep),
        ("/var/log/busbar/requests.jsonl", 64, 9)
    );
    for bad in [
        json!({"sink": {"path": "/x", "keep": 65}}),
        json!({"sink": {"path": ""}}),
        json!({"sink": {"path": "/var/../etc/x"}}),
        json!({"sink": {"path": "/x", "mode": "a"}}),
    ] {
        assert!(matches!(
            b.bind(5, &bytes(&bad), &[], &[], &["/sink"], &[]),
            Err(BindError::BadDest { pointer }) if &*pointer == "/sink"
        ));
    }
}

#[test]
fn a_trust_path_holds_pem_or_refuses() {
    let b = binder("unused");
    let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    let cfg = json!({"ca_cert_pem": pem});
    let out = read(
        &b.bind(6, &bytes(&cfg), &[], &["/ca_cert_pem"], &[], &[])
            .expect("binds"),
    );
    assert_eq!(out, json!({"ca_cert_pem": {"$trust": 1}}));
    let anchor = b.trust(6, 1).expect("bound");
    assert_eq!(anchor.der.len(), 1);
    assert_eq!(
        anchor.sha256,
        busbar_contract::crypto::sha256(&anchor.der[0])
    );
    let back = read(&b.unbind_refs(6, &bytes(&out)).expect("unbinds"));
    assert_eq!(back, cfg);
    let bad = json!({"ca_cert_pem": "not a pem"});
    assert!(matches!(
        b.bind(6, &bytes(&bad), &[], &["/ca_cert_pem"], &[], &[]),
        Err(BindError::BadPem { .. })
    ));
}

#[test]
fn unix_paths_are_frozen_check_targets_only() {
    use busbar_plugin_abi::need::{egress, need_flag, op};
    use busbar_ports::binder::NetworkEndpoint;
    let endpoint = |path: &str| {
        NetworkEndpoint::new(
            op::OPEN,
            need_flag::TLS_NONE | (egress::OPERATOR_INFRASTRUCTURE << 16),
            &format!("unix:{path}"),
        )
        .expect("absolute socket path")
    };
    let allowed = |b: &Binder, instance: u64, path: &str| {
        b.admit_network(instance, &endpoint(path)).is_some()
    };
    let b = binder("unused");
    let cfg = json!({
        "url": "mysql://u@localhost/db?socket=%2Frun%2Fmysqld%2Fmysqld.sock",
        "valkey": "redis+unix:///var/run/valkey.sock",
        "file": "/srv/data.db",
        "web": "https://example.com/path",
    });
    b.bind(1, &bytes(&cfg), &[], &[], &[], &[]).expect("binds");
    assert!(
        !allowed(&b, 1, "/run/mysqld/mysqld.sock"),
        "raw strings never grant reach"
    );
    b.freeze_network(
        1,
        &[
            endpoint("/run/mysqld/mysqld.sock"),
            endpoint("/var/run/valkey.sock"),
            endpoint("/srv/data.db"),
        ],
    )
    .expect("config-only CHECK endpoints");
    assert!(allowed(&b, 1, "/run/mysqld/mysqld.sock"));
    assert!(allowed(&b, 1, "/var/run/valkey.sock"));
    assert!(allowed(&b, 1, "/srv/data.db"));
    assert!(
        !allowed(&b, 1, "/path"),
        "a URI with an authority yields no path"
    );
    assert!(!allowed(&b, 1, "/var/run/docker.sock"));
    assert!(!allowed(&b, 2, "/srv/data.db"), "unknown instance");

    b.bind(2, b"{}", &[], &[], &[], &[])
        .expect("second candidate");
    let many: Vec<_> = (0..17).map(|i| endpoint(&format!("/sock/{i}"))).collect();
    assert!(matches!(
        b.freeze_network(2, &many),
        Err(BindError::TooMany)
    ));
}

#[test]
fn more_than_max_bindings_is_too_many() {
    let b = binder("unused");
    let mut keys = Vec::with_capacity(MAX_BINDINGS + 1);
    for _ in 0..=MAX_BINDINGS {
        keys.push(json!({"env": "K"}));
    }
    let cfg = json!({"keys": keys});
    assert!(matches!(
        b.bind(1, &bytes(&cfg), &["/keys/*"], &[], &[], &[]),
        Err(BindError::TooMany)
    ));
}

#[test]
fn reference_resolution_uses_each_opens_explicit_source_and_actual_slot() {
    struct Scoped {
        id: u64,
        slot: u32,
        value: &'static str,
    }
    impl RefSource for Scoped {
        fn resolve<'a>(
            &'a self,
            id: u64,
            slot: u32,
            _: u32,
            _: &'a SecretRef,
        ) -> BoxFut<'a, Option<SecureVec>> {
            Box::pin(async move {
                assert_eq!(
                    (id, slot),
                    (self.id, self.slot),
                    "actual reservation metadata reaches custody"
                );
                Some(SecureVec::from(self.value.as_bytes()))
            })
        }
    }
    let binder = Binder::new(sugars(), Vec::new());
    let config = bytes(&json!({"path": {"env": "DB"}}));
    let first = binder
        .bind(19, &config, &[], &[], &[], &["/path"])
        .expect("first bind");
    let second = binder
        .bind(23, &config, &[], &[], &[], &["/path"])
        .expect("second bind");
    let first_source = Scoped {
        id: 19,
        slot: 7,
        value: "/first",
    };
    let second_source = Scoped {
        id: 23,
        slot: 11,
        value: "/second",
    };
    let first = run(binder.resolve_refs(19, 7, first, &first_source)).expect("first resolves");
    let second = run(binder.resolve_refs(23, 11, second, &second_source)).expect("second resolves");
    assert_eq!(read(first.as_slice()), json!({"path": "/first"}));
    assert_eq!(read(second.as_slice()), json!({"path": "/second"}));
    assert_eq!(
        read(
            &binder
                .unbind_refs(19, first.as_slice())
                .expect("first reference mapping")
        ),
        read(&config)
    );
    assert_eq!(
        read(
            &binder
                .unbind_refs(23, second.as_slice())
                .expect("second reference mapping")
        ),
        read(&config)
    );
}

#[test]
fn reference_source_receives_a_distinct_stable_binding_ordinal() {
    struct Ordinals(std::sync::Mutex<Vec<u32>>);
    impl RefSource for Ordinals {
        fn resolve<'a>(
            &'a self,
            _: u64,
            _: u32,
            binding: u32,
            _: &'a SecretRef,
        ) -> BoxFut<'a, Option<SecureVec>> {
            Box::pin(async move {
                self.0.lock().expect("ordinals").push(binding);
                Some(SecureVec::from(b"resolved".as_slice()))
            })
        }
    }
    let binder = Binder::new(sugars(), Vec::new());
    let config = bytes(&json!({"a": {"env":"A"}, "b": {"env":"B"}, "c": {"env":"C"}}));
    let source = Ordinals(std::sync::Mutex::new(Vec::new()));
    let bound = binder
        .bind(71, &config, &[], &[], &[], &["/a", "/b", "/c"])
        .expect("bind three references");
    run(binder.resolve_refs(71, 9, bound.clone(), &source)).expect("resolve three");
    run(binder.resolve_refs(71, 9, bound, &source)).expect("repeat same bindings");
    assert_eq!(*source.0.lock().expect("ordinals"), [0, 1, 2, 0, 1, 2]);
}

/// A reference source whose every resolve fails.
struct Refusing;
impl RefSource for Refusing {
    fn resolve<'a>(
        &'a self,
        _: u64,
        _: u32,
        _: u32,
        _: &'a SecretRef,
    ) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async { None })
    }
}

/// DES-454 I1 (T1, binder side): `committed` reads the digest of each D_REF_PATH value `resolve_refs` wrote, in
/// binding order. A failed resolve for another instance (a refused rotation successor) leaves it unchanged.
#[test]
fn committed_reads_each_ref_digest_and_a_failed_successor_changes_nothing() {
    let b = binder("unused");
    let cfg = json!({"a": {"env": "A"}, "b": {"env": "B"}});
    let paths = ["/a", "/b"];
    let bound = b
        .bind(3, &bytes(&cfg), &[], &[], &[], &paths)
        .expect("binds");
    assert_eq!(b.committed(3), None, "nothing resolved yet");
    run(b.resolve_refs(3, 0, bound, &Fixed("sk-live-0010-ref"))).expect("resolves");
    let digest = busbar_contract::crypto::sha256(b"sk-live-0010-ref");
    assert_eq!(b.committed(3), Some(vec![digest, digest]));

    let successor = b
        .bind(4, &bytes(&cfg), &[], &[], &[], &paths)
        .expect("binds");
    assert!(run(b.resolve_refs(4, 0, successor, &Refusing)).is_err());
    assert_eq!(b.committed(4), None, "a refused successor commits nothing");
    assert_eq!(
        b.committed(3),
        Some(vec![digest, digest]),
        "the predecessor is unchanged"
    );
    assert_eq!(
        read(
            &b.unbind_refs(3, &bytes(&json!({"a": "sk-live-0010-ref"})))
                .expect("unbinds")
        ),
        json!({"a": {"env": "A"}}),
        "the read-back is unchanged"
    );
    assert_eq!(b.committed(9), None, "an unknown instance");
    b.unbind(3);
    assert_eq!(b.committed(3), None);
}
