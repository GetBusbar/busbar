// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 7.2: the audit row's new fields under hash scheme 3, the request context
//! that fills them, the severity, kind and instance filters, and the Store-ranged read.

use super::tests::native_over;
use super::*;

fn full_row() -> AuditRowInput {
    AuditRowInput {
        action: "config.apply".into(),
        resource: "config:models".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        config_generation: Some("42".into()),
        sections_changed: vec!["models".into(), "limits".into()],
        request_id: Some("r_0000000000000001".into()),
        idempotency_key: Some("cr-9".into()),
        kind: Some("openai".into()),
        instance: Some("primary".into()),
        severity: "warning".into(),
        message: "applied".into(),
        data: AuditData::from_json(r#"{"plugin_diag":"d1","text":"t1","n":12345678901234567890}"#)
            .unwrap(),
    }
}

#[test]
fn scheme3_row_round_trips_through_its_suffix() {
    let row = full_row();
    let suffix = row_suffix(1_700_000_000, &row);
    let parsed = parse_suffix_entry(&suffix);
    assert_eq!(parsed.scheme, crate::audit_ring::AUDIT_SCHEME_ROW);
    assert_eq!(parsed.ts, 1_700_000_000);
    assert_eq!(parsed.row, row);
}

#[test]
fn scheme3_digests_every_field() {
    let base = row_suffix(10, &full_row());
    let edits: Vec<(&str, Box<dyn Fn(&mut AuditRowInput)>)> = vec![
        ("action", Box::new(|r| r.action.push('x'))),
        ("resource", Box::new(|r| r.resource.push('x'))),
        ("outcome", Box::new(|r| r.outcome = "rejected".into())),
        ("principal", Box::new(|r| r.principal.push('x'))),
        (
            "config_generation",
            Box::new(|r| r.config_generation = Some("43".into())),
        ),
        (
            "config_generation absent",
            Box::new(|r| r.config_generation = None),
        ),
        (
            "config_generation empty",
            Box::new(|r| r.config_generation = Some(String::new())),
        ),
        (
            "sections_changed",
            Box::new(|r| r.sections_changed.push("x".into())),
        ),
        (
            "sections_changed order",
            Box::new(|r| r.sections_changed.reverse()),
        ),
        (
            "request_id",
            Box::new(|r| r.request_id = Some("r_2".into())),
        ),
        ("idempotency_key", Box::new(|r| r.idempotency_key = None)),
        ("kind", Box::new(|r| r.kind = Some("anthropic".into()))),
        ("instance", Box::new(|r| r.instance = Some("backup".into()))),
        ("severity", Box::new(|r| r.severity = "error".into())),
        ("message", Box::new(|r| r.message.push('x'))),
        (
            "data.plugin_diag",
            Box::new(|r| {
                r.data = AuditData::from_json(
                    r#"{"plugin_diag":"d2","text":"t1","n":12345678901234567890}"#,
                )
                .unwrap();
            }),
        ),
        (
            "data.text",
            Box::new(|r| {
                r.data = AuditData::from_json(
                    r#"{"plugin_diag":"d1","text":"t2","n":12345678901234567890}"#,
                )
                .unwrap();
            }),
        ),
    ];
    for (name, edit) in edits {
        let mut row = full_row();
        edit(&mut row);
        assert_ne!(
            row_suffix(10, &row),
            base,
            "a changed {name} must change the sealed bytes"
        );
    }
    assert_ne!(row_suffix(11, &full_row()), base, "ts is sealed");
}

#[test]
fn data_is_digested_in_canonical_form() {
    let a = AuditData::from_json(
        r#"{ "b" : 1, "a" : { "z" : null, "y" : "x\/é\u0001\n" }, "c": [ 3, 1.50, true ] }"#,
    )
    .unwrap();
    assert_eq!(
        a.as_str(),
        r#"{"a":{"y":"x/é\u0001\n","z":null},"b":1,"c":[3,1.50,true]}"#
    );
    let b = AuditData::from_json(r#"{"c":[3,1.50,true],"b":1,"a":{"y":"x/é\u0001\n","z":null}}"#)
        .unwrap();
    assert_eq!(a, b, "member order does not change the digested bytes");
    let pair = AuditData::from_json(r#"{"k":"😀"}"#).unwrap();
    assert_eq!(pair.as_str(), "{\"k\":\"\u{1F600}\"}");
    assert_eq!(AuditData::default().as_str(), "{}");
    for bad in ["[1]", "not json", r#"{"a":1} x"#, "", r#"{"a":}"#] {
        assert!(
            AuditData::from_json(bad).is_err(),
            "{bad:?} is not an object"
        );
    }
}

#[test]
fn legacy_suffixes_read_with_row_defaults() {
    let pipe = parse_suffix_entry(&audit_suffix(
        5,
        "hook.register",
        "hook:a",
        "applied",
        "admin",
    ));
    assert_eq!(pipe.scheme, crate::audit_ring::AUDIT_SCHEME_PIPE);
    assert_eq!(pipe.row.severity, "info");
    assert_eq!(pipe.row.data.as_str(), "{}");
    assert!(pipe.row.request_id.is_none() && pipe.row.sections_changed.is_empty());
    let safe = parse_suffix_entry(&audit_suffix_safe(5, "a|b.c", "r", "applied", "admin"));
    assert_eq!(safe.scheme, crate::audit_ring::AUDIT_SCHEME_LENGTH_PREFIXED);
    assert_eq!(safe.row.action, "a|b.c");
}

#[test]
fn a_truncated_scheme3_body_does_not_panic() {
    let suffix = row_suffix(1, &full_row());
    for cut in 0..suffix.len() {
        let _ = parse_suffix_entry(&suffix[..cut]);
    }
}

#[test]
fn entry_serializes_new_fields_and_reads_old_json() {
    let entry = AuditEntry {
        seq: 3,
        action: "config.apply".into(),
        config_generation: Some("42".into()),
        sections_changed: vec!["models".into()],
        severity: "warning".into(),
        data: AuditData::from_json(r#"{"b":2,"a":1}"#).unwrap(),
        ..Default::default()
    };
    let text = sonic_rs::to_string(&entry).unwrap();
    assert!(text.contains(r#""config_generation":"42""#), "{text}");
    assert!(text.contains(r#""sections_changed":["models"]"#), "{text}");
    assert!(text.contains(r#""severity":"warning""#), "{text}");
    assert!(text.contains(r#""data":{"a":1,"b":2}"#), "{text}");
    let old = r#"{"seq":1,"ts":2,"action":"a.b","resource":"r","outcome":"applied","principal":"p","prev_hash":"","hash":"h"}"#;
    let read: AuditEntry = sonic_rs::from_str(old).unwrap();
    assert_eq!(read.severity, "info");
    assert_eq!(read.data.as_str(), "{}");
    assert_eq!(read.scheme, crate::audit_ring::AUDIT_SCHEME_PIPE);
}

#[tokio::test]
async fn audit_rows_carry_generation_and_request() {
    let request = Arc::new(AuditRequest::default());
    let (applied, rejected) = crate::admin::gate::with_request_id(
        "r_00000000000000aa".into(),
        scope_request(Some(request), async {
            note_idempotency_key("cr-77");
            note_generation_source(Arc::new(|| 9));
            note_sections_changed(vec!["prices".into()]);
            let mut applied = AuditRowInput {
                outcome: "applied".into(),
                ..Default::default()
            };
            stamp_request_context(&mut applied);
            let mut rejected = AuditRowInput {
                outcome: "rejected".into(),
                ..Default::default()
            };
            stamp_request_context(&mut rejected);
            (applied, rejected)
        }),
    )
    .await;
    assert_eq!(applied.request_id.as_deref(), Some("r_00000000000000aa"));
    assert_eq!(applied.idempotency_key.as_deref(), Some("cr-77"));
    assert_eq!(applied.config_generation.as_deref(), Some("9"));
    assert_eq!(applied.sections_changed, vec!["prices".to_string()]);
    assert_eq!(rejected.request_id.as_deref(), Some("r_00000000000000aa"));
    assert_eq!(rejected.idempotency_key.as_deref(), Some("cr-77"));
    assert!(
        rejected.config_generation.is_none() && rejected.sections_changed.is_empty(),
        "a rejected row changed nothing, so it names no generation and no section"
    );
    let mut outside = AuditRowInput::default();
    stamp_request_context(&mut outside);
    assert!(outside.request_id.is_none() && outside.idempotency_key.is_none());
}

fn push(log: &PlaneAuditLog, seq: u64, severity: &str, kind: Option<&str>, instance: Option<&str>) {
    log.push_entry(
        AuditEntry {
            seq,
            ts: seq,
            action: "plugin.health".into(),
            severity: severity.into(),
            kind: kind.map(Into::into),
            instance: instance.map(Into::into),
            hash: seq.to_string(),
            ..Default::default()
        },
        "admin",
        Vec::new(),
        false,
    );
}

fn seqs(page: &crate::audit_ring::AuditPage) -> Vec<u64> {
    page.items.iter().map(|e| e.seq).collect()
}

#[test]
fn severity_kind_and_instance_filters() {
    let log = PlaneAuditLog::new();
    push(&log, 1, "info", None, None);
    push(&log, 2, "error", Some("openai"), Some("primary"));
    push(&log, 3, "warning", Some("openai"), Some("backup"));
    push(&log, 4, "error", Some("anthropic"), Some("primary"));
    let ask = |severity, kind, instance| {
        let q = AuditQuery {
            limit: 100,
            severity,
            kind,
            instance,
            ..Default::default()
        };
        seqs(&log.list_after(&q).unwrap())
    };
    assert_eq!(ask(Some("error"), None, None), vec![2, 4]);
    assert_eq!(ask(None, Some("openai"), None), vec![2, 3]);
    assert_eq!(ask(None, None, Some("primary")), vec![2, 4]);
    assert_eq!(ask(Some("error"), Some("openai"), Some("primary")), vec![2]);
    assert_eq!(ask(Some("info"), Some("openai"), None), Vec::<u64>::new());
}

#[tokio::test]
async fn audit_sees_other_node_change_and_asc_restart_safe() {
    let store = crate::real_store::core().await;
    let a = native_over(store.clone()).await;
    let b = native_over(store.clone()).await;
    a.restore().await.unwrap();
    b.restore().await.unwrap();
    a.emit(ADMIN_LOG, row_suffix(100, &full_row())).await;
    assert!(
        b.log.list_filtered(0, 10, None, None).is_empty(),
        "node B's ring has not seen node A's change"
    );
    let ask = |after| AuditQuery {
        after,
        limit: 10,
        ..Default::default()
    };
    let page = b.log.list_after_store(&ask(None)).await.unwrap();
    assert_eq!(
        seqs(&page),
        vec![1],
        "the feed reads the Store, not only the ring"
    );
    assert_eq!(
        page.items[0].request_id.as_deref(),
        Some("r_0000000000000001")
    );
    assert_eq!(page.items[0].scheme, crate::audit_ring::AUDIT_SCHEME_ROW);
    assert_eq!(page.items[0].data.as_str(), full_row().data.as_str());

    let c = native_over(store.clone()).await;
    c.restore().await.unwrap();
    let again = c.log.list_after_store(&ask(Some(1))).await.unwrap();
    assert!(
        again.items.is_empty() && again.complete,
        "restart resumes after seq 1"
    );
    a.emit(ADMIN_LOG, row_suffix(101, &full_row())).await;
    let next = c.log.list_after_store(&ask(Some(1))).await.unwrap();
    assert_eq!(seqs(&next), vec![2]);
}

#[test]
fn audit_action_catalogue_closed() {
    let mut sorted = AUDIT_ACTIONS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, AUDIT_ACTIONS.to_vec(), "sorted, no duplicates");
    for action in AUDIT_ACTIONS {
        assert!(action.contains('.') && !action.starts_with('.'), "{action}");
    }
    for known in [
        "keyset.rotated",
        "config.apply",
        "hook.register",
        "plugin.health",
    ] {
        assert!(AUDIT_ACTIONS.contains(&known), "{known}");
    }
    assert!(action_admitted(&["config"], "config.apply"));
}
