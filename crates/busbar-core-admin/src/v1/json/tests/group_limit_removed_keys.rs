// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2f: the admin group doors refuse the removed 1.6.0 pre-release group-limit keys as unknown,
//! and still accept 1.5.5's limit shapes.

use super::{GroupPatchReq, PutGroupReq, RegisterGroupReq};

const REMOVED_LIMITS: [&str; 10] = [
    r#"{"tokens_input":1,"per":"day"}"#,
    r#"{"tokens_output":1,"per":"day"}"#,
    r#"{"tokens_cache_read":1,"per":"day"}"#,
    r#"{"tokens_cache_write":1,"per":"day"}"#,
    r#"{"budget":1,"per":"day","admission":"exact"}"#,
    r#"{"budget":1,"per":"day","admission":"estimate"}"#,
    r#"{"budget":1,"per":"day","on_exhaustion":"finish-unit"}"#,
    r#"{"budget":1,"per":"day","on_exhaustion":"cut-stream"}"#,
    r#"{"requests":1,"per":"day","admission":null}"#,
    r#"{"tokens":1,"per":"day","on_exhaustion":null}"#,
];

#[test]
fn the_group_doors_refuse_the_removed_limit_keys() {
    for limit in REMOVED_LIMITS {
        let patch = format!(r#"{{"limits":[{limit}]}}"#);
        assert!(
            serde_json::from_str::<GroupPatchReq>(&patch).is_err(),
            "PATCH accepted {limit}"
        );
        let put = format!(r#"{{"config":{{"limits":[{limit}]}}}}"#);
        assert!(
            serde_json::from_str::<PutGroupReq>(&put).is_err(),
            "PUT accepted {limit}"
        );
        let register =
            format!(r#"{{"name":"g","config":{{"child_default":{{"limits":[{limit}]}}}}}}"#);
        assert!(
            serde_json::from_str::<RegisterGroupReq>(&register).is_err(),
            "register accepted {limit}"
        );
    }
}

#[test]
fn the_group_doors_still_accept_1_5_5_limit_shapes() {
    let limits = r#"[{"requests":5,"per":"minute"},{"tokens":9,"per":"day"},{"budget":3,"per":"month","pool":"a","on_exhaust":"downgrade","downgrade_to":"b"},{"concurrent":2}]"#;
    serde_json::from_str::<GroupPatchReq>(&format!(r#"{{"limits":{limits}}}"#)).expect("PATCH");
    serde_json::from_str::<PutGroupReq>(&format!(r#"{{"config":{{"limits":{limits}}}}}"#))
        .expect("PUT");
}
