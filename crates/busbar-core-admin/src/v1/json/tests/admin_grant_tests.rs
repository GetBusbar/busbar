//! ADMIN-API r5 section 2 (MR2): the mint of an admin key, `GET /whoami`, and `x-busbar-verb`.

use crate::admin_codec::verbs::name_at;
use crate::verb::{admin_rows, VerbScope};
use busbar_contract::auth::Principal;
use busbar_contract::authz::{Grants, Scope};
use busbar_kernel::auth::{admin_door_admits, AdminDoor, VerbAllowList};

fn mint(body: &str) -> Result<Option<busbar_contract::records::AdminGrant>, String> {
    let req: crate::keys::CreateKeyReq = serde_json::from_str(body).expect("a well-formed body");
    req.admin_grant(false)
}

#[test]
fn admin_mint_refuses_mixed_grants() {
    for mixed in [
        r#"{"name":"c","admin":{"scope":"full"},"group":"g"}"#,
        r#"{"name":"c","admin":{"scope":"full"},"allowed_pools":["fast"]}"#,
        r#"{"name":"c","admin":{"scope":"full"},"audience":"https://x"}"#,
        r#"{"name":"c","admin":{"scope":"full"},"issue_aws_credential":true}"#,
    ] {
        assert!(mint(mixed).is_err(), "{mixed} must be refused");
    }
    assert!(
        mint(r#"{"name":"c","admin":{"scope":"admin"}}"#).is_err(),
        "unknown scope"
    );
    assert!(
        mint(r#"{"name":"c","admin":{"scope":"full","verbs":["not_a_verb"]}}"#).is_err(),
        "a verb outside the closed table"
    );
    let ok = mint(
        r#"{"name":"c","admin":{"scope":"read-only","verbs":["get_keys"]},"allowed_pools":[]}"#,
    )
    .expect("a pure admin grant")
    .expect("a grant");
    assert_eq!(ok.scope, "read-only");
    assert_eq!(ok.verbs, vec!["get_keys".to_string()]);
    assert_eq!(
        mint(r#"{"name":"c"}"#),
        Ok(None),
        "no admin member is a data key"
    );
}

#[test]
fn whoami_matches_gate() {
    crate::ensure_seam();
    let principal = || Principal::from_id("key:vk_x");
    let named = |verbs: &[&str], rungs: Grants| {
        let named: std::collections::BTreeSet<String> =
            verbs.iter().map(|v| v.to_string()).collect();
        let reach = verbs
            .iter()
            .filter_map(|v| crate::admin_codec::verbs::named_rung(v))
            .fold(rungs, Grants::with);
        AdminDoor::Listed(principal(), reach, VerbAllowList { rungs, named })
    };
    let doors = [
        AdminDoor::Open,
        AdminDoor::Denied,
        AdminDoor::Identified(principal(), Grants::of(Scope::Full)),
        AdminDoor::Identified(principal(), Grants::of(Scope::ReadOnly)),
        AdminDoor::Identified(principal(), Grants::default()),
        named(&["get_keys", "post_keys"], Grants::default()),
        named(&["post_config_apply"], Grants::of(Scope::ReadOnly)),
    ];
    for door in &doors {
        for row in admin_rows() {
            let path = row
                .path
                .split('/')
                .map(|s| if s.starts_with('{') { "x" } else { s })
                .collect::<Vec<_>>()
                .join("/");
            assert_eq!(
                name_at(row.method, &path),
                Some(row.name),
                "{} {path}",
                row.method
            );
            let needed = match row.scope {
                VerbScope::ReadOnly => Scope::ReadOnly,
                VerbScope::Full => Scope::Full,
            };
            assert_eq!(
                super::whoami::door_admits_verb(door, row.name, needed),
                admin_door_admits(door, row.method, &path),
                "{door:?} disagrees with the gate on {} {path}",
                row.name
            );
        }
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_every_op_has_verb() {
    let doc = crate::v1::json::openapi_doc();
    let paths = doc["paths"].as_object().expect("paths");
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if !op.is_object() || op.get("x-busbar-required-scope").is_none() {
                continue;
            }
            let verb = op["x-busbar-verb"].as_str().unwrap_or_else(|| {
                panic!("{method} {path} carries x-busbar-required-scope but no x-busbar-verb")
            });
            assert_eq!(
                name_at(&method.to_uppercase(), path),
                Some(verb),
                "{method} {path}: the verb is the table row's name"
            );
        }
    }
}
