// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH r3.1 (ruling 2; §3.6, §3.6.1, §000.1): the operator credential is
//! FILE policy at every admin write door. An admin write can neither create, re-point nor re-key a
//! definition backed by the operator credential, nor move the plugin admission set that decides it.
//! Each refusal answers 409 `operator_file_policy` before anything is built or written, and leaves
//! the `auth.operator.refused / file_policy` row. Each test runs at the seam its door calls. nextest
//! runs every test in its own process, so each binds the operator words for itself.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::Response;
use busbar_contract::auth_calls::OperatorClaim;
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::config::named_map::NamedMapSection;
use busbar_kernel::config::overlay::OverlayDoc;
use busbar_kernel::config::{DeployCfg, OperatorFileDefs};
use busbar_kernel::preflight::{install_operator, Judged, OperatorBinding};
use serde_json::json;

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;
use crate::v1::json::err_json_cond;

const OP: &str = "dropped-op";
const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const OTHER: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";
const POLICY: &str = "is backed by the operator credential, which is set only in config.yaml";

fn bind_operator() {
    install_operator(OperatorBinding::Bound(Judged {
        words: Ok(Some(OperatorClaim {
            provider: OP.to_owned(),
            canonical: "busbar-auth-dropped-op".to_owned(),
            principal: "admin".to_owned(),
            first_party: true,
            version: "1.6.0".to_owned(),
            signer: "busbar".to_owned(),
        })),
        inert: Vec::new(),
    }));
}

/// config.yaml: the operator credential, and one ordinary provider.
fn file() -> String {
    format!(
        "identity-providers:\n  {OP}:\n    module: {OP}\n    settings: {{ sha256: \"{DIGEST}\" }}\n  \
         corp:\n    module: corp-idp\n    max_admin_scope: read-only\n"
    )
}

fn base() -> DeployCfg {
    busbar_kernel::config::deploy_from_yaml_str(&file(), &busbar_kernel::config::Grammar::empty())
        .expect("config.yaml parses")
}

fn reference() -> OperatorFileDefs {
    OperatorFileDefs::of(&base().identity_providers)
}

async fn answer(resp: Response) -> (StatusCode, serde_json::Value) {
    use http_body_util::BodyExt;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).expect("an error envelope"),
    )
}

/// The 409 `operator_file_policy` envelope of `rejection`, and its message.
async fn assert_operator_file_policy(rejection: (AdminError, Cond), what: &str) -> String {
    let (error, cond) = rejection;
    assert_eq!(cond, Cond::OperatorFilePolicy, "{what}: the condition");
    let (status, body) = answer(err_json_cond(&error, cond)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{what}: {body}");
    assert_eq!(
        body["error"]["reason"], "operator_file_policy",
        "{what}: {body}"
    );
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn assert_audited(door: &str, what: &str) {
    let held = busbar_kernel::audit::auditlog::held_operator_rows();
    assert!(
        held.iter()
            .any(|row| row.starts_with("auth.operator.refused ")
                && row.contains("file_policy")
                && row.contains(door)),
        "{what}: the auth.operator.refused / file_policy row names {door}: {held:?}"
    );
}

// --- the named-map doors (R11-R13) -------------------------------------------------------------

/// The base file with only the operator definition, and the overlay a write would leave.
fn named_map_candidate(name: &str, def: serde_json::Value) -> DeployCfg {
    let mut deploy = busbar_kernel::config::deploy_from_yaml_str(
        &format!(
        "identity-providers:\n  {OP}:\n    module: {OP}\n    settings: {{ sha256: \"{DIGEST}\" }}\n"
    ),
        &busbar_kernel::config::Grammar::empty(),
    )
    .expect("config.yaml parses");
    let mut doc = OverlayDoc::default();
    doc.named_maps.insert(
        NamedMapSection::IdentityProviders.key().to_owned(),
        BTreeMap::from([(name.to_owned(), def)]),
    );
    busbar_kernel::config::overlay::apply_root_to_deploy(&mut deploy, &doc);
    deploy
}

fn named_map_rejection(deploy: &DeployCfg) -> Option<(AdminError, Cond)> {
    super::named_map::operator_file_rejection(
        NamedMapSection::IdentityProviders,
        deploy,
        "identity-providers",
    )
}

#[tokio::test]
async fn r11_re_pointing_an_overlay_definition_to_the_operator_is_refused() {
    bind_operator();
    for ceiling in ["read-only", "full"] {
        let what = format!("PUT /identity-providers/corp (live ceiling {ceiling})");
        let deploy = named_map_candidate("corp", json!({"module": OP, "max_admin_scope": ceiling}));
        let rejection = named_map_rejection(&deploy)
            .unwrap_or_else(|| panic!("{what}: re-pointing to the operator is refused"));
        let message = assert_operator_file_policy(rejection, &what).await;
        assert!(
            message.contains("identity-providers.corp") && message.contains(POLICY),
            "{what}: {message}"
        );
    }
    assert_audited("identity-providers", "R11");
}

#[tokio::test]
async fn r12_a_new_operator_backed_overlay_definition_is_refused_at_the_first_call() {
    bind_operator();
    let deploy = named_map_candidate("ops2", json!({"module": OP, "settings": {"sha256": OTHER}}));
    let rejection = named_map_rejection(&deploy)
        .expect("PUT /identity-providers/ops2 creating an operator credential is refused");
    let message = assert_operator_file_policy(rejection, "R12").await;
    assert!(
        message.contains("identity-providers.ops2"),
        "R12: names the definition: {message}"
    );
    assert_audited("identity-providers", "R12");
}

#[tokio::test]
async fn r13_editing_the_settings_of_an_overlay_held_operator_definition_is_refused() {
    bind_operator();
    let deploy = named_map_candidate("ops3", json!({"module": OP, "settings": {"sha256": OTHER}}));
    let rejection = named_map_rejection(&deploy)
        .expect("PATCH /identity-providers/ops3/settings re-keying the operator is refused");
    assert_operator_file_policy(rejection, "R13").await;
    assert_audited("identity-providers", "R13");
}

#[test]
fn an_ordinary_overlay_definition_and_a_base_file_operator_definition_keep_their_answers() {
    bind_operator();
    let deploy = named_map_candidate(
        "corp",
        json!({"module": "corp-idp", "max_admin_scope": "read-only"}),
    );
    assert!(
        named_map_rejection(&deploy).is_none(),
        "an ordinary overlay definition is not the operator file policy's"
    );
    assert!(
        NamedMapSection::IdentityProviders.contains(&base(), OP),
        "re-pointing, deleting or re-keying the base file's operator definition stays BaseDefined"
    );
}

// --- POST /config/apply and POST /config/validate (R17, R17b, R17c, R18) -------------------------

/// The three bodies apply and validate must refuse, each with the definition it names.
fn refused_bodies() -> [(&'static str, &'static str, serde_json::Value); 3] {
    [
        (
            "R17 (adds an operator-backed definition)",
            "ops2",
            json!({"identity-providers": {
                OP: {"module": OP, "settings": {"sha256": DIGEST}},
                "corp": {"module": "corp-idp", "max_admin_scope": "read-only"},
                "ops2": {"module": OP, "settings": {"sha256": OTHER}},
            }}),
        ),
        (
            "R17b (changes the file operator definition's settings)",
            OP,
            json!({"identity-providers": {
                OP: {"module": OP, "settings": {"sha256": OTHER}},
                "corp": {"module": "corp-idp", "max_admin_scope": "read-only"},
            }}),
        ),
        (
            "R17c (re-points a file-defined name to the operator)",
            "corp",
            json!({"identity-providers": {
                OP: {"module": OP, "settings": {"sha256": DIGEST}},
                "corp": {"module": OP, "max_admin_scope": "read-only"},
            }}),
        ),
    ]
}

fn body(config: serde_json::Value) -> DeployCfg {
    busbar_kernel::config::deploy_from_deserializer(
        config,
        &busbar_kernel::config::Grammar::empty(),
    )
    .expect("the body parses")
}

async fn body_answer(deploy: &DeployCfg, door: &str) -> Option<(StatusCode, serde_json::Value)> {
    let refusal = super::handlers::config_body_refusal(deploy, &reference(), door)?;
    Some(answer(err_json_cond(&refusal, Cond::OperatorFilePolicy)).await)
}

#[tokio::test]
async fn r17_apply_refuses_a_body_that_moves_the_operator_credential() {
    bind_operator();
    for (what, name, config) in refused_bodies() {
        let (status, envelope) = body_answer(&body(config), "config.apply")
            .await
            .unwrap_or_else(|| panic!("{what}: apply refuses before any build"));
        assert_eq!(status, StatusCode::CONFLICT, "{what}: {envelope}");
        assert_eq!(
            envelope["error"]["reason"], "operator_file_policy",
            "{what}"
        );
        let message = envelope["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&format!("identity-providers.{name}"))
                && message.contains(POLICY)
                && message.contains(super::handlers::CONFIG_BODY_REMEDY.trim()),
            "{what}: {message}"
        );
    }
    assert_audited("config.apply", "R17");
}

#[tokio::test]
async fn r18_validate_answers_exactly_what_apply_answers() {
    bind_operator();
    for (what, _, config) in refused_bodies() {
        let deploy = body(config);
        let apply = body_answer(&deploy, "config.apply").await;
        let validate = body_answer(&deploy, "config.validate").await;
        let (Some((apply_status, apply)), Some((validate_status, validate))) = (apply, validate)
        else {
            panic!("{what}: apply and validate both refuse");
        };
        assert_eq!(apply_status, validate_status, "{what}: the status");
        assert_eq!(
            apply["error"]["reason"], validate["error"]["reason"],
            "{what}"
        );
        assert_eq!(
            apply["error"]["message"], validate["error"]["message"],
            "{what}"
        );
    }
    assert_audited("config.validate", "R18");

    let unchanged = body(json!({"identity-providers": {
        OP: {"module": OP, "settings": {"sha256": DIGEST}},
        "corp": {"module": "corp-idp", "max_admin_scope": "read-only"},
    }}));
    for door in ["config.apply", "config.validate"] {
        assert!(
            body_answer(&unchanged, door).await.is_none(),
            "{door}: a body carrying the file's operator definitions unchanged passes"
        );
    }
}

// --- PUT /config/settings with document_patch (R23-R23f) ---------------------------------------

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-operator-file-policy-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The composed patch over config.yaml, as the door reads it: the same loader, before any write.
fn compose(
    tag: &str,
    patch: serde_json::Value,
) -> (DocumentPatch, busbar_kernel::appbuild::LoadedConfig) {
    let dir = scratch(tag);
    let config = dir.join("config.yaml");
    std::fs::write(&config, file()).expect("config.yaml");
    let mut patch = DocumentPatch::from_value(patch).expect("a well-formed document_patch");
    let loaded = busbar_kernel::appbuild::load_config_from_disk_compacting_document_patches(
        &config,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &busbar_kernel::appbuild::AcceptAll,
        busbar_kernel::appbuild::DocumentPatchLoad {
            patch: Some(&mut patch),
            providers_patch: None,
            admission: None,
        },
    )
    .expect("the composed document loads");
    let _ = std::fs::remove_dir_all(&dir);
    (patch, loaded)
}

async fn assert_patch_refused(tag: &str, patch: serde_json::Value, names: &str) {
    let (patch, loaded) = compose(tag, patch);
    let rejection = super::config_document::document_patch_rejection(&patch, Some(&loaded))
        .unwrap_or_else(|| panic!("{tag}: the document_patch is refused before any write"));
    let message = assert_operator_file_policy(rejection, tag).await;
    assert!(
        message.contains(names)
            && message.contains("document_patch cannot set the operator credential"),
        "{tag}: {message}"
    );
    assert_audited("config.settings", tag);
}

#[tokio::test]
async fn r23_a_patch_adding_an_operator_backed_definition_is_refused() {
    bind_operator();
    assert_patch_refused(
        "r23",
        json!({"set": {"/identity-providers/x": {"module": OP}}}),
        "identity-providers.x",
    )
    .await;
}

#[tokio::test]
async fn r23b_a_patch_re_keying_the_operator_definition_is_refused() {
    bind_operator();
    assert_patch_refused(
        "r23b",
        json!({"set": {format!("/identity-providers/{OP}/settings/sha256"): OTHER}}),
        &format!("identity-providers.{OP}"),
    )
    .await;
}

#[tokio::test]
async fn r23c_a_patch_re_pointing_a_definition_to_the_operator_is_refused() {
    bind_operator();
    assert_patch_refused(
        "r23c",
        json!({"set": {"/identity-providers/corp/module": OP}}),
        "identity-providers.corp",
    )
    .await;
}

#[tokio::test]
async fn r23d_a_patch_on_the_plugins_dir_is_refused() {
    bind_operator();
    let patch = json!({"set": {"/plugins/dir": "/srv/elsewhere"}});
    assert!(
        super::config_document::document_patch_rejection(
            &DocumentPatch::from_value(patch.clone()).expect("a well-formed document_patch"),
            None
        )
        .is_some(),
        "R23d: the admission path is refused before config.yaml is read"
    );
    assert_patch_refused("r23d", patch, "plugins").await;
}

#[tokio::test]
async fn r23e_a_patch_on_the_trust_policy_is_refused() {
    bind_operator();
    assert_patch_refused(
        "r23e",
        json!({"set": {"/plugins/trust/allow_third_party": true}}),
        "plugins",
    )
    .await;
}

#[test]
fn r23f_a_patch_on_plugin_logs_is_accepted() {
    bind_operator();
    let (patch, loaded) = compose("r23f", json!({"set": {"/plugins/logs/level": "debug"}}));
    assert!(
        super::config_document::document_patch_rejection(&patch, None).is_none()
            && super::config_document::document_patch_rejection(&patch, Some(&loaded)).is_none(),
        "R23f: plugins.logs has no admission effect"
    );
}
