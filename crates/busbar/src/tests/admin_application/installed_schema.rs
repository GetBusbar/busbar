// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use std::collections::HashSet;
use std::sync::Arc;
const TOKEN: &str = "admintok";

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn isolated() -> bool {
    const CHILD: &str = "BUSBAR_INSTALLED_SCHEMA_ROOT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let name = std::thread::current().name().unwrap().to_owned();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    true
}

async fn application() -> (Arc<busbar_kernel::state::App>, Scratch) {
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("installed-schema-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual Store hydrates");
    (app, Scratch(directory))
}

async fn body(response: reqwest::Response, status: u16) -> serde_json::Value {
    let actual = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    assert_eq!(actual, status, "{}", String::from_utf8_lossy(&bytes));
    if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn schema_candidate(schema: &'static [u8], legacy: Option<&str>) -> Vec<u8> {
    declaration_candidate("store", schema, legacy, &[], &[])
}

fn declaration_candidate(
    kind: &str,
    schema: &'static [u8],
    legacy: Option<&str>,
    sections: &[(&str, u32)],
    claims: &[&str],
) -> Vec<u8> {
    let mut manifest =
        plugins::manifest(kind, "installed-schema-target", plugins::FIXTURE_PUBLISHER);
    // Encode the documented pointer-free canonical metadata format directly. This fixture
    // exercises signed archive inspection, never a plugin door or executable library. The real
    // canonical reader below verifies the byte structure before the archive is signed.
    fn word(out: &mut Vec<u8>, value: u32) {
        out.extend(value.to_le_bytes());
    }
    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        word(out, u32::try_from(value.len()).unwrap());
        out.extend(value);
    }
    let mut rendering = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.to_vec();
    word(
        &mut rendering,
        busbar_contract::abi::mechanism::MECHANISM_VERSION,
    );
    word(
        &mut rendering,
        match kind {
            "plane" => busbar_contract::abi::mechanism::KindCode::Plane,
            "transport" => busbar_contract::abi::mechanism::KindCode::Transport,
            _ => busbar_contract::abi::mechanism::KindCode::Store,
        } as u32,
    );
    word(&mut rendering, manifest.abi_version);
    word(&mut rendering, 1); // max_inflight
    bytes(&mut rendering, b"installed-schema-target");
    bytes(&mut rendering, manifest.version.as_bytes());
    for _ in 0..8 {
        word(&mut rendering, 0);
    } // families, diagnostics, tail, tail facts,
      // extension blob (3 words), secret refs
    word(
        &mut rendering,
        if schema.is_empty() {
            0
        } else {
            busbar_contract::abi::mechanism::call::BLOB_JSON
        },
    );
    word(&mut rendering, 0); // blob flags
    bytes(&mut rendering, schema);
    rendering.extend(0u64.to_le_bytes()); // marks
    word(&mut rendering, 0); // words
    word(&mut rendering, 0); // rewrites
    word(&mut rendering, sections.len().try_into().unwrap());
    for (name, flags) in sections {
        bytes(&mut rendering, name.as_bytes());
        word(&mut rendering, *flags);
    }
    for _ in 0..4 {
        word(&mut rendering, 0);
    } // needs, target, trust, answers
    word(&mut rendering, claims.len().try_into().unwrap());
    for claim in claims {
        bytes(&mut rendering, claim.as_bytes());
    }
    let facts = busbar_contract::abi::mechanism::rendering::read(&rendering).unwrap();
    assert_eq!(facts.name, "installed-schema-target");
    manifest.statement = Some(hex::encode(rendering));
    manifest.settings_schema = legacy.map(str::to_string);
    plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        b"metadata inspection fixture, never executed",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installed_schema_urls_bind_actual_archive_before_reload_and_refuse_stale_bytes() {
    if isolated() {
        return;
    }
    let (app, scratch) = application().await;
    let router = busbar_core_admin::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let origin = format!("http://{addr}");
    let base = format!("{origin}/api/v1/admin");
    const V1: &[u8] = br#"{"type":"object","properties":{"first":{"type":"boolean"}},"additionalProperties":false}"#;
    const V2: &[u8] = br#"{"type":"object","properties":{"second":{"type":"boolean"}},"additionalProperties":false}"#;
    use base64::Engine as _;
    let mut old_url = String::new();
    for (index, schema) in [V1, V2].into_iter().enumerate() {
        let archive = schema_candidate(
            schema,
            Some(r#"{"type":"object","properties":{"legacy":{"type":"string"}}}"#),
        );
        let digest = busbar_contract::redacted::sha256_hex(&archive);
        body(client.post(format!("{base}/plugins")).bearer_auth(TOKEN)
            .json(&serde_json::json!({"file":"reviewed.tar.gz","tarball_b64":base64::engine::general_purpose::STANDARD.encode(&archive)}))
            .send().await.unwrap(),201).await;
        // No reload: the loaded name remains absent, but the installed artifact URL must work.
        body(
            client
                .get(format!("{base}/plugins/installed-schema-target/schema"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            404,
        )
        .await;
        if index == 1 {
            body(
                client
                    .get(format!("{origin}{old_url}"))
                    .bearer_auth(TOKEN)
                    .send()
                    .await
                    .unwrap(),
                409,
            )
            .await;
        }
        let listed = body(
            client
                .get(format!("{base}/plugins?type=store"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            200,
        )
        .await;
        let row = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| artifact_file(row) == "reviewed.tar.gz")
            .unwrap();
        let url = row["schema_url"].as_str().unwrap();
        assert!(url.starts_with("/api/v1/admin/plugins/reviewed.tar.gz/schema?source=installed_archive&expected_archive_sha256="));
        assert_eq!(row["archive_sha256"], digest);
        body(
            client.get(format!("{origin}{url}")).send().await.unwrap(),
            401,
        )
        .await;
        let read = body(
            client
                .get(format!("{origin}{url}"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            200,
        )
        .await;
        assert_eq!(read["source"], "installed_archive");
        assert_eq!(read["schema_state"], "present");
        assert_eq!(read["archive_sha256"], digest);
        assert_eq!(
            read["schema"],
            serde_json::from_slice::<serde_json::Value>(schema).unwrap()
        );
        assert!(read["schema"]["properties"].get("legacy").is_none());
        old_url = url.to_string();
    }
    let absent = schema_candidate(b"", None);
    let digest = busbar_contract::redacted::sha256_hex(&absent);
    body(client.post(format!("{base}/plugins")).bearer_auth(TOKEN)
        .json(&serde_json::json!({"file":"reviewed.tar.gz","tarball_b64":base64::engine::general_purpose::STANDARD.encode(&absent)}))
        .send().await.unwrap(),201).await;
    let url = format!(
        "{base}/plugins/reviewed.tar.gz/schema?source=installed_archive&expected_archive_sha256={digest}"
    );
    let read = body(
        client.get(url).bearer_auth(TOKEN).send().await.unwrap(),
        200,
    )
    .await;
    assert_eq!(read["schema_state"], "absent");
    assert!(read["schema"].is_null());
    assert!(read["schema_error"].is_null());
    let listed = body(
        client
            .get(format!("{base}/plugins?type=store"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    let row = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| artifact_file(row) == "reviewed.tar.gz")
        .unwrap();
    assert_eq!(row["has_schema"], false);
    assert!(row.get("schema_url").is_none());
    for query in [
        "source=unknown",
        "source=installed_archive&expected_archive_sha256=bad",
        "expected_archive_sha256=bad",
    ] {
        body(
            client
                .get(format!("{base}/plugins/reviewed.tar.gz/schema?{query}"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            400,
        )
        .await;
    }
    let missing = format!(
        "{base}/plugins/missing.tar.gz/schema?source=installed_archive&expected_archive_sha256={digest}"
    );
    body(
        client.get(missing).bearer_auth(TOKEN).send().await.unwrap(),
        409,
    )
    .await;
    // A structurally invalid Statement is never hidden as an absent schema.
    let invalid = schema_candidate(b"{", None);
    busbar_kernel::durable::write(&scratch.0.join("reviewed.tar.gz"), &invalid).unwrap();
    body(
        client
            .get(format!(
                "{base}/plugins/reviewed.tar.gz/schema?source=installed_archive"
            ))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        400,
    )
    .await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_configuration_inactive_signed_archives_report_declarations_without_loading_code() {
    if isolated() {
        return;
    }
    use busbar_contract::abi::mechanism::door::{
        SECTION_CONSUMED, SECTION_DECLARING, SECTION_SELECTS,
    };
    let (app, scratch) = application().await;
    let router = busbar_core_admin::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin");
    let stores = body(
        client
            .get(format!("{base}/plugins?type=store"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    let store = stores["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| artifact_file(row) == "store.tar.gz")
        .unwrap();
    let loaded = body(
        client
            .get(format!(
                "{base}/plugins/{}/schema",
                store["name"].as_str().unwrap()
            ))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(
        loaded["configuration"]["declaration_availability"],
        "present"
    );
    assert_eq!(
        loaded["configuration"]["declaration_source"],
        "loaded_manifest"
    );
    assert_eq!(
        loaded["configuration"]["root_keys"],
        store["configuration"]["root_keys"]
    );
    assert_eq!(
        loaded["configuration"]["sections"],
        store["configuration"]["sections"]
    );
    for kind in ["plane", "transport"] {
        let sections = if kind == "plane" {
            vec![
                ("fixture-root", SECTION_DECLARING),
                ("fixture-owned", SECTION_SELECTS),
                ("fixture-shared", SECTION_CONSUMED),
            ]
        } else {
            Vec::new()
        };
        let claims = if kind == "transport" {
            vec!["fixture-wire"]
        } else {
            Vec::new()
        };
        let archive = declaration_candidate(kind, b"", None, &sections, &claims);
        let digest = busbar_contract::redacted::sha256_hex(&archive);
        std::fs::write(scratch.0.join("inactive.tar.gz"), &archive).unwrap();
        body(
            client
                .get(format!("{base}/plugins/installed-schema-target/schema"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            404,
        )
        .await;
        let listed = body(
            client
                .get(format!("{base}/plugins?type={kind}"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            200,
        )
        .await;
        let row = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| artifact_file(row) == "inactive.tar.gz")
            .unwrap();
        assert_eq!(row["has_schema"], false);
        assert_eq!(row["archive_sha256"], digest);
        let metadata = &row["configuration"];
        assert_eq!(metadata["declaration_availability"], "present");
        assert_eq!(metadata["declaration_source"], "installed_archive");
        assert_eq!(metadata["input_schema_complete"], false);
        if kind == "plane" {
            assert_eq!(
                metadata["root_keys"],
                serde_json::json!(["fixture-root", "fixture-owned"])
            );
            assert_eq!(metadata["sections"][2]["consumed"], true);
        } else {
            assert_eq!(
                metadata["root_keys"],
                serde_json::json!([busbar_contract::plugin::Kind::Transport.root()])
            );
            assert_eq!(metadata["claims"], serde_json::json!(["fixture-wire"]));
        }
        let url = format!(
            "{base}/plugins/inactive.tar.gz/schema?source=installed_archive&expected_archive_sha256={digest}"
        );
        let inspected = body(
            client.get(&url).bearer_auth(TOKEN).send().await.unwrap(),
            200,
        )
        .await;
        assert_eq!(&inspected["configuration"], metadata);
        assert_eq!(inspected["schema_state"], "absent");
        // Changing the installed Statement invalidates the same archive fence, even without a schema.
        std::fs::write(
            scratch.0.join("inactive.tar.gz"),
            declaration_candidate(kind, b"", None, &[], &[]),
        )
        .unwrap();
        body(
            client.get(&url).bearer_auth(TOKEN).send().await.unwrap(),
            409,
        )
        .await;
    }
    let invalid = declaration_candidate("plane", b"", None, &[("fixture-invalid", u32::MAX)], &[]);
    let digest = busbar_contract::redacted::sha256_hex(&invalid);
    std::fs::write(scratch.0.join("inactive.tar.gz"), invalid).unwrap();
    let inspected = body(client.get(format!("{base}/plugins/inactive.tar.gz/schema?source=installed_archive&expected_archive_sha256={digest}")).bearer_auth(TOKEN).send().await.unwrap(), 200).await;
    assert_eq!(
        inspected["configuration"]["declaration_availability"],
        "unavailable"
    );
    assert_eq!(
        inspected["configuration"]["root_keys"],
        serde_json::json!([])
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_configuration_actual_linked_plane_and_transport_reads_never_call_doors() {
    if isolated() {
        return;
    }
    use busbar_contract::abi::mechanism::door::{Door, DoorFn};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static PLANE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TRANSPORT_CALLS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn plane_door() -> &'static Door {
        PLANE_CALLS.fetch_add(1, Ordering::SeqCst);
        crate::LINKED.plane_doors[0]()
    }
    extern "C" fn transport_door() -> &'static Door {
        TRANSPORT_CALLS.fetch_add(1, Ordering::SeqCst);
        (crate::LINKED_TRANSPORT_DOORS[0].1)()
    }
    static PLANES: [DoorFn; 1] = [plane_door];
    let linked = crate::root::linked::Linked {
        plane_doors: &PLANES,
        ..crate::LINKED
    };
    let transport_key = crate::LINKED_TRANSPORT_DOORS[0].0;
    crate::root::settings_public::install_with_transports(
        &linked,
        None,
        &[(transport_key, transport_door)],
    );
    let (app, _scratch) = application().await;
    let expected = crate::root::settings_public::linked_configuration();
    assert_eq!(expected.iter().filter(|row| row.kind == "plane").count(), 1);
    assert_eq!(
        expected
            .iter()
            .filter(|row| row.kind == "transport")
            .count(),
        1
    );
    let calls = (
        PLANE_CALLS.load(Ordering::SeqCst),
        TRANSPORT_CALLS.load(Ordering::SeqCst),
    );
    assert!(calls.0 > 0 && calls.1 > 0);
    let router = busbar_core_admin::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin");
    for declared in expected {
        let listed = body(
            client
                .get(format!("{base}/plugins?type={}", declared.kind))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            200,
        )
        .await;
        let rows: Vec<_> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["loader"] == "compiled-in" && row["name"] == declared.name)
            .collect();
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(row["version"], declared.version);
        assert_eq!(
            row["configuration"]["declaration_source"],
            "linked_statement"
        );
        assert_eq!(row["configuration"]["declaration_availability"], "present");
        let url = format!(
            "{base}/plugins/{}/schema?source=linked_statement",
            declared.name
        );
        let read = body(
            client.get(&url).bearer_auth(TOKEN).send().await.unwrap(),
            200,
        )
        .await;
        assert_eq!(read["configuration"], row["configuration"]);
        assert_eq!(read["source"], "statement");
        let facts = declared.configuration.unwrap();
        if declared.kind == "transport" {
            assert_eq!(
                row["configuration"]["claims"],
                serde_json::json!(facts.claims)
            );
            assert_eq!(
                row["configuration"]["root_keys"],
                serde_json::json!([busbar_contract::Kind::Transport.root()])
            );
        } else {
            use busbar_contract::abi::mechanism::door::{SECTION_CONSUMED, SECTION_DECLARING};
            let roots: Vec<_> = facts
                .sections
                .iter()
                .filter(|(_, flags)| {
                    flags & SECTION_DECLARING != 0 || flags & SECTION_CONSUMED == 0
                })
                .map(|(name, _)| name)
                .collect();
            assert_eq!(row["configuration"]["root_keys"], serde_json::json!(roots));
            assert!(!roots.is_empty());
        }
        if let Some(url) = row["schema_url"].as_str() {
            assert!(url.ends_with("?source=linked_statement"));
        }
        body(
            client
                .get(format!("{url}&expected_archive_sha256={}", "0".repeat(64)))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap(),
            400,
        )
        .await;
    }
    assert_eq!(
        (
            PLANE_CALLS.load(Ordering::SeqCst),
            TRANSPORT_CALLS.load(Ordering::SeqCst)
        ),
        calls
    );
    server.abort();
}

// Decode the archive listing's field schema; the field name is not a provider selector.
fn artifact_file(row: &serde_json::Value) -> &str {
    #[derive(serde::Deserialize)]
    struct Artifact<'a> {
        file: &'a str,
    }
    <Artifact<'_> as serde::Deserialize>::deserialize(row)
        .expect("the archive listing supplies its file field")
        .file
}
