// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVED ADMIN SURFACE, RECONCILED — against the oracle's admin corpus (item 44) and against
//! the one generated OpenAPI document (items 45/46).
//!
//! The admin corpus (`testing/shadow-oracle/fixtures/admin-bodies.json`, enumerated into the
//! `admin.ops` family of `cells.json`) was a fixture frozen at the 1.5.5 operation set, and nothing
//! compared it with what the node serves: every operation 1.6.0 added had zero cells and no
//! mechanism that could give it one. The OpenAPI document had the same blindness from the other
//! side — 26 served verbs were in no document, and five more in a side-car one kept so the served
//! bytes need not move.
//!
//! Both now answer to ONE list: [`served_admin_operations`], built from the three sources the
//! administrative listener actually mounts from —
//!
//! 1. the closed verb table (`admin_codec::verbs::table`): every `(method, path)` the node's
//!    administrative mount walks through the kernel loop, which is how the 66 legacy operations and
//!    the 26 1.6.0 kernel verbs are answered;
//! 2. every named-definition section (`NamedMapSection::sections`), five operations each, which the
//!    router mounts in one loop — including each plane-owned section;
//! 3. every plane's admin trust verbs (`PlaneDecl::admin_routes`), which the router mounts in one
//!    loop too.
//!
//! and the router half of it is checked LIVE: every operation this crate's router is responsible
//! for is asked, over a real listener, and must answer something other than the router's own
//! unmatched-path fallback.

use std::collections::{BTreeMap, BTreeSet};

use busbar_kernel::admin::v1::contract::ADMIN_PREFIX;
use busbar_kernel::config::named_map::NamedMapSection;

/// One served operation: the upper-case HTTP method and the absolute, `{param}`-templated path.
type Op = (String, String);

/// Where an operation comes from — which decides who answers it and whether it is always present.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// A closed-table row the node's administrative loop answers itself (a 1.6.0 kernel verb).
    KernelLoop,
    /// A row this crate's router answers on every node (the 66 legacy operations, the core
    /// named-definition sections).
    Router,
    /// A plane's section or trust verb: mounted only when the plane is configured.
    Plane(&'static str),
}

/// The absolute admin path for a relative one.
fn abs(rel: &str) -> String {
    format!("{ADMIN_PREFIX}{rel}")
}

/// EVERY ADMIN OPERATION THIS BUILD CAN SERVE, and who serves it. See the module doc for the three
/// sources and why they are the complete set.
fn served_admin_operations() -> BTreeMap<Op, Source> {
    crate::ensure_seam();
    let mut out = BTreeMap::new();
    let loop_verbs: BTreeSet<&'static str> = crate::verb::NEW_VERBS
        .iter()
        .chain(crate::verb::LEDGER_VERBS)
        .chain(crate::verb::AUDIT_VERBS)
        .filter_map(|v| crate::verb::verb_name(*v))
        .collect();
    for row in crate::admin_codec::verbs::table() {
        let source = if loop_verbs.contains(row.verb) {
            Source::KernelLoop
        } else {
            Source::Router
        };
        out.insert((row.method.to_string(), row.template.to_string()), source);
    }
    for section in NamedMapSection::sections() {
        let source = match section {
            NamedMapSection::Plane(key) => Source::Plane(key),
            _ => Source::Router,
        };
        let root = abs(section.path_root().as_ref());
        let item = format!("{root}/{{name}}");
        for op in [
            ("GET", root.clone()),
            ("GET", item.clone()),
            ("PUT", item.clone()),
            ("DELETE", item.clone()),
            ("PATCH", format!("{item}/settings")),
        ] {
            out.entry((op.0.to_string(), op.1))
                .or_insert_with(|| source.clone());
        }
    }
    for decl in busbar_kernel::plane::registry::plane_decls() {
        let Some(admin_routes) = decl.admin_routes else {
            continue;
        };
        for spec in admin_routes(&() as &dyn std::any::Any) {
            let method = serde_json::to_value(spec.method)
                .ok()
                .and_then(|m| m.as_str().map(str::to_string))
                .expect("a route method serializes as its upper-case token");
            out.insert(
                (method, abs(&spec.path)),
                Source::Plane(decl.config_section),
            );
        }
    }
    out
}

/// `METHOD + path -> PascalCase` — the operation-id scheme the admin corpus keys its operations by
/// (the 1.5.5 document's own `operationId`s), reproduced independently of the document generator.
fn op_id(method: &str, path: &str) -> String {
    fn cap(s: &str) -> String {
        let mut c = s.chars();
        match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
            None => String::new(),
        }
    }
    let mut id = cap(method);
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        let seg = seg.trim_matches(|c| c == '{' || c == '}');
        for word in seg.split(|c: char| !c.is_ascii_alphanumeric()) {
            if !word.is_empty() {
                id.push_str(&cap(word));
            }
        }
    }
    id
}

/// Whether a concrete request path (query cut) is an instance of a `{param}`-templated one.
fn instance_of(template: &str, concrete: &str) -> bool {
    let concrete = concrete.split(['?', '#']).next().unwrap_or(concrete);
    let (t, c): (Vec<&str>, Vec<&str>) =
        (template.split('/').collect(), concrete.split('/').collect());
    t.len() == c.len()
        && t.iter()
            .zip(&c)
            .all(|(t, c)| (t.starts_with('{') && t.ends_with('}') && !c.is_empty()) || t == c)
}

/// The oracle's data directory.
fn oracle_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle")
}

fn read_json(path: std::path::PathBuf) -> serde_json::Value {
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Build a governance with a known admin token (the shape the moved admin e2e tests use).
fn gov(admin_token: &str) -> std::sync::Arc<busbar_kernel::governance::GovState> {
    std::sync::Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(
            std::sync::Arc::new(busbar_kernel::governance::MemoryStore::new()),
            Some(admin_token.to_string()),
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("governance"),
    )
}

/// ITEM 44 — THE ADMIN CORPUS IS RECONCILED AGAINST THE SERVED ROUTER.
///
/// Fails when a served operation has no corpus entry or no `admin.ops` cell, and when a corpus
/// entry or an `admin.ops` cell names an operation the build does not serve. The router half of the
/// served list is asked live first, so "served" is a measurement of the router and not a second
/// copy of a list.
#[tokio::test]
async fn admin_corpus_reconciles_with_the_served_router() {
    busbar_kernel::metrics::init();
    let served = served_admin_operations();

    // ── the router half, asked live ──
    const TOKEN: &str = "served-surface-token";
    let app = crate::new_test_app().governance(gov(TOKEN)).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let ask = |method: &str, path: &str| {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let req = client
            .request(method.clone(), format!("http://{addr}{path}"))
            .header("x-admin-token", TOKEN);
        // A deliberately unparseable body on every write: a served handler refuses it before it
        // touches anything, and an unserved path answers its fallback either way.
        let req = if method == reqwest::Method::GET {
            req
        } else {
            req.header("content-type", "application/json").body("{")
        };
        async move {
            let resp = req.send().await.unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };
    let fallback_for = |method: &str| {
        let method = method.to_string();
        let ask = &ask;
        async move { ask(&method, &abs("/no-such-admin-route/served-surface")).await }
    };
    // CONTROL: the fallback is a 404 not_found — so "differs from the fallback" is not vacuous.
    let (control_status, _) = fallback_for("GET").await;
    assert_eq!(
        control_status, 404,
        "the unmatched-path control must be the router's 404"
    );
    let mut router_ops = 0usize;
    for ((method, path), source) in &served {
        if *source != Source::Router {
            continue;
        }
        let concrete = path
            .split('/')
            .map(|seg| {
                if seg.starts_with('{') {
                    "served-surface-probe"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        let answer = ask(method, &concrete).await;
        let fallback = fallback_for(method).await;
        assert_ne!(
            answer, fallback,
            "{method} {path} is in the served list but the router answers it with its \
             unmatched-path fallback: nothing serves it"
        );
        assert_ne!(
            answer.0, 405,
            "{method} {path}: the router has the path but not this method"
        );
        router_ops += 1;
    }
    assert!(
        router_ops >= 66,
        "only {router_ops} router operations were probed"
    );
    handle.abort();

    // ── the corpus source: one entry per served operation, nothing else ──
    let fixture = read_json(oracle_dir().join("fixtures/admin-bodies.json"));
    let ops = fixture["ops"]
        .as_object()
        .expect("admin-bodies.json `ops` object");
    let mut entries: BTreeMap<Op, String> = BTreeMap::new();
    for (id, op) in ops {
        let method = op["method"].as_str().expect("method").to_string();
        let path = op["path"].as_str().expect("path").to_string();
        assert_eq!(
            *id,
            op_id(&method, &path),
            "admin-bodies.json entry {id} is keyed under a name that is not its operation's"
        );
        entries.insert((method, path), id.clone());
    }
    let unserved: Vec<&Op> = entries
        .keys()
        .filter(|op| !served.contains_key(*op))
        .collect();
    assert!(
        unserved.is_empty(),
        "admin-bodies.json names operations this build does not serve: {unserved:?}"
    );
    let uncorpused: Vec<&Op> = served
        .keys()
        .filter(|op| !entries.contains_key(*op))
        .collect();
    assert!(
        uncorpused.is_empty(),
        "served operations with NO admin-bodies.json entry (so no oracle cell can exist): \
         {uncorpused:?}"
    );

    // ── the corpus itself: every served operation has a cell, every cell a served operation ──
    let corpus = read_json(oracle_dir().join("cells.json"));
    let by_id: BTreeMap<&str, &Op> = entries.iter().map(|(op, id)| (id.as_str(), op)).collect();
    let mut celled: BTreeSet<&str> = BTreeSet::new();
    for cell in corpus["cells"].as_array().expect("cells array") {
        if cell["family"] != "admin.ops" {
            continue;
        }
        let id = cell["id"].as_str().expect("cell id");
        let op_name = id.split('|').nth(1).expect("admin.ops|<op>|<variant>");
        // The teller-row cells ride this family to exercise the admin TOKEN on the data plane;
        // they name a credential, not an admin operation.
        if op_name == "admin-token" {
            continue;
        }
        let (method, template) = by_id.get(op_name).unwrap_or_else(|| {
            panic!("cell {id} names {op_name}, which is not a served admin operation")
        });
        let request = &cell["request"];
        assert_eq!(
            request["method"].as_str(),
            Some(method.as_str()),
            "cell {id} does not call its operation's method"
        );
        let concrete = request["path"].as_str().expect("request path");
        assert!(
            instance_of(template, concrete),
            "cell {id} calls {concrete}, which is not an instance of {template}"
        );
        celled.insert(op_name);
    }
    let cell_less: Vec<&str> = by_id
        .keys()
        .filter(|id| !celled.contains(*id))
        .copied()
        .collect();
    assert!(
        cell_less.is_empty(),
        "served operations with NO admin.ops cell in cells.json (regenerate the corpus from \
         admin-bodies.json): {cell_less:?}"
    );
}

/// ITEMS 45/46 — EVERY SERVED VERB IS IN THE ONE SPEC, AND THERE IS ONLY ONE SPEC.
///
/// The generated document describes exactly the served list: no served operation missing, no
/// documented operation unserved. A plane's operations carry `x-busbar-plane: <section>` (they are
/// mounted only when that plane is configured) and nothing else does; the kernel loop's operations
/// carry `x-busbar-since: 1.6.0`. And the side-car document, which existed so the served bytes need
/// not move, is gone — this test is the behaviour that replaced it.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_documents_every_served_admin_operation() {
    let served = served_admin_operations();
    let doc = super::openapi_doc_seamed();
    let mut documented: BTreeMap<Op, &serde_json::Value> = BTreeMap::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (method, op) in item.as_object().expect("path item") {
            if method.starts_with("x-") {
                continue;
            }
            documented.insert((method.to_ascii_uppercase(), path.clone()), op);
        }
    }
    let undocumented: Vec<&Op> = served
        .keys()
        .filter(|op| !documented.contains_key(*op))
        .collect();
    assert!(
        undocumented.is_empty(),
        "served admin operations in NO OpenAPI document: {undocumented:?}"
    );
    let phantom: Vec<&Op> = documented
        .keys()
        .filter(|op| !served.contains_key(*op))
        .collect();
    assert!(
        phantom.is_empty(),
        "documented admin operations this build does not serve: {phantom:?}"
    );
    for (op, source) in &served {
        let doc_op = documented[op];
        let plane = doc_op["x-busbar-plane"].as_str();
        match source {
            Source::Plane(section) => assert_eq!(
                plane,
                Some(*section),
                "{op:?} is mounted only when `{section}:` is configured and must say so"
            ),
            _ => assert_eq!(
                plane, None,
                "{op:?} is served on every node but is marked {plane:?}"
            ),
        }
        assert_eq!(
            doc_op["x-busbar-since"].as_str() == Some("1.6.0"),
            *source == Source::KernelLoop,
            "{op:?}: `x-busbar-since: 1.6.0` marks exactly the kernel loop's operations"
        );
    }
    let side_car = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/openapi-1.6.0-additive.json");
    assert!(
        !side_car.exists(),
        "{} exists: there is ONE administrative OpenAPI document, generated from the code",
        side_car.display()
    );
}

/// Serve one app's `GET /openapi.json` (identity encoding) and parse it.
async fn served_openapi(app: std::sync::Arc<busbar_kernel::state::App>) -> serde_json::Value {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{}", abs("/openapi.json")))
        .header("x-admin-token", "served-openapi-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the node serves its document");
    let doc = resp.json().await.unwrap();
    handle.abort();
    doc
}

/// LAW 7 ON THE SERVED DOCUMENT. The committed document describes every operation the build can
/// serve; a node serves it FILTERED to the planes it configured.
///
/// With a 1.5.5 config (no plane section) the served document names no `tools`/`agents` path, and
/// its paths are exactly the published 1.5.5 golden's (the recorded `admin.ops|GetOpenapiJson|ok`
/// cell) plus the node's always-served 1.6.0 kernel verbs — nothing a 1.5.5 config does not mount.
/// With `tools:` configured, the `tools` operations are described again and the `agents` ones are
/// still not.
#[tokio::test]
async fn served_openapi_lists_only_the_configured_planes() {
    busbar_kernel::metrics::init();
    let served = served_admin_operations();
    let plane_paths = |doc: &serde_json::Value, section: &str| -> Vec<String> {
        let root = abs(&format!("/{section}"));
        doc["paths"]
            .as_object()
            .expect("paths")
            .keys()
            .filter(|p| **p == root || p.starts_with(&format!("{root}/")))
            .cloned()
            .collect()
    };

    // ── a 1.5.5 config: no plane section at all ──
    let app = crate::new_test_app()
        .governance(gov("served-openapi-token"))
        .plane_sections(&[])
        .build();
    let doc = served_openapi(app).await;
    for section in ["tools", "agents"] {
        let leaked = plane_paths(&doc, section);
        assert!(
            leaked.is_empty(),
            "a node with no `{section}:` section serves a document describing {leaked:?}"
        );
    }
    let golden =
        read_json(oracle_dir().join("golden/1.5.5/cells/admin.ops__GetOpenapiJson__ok.json"));
    let mut expected: BTreeSet<String> = golden["body"]["json"]["paths"]
        .as_object()
        .expect("the 1.5.5 golden document's paths")
        .keys()
        .cloned()
        .collect();
    expected.extend(
        served
            .iter()
            .filter(|(_, source)| **source == Source::KernelLoop)
            .map(|((_, path), _)| path.clone()),
    );
    let got: BTreeSet<String> = doc["paths"]
        .as_object()
        .expect("paths")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        got, expected,
        "with a 1.5.5 config the served document must describe the 1.5.5 surface plus the \
         always-served kernel verbs, and nothing else"
    );
    // No component survives that only a dropped plane operation referenced.
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    for plane_only in ["McpTrustView", "A2aTrustView"] {
        assert!(
            !schemas.contains_key(plane_only),
            "{plane_only} is referenced only by unconfigured plane operations and was served"
        );
    }

    // ── `tools:` configured, `agents:` not ──
    let app = crate::new_test_app()
        .governance(gov("served-openapi-token"))
        .plane_sections(&["tools"])
        .build();
    let doc = served_openapi(app).await;
    assert!(
        !plane_paths(&doc, "tools").is_empty(),
        "a node that configured `tools:` must describe the tools operations"
    );
    assert!(
        plane_paths(&doc, "agents").is_empty(),
        "a node that did not configure `agents:` must not describe the agents operations"
    );
}
