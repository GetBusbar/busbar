// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: secret`, `kind: auth`, `kind: store` AND `kind: hook`, PROVEN BY REAL PLUGINS.** The owner
//! deleted the in-tree fixtures ("these are trash … real plugins are the examples",
//! `docs/design/1.6.0-QUESTIONS.md` "FIXTURES"): the proofs of these kinds are the real plugin repos —
//! `GetBusbar/busbar-secret-vault` (secret), `GetBusbar/busbar-auth-github` (auth), and, per the R-FIX2 ruling
//! (dropped-in door proofs use REAL plugins), `GetBusbar/busbar-store-sqlite` (store: a durable file, a
//! restart, two nodes on one file) and `GetBusbar/busbar-hook-webrequest` (hook: reject, restrict and a slow
//! upstream, against a local mock upstream).
//!
//! ci.yml's `plugin-proofs` job checks hashicorp-vault and auth-github out beside this one at `dev`,
//! `[patch]`es the busbar crates they name by git (busbar-contract, and busbar-plugin-loader
//! dev-only) to this tree through cargo config, and builds their `cdylib`s; it checks store-sqlite
//! and webrequest-hook out at the revs it pins and builds their `cdylib`s `--locked`
//! against their own busbar pin (the artifact each repo ships). It runs these tests with `BUSBAR_PLUGIN_PROOF_DIR`
//! naming the directory the `cdylib`s were built into. Each test takes the REAL artifact through the
//! DROPPED-IN door ([`super::both_ways::dropped`]: signed first-party into a fresh `plugins/`,
//! found by [`crate::scan_and_validate`], opened by the registry's own `open_*`) and asserts:
//!
//! * the KIND HANDSHAKE — the row resolves, and the library opens as the kind it exports;
//! * REAL OPERATIONS — the plugin's own code runs over the ABI and answers what only it would;
//! * the RED ARMS — the same bytes signed as ANOTHER kind are refused at the handshake, naming both
//!   kinds, and a bad config is refused with the plugin's own words.
//!
//! The artifact names and the plugin-specific expectations are DATA
//! (`tests/fixtures/plugin_artifacts.txt`, `proof_*` rows): the loader names no plugin instance.
//!
//! `#[ignore]`d: a local `cargo test` has no plugin repos beside it. With `--ignored` and no
//! `BUSBAR_PLUGIN_PROOF_DIR`, each test FAILS naming the variable — a proof that was asked for never
//! passes by finding nothing.

use super::both_ways::{dropped, statement};
use crate::tests::{
    artifact, call_record, event_record, n_get_task, n_list_call_principals, n_list_calls,
    n_list_task_events, n_list_tasks, sample_task_row, task_record, SampleCall, SampleEvent,
};
use busbar_contract::auth::{BeginLogin, LoginOutcome};

/// The environment variable naming the directory the real plugins' `cdylib`s were built into.
const PROOF_DIR: &str = "BUSBAR_PLUGIN_PROOF_DIR";

/// The REAL `cdylib` bytes for the `proof_<kind>_cdylib` row, from [`PROOF_DIR`].
fn real_cdylib(kind: &str) -> Vec<u8> {
    let dir = std::env::var_os(PROOF_DIR).unwrap_or_else(|| {
        panic!(
            "{PROOF_DIR} is not set: these proofs dlopen the REAL {kind} plugin's cdylib and must \
             be pointed at the directory it was built into (ci.yml `plugin-proofs`)"
        )
    });
    let path = std::path::Path::new(&dir).join(crate::plugin_library_filename(artifact(&format!(
        "proof_{kind}_cdylib"
    ))));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("the real {kind} plugin is not at {}: {e}", path.display()))
}

/// The manifest the real `kind` plugin is signed under, at the newest payload schema this loader
/// speaks for `as_kind`.
fn manifest(as_kind: &str, name: &str) -> crate::sign::Manifest {
    let abi = *crate::supported_abi(as_kind)
        .iter()
        .max()
        .expect("a payload schema for the kind");
    statement(as_kind, name, name, abi)
}

/// `open`'s error, or a panic naming what opened when it must not have.
fn refused<T>(what: &str, r: Result<T, String>) -> String {
    match r {
        Ok(_) => panic!("{what} opened; it must be refused"),
        Err(e) => e,
    }
}

/// SECRET: the real secret plugin, dropped in, resolves a reference by doing its own work — it
/// addresses the backend it was configured with and reports that backend unreachable — and the RED
/// arms refuse it as the wrong kind and without config.
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn the_real_secret_plugin_resolves_through_the_dropped_in_door() {
    let lib = real_cdylib("secret");
    let registry = dropped("proof-secret", manifest("secret", "proof-secret"), &lib);

    // The kind handshake: the row resolves, and the library opens as the kind it exports.
    let module = registry
        .open_secret("proof-secret", artifact("proof_secret_config"))
        .expect("the real secret plugin opens as `secret`");

    // One real operation: the plugin parses the reference and goes to its backend.
    let mut settings = serde_json::Map::new();
    settings.insert(
        "path".into(),
        serde_json::Value::String(artifact("proof_secret_reference").into()),
    );
    let err = module
        .resolve(&settings)
        .expect_err("the configured backend is unreachable, so the reference cannot resolve");
    let want = artifact("proof_secret_resolve_error");
    assert!(
        err.to_string().contains(want),
        "the plugin's own resolve must address its configured backend (`{want}`): {err}"
    );

    // RED: an empty config is refused in the plugin's own words.
    let e = refused(
        "the secret plugin with no config",
        registry.open_secret("proof-secret", ""),
    );
    let want = artifact("proof_secret_refusal");
    assert!(e.contains(want), "want `{want}`: {e}");

    // RED: the same bytes signed as `auth` are refused at the kind handshake, naming both kinds.
    let wrong = dropped(
        "proof-secret-as-auth",
        manifest("auth", "proof-secret-as-auth"),
        &lib,
    );
    let e = refused(
        "a secret library signed as auth",
        wrong.open_auth("proof-secret-as-auth", artifact("proof_secret_config")),
    );
    assert!(
        e.contains(
            "plugin 'proof-secret-as-auth' exports kind 'secret' but is being loaded as 'auth'"
        ),
        "{e}"
    );
}

/// AUTH: the real auth plugin, dropped in, starts a browser login by building its IdP's authorize
/// URL from the core-minted state and PKCE challenge — and the RED arms refuse it as the wrong kind
/// and without config.
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn the_real_auth_plugin_begins_a_login_through_the_dropped_in_door() {
    let lib = real_cdylib("auth");
    let registry = dropped("proof-auth", manifest("auth", "proof-auth"), &lib);

    // The kind handshake: the row resolves, and the library opens as the kind it exports, at the
    // payload schema it was signed under.
    let (module, abi) = registry
        .open_login("proof-auth", artifact("proof_auth_config"))
        .expect("the real auth plugin opens as `auth`");
    assert_eq!(
        abi,
        *crate::supported_abi("auth").iter().max().unwrap(),
        "the row carries the schema it was signed under"
    );

    // One real operation: `begin_login` builds the IdP authorize URL from what the core minted.
    let outcome = module.begin_login(&BeginLogin {
        redirect_uri: artifact("proof_auth_redirect_uri").into(),
        state: "proof-state".into(),
        code_challenge: "proof-challenge".into(),
        nonce: None,
        scopes: Vec::new(),
    });
    let LoginOutcome::Authorize(url) = outcome else {
        panic!("a redirect login module must answer Authorize: {outcome:?}");
    };
    let want = artifact("proof_auth_authorize_prefix");
    assert!(url.starts_with(want), "want prefix `{want}`: {url}");
    assert!(
        url.contains(
            "&state=proof-state&code_challenge=proof-challenge&code_challenge_method=S256"
        ),
        "the core-minted state and PKCE challenge ride the URL: {url}"
    );

    // RED: an empty config is refused in the plugin's own words.
    let e = refused(
        "the auth plugin with no config",
        registry.open_login("proof-auth", "").map(|_| ()),
    );
    let want = artifact("proof_auth_refusal");
    assert!(e.contains(want), "want `{want}`: {e}");

    // RED: the same bytes signed as `secret` are refused at the kind handshake, naming both kinds.
    let wrong = dropped(
        "proof-auth-as-secret",
        manifest("secret", "proof-auth-as-secret"),
        &lib,
    );
    let e = refused(
        "an auth library signed as secret",
        wrong.open_secret("proof-auth-as-secret", artifact("proof_auth_config")),
    );
    assert!(
        e.contains(
            "plugin 'proof-auth-as-secret' exports kind 'auth' but is being loaded as 'secret'"
        ),
        "{e}"
    );
}

// ── `kind: store` — the REAL durable store (GetBusbar/busbar-store-sqlite), R-FIX2 ─────────────────────────

/// A fresh scratch directory for one proof, unique to this process and `tag`.
fn proof_scratch(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("busbar-plugin-proof-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the proof's scratch directory");
    dir
}

/// The real store's configuration naming `file` as its durable file (the key is DATA:
/// `proof_store_path_key`).
fn store_config(file: &std::path::Path) -> String {
    let mut cfg = serde_json::Map::new();
    cfg.insert(
        artifact("proof_store_path_key").into(),
        serde_json::Value::String(file.display().to_string()),
    );
    serde_json::Value::Object(cfg).to_string()
}

/// One plane record of `kind` (the store never decodes `body`).
fn plane_record(
    kind: &str,
    id: &str,
    parent: Option<&str>,
    seq: u64,
    body: &[u8],
) -> busbar_contract::records::PlaneRecord {
    busbar_contract::records::PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(Into::into),
        seq,
        ts: 1_000 + seq,
        disposition: busbar_contract::records::PlaneDisposition::Active,
        body: body.to_vec(),
    }
}

/// What a store holds for the proof's records, as one comparable value.
fn store_holdings(store: &dyn busbar_contract::records::RecordStore) -> serde_json::Value {
    use busbar_contract::records::PlaneSelector;
    let text = |b: Vec<u8>| String::from_utf8(b).expect("the proof wrote utf-8 bodies");
    serde_json::json!({
        "task": store.get_plane_record("task", "t-1").expect("get task").map(text),
        "calls": store
            .list_plane_records("call", &PlaneSelector::Parent("p-1".into()))
            .expect("list calls")
            .into_iter()
            .map(text)
            .collect::<Vec<_>>(),
        "parents": store.list_plane_record_parents("call").expect("list parents"),
    })
}

/// STORE — THE RESTART: the real durable store, dropped in, keeps what it was handed across a
/// restart. The first instance writes a task and a three-link call chain and is closed; a FRESH
/// scan and a fresh `open` (the only source of state left is the file the operator named) reads
/// every record back. RED arms: the same bytes opened on ANOTHER file hold nothing (the state is the
/// file's, not the process's), a config naming the file with the wrong JSON type is refused in the
/// plugin's own words, and the bytes signed as `hook` are refused at the kind handshake.
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn the_real_store_plugin_keeps_its_records_across_a_restart_through_the_dropped_in_door() {
    let lib = real_cdylib("store");
    let dir = proof_scratch("store-restart");
    let cfg = store_config(&dir.join("governance.db"));

    // BEFORE THE RESTART: write through the dropped-in door, then close (drop) the instance.
    {
        let registry = dropped("proof-store-a", manifest("store", "proof-store"), &lib);
        let store = registry
            .open_store("proof-store", &cfg)
            .expect("the real store plugin opens as `store`");
        store
            .upsert_plane_record(&plane_record("task", "t-1", None, 0, b"task one"))
            .expect("upsert the task");
        for seq in 0..3 {
            store
                .append_plane_record(&plane_record(
                    "call",
                    &format!("c-{seq}"),
                    Some("p-1"),
                    seq,
                    format!("call {seq}").as_bytes(),
                ))
                .expect("append a call");
        }
    }

    // THE RESTART: a fresh scan, a fresh load, a fresh `open` on the same file.
    let registry = dropped("proof-store-b", manifest("store", "proof-store"), &lib);
    let store = registry
        .open_store("proof-store", &cfg)
        .expect("the real store plugin re-opens after the restart");
    assert_eq!(
        store_holdings(store.as_ref()),
        serde_json::json!({
            "task": "task one",
            "calls": ["call 0", "call 1", "call 2"],
            "parents": ["p-1"],
        }),
        "every record written before the restart must be read back after it"
    );

    // RED: the same bytes on ANOTHER file hold nothing — what survived lives in the named file.
    let other = registry
        .open_store("proof-store", &store_config(&dir.join("other.db")))
        .expect("the real store plugin opens a second file");
    assert_eq!(
        store_holdings(other.as_ref()),
        serde_json::json!({"task": null, "calls": [], "parents": []}),
    );

    // RED: the durable file named with the wrong JSON type is refused in the plugin's own words.
    let bad = format!(r#"{{"{}": 5}}"#, artifact("proof_store_path_key"));
    let e = refused(
        "the store plugin with a non-string path",
        registry.open_store("proof-store", &bad),
    );
    let want = artifact("proof_store_refusal");
    assert!(e.contains(want), "want `{want}`: {e}");

    // RED: the same bytes signed as `hook` are refused at the kind handshake, naming both kinds.
    let wrong = dropped(
        "proof-store-as-hook",
        manifest("hook", "proof-store-as-hook"),
        &lib,
    );
    let e = match wrong.open_hook(
        "proof-store-as-hook",
        &cfg,
        "proof-store-as-hook",
        hook_projectors(),
    ) {
        Ok(_) => panic!("a store library signed as hook opened; it must be refused"),
        Err(e) => e,
    };
    assert!(
        e.contains(
            "plugin 'proof-store-as-hook' exports kind 'store' but is being loaded as 'hook'"
        ),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The environment variable that turns [`store_proof_second_node`] into the second writer of
/// [`the_real_store_plugin_loses_no_record_across_two_nodes_on_one_file`]: the durable file's path.
const SECOND_NODE: &str = "BUSBAR_PLUGIN_PROOF_STORE_SECOND_NODE";

/// Records each node appends to the shared chain in the two-node proof.
const PER_NODE: u64 = 200;

/// THE TASK-STATE RESTART, over the real durable store. Load the store as a PLUGIN, write a task (plus its provenance chain and an MCP call
/// record), then RESTART the plugin — drop the handle, unload the library, `dlopen` it again and
/// `busbar_open` a fresh instance whose only possible source of state is the bytes on disk — and
/// read everything back over the same ABI.
///
/// Against the ABI as it stood before the ten variants were added this fails at the first
/// assertion: `get_task` returns `None`, because `DynStore` never sent the write anywhere.
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn task_state_written_through_a_plugin_store_survives_a_restart() {
    // The REAL durable store (GetBusbar/busbar-store-sqlite), dropped in, on a private file of this test's
    // own: `open` is handed that file, the only place a restarted instance can find the rows.
    let lib = real_cdylib("store");
    let dir = proof_scratch("task-durability");
    let cfg = store_config(&dir.join("governance.db"));
    let load = |tag: &str| {
        dropped(tag, manifest("store", "proof-store"), &lib)
            .open_store("proof-store", &cfg)
            .expect("the real store plugin opens as `store`")
    };

    let task = sample_task_row("task-abc", "input-required", 2_000);
    let event = SampleEvent {
        task_id: "task-abc".into(),
        seq: 1,
        ts: 1_500,
        kind: "task.submitted".into(),
        context_id: "ctx-42".into(),
        principal: "vk_owner".into(),
        agent_id: "agent-7".into(),
        state: "submitted".into(),
        request_id: "req-9".into(),
        prev_hash: String::new(),
        hash: "deadbeef".into(),
    };
    let call = SampleCall {
        principal: "vk_owner".into(),
        seq: 1,
        ts: 1_600,
        server: "srv".into(),
        tool: "srv_echo".into(),
        outcome: "dispatched".into(),
        reason: String::new(),
        tool_digest: "sha256:aaa".into(),
        pin_generation: 4,
        request_id: "req-9".into(),
        prev_hash: String::new(),
        hash: "cafebabe".into(),
    };

    // ── BEFORE THE RESTART: write through the plugin, and assert NOTHING ──────────────────────
    //
    // Deliberately no read-back here. The failure this test exists to show is the one AFTER the
    // restart, and an assertion in this block would fire first and report a same-process symptom
    // instead — which is exactly what happened on the first red run. The same-handle round trip is
    // its own test below, so that diagnostic is not lost, it just does not pre-empt this one.
    {
        let store = load("task-durability-a");
        store
            .upsert_plane_record(&task_record(&task))
            .expect("upsert task");
        store
            .append_plane_record(&event_record(&event))
            .expect("append task_event");
        store
            .append_plane_record(&call_record(&call))
            .expect("append call");
        // Dropping the box closes the plugin handle and unloads the library. Everything the plugin
        // held in memory goes with it.
    }

    // ── THE RESTART: a fresh dlopen and a fresh `busbar_open` ─────────────────────────────────
    let store = load("task-durability-b");

    assert_eq!(
        n_get_task(store.as_ref(), "task-abc").expect("get_task after restart"),
        Some(task.clone()),
        "THE WHOLE POINT: a task written through the plugin ABI must still be there after a \
         restart. `None` here is the production defect — `put_task` reported success and the \
         engine kept nothing."
    );
    assert_eq!(
        n_list_tasks(store.as_ref()).expect("list_tasks after restart"),
        vec![task.clone()]
    );
    assert_eq!(
        n_list_task_events(store.as_ref(), "task-abc").expect("list_task_events after restart"),
        vec![event],
        "the provenance chain must survive with `hash`/`prev_hash` verbatim"
    );
    assert_eq!(
        n_list_calls(store.as_ref(), "vk_owner").expect("list_calls after restart"),
        vec![call]
    );
    assert_eq!(
        n_list_call_principals(store.as_ref()).expect("list_call_principals after restart"),
        vec!["vk_owner".to_string()],
        "the boot enumeration must find the principal whose chain this process never saw written"
    );

    // ── retention over the plugin RPC: the ops route and their COUNT comes from the plugin, not a
    // defaulted `Ok(0)` no-op. This exercises the AGE axis — the `kind: call` "drop all older"
    // contract — against a row whose `ts` reached the plugin over the wire. Both retention axes and
    // the sidecar that carries them are pinned directly in `plane_sidecar_tests`; this test's unique
    // job is the DLOPEN-RESTART round trip of the durable body/identity, which the assertions above
    // have already proven.
    let call_purged = store
        .purge_plane_records_before("call", 2_000)
        .expect("purge_calls_before");
    assert_eq!(
        call_purged, 1,
        "the `call` retention op drops the older row and the count comes from the plugin, not a default"
    );

    // The purge is durable too: a third open sees the compacted state — the call chain is gone, the
    // still-open `input-required` task survives (a `task` row is never age-collected while non-terminal).
    drop(store);
    let store = load("task-durability-c");
    assert_eq!(
        n_list_tasks(store.as_ref()).expect("list_tasks"),
        vec![task.clone()],
        "the purge must have been written through, not just applied in the plugin's memory"
    );
    assert!(n_list_calls(store.as_ref(), "vk_owner")
        .expect("list_calls")
        .is_empty());

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Append `seqs` to the proof's `call` chain on `file`, through the real store dropped in.
fn append_chain(file: &std::path::Path, tag: &str, seqs: std::ops::Range<u64>) {
    let registry = dropped(tag, manifest("store", "proof-store"), &real_cdylib("store"));
    let store = registry
        .open_store("proof-store", &store_config(file))
        .expect("the real store plugin opens");
    for seq in seqs {
        store
            .append_plane_record(&plane_record(
                "call",
                &format!("c-{seq}"),
                Some("p-1"),
                seq,
                seq.to_string().as_bytes(),
            ))
            .expect("append through this node");
    }
}

/// THE SECOND NODE of the two-node proof: run as a child process by that proof (with [`SECOND_NODE`]
/// naming the shared file); on its own it does nothing.
#[test]
#[ignore = "the second node of the_real_store_plugin_loses_no_record_across_two_nodes_on_one_file"]
fn store_proof_second_node() {
    if let Some(file) = std::env::var_os(SECOND_NODE) {
        append_chain(
            std::path::Path::new(&file),
            "proof-store-node-2",
            PER_NODE..2 * PER_NODE,
        );
    }
}

/// STORE — TWO NODES, ONE FILE: two busbar processes sharing one durable file (the fleet a
/// durable store serves), each loading the real store through the dropped-in door and appending its
/// own half of one chain AT THE SAME TIME, lose nothing — every record is there, in order, read back
/// through a third load. The store's cross-process file locking is what makes this hold; without it
/// the two writers' transactions interleave and records go missing.
///
/// Two PROCESSES, not two handles in this one: each `open_store` stages and loads its own copy of the
/// library, so two handles in one process are two independent copies of the store's embedded
/// database engine on one file — the configuration its engine documents as unsafe (one copy's
/// `close` drops the other's POSIX locks), and not one a node ever runs (a node opens its store once).
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn the_real_store_plugin_loses_no_record_across_two_nodes_on_one_file() {
    use busbar_contract::records::PlaneSelector;
    let dir = proof_scratch("store-nodes");
    let file = dir.join("governance.db");
    // Create the schema first, so neither node races the other's first-open migration.
    append_chain(&file, "proof-store-node-0", 0..0);

    let second = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "plugin_proof_tests::store_proof_second_node",
            "--ignored",
            "--nocapture",
        ])
        .env(SECOND_NODE, &file)
        .spawn()
        .expect("start the second node");
    append_chain(&file, "proof-store-node-1", 0..PER_NODE);
    let status = second
        .wait_with_output()
        .expect("the second node ends")
        .status;
    assert!(status.success(), "the second node failed: {status}");

    let registry = dropped(
        "proof-store-node-3",
        manifest("store", "proof-store"),
        &real_cdylib("store"),
    );
    let store = registry
        .open_store("proof-store", &store_config(&file))
        .expect("the real store plugin re-opens the shared file");
    let want: Vec<Vec<u8>> = (0..2 * PER_NODE)
        .map(|seq| seq.to_string().into_bytes())
        .collect();
    assert_eq!(
        store
            .list_plane_records("call", &PlaneSelector::Parent("p-1".into()))
            .expect("list the chain"),
        want,
        "two nodes on one file lost or reordered a record"
    );
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── `kind: hook` — the REAL forwarding hook (GetBusbar/busbar-hook-webrequest), R-FIX2 ─────────────────────

/// The engine-side projectors for the hook proofs: the decide projection carries the pool and the
/// candidate indices, and the decide reply is read by the engine's reply precedence (reject, then
/// restrict, then a ranked order, else abstain; an unreadable reply is an error) — the loader is
/// handed these by the engine and never parses a reply itself.
fn hook_projectors() -> std::sync::Arc<crate::hook::HookProjectors> {
    use busbar_contract::hooks::{RoutingDecision, TransformOutcome};
    std::sync::Arc::new(crate::hook::HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": {"pool": req.pool},
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| serde_json::json!({"request": {"pool": req.pool}})),
        normalize: Box::new(|v, cands| {
            if let Some(reject) = v.get("reject") {
                return Ok(RoutingDecision::Reject {
                    status: reject.get("status").and_then(|s| s.as_u64()).unwrap_or(403) as u16,
                    message: reject
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or_default()
                        .into(),
                });
            }
            if let Some(restrict) = v.get("restrict") {
                let tags = restrict
                    .get("tags_any")
                    .and_then(|t| t.as_array())
                    .ok_or("restrict without tags_any")?;
                return Ok(RoutingDecision::Restrict {
                    tags_any: tags
                        .iter()
                        .filter_map(|t| t.as_str().map(Into::into))
                        .collect(),
                });
            }
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return Ok(RoutingDecision::Abstain);
            };
            let valid = cands.iter().map(|c| c.idx).collect();
            Ok(RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            ))
        }),
        transform_outcome: Box::new(|_| TransformOutcome::Abstain),
        status: Box::new(|_| None),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

/// A LOCAL MOCK UPSTREAM for the forwarding hook: an HTTP/1.1 server on loopback whose reply is
/// chosen by the request path — `/allow` ranks, `/reject` rejects, `/restrict` restricts, `/sleep`
/// answers only after `SLOW_UPSTREAM`. Every request body it received is kept, in arrival order.
struct MockUpstream {
    base: String,
    seen: std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
}

/// How long the `/sleep` route waits before answering — well past the hook's configured timeout.
const SLOW_UPSTREAM: std::time::Duration = std::time::Duration::from_millis(4_500);

/// The hook's configured timeout on the `/sleep` route (the other routes keep the plugin's default,
/// so a loaded machine never turns an answer into a timeout).
const HOOK_TIMEOUT_MS: u64 = 500;

impl MockUpstream {
    fn start() -> Self {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the mock upstream");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let log = log.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    let mut len = 0usize;
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    let mut body = vec![0u8; len];
                    let _ = reader.read_exact(&mut body);
                    let received = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                    log.lock().unwrap().push((path.clone(), received));
                    let reply = match path.as_str() {
                        "/allow" => serde_json::json!({"order": [1, 0]}),
                        "/reject" => serde_json::json!({"reject": {"status": 403, "message": "blocked upstream"}}),
                        "/restrict" => serde_json::json!({"restrict": {"tags_any": ["baa"]}}),
                        "/sleep" => {
                            std::thread::sleep(SLOW_UPSTREAM);
                            serde_json::json!({"order": [0]})
                        }
                        _ => serde_json::json!({}),
                    }
                    .to_string();
                    let mut out = stream;
                    let _ = write!(
                        out,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                });
            }
        });
        MockUpstream { base, seen }
    }

    /// The hook's configuration pointing it at `route` on this upstream (keys are DATA); the `/sleep`
    /// route also sets the hook's timeout to [`HOOK_TIMEOUT_MS`].
    fn config(&self, route: &str) -> String {
        let mut cfg = serde_json::Map::new();
        cfg.insert(
            artifact("proof_hook_url_key").into(),
            serde_json::Value::String(format!("{}{route}", self.base)),
        );
        if route == "/sleep" {
            cfg.insert(
                artifact("proof_hook_timeout_key").into(),
                serde_json::Value::from(HOOK_TIMEOUT_MS),
            );
        }
        serde_json::Value::Object(cfg).to_string()
    }
}

/// HOOK — REJECT, RESTRICT, SLEEP: the real forwarding hook, dropped in, relays what its upstream
/// decides. Against a local mock upstream: a ranked reply ranks, a reject reply rejects the request
/// with the upstream's status and words, a restrict reply restricts the candidate set to the
/// upstream's tags, and an upstream that answers only after the hook's timeout fails the decision
/// (the engine coerces it to the hook's `on_error`) promptly, in the plugin's own words. Each call
/// reached the upstream as a `decide` envelope. RED arms: an empty config is refused in the plugin's
/// own words, and the bytes signed as `store` are refused at the kind handshake.
#[tokio::test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
async fn the_real_hook_plugin_rejects_restricts_and_times_out_through_the_dropped_in_door() {
    use busbar_contract::hooks::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
    let lib = real_cdylib("hook");
    let upstream = MockUpstream::start();
    let registry = dropped("proof-hook", manifest("hook", "proof-hook"), &lib);
    let open = |route: &str| {
        registry
            .open_hook(
                "proof-hook",
                &upstream.config(route),
                "proof-hook",
                hook_projectors(),
            )
            .expect("the real hook plugin opens as `hook`")
    };
    let cand = |idx| Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: Default::default(),
    };
    let cands = [cand(0), cand(1)];
    let req = RoutingRequest {
        request_id: 1,
        pool: "proof-pool",
        ingress_protocol: "proto-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 5,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: Default::default(),
    };
    let ctx = RoutingContext {
        pool: "proof-pool",
        budget_remaining: None,
        budget: &[],
    };
    let budget = std::time::Duration::from_secs(5);

    let allow = open("/allow").decide(&req, &cands, &ctx, budget).await;
    assert_eq!(
        allow.expect("the ranked reply"),
        RoutingDecision::Prefer(vec![1, 0])
    );

    let reject = open("/reject").decide(&req, &cands, &ctx, budget).await;
    assert_eq!(
        reject.expect("the reject reply"),
        RoutingDecision::Reject {
            status: 403,
            message: "blocked upstream".into()
        }
    );

    let restrict = open("/restrict").decide(&req, &cands, &ctx, budget).await;
    assert_eq!(
        restrict.expect("the restrict reply"),
        RoutingDecision::Restrict {
            tags_any: vec!["baa".into()]
        }
    );

    // Timed from the call, not the open: the upstream would answer `{"order":[0]}` (a success), so
    // an error in the plugin's timeout words before the upstream answers is the cut-off.
    let sleepy = open("/sleep");
    let started = std::time::Instant::now();
    let slow = sleepy.decide(&req, &cands, &ctx, budget).await;
    let e = slow.expect_err("an upstream slower than the hook's timeout fails the decision");
    assert!(
        started.elapsed() < SLOW_UPSTREAM,
        "the hook's own timeout must cut the call off before the upstream answers ({:?})",
        started.elapsed()
    );
    let want = artifact("proof_hook_timeout_error");
    assert!(e.to_string().contains(want), "want `{want}`: {e}");

    // Every decision reached the upstream as a `decide` envelope carrying the engine's projection.
    let seen = upstream.seen.lock().unwrap().clone();
    let paths: Vec<&str> = seen.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["/allow", "/reject", "/restrict", "/sleep"]);
    for (path, envelope) in &seen {
        assert_eq!(envelope["op"], "decide", "{path}: {envelope}");
        assert_eq!(
            envelope["request"]["pool"], "proof-pool",
            "{path}: {envelope}"
        );
    }

    // RED: an empty config is refused in the plugin's own words.
    let e = match registry.open_hook("proof-hook", "", "proof-hook", hook_projectors()) {
        Ok(_) => panic!("the hook plugin with no url opened; it must be refused"),
        Err(e) => e,
    };
    let want = artifact("proof_hook_refusal");
    assert!(e.contains(want), "want `{want}`: {e}");

    // RED: the same bytes signed as `store` are refused at the kind handshake, naming both kinds.
    let wrong = dropped(
        "proof-hook-as-store",
        manifest("store", "proof-hook-as-store"),
        &lib,
    );
    let e = refused(
        "a hook library signed as store",
        wrong.open_store("proof-hook-as-store", &upstream.config("/allow")),
    );
    assert!(
        e.contains(
            "plugin 'proof-hook-as-store' exports kind 'hook' but is being loaded as 'store'"
        ),
        "{e}"
    );
}
