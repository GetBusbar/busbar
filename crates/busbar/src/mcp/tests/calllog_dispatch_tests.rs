// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WRITER, PROVEN FROM THE OUTSIDE: a real `tools/call`, through the real dispatcher, against a
//! real socket upstream, landing a real row in a real `kind: store` plugin that was `dlopen`ed from
//! a real cdylib — and read back after the handle is dropped and re-opened, which is what a restart
//! is.
//!
//! ## Why none of the four "real"s above is decoration
//!
//! The per-call log had a complete substrate, a hash chain, a verifier, a restore path and its own
//! passing battery — and **no production call site at all**. Everything was exercised by driving
//! `McpCallLog` directly, so the whole subsystem could be, and was, correct and unreached. A test
//! that calls `CALLS.record(..)` itself would have reproduced exactly that: it proves the substrate
//! and says nothing about whether a customer's `tools/call` ever reaches it. So this battery does not
//! touch the log's write surface. It drives `tools/call` and then LOOKS.
//!
//! The `dlopen` half is the other lesson, and it is a lesson this release already paid for once. The
//! plugin ABI carried four store methods while the trait carried ten, so every task and call-log
//! write through the real plugin path was accepted and silently discarded — while each store
//! plugin's own unit tests passed, because they never crossed the ABI. A call-log test held against
//! an in-process `Store` double would have been green throughout that entire defect. The store here
//! is therefore the genuine `busbar-store-example-plugin` cdylib, loaded through
//! `busbar_plugin_loader::load_store`, i.e. across the same C ABI a customer's postgres or sqlite
//! plugin is reached over.
//!
//! ## Why the read-back is a second `dlopen` and not a second method call
//!
//! `Ok(())` from a write is worthless as evidence — the `Store` trait's defaults accept and keep
//! nothing — so durability is only ever learned by READING BACK. Reading back through the SAME
//! handle would still pass against a plugin that kept the row in a map it drops on close. The
//! fixture's `durable_path` mode puts bytes on disk precisely so a second `busbar_open` can find
//! them, and a second `busbar_open` is what this file does.
//!
//! ## The `CALLS` global is serialised here, deliberately
//!
//! [`crate::mcp::calllog::CALLS`] is process state (see its own header for why it must not ride the
//! swappable `App`). Two tests in this binary attaching different sinks to it concurrently would
//! interleave, so they take one lock — and each also uses its own principal, so a leaked chain
//! position from a sibling cannot make a green.

use super::upstream_support::{
    call_as, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::mcp::calllog::{verify_chain, CALLS, OUTCOME_DISPATCHED, OUTCOME_REFUSED};
use crate::test_support::TestApp;
use busbar_api::{McpCallRecord, Store};
use std::path::PathBuf;
use std::sync::Arc;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// The process-wide `CALLS` sink is shared, so these tests run one at a time.
///
/// An ASYNC mutex, not a `std` one: every test here holds the guard across `.await` points (the fake
/// peer starts asynchronously and the dispatch is async), and a blocking guard held across an await
/// parks a runtime worker on a lock another task must run to release. It is also why this is not
/// poison-recovering — `tokio::sync::Mutex` has no poisoning, so a panicking test cannot wedge the
/// ones after it either.
static CALLS_GLOBAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Locate the REAL `busbar-store-example-plugin` cdylib.
///
/// Derived from THIS TEST BINARY's own path (`<target>/<profile>/deps/<bin>`) rather than from a
/// hard-coded `target/debug`, so it is correct under `--release`, under a custom `CARGO_TARGET_DIR`,
/// and under a workspace built into a shared target directory.
///
/// ITS ABSENCE IS A HARD FAILURE, never a skip. A "skip: cdylib not built" line is how the coverage
/// that would have caught the four-method ABI silently stops running — the run stays green and
/// nobody reads the line. The panic names the exact command that fixes it.
fn example_store_cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("<target>/<profile>/deps/<test-binary>")
        .to_path_buf();
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_example_plugin");
    let path = profile_dir.join(&name);
    assert!(
        path.exists(),
        "the busbar-store-example-plugin cdylib is not built at {}. This battery crosses the REAL \
         plugin C ABI on purpose — the defect it exists to catch (an ABI that carried four store \
         methods and discarded every call-log write) is invisible to any in-process double — so it \
         refuses to skip. Build it: `cargo build -p busbar-store-example-plugin` (or run the suite \
         with `--workspace`, which builds it).",
        path.display()
    );
    path
}

/// A private durable file for one test, and the plugin config that selects the fixture's on-disk
/// mode. Per-test and per-thread, so the parallel harness cannot make two tests share a ledger.
fn durable_cfg(tag: &str) -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-mcp-calllog-{}-{tag}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("create the durable fixture directory");
    let file = dir.join("durable.json");
    let _ = std::fs::remove_file(&file);
    let cfg = serde_json::json!({ "durable_path": file.to_string_lossy() }).to_string();
    (file, cfg)
}

/// Open the plugin over the ABI. Each call is a fresh `dlopen` + `busbar_open`, i.e. a restart.
fn open_plugin(cfg: &str) -> Arc<dyn Store> {
    let path = example_store_cdylib();
    Arc::from(
        busbar_plugin_loader::load_store(&path, cfg)
            .expect("load busbar-store-example-plugin over the real plugin C ABI"),
    )
}

/// Every field of a record, named. A whole-struct comparison would let a field be ADDED and never
/// checked, which on a hash-chained record means a field that is chained but never asserted.
fn assert_record(
    got: &McpCallRecord,
    principal: &str,
    seq: u64,
    server: &str,
    tool: &str,
    outcome: &str,
    reason_is_empty: bool,
) {
    let McpCallRecord {
        principal: p,
        seq: s,
        ts,
        server: srv,
        tool: t,
        outcome: o,
        reason: r,
        tool_digest,
        pin_generation: _,
        request_id,
        prev_hash,
        hash,
    } = got;
    assert_eq!(
        p, principal,
        "the chain is scoped to the AUTHENTICATED caller"
    );
    assert_eq!(*s, seq, "sequence is 1-based within the principal");
    assert!(*ts > 0, "a record with no timestamp joins to nothing");
    assert_eq!(srv, server);
    assert_eq!(t, tool, "the tool is the PUBLISHED namespaced routing key");
    assert_eq!(o, outcome);
    assert_eq!(
        r.is_empty(),
        reason_is_empty,
        "a dispatch carries no reason token and a refusal must carry one: got {r:?}"
    );
    assert!(
        !tool_digest.is_empty(),
        "the record must tie the call to the digest the operator approved"
    );
    assert!(
        !request_id.is_empty(),
        "the request-spine join key is what makes a record findable from a log line"
    );
    assert!(hash.len() == 64, "a sha256 hex digest, got {hash:?}");
    if seq == 1 {
        assert!(
            prev_hash.is_empty(),
            "the first link of a chain has no prev"
        );
    } else {
        assert!(!prev_hash.is_empty());
    }
}

/// THE HEADLINE. A granted `tools/call` reaches a real upstream, and the per-call record for it is
/// found in the plugin's durable ledger AFTER the handle that wrote it has been closed and reopened.
#[tokio::test]
async fn a_dispatched_tools_call_lands_a_durable_record_through_a_real_dlopened_store_plugin() {
    let _serial = CALLS_GLOBAL.lock().await;
    crate::metrics::init();
    let (file, cfg) = durable_cfg("dispatched");
    // ITS OWN PRINCIPAL. `CALLS` chains per principal in a process global that no test resets, so a
    // shared principal would carry a sibling test's sequence into this one's fresh store — observed,
    // as a `seq 3` against a ledger holding one record.
    let principal = "calllog-dispatched-principal";

    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    // THE SINK IS THE PLUGIN. Attached exactly as `main.rs` attaches the configured governance
    // store at boot, and then dropped from this test's hands entirely: everything below reaches the
    // store only through the dispatcher.
    {
        let store = open_plugin(&cfg);
        CALLS.set_sink(store);
    }

    let (status, body) = call_as(
        &app,
        &g,
        principal,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;
    assert_eq!(status, 200, "the call itself must succeed: {body}");
    assert_eq!(peer.mcp_hits(), 1, "the upstream really was dispatched to");

    // THE RESTART. A fresh `dlopen` + `busbar_open` over the same on-disk ledger — the only way a
    // durability claim can be made honestly, because a write's `Ok(())` is worth nothing.
    let reopened = open_plugin(&cfg);
    let records = reopened
        .list_mcp_calls(principal)
        .expect("list_mcp_calls over the ABI after the restart");

    assert_eq!(
        records.len(),
        1,
        "ONE record for one dispatched tools/call. Zero here is the defect this battery exists for: \
         the substrate, the chain, the verifier and the restore are all real and NOTHING WRITES. \
         The durable ledger at {} holds: {}",
        file.display(),
        std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
    );
    assert_record(
        &records[0],
        principal,
        1,
        "fs",
        "fs_read",
        OUTCOME_DISPATCHED,
        true,
    );
    verify_chain(&records).expect("the persisted chain must verify against its own hashes");

    // The BYTES the plugin actually kept, printed so a release report can quote evidence rather
    // than quote an assertion that passed.
    eprintln!(
        "DURABLE LEDGER {}:\n{}",
        file.display(),
        std::fs::read_to_string(&file).expect("the plugin's on-disk ledger")
    );

    // And the store enumerates the principal, which is what the boot rehydrate walks.
    assert!(
        reopened
            .list_mcp_call_principals()
            .expect("list_mcp_call_principals over the ABI")
            .contains(&principal.to_string()),
        "a principal with rows must be enumerable, or `restore_from_store` finds nothing to restore"
    );
}

/// THE OTHER HALF, and it is not a lesser case. A refusal is the record an operator most wants: it
/// is the evidence that somebody asked for something they could not have. A log that recorded only
/// successes would be an activity feed, not an audit.
#[tokio::test]
async fn a_refused_tools_call_lands_a_durable_record_carrying_the_refusal_reason() {
    let _serial = CALLS_GLOBAL.lock().await;
    crate::metrics::init();
    let (_file, cfg) = durable_cfg("refused");
    let principal = "calllog-refused-principal";

    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    // Granted the SERVER and not the TOOL: refused at admission, before any network I/O.
    let g = gov_with_scopes(&[("mcp_server", "fs")]);

    {
        let store = open_plugin(&cfg);
        CALLS.set_sink(store);
    }

    let (status, _body) = call_as(
        &app,
        &g,
        principal,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;
    assert_eq!(status, 404, "an ungranted tool is refused");
    assert_eq!(peer.mcp_hits(), 0, "and the upstream is never contacted");

    let reopened = open_plugin(&cfg);
    let records = reopened
        .list_mcp_calls(principal)
        .expect("list_mcp_calls over the ABI after the restart");
    assert_eq!(
        records.len(),
        1,
        "a REFUSED call is evidence and must be recorded; got {records:?}"
    );
    assert_eq!(records[0].outcome, OUTCOME_REFUSED);
    assert!(
        !records[0].reason.is_empty(),
        "the refusal must carry a stable, greppable reason token: {:?}",
        records[0]
    );
    verify_chain(&records).expect("the persisted chain must verify");
}

/// THE PERMANENT NEGATIVE. With NO sink attached — which is what `store: memory` is from the
/// engine's side — a dispatched call still succeeds and nothing is persisted. Without this the two
/// tests above would pass identically against an engine that wrote to a global nobody configured,
/// and "durable" would be an unfalsifiable word.
#[tokio::test]
async fn with_no_durable_sink_the_call_still_serves_and_nothing_is_kept() {
    let _serial = CALLS_GLOBAL.lock().await;
    crate::metrics::init();
    let (_file, cfg) = durable_cfg("nosink");
    let principal = "calllog-nosink-principal";

    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    // The RAM default: `busbar-store-memory` implements none of the call-log methods, so attaching
    // it is indistinguishable from attaching nothing — which is the documented `store: memory`
    // contract, asserted rather than assumed.
    CALLS.set_sink(Arc::new(busbar_store_memory::MemoryStore::new()));

    let (status, body) = call_as(
        &app,
        &g,
        principal,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;
    assert_eq!(
        status, 200,
        "an undurable deployment must still SERVE: the log is evidence, not admission: {body}"
    );

    let plugin = open_plugin(&cfg);
    assert!(
        plugin
            .list_mcp_calls(principal)
            .expect("list_mcp_calls over the ABI")
            .is_empty(),
        "nothing was configured to persist, so nothing may be found — a durability test that has \
         never seen a NON-durable store has proven nothing"
    );
}
