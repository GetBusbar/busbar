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
//! `PlaneCallLog` directly, so the whole subsystem could be, and was, correct and unreached. A test
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
//! [`busbar_core::calllog::CALLS`] is process state (see its own header for why it must not ride the
//! swappable `App`). Two tests in this binary attaching different sinks to it concurrently would
//! interleave, so they take one lock — and each also uses its own principal, so a leaked chain
//! position from a sibling cannot make a green.

use super::upstream_support::{
    call_as, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::testkit::TestAppMcpExt;
use busbar_api::{McpCallRecord, Store};
use busbar_core::calllog::verify_call_rows;
use busbar_core::calllog::{OUTCOME_DISPATCHED, OUTCOME_REFUSED, REASON_UPSTREAM_FAILED};
use busbar_core::plane::store::StoreNamedTestExt;
use busbar_core::test_support::TestApp;
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
///
/// AND ITS STALENESS IS A HARD FAILURE TOO, with a DIFFERENT message, because a stale cdylib is the
/// more dangerous of the two and it was very nearly missed here. An out-of-date artifact answers
/// every write `Ok(())` and every read empty — which is byte-for-byte the signature of the very ABI
/// defect this battery exists to catch. So a stale artifact produces a failure indistinguishable
/// from a real regression, and, in the other direction, an artifact built BEFORE a regression was
/// introduced produces a PASS while the shipped ABI is broken. Neither reading is survivable, so
/// staleness must not reach the assertions at all.
///
/// A `[dev-dependencies]` edge on the plugin crate does NOT solve this, and believing it did is how
/// this hole stayed open: cargo satisfies that edge with the crate's RLIB and never emits the
/// cdylib, because nothing in the build graph consumes it — the test loads it by path at runtime,
/// which cargo cannot see. Verified by deleting the cdylib and running `cargo test -p busbar
/// --no-run`: the build completes and the cdylib is still absent.
///
/// This check does not BUILD the artifact, deliberately. Shelling out to cargo from inside a test
/// would contend for the target-directory lock the running `cargo test` already holds.
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
         refuses to skip. Build it: `cargo build -p busbar-store-example-plugin`.",
        path.display()
    );

    // The crates whose sources decide what the cdylib DOES across the ABI. The plugin itself, the
    // SDK it is written against, and the ABI header both sides compile to: a change to any of the
    // three can move the artifact's behaviour, and the four-method defect lived in the last one.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|c| c.parent())
        .expect("<workspace>/crates/busbar")
        .to_path_buf();
    let built = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .expect("the cdylib's build time");
    for crate_dir in ["store-example-plugin", "plugin-sdk", "busbar-plugin"] {
        let root = workspace.join("crates").join(crate_dir);
        if let Some(newer) = newest_source_under(&root, built) {
            panic!(
                "the busbar-store-example-plugin cdylib at {} is STALE — {} is newer than the \
                 artifact. THIS IS NOT A DURABILITY FAILURE, and it must not be read as one: a \
                 stale cdylib keeps nothing and reports success, which is exactly what the ABI \
                 defect this battery hunts looks like, so judging it would mean judging the wrong \
                 tree. Rebuild first: `cargo build -p busbar-store-example-plugin`.",
                path.display(),
                newer.display()
            );
        }
    }
    path
}

/// The first `.rs` or `Cargo.toml` under `root` modified after `built`, if any. Returns the file so
/// the panic can name it — "something is stale" sends a reader hunting; naming the file does not.
fn newest_source_under(root: &std::path::Path, built: std::time::SystemTime) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                // `target/` under a crate dir is build output, not source; it is always newer.
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
                continue;
            }
            let is_source = p.extension().is_some_and(|e| e == "rs")
                || p.file_name().is_some_and(|n| n == "Cargo.toml");
            if is_source
                && entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|m| m > built)
            {
                return Some(p);
            }
        }
    }
    None
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
    // `request_id` is a JOIN KEY, excluded from the digest and therefore NOT carried in the neutral
    // `{seq,prev_hash,hash,content}` body the durable seam persists — so a record READ BACK from the
    // store reconstructs it EMPTY. The join key still rides the success/refusal LOG LINE at emit time
    // (that is where a request is tied to its record); durability does not preserve it.
    assert!(
        request_id.is_empty(),
        "request_id is not persisted through the neutral seam, so it reads back empty; got {request_id:?}"
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
    busbar_core::metrics::init();
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
        busbar_core::calllog::aim_global_call_sink(Some(
            busbar_core::plane::store::PlaneStoreView::narrow(store),
        ));
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

    // DETACH before the read-back. `CALLS` is process-global and SIBLING tests in this binary
    // dispatch through it without taking `CALLS_GLOBAL` (they never touch the sink, so they need
    // no exclusivity) — but while OUR durable plugin is installed, their records write to OUR
    // ledger file. The plugin's persist is atomic (see `FileStore::mutate`), so those writes can't
    // tear the reopen below; detaching anyway keeps this test's ledger holding exactly what this
    // test wrote, so the `records.len()` assertion is about dispatch, not about scheduling.
    busbar_core::calllog::aim_global_call_sink(None);

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
    verify_call_rows(&records).expect("the persisted chain must verify against its own hashes");

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
    busbar_core::metrics::init();
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
        busbar_core::calllog::aim_global_call_sink(Some(
            busbar_core::plane::store::PlaneStoreView::narrow(store),
        ));
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

    // DETACH before the read-back — same isolation as the dispatched-call test above: siblings
    // record through the process-global `CALLS` without the lock, and this test's ledger must hold
    // exactly what this test wrote when the reopened handle reads it.
    busbar_core::calllog::aim_global_call_sink(None);

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
    verify_call_rows(&records).expect("the persisted chain must verify");
}

/// THE PERMANENT NEGATIVE. With NO sink attached — which is what `store: memory` is from the
/// engine's side — a dispatched call still succeeds and nothing is persisted. Without this the two
/// tests above would pass identically against an engine that wrote to a global nobody configured,
/// and "durable" would be an unfalsifiable word.
#[tokio::test]
async fn with_no_durable_sink_the_call_still_serves_and_nothing_is_kept() {
    let _serial = CALLS_GLOBAL.lock().await;
    busbar_core::metrics::init();
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
    busbar_core::calllog::aim_global_call_sink(None);

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

/// THE EQUALITY CELL `audit-chain × mcp-client`: the outcome of the leg BUSBAR ITSELF made — the
/// outbound call to a registered MCP server — is what the tamper-evident chain records, and the
/// chain distinguishes a leg that went out and came back badly from a leg that went out and worked.
///
/// ## Why this is a different claim from the two tests above, and not a third durability test
///
/// `a_dispatched_tools_call_lands_a_durable_record_...` proves the FRONT DOOR writes a row, and
/// `a_refused_tools_call_...` proves busbar's OWN refusal is written. Neither says anything about
/// the client leg: both would pass unchanged against an engine that made the outbound call, threw
/// its outcome away, and recorded `dispatched` unconditionally. That engine is exactly what the
/// ledger's `audit-chain × mcp-client` note describes — "no test proves a client-leg outcome lands
/// in a chain of its own" — and it is what this test refuses to accept.
///
/// ## The control is load-bearing, and it is the whole test
///
/// A single assertion that a failing leg records `upstream_failed` passes against a hard-coded
/// reason string. So BOTH outcomes are driven through the SAME principal, the SAME server and the
/// SAME tool, differing ONLY in what the upstream answered, and the two rows are asserted to differ
/// in exactly that field. The chain can only satisfy both if it is reading the real client leg.
///
/// `dispatched` + `upstream_failed` (rather than `refused`) is itself the engine's claim — see
/// `method.rs`'s `Outcome::UpstreamFailed` arm: "the record now says `dispatched` with the reason
/// token `upstream_failed`, so the chain distinguishes a call busbar blocked from a call that was
/// made and came back badly". If that distinction regressed to `refused`, or to an empty reason,
/// this test fails.
#[tokio::test]
async fn the_client_legs_own_outcome_is_what_the_chain_records_success_and_failure_apart() {
    let _serial = CALLS_GLOBAL.lock().await;
    busbar_core::metrics::init();
    let (file, cfg) = durable_cfg("clientleg");
    let principal = "calllog-clientleg-principal";
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    {
        let store = open_plugin(&cfg);
        busbar_core::calllog::aim_global_call_sink(Some(
            busbar_core::plane::store::PlaneStoreView::narrow(store),
        ));
    }

    // ── LEG 1: THE UPSTREAM ANSWERS BADLY. A JSON-RPC error from the registered server. ──────────
    // Not a transport failure: the socket worked, the exchange worked, busbar's admission passed,
    // and the ONLY thing that went wrong is the answer the far end gave. Nothing on busbar's side
    // of the leg can be blamed, so a chain that records this as a refusal is lying about who failed.
    let failing = Peer::start(Behaviour::Errors, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&failing, SUBJECT))
        .build();
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
        "the tool failed; busbar did not refuse — the leg is the subject, not the admission: {body}"
    );
    assert_eq!(
        failing.mcp_hits(),
        1,
        "THE LEG MUST HAVE GONE OUT. A record about a client leg that was never made is a record \
         about nothing, and every assertion below would be vacuous."
    );

    // ── LEG 2: THE CONTROL. The identical call, the identical principal, a working upstream. ─────
    let working = Peer::start(Behaviour::Result, ISSUED).await;
    let app_ok = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&working, SUBJECT))
        .build();
    let (status, body) = call_as(
        &app_ok,
        &g,
        principal,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;
    assert_eq!(status, 200, "the control call must succeed: {body}");
    assert_eq!(working.mcp_hits(), 1, "the control leg really went out");

    // Detach before the read-back, for the reason the headline test states: siblings in this binary
    // dispatch through the process-global `CALLS` without taking the serialising lock.
    busbar_core::calllog::aim_global_call_sink(None);

    let reopened = open_plugin(&cfg);
    let records = reopened
        .list_mcp_calls(principal)
        .expect("list_mcp_calls over the ABI after the restart");
    assert_eq!(
        records.len(),
        2,
        "one row per leg, in the order the legs were made. The durable ledger at {} holds: {}",
        file.display(),
        std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
    );

    // ── THE CLAIM. Both legs are `dispatched` — both went out — and the REASON is the only thing
    // that differs, because the reason is the only place the client leg's own outcome is carried.
    assert_eq!(
        records[0].outcome, OUTCOME_DISPATCHED,
        "a leg that went out and came back badly is still a leg that WENT OUT; recording it as a \
         refusal would attribute the upstream's failure to busbar's admission"
    );
    assert_eq!(
        records[0].reason, REASON_UPSTREAM_FAILED,
        "the failing leg's outcome must reach the chain as its own token. An empty reason here is \
         the defect this cell names: the outbound call was made, it failed, and the chain an \
         investigator reads cannot tell"
    );
    assert_eq!(
        records[1].outcome, OUTCOME_DISPATCHED,
        "the control leg went out and worked"
    );
    assert!(
        records[1].reason.is_empty(),
        "THE CONTROL. A successful leg carries NO reason token — so the assertion above is about \
         the upstream's actual answer and not about a constant the engine always writes. Got {:?}",
        records[1].reason
    );

    // ── AND IT IS A CHAIN, not a list. The two legs are linked, so neither row can be edited,
    // reordered or dropped without the verifier saying so.
    verify_call_rows(&records)
        .expect("the persisted client-leg chain must verify against its own hashes");
    assert_eq!(records[0].seq, 1);
    assert_eq!(records[1].seq, 2);
    assert!(
        records[0].prev_hash.is_empty() && records[1].prev_hash == records[0].hash,
        "the second leg's record must link to the first: a tamper-evident chain is what makes this \
         capability the audit capability rather than a log"
    );
}
