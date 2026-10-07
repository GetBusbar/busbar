//! THE INSTANCE-NOUN CENSUS'S VERDICT, PINNED ON A KNOWN-BAD TREE.
//!
//! The census was made fast (a per-file needle test before any per-line matcher, and the files
//! judged in parallel). Speed is only allowed to change how long the answer takes, never the
//! answer: this tree is built to sit on every edge the fast path skips past — a noun named only in
//! comments, a CamelCase tail of a lowercase word, a `streams:` key with an inline value, a noun in
//! its own family, the generic `gcp` mention file, a baseline that is grown, stale and dead at once
//! — and the gate's full row set over it is pinned byte for byte. The pin was taken from the serial
//! census before the change and passes unchanged after it.

use std::path::{Path, PathBuf};

use xtask::ctx::Ctx;
use xtask::gates::execute;
use xtask::gates::instance_noun_neutrality::InstanceNounNeutralityGate;

const TREE: &[(&str, &str)] = &[
    (
        "crates/busbar-core/src/lib.rs",
        r#"pub fn handle_mcp() {}
pub struct McpTransport;
pub struct deepMcp;
pub fn llmx() {}
// mcp named in a line comment only
/* a block comment naming a2a
   and postgres, still comment */
pub const SECTION: &str = "streams:\n  ingest: {}";
pub const INLINE: &str = "streams: [logs]";
pub type Plane = StreamingPlane;
pub fn a2a_x() {} pub fn a2a_y() {}
pub fn mysql() {}
pub fn x() { let _ = "jev"; }
pub fn y() { let _ = "Ünïcödé mcp"; }
pub fn z() { let _ = "GCP metadata"; }
pub use busbar_transport_tls as gone;
"#,
    ),
    (
        "crates/busbar-mcp/src/lib.rs",
        r#"pub fn mcp_codec() {}
pub fn a2a_bridge() {}
pub fn a2a_again() {}
"#,
    ),
    (
        "crates/busbar/src/main.rs",
        r#"use busbar_transport_http::Server;
fn main() { let _ = "plane-streaming"; }
"#,
    ),
    (
        "crates/busbar-kernel/src/diagnostics/mod.rs",
        r#"pub const WARN: &str = "the GCP/Azure metadata hosts";
pub fn valkey_store() {}
"#,
    ),
    (
        "crates/busbar-contract/src/lib.rs",
        r#"pub struct HashicorpVault;
pub fn hashicorp_vault() {}
"#,
    ),
    (
        "qa/instance-noun-neutrality.toml",
        r#"[pragma_ceiling]
frozen_literal = 0

[[leak]]
noun = "mcp"
file = "crates/busbar-core/src/lib.rs"
count = 1

[[leak]]
noun = "a2a"
file = "crates/busbar-mcp/src/lib.rs"
count = 5

[[leak]]
noun = "voice"
file = "crates/busbar-core/src/lib.rs"
count = 1

[[leak]]
noun = "mysql"
file = "crates/gone.rs"
count = 1
"#,
    ),
];

/// `Row::tsv` of every row, in order, as the serial census printed it over [`TREE`].
const PINNED: &str = r#"instance-noun-neutrality:scan-floor	PASS	the crates tree was scanned	the scan cleared its floors and named nothing
instance-noun-neutrality:mcp	FAIL	`mcp` (plane) is named in 1 file(s) outside its family [busbar-mcp, busbar-plane-mcp]	tracked known-debt census — 1: crates/busbar-core/src/lib.rs×3 [core]
instance-noun-neutrality:a2a	FAIL	`a2a` (plane) is named in 2 file(s) outside its family [busbar-a2a, busbar-plane-a2a]	tracked known-debt census — 2: crates/busbar-core/src/lib.rs×1 [core] | crates/busbar-mcp/src/lib.rs×2 [cross-plugin]
instance-noun-neutrality:llm	PASS	no crate outside the plane family names `llm`	the scan cleared its floors and named nothing
instance-noun-neutrality:streaming	FAIL	`streaming` (plane) is named in 2 file(s) outside its family [busbar-plane-streaming, busbar-voice]	tracked known-debt census — 2: crates/busbar-core/src/lib.rs×2 [core] | crates/busbar/src/main.rs×1 [composition-root]
instance-noun-neutrality:voice	PASS	no crate outside the plane family names `voice`	the scan cleared its floors and named nothing
instance-noun-neutrality:jev	FAIL	`jev` (plane) is named in 1 file(s) outside its family [busbar-plane-decisions]	tracked known-debt census — 1: crates/busbar-core/src/lib.rs×1 [core]
instance-noun-neutrality:http	FAIL	`http` (transport) is named in 1 file(s) outside its family [busbar-transport-http]	tracked known-debt census — 1: crates/busbar/src/main.rs×1 [composition-root]
instance-noun-neutrality:ws	PASS	no crate outside the transport family names `ws`	the scan cleared its floors and named nothing
instance-noun-neutrality:stdio	PASS	no crate outside the transport family names `stdio`	the scan cleared its floors and named nothing
instance-noun-neutrality:tcp	PASS	no crate outside the transport family names `tcp`	the scan cleared its floors and named nothing
instance-noun-neutrality:tls	FAIL	`tls` (transport) is named in 1 file(s) outside its family [(no crate in this tree)]	tracked known-debt census — 1: crates/busbar-core/src/lib.rs×1 [core]
instance-noun-neutrality:sse	PASS	no crate outside the transport family names `sse`	the scan cleared its floors and named nothing
instance-noun-neutrality:grpc	PASS	no crate outside the transport family names `grpc`	the scan cleared its floors and named nothing
instance-noun-neutrality:postgres	PASS	no crate outside the store family names `postgres`	the scan cleared its floors and named nothing
instance-noun-neutrality:mysql	FAIL	`mysql` (store) is named in 1 file(s) outside its family [(no crate in this tree)]	tracked known-debt census — 1: crates/busbar-core/src/lib.rs×1 [core]
instance-noun-neutrality:valkey	FAIL	`valkey` (store) is named in 1 file(s) outside its family [(no crate in this tree)]	tracked known-debt census — 1: crates/busbar-kernel/src/diagnostics/mod.rs×1 [core]
instance-noun-neutrality:sqlite	PASS	no crate outside the store family names `sqlite`	the scan cleared its floors and named nothing
instance-noun-neutrality:memory	PASS	no crate outside the store family names `memory`	the scan cleared its floors and named nothing
instance-noun-neutrality:store	PASS	no crate outside the store family names `store`	the scan cleared its floors and named nothing
instance-noun-neutrality:gcp	FAIL	`gcp` (auth) is named in 1 file(s) outside its family [auth-admin-tokens, busbar-core-oauth2]	tracked known-debt census — 1: crates/busbar-core/src/lib.rs×1 [core]
instance-noun-neutrality:vault	FAIL	`vault` (secret) is named in 1 file(s) outside its family [(no crate in this tree)]	tracked known-debt census — 1: crates/busbar-contract/src/lib.rs×1 [shared-crate]
instance-noun-neutrality:hook	PASS	no crate outside the hook family names `hook`	the scan cleared its floors and named nothing
instance-noun-neutrality:ranking	PASS	no crate outside the hook family names `ranking`	the scan cleared its floors and named nothing
instance-noun-neutrality:undocumented	FAIL	a live instance-noun leak is NOT in the baseline, or outgrew its baselined count	11 undocumented leak(s): a2a@crates/busbar-core/src/lib.rs, gcp@crates/busbar-core/src/lib.rs, http@crates/busbar/src/main.rs, jev@crates/busbar-core/src/lib.rs, mcp@crates/busbar-core/src/lib.rs grew 1→3, mysql@crates/busbar-core/src/lib.rs, streaming@crates/busbar-core/src/lib.rs, streaming@crates/busbar/src/main.rs, tls@crates/busbar-core/src/lib.rs, valkey@crates/busbar-kernel/src/diagnostics/mod.rs, vault@crates/busbar-contract/src/lib.rs — a NEW cross-family coupling landed. Neutralize it, or (if it is genuine debt) record it in qa/instance-noun-neutrality.toml with its owning wave.
instance-noun-neutrality:stale-baseline	FAIL	a baseline row no longer names a live leak	2 stale row(s): mysql@crates/gone.rs, voice@crates/busbar-core/src/lib.rs — the coupling is gone; strike the row from qa/instance-noun-neutrality.toml in the same commit that neutralized it.
instance-noun-neutrality:dead-path	FAIL	a baseline row names a path the census cannot scan	1 zero-match row(s): mysql@crates/gone.rs — the path matches no scanned `.rs` file (deleted, renamed, or now a directory), so the row can only ever measure zero. Repoint it at the file(s) that now hold the code, or strike it, in qa/instance-noun-neutrality.toml.
instance-noun-neutrality:frozen-literal	PASS	every frozen-literal pragma is reasoned, literal-only and pinned	0 pragma(s) honoured:
instance-noun-neutrality:pragma-ceiling	PASS	the frozen-literal pragma count sits exactly at its ledger ceiling	frozen_literal 0 == ceiling 0
"#;

fn plant(root: &Path) {
    for (rel, text) in TREE {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a planted file has a parent"))
            .expect("the planted tree's directories are creatable");
        std::fs::write(&path, text).expect("the planted file is writable");
    }
}

fn scratch_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xtask-insn-verdict-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn the_census_verdict_on_a_known_bad_tree_is_pinned_row_for_row() {
    let root = scratch_root("tree");
    plant(&root);
    let cx = Ctx::at(&root, root.join(".scratch")).expect("the planted tree opens");
    let verdict = execute(&InstanceNounNeutralityGate::check(), &cx);
    // Each line is compared with its trailing whitespace trimmed, so the pin carries none.
    let got: String = verdict
        .rows
        .iter()
        .map(|r| format!("{}\n", r.tsv().trim_end()))
        .collect();
    let _ = std::fs::remove_dir_all(&root);
    assert!(verdict.red, "the known-bad tree must be red");
    assert_eq!(
        got, PINNED,
        "the census verdict over the known-bad tree moved; a speed change must not move a row"
    );
}
