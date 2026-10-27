// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNING GATE READS THE RENDERING THIS CRATE WRITES. `scripts/signing-gate.sh` carries its own
//! reader of the Statement rendering (a Python heredoc) to find a plugin's first-party need in the
//! signed manifest. This drives that very reader over a real rendering of a Statement whose kind tail
//! carries facts and which declares a secret field, so the two cannot drift apart unseen.

use std::path::Path;
use std::process::Command;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::hook::{statement_with_tail, tail};

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_LOOPBACK_ALLOWED,
    transport: abi_str("http"),
    auth: NONE,
    target_from: NONE,
    trust_from: NONE,
    details: Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_RW, USER_RO);

const SECRET_REFS: &[AbiStr] = &[abi_str("url")];

const STATEMENT: Statement = Statement {
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    secret_refs: SECRET_REFS.as_ptr(),
    secret_refs_len: SECRET_REFS.len(),
    ..statement_with_tail(statement("gate-reader", "1.0.0", 8), TAIL)
};

/// The gate's reader: the `GRANT_NEED` heredoc of `scripts/signing-gate.sh`, verbatim.
fn reader() -> String {
    let gate = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/signing-gate.sh"),
    )
    .expect("read scripts/signing-gate.sh");
    let open = "GRANT_NEED=$(python3 - \"$WORK/unsigned.tar.gz\" <<'EOF'\n";
    let start = gate.find(open).expect("the gate's reader heredoc") + open.len();
    let len = gate[start..].find("\nEOF\n").expect("the heredoc's end");
    gate[start..start + len].to_string()
}

#[test]
fn the_signing_gates_reader_reads_a_tailed_statement_that_declares_secret_fields() {
    // SAFETY: every list and the tail `STATEMENT` points at is `'static`.
    let rendered = unsafe { busbar_contract::abi::mechanism::rendering::render(&STATEMENT) }
        .expect("the Statement renders");
    let hex: String = rendered.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("gate-reader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::json!({ "statement": hex }).to_string(),
    )
    .expect("manifest");
    let tarball = dir.join("unsigned.tar.gz");
    let packed = Command::new("tar")
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(&dir)
        .arg("manifest.json")
        .status()
        .expect("run tar");
    assert!(packed.success(), "tar packs the manifest");
    let script = dir.join("reader.py");
    std::fs::write(&script, reader()).expect("reader");
    let out = Command::new("python3")
        .arg(&script)
        .arg(&tarball)
        .output()
        .expect("run python3");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "the gate's reader refused a real rendering: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "http\tloopback-allowed\n",
        "the gate reads the first-party need"
    );
}
