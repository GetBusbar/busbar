// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNING GATE READS THE RENDERING THIS CRATE WRITES. `scripts/signing-gate.sh` carries its own

use std::path::Path;
use std::process::Command;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_PROVIDER, KEEP_ALL_EXCEPT_DENIED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::hook::{statement_with_tail, tail};

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const KEPT: &[AbiStr] = &[abi_str("x-reader-kept")];
const DENIED: &[AbiStr] = &[abi_str("x-reader-denied")];
const NEEDS: &[Need] = &[
    Need {
        direction: DIRECTION_OUTBOUND,

        egress_class: EGRESS_PROVIDER,
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
        keep_response_headers: KEPT.as_ptr(),
        keep_response_headers_len: KEPT.len(),
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    },
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_DEFAULT,
        transport: abi_str("http"),
        keep_mode: KEEP_ALL_EXCEPT_DENIED,
        deny_response_headers: DENIED.as_ptr(),
        deny_response_headers_len: DENIED.len(),
        ..Need::ZERO
    },
];

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
    use busbar_contract::abi::mechanism::rendering::{
        RENDERING_MAGIC_TAIL_SIZE_ONLY, RENDERING_MAGIC_WITHOUT_NEED_RETENTION,
    };
    // SAFETY: every list and the tail `STATEMENT` points at is `'static`.
    let rendered = unsafe { busbar_contract::abi::mechanism::rendering::render(&STATEMENT) }
        .expect("the Statement renders");
    let dir = std::env::temp_dir().join(format!("gate-reader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let tarball = dir.join("unsigned.tar.gz");
    let script = dir.join("reader.py");
    std::fs::write(&script, reader()).expect("reader");
    let mut cases = vec![("whole", rendered.clone(), true)];
    for magic in [
        RENDERING_MAGIC_TAIL_SIZE_ONLY,
        RENDERING_MAGIC_WITHOUT_NEED_RETENTION,
    ] {
        let mut old = rendered.clone();
        old[..magic.len()].copy_from_slice(magic);
        cases.push(("older format", old, false));
    }
    for name in ["x-reader-kept", "x-reader-denied"] {
        let name_at = rendered
            .windows(name.len())
            .position(|b| b == name.as_bytes())
            .unwrap();
        let count_at = name_at - 2 * std::mem::size_of::<u32>();
        let mut huge = rendered.clone();
        huge[count_at..count_at + std::mem::size_of::<u32>()]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("retention count", huge, false));
        cases.push((
            "short retention name",
            rendered[..name_at + name.len() - 1].to_vec(),
            false,
        ));
    }
    let mut padded = rendered.clone();
    padded.push(0);
    cases.push(("trailing bytes", padded, false));
    for (name, bytes, valid) in cases {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::json!({ "statement": hex }).to_string(),
        )
        .expect("manifest");
        let packed = Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&dir)
            .arg("manifest.json")
            .status()
            .expect("run tar");
        assert!(packed.success(), "tar packs the manifest");
        let out = Command::new("python3")
            .arg(&script)
            .arg(&tarball)
            .output()
            .expect("run python3");
        assert_eq!(
            out.status.success(),
            valid,
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if valid {
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                "http\tprovider\n",
                "the gate reads the first-party need"
            );
        } else {
            assert!(
                out.stdout.is_empty(),
                "{name}: no partial first-party grant may escape"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
