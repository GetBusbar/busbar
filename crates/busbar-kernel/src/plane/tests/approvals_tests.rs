// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE HOLDS NO PLANE'S SEAL (audit K2-H3). The caller-facing ask-state seal is the plane's own,
//! sealed over the host's `sign`; core keeps only the spent-approval ledger, the replay window and
//! the nonce. RED before the deletion: the kernel carried a dead copy of the seal, its payload and
//! its two MAC domains, spelled with the plane token escaped.

use std::path::Path;

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a source directory").flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_kernel_holds_no_plane_named_seal_domain() {
    // The needles are built here, so this file does not carry them: the escaped plane token the
    // seal domains were spelled with, and the domains' own path segment.
    let escaped = format!("busbar/\\x{:02x}", b'm');
    let segment = ["ask", "state/"].concat();
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(!files.is_empty(), "the kernel's sources are read");
    let carriers: Vec<String> = files
        .iter()
        .filter(|f| {
            let text = std::fs::read_to_string(f).unwrap_or_default();
            text.contains(&escaped) || text.contains(&segment)
        })
        .map(|f| f.display().to_string())
        .collect();
    assert!(
        carriers.is_empty(),
        "the kernel carries a plane's seal domain: {carriers:?}"
    );
}

#[test]
fn the_ledger_spends_an_approval_once() {
    let ledger = super::SpentTokenLedger::new();
    let nonce = super::nonce().expect("a nonce");
    assert!(ledger.spend(&nonce, 100 + super::DEFAULT_TTL_SECS, 100));
    assert!(!ledger.spend(&nonce, 100 + super::DEFAULT_TTL_SECS, 101));
}
