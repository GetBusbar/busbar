// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LOGIN-PKCE (ABI-MIN3-INTERFACE §14): Core mints the PKCE challenge, verifier and nonce once
//! (`busbar-core-oauth2::pkce`; K8 + K10). The auth plugins' arms run in their repos.
//!
//! W1-K10's arms: for a CONNECT(BEGIN), BEGIN carries L_CODE_CHALLENGE and L_NONCE, the plugin's REDIRECT URL
//! carries exactly that challenge, COMPLETE carries L_CODE_VERIFIER and the same L_NONCE, S256(verifier) equals the
//! challenge, and the plugin's STATE never holds the verifier or the nonce; and core's two minting functions have
//! exactly one definition, called by the hosted login and by K10. The hosted REDIRECT login half (BEGIN/COMPLETE
//! through an auth port) lands with the auth switch-over.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::path::Path;

use busbar_kernel::connections::{pkce, CallbackAnswer};

use crate::k10_rig::{connect, runtime, Deployment};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn connect_begin_carries_core_minted_pkce_and_nonce() {
    let rt = runtime();
    let deployment = rt.block_on(Deployment::new());
    let conns = deployment.connections();
    assert_eq!(
        connect(&rt, &deployment, &conns, "&iss=https://as.example"),
        CallbackAnswer::Connected {
            location: "/".into()
        }
    );
    let seen = deployment.seen();
    let challenge = seen.challenge.expect("BEGIN carried L_CODE_CHALLENGE");
    let nonce = seen.begin_nonce.expect("BEGIN carried L_NONCE");
    let verifier = seen.verifier.expect("COMPLETE carried L_CODE_VERIFIER");
    assert_eq!(seen.complete_nonce.as_deref(), Some(nonce.as_str()));
    assert_eq!(pkce::code_challenge_s256(&verifier), challenge);
    assert_eq!(verifier.len(), 43, "32 random bytes, base64url");
    assert_eq!(challenge.len(), 43);
    assert!(!seen.states.is_empty());
    for state in &seen.states {
        assert!(
            !contains(state, verifier.as_bytes()),
            "no STATE holds the verifier"
        );
        assert!(
            !contains(state, nonce.as_bytes()),
            "no STATE holds the nonce"
        );
    }
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "target" || n == "tests")
            {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn core_mints_pkce_in_exactly_one_place() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(crates).expect("crates/").flatten() {
        rust_files(&krate.path().join("src"), &mut files);
    }
    let mut definitions: Vec<(String, &str)> = Vec::new();
    let mut callers: Vec<String> = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for name in ["fn random_b64url(", "fn code_challenge_s256("] {
            if text.contains(name) {
                definitions.push((file.display().to_string(), name));
            }
        }
        if text.contains("pkce::code_challenge_s256(") {
            callers.push(file.display().to_string());
        }
    }
    assert_eq!(
        definitions.len(),
        2,
        "each minting function is defined once: {definitions:?}"
    );
    assert!(
        definitions
            .iter()
            .all(|(file, _)| file.ends_with("busbar-kernel/src/connections/pkce.rs")),
        "{definitions:?}"
    );
    for caller in [
        "busbar-core-oauth2/src/hosted_login.rs",
        "busbar-kernel/src/connections/store.rs",
    ] {
        assert!(
            callers.iter().any(|f| f.ends_with(caller)),
            "{caller} calls the one module: {callers:?}"
        );
    }
}

#[test]
#[ignore = "owner: W2-SW-AUTH, #275 (the hosted REDIRECT login BEGIN/COMPLETE through an auth port)"]
fn hosted_redirect_login_arms() {
    todo!("owner: W2-SW-AUTH (C-LOGIN-PKCE hosted login arm)")
}
