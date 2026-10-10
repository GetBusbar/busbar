// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER HOLDS NO DTLS (THE DESIGN l.749-757 and the who-sees-what row, l.657): DTLS runs in
//! the host's secure layer, and the framer never sees its keys, the certificate's private key or
//! its state. So the framer's source names no DTLS type:
//!
//! * no file of this crate (its dropped-in door included) names a DTLS ENGINE (`dimpl`, `rustls`, OpenSSL
//!   and its forks, `webrtc-dtls`, mbed TLS, wolfSSL), as code or as a dependency;
//! * no file but `src/shim.rs` names anything DTLS at all. The shim is the one adapter between the
//!   media stack's DTLS interface (the traits it calls in place of a handshake) and the host's
//!   lane: it relays the exported keying material and the verified bit, and runs no handshake.
//!
//! THE RED ARMS, kept: the same scan over a shim that names an engine, and over a framing that
//! names the media stack's DTLS interface, must refuse.

use std::path::{Path, PathBuf};

/// The DTLS engines: no file here may name one.
const ENGINES: [&str; 8] = [
    "dimpl",
    "rustls",
    "openssl",
    "boring",
    "webrtc_dtls",
    "webrtc-dtls",
    "mbedtls",
    "wolfssl",
];

/// The one file allowed to name the media stack's DTLS interface.
const SHIM: &str = "shim.rs";

fn crate_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join(name)
}

/// The line without its comment (`//` for Rust, `#` for a manifest).
fn code(line: &str, comment: &str) -> String {
    line.split(comment)
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// What `path` (relative to its crate) names that it may not.
fn findings(path: &str, text: &str) -> Vec<String> {
    let manifest = path.ends_with(".toml");
    let comment = if manifest { "#" } else { "//" };
    let file = path.rsplit('/').next().unwrap_or(path);
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = code(line, comment);
        for engine in ENGINES {
            if code.contains(engine) {
                out.push(format!("{path}:{}: names the DTLS engine `{engine}`", n + 1));
            }
        }
        if !manifest && file != SHIM && code.contains("dtls") {
            out.push(format!("{path}:{}: names DTLS outside the shim: {}", n + 1, line.trim()));
        }
    }
    out
}

/// Every shipped source file under `dir/src` (the crate's own `src/tests/` aside: tests name
/// what they test) and the crate's manifest, as `(path, text)`.
fn shipped(dir: &Path) -> Vec<(String, String)> {
    fn walk(d: &Path, rel: &str, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(d).expect("readable") {
            let p = e.expect("an entry").path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            let at = format!("{rel}/{name}");
            if p.is_dir() {
                if name != "tests" {
                    walk(&p, &at, out);
                }
            } else if name.ends_with(".rs") {
                out.push((at, std::fs::read_to_string(&p).expect("a source file")));
            }
        }
    }
    let mut out = vec![(
        "Cargo.toml".to_owned(),
        std::fs::read_to_string(dir.join("Cargo.toml")).expect("the manifest"),
    )];
    walk(&dir.join("src"), "src", &mut out);
    out
}

fn scan(files: &[(String, String)]) -> Vec<String> {
    files.iter().flat_map(|(p, t)| findings(p, t)).collect()
}

#[test]
fn the_framer_source_names_no_dtls_type() {
    let files = shipped(&crate_dir("busbar-transport-webrtc"));
    assert!(files.len() > 1, "the source is read");
    let found = scan(&files);
    assert!(found.is_empty(), "{}", found.join("\n"));
    // The scan read the shim with its allowance: the shim is where the interface is named.
    let shim = shipped(&crate_dir("busbar-transport-webrtc"))
        .into_iter()
        .find(|(p, _)| p == "src/shim.rs")
        .expect("src/shim.rs");
    assert!(shim.1.contains("impl DtlsInstance for Shim"));
}

// ── THE RED ARMS ────────────────────────────────────────────────────────────────────────────────

#[test]
fn red_arm_an_engine_in_the_shim_or_the_manifest_is_refused() {
    let found = findings("src/shim.rs", "use dimpl::{Config, Dtls};\n");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("`dimpl`"));
    let found = findings(
        "Cargo.toml",
        "[dependencies]\nrustls = { workspace = true } # a second secure layer\n",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    // A comment that names an engine is not code.
    assert!(findings("src/framing.rs", "// unlike dimpl, nothing here handshakes\n").is_empty());
}

#[test]
fn red_arm_the_dtls_interface_outside_the_shim_is_refused() {
    for (path, line) in [
        ("src/framing.rs", "use str0m::crypto::dtls::DtlsInstance;"),
        ("src/door.rs", "let cert: DtlsCert = todo!();"),
        ("src/crypto.rs", "impl DtlsProvider for Ring {}"),
    ] {
        let found = findings(path, line);
        assert_eq!(found.len(), 1, "{path}: {found:?}");
        assert!(found[0].contains("outside the shim"));
    }
    // The same line in the shim is its job.
    assert!(findings("src/shim.rs", "use str0m::crypto::dtls::DtlsInstance;").is_empty());
}
