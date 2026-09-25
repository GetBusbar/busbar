// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE EXPORT SINK, BOTH DOORS, ONE ROW** — #2 rule (1) on the export axis, at the composition root
//! (K9b).
//!
//! Every export sink this build links ([`Linked::exports`]) is a `["cdylib", "rlib"]` crate, so this
//! binary holds it two ways at once: LINKED (its statement and boundary, through [`linked_exports`],
//! the rows boot registers) and DROPPED IN (its cdylib, signed first-party under the SAME statement —
//! `declares` included, which is what `busbar-plugin-pack --declares-file` embeds — into a temp
//! `plugins/` directory and found by the scan boot runs). Each arm is opened by the one
//! `open_export`, its settings validated by the one `probe_export`, and driven through a rotation
//! scenario against a real file: the two arms must agree byte for byte on the row, on the
//! validation lines, on the grants the host makes (series, diagnostics) and on every file the
//! deliveries leave behind — lines, rotation and retention.
//!
//! No sink is named here: the rows come from the build's own table.
//!
//! ## Red-before-green, PERMANENTLY
//!
//! The RED arm is in the same test: the same cdylib dropped in WITHOUT its declarations (a tarball
//! packed without `--declares-file`) is not the same sink — the host binds it no destination, so its
//! deliveries leave no file, and its codes do not join the catalogue.

use super::*;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::PluginRegistry;

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// The built cdylib of the crate whose row is named `name` (uplifted or under `deps`, newest wins).
/// Under CI a missing artifact is a failure, never a skip.
fn cdylib(name: &str) -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let file = busbar_plugin_loader::plugin_library_filename(&name.replace('-', "_"));
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the {name} cdylib is not built under CI; a both-ways proof must not skip"
    );
    std::fs::read(found?).ok()
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = scratch(&format!("plugins-{tag}"));
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libsink.so", lib).unwrap();
    std::fs::write(dir.join("sink.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed sink scans")
}

/// A fresh scratch directory for this process.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-k9b-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What one door does with the row `name` resolves to, as one comparable transcript: the row's
/// statement, whether it is first-party, the codes it registers, the validation lines, the series
/// the host granted it, and — after a rotation scenario against a real file under `tag` — every
/// file left behind, by name relative to the scenario directory, with its bytes.
fn transcript(tag: &str, registry: &PluginRegistry, alias: &str) -> serde_json::Value {
    let p = registry.resolve(alias).expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let codes = declared_diagnostics(registry, &[]).map(|d| {
        d.iter()
            .map(|d| (d.code, d.slug, d.title, d.summary, d.action))
            .map(|(c, s, t, m, a)| format!("{c} {s} {t} {m} {a}"))
            .collect::<Vec<_>>()
    });
    let validation = [
        serde_json::json!({"path": "/x"}),
        serde_json::json!({}),
        serde_json::json!({"path": "/x", "rotate_mb": "one"}),
        serde_json::json!({"path": "/x", "rotate": 1}),
    ]
    .map(|s| registry.probe_export(alias, "tail", &s));

    // THE ROTATION SCENARIO: a live file already at `rotate_mb`, a full archive series (so the
    // oldest is retired), then three deliveries — the first rotates, the next two append.
    let dir = scratch(&format!("files-{tag}"));
    let path = dir.join("requests.jsonl");
    std::fs::write(&path, vec![b'x'; 1024 * 1024]).unwrap();
    for i in 1..=9 {
        std::fs::write(
            dir.join(format!("requests.jsonl.{i}")),
            format!("archive {i}\n"),
        )
        .unwrap();
    }
    let settings = serde_json::json!({"path": path.display().to_string(), "rotate_mb": 1});
    let sink = registry
        .open_export(alias, &settings.to_string())
        .expect("the sink opens");
    let granted: Vec<String> = stated
        .declares
        .metrics
        .iter()
        .filter(|d| {
            busbar_plugin_loader::observe::first_party_series(&stated.name, &d.name, &d.kind)
        })
        .map(|d| d.name.clone())
        .collect();
    for n in 0..3 {
        let line = serde_json::json!({"ingress_protocol": "k9b", "outcome": "ok", "ts": n});
        sink.deliver(busbar_plugin_loader::ExportStream::Logs, &line)
            .expect("the delivery completes");
    }
    let mut files: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .map(|f| {
            let bytes = std::fs::read(&f).unwrap();
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            let text = match bytes.len() > 4096 {
                true => format!("{} bytes", bytes.len()),
                false => String::from_utf8_lossy(&bytes).into_owned(),
            };
            (name, text)
        })
        .collect();
    files.sort();
    let _ = std::fs::remove_dir_all(&dir);
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "codes": codes,
        "validation": validation,
        "granted": granted,
        "files": files,
    })
}

/// Every linked export sink registers ONE row and behaves as ONE sink through either door — and
/// the same cdylib without its declarations does not (the RED arm).
#[test]
fn a_linked_and_a_dropped_in_export_sink_are_one_sink() {
    let rows = linked_exports(crate::LINKED.exports).expect("the linked sinks state their rows");
    assert!(
        !rows.is_empty() || crate::LINKED.exports.is_empty(),
        "every linked export sink states a row"
    );
    for row in rows {
        let (manifest, name) = (row.manifest.clone(), row.manifest.name.clone());
        let alias = manifest.alias.clone();
        let Some(lib) = cdylib(&name) else {
            continue;
        };
        let linked_registry = PluginRegistry::empty().link(vec![row]).unwrap();
        let linked = transcript("linked", &linked_registry, &alias);
        let dropped_registry = dropped("dropped", manifest.clone(), &lib);
        let dropped_in = transcript("dropped", &dropped_registry, &alias);
        assert_eq!(linked, dropped_in, "{name}: the two doors are not one sink");

        // The scenario did what the sink is for: the full archive series shifted up and the
        // oldest retired, the live file renamed to `.1`, and the three lines in a fresh file.
        let files = linked["files"].as_array().unwrap();
        assert_eq!(files.len(), 10, "{name}: {files:?}");
        assert_eq!(files[0][0], "requests.jsonl", "{name}");
        assert_eq!(
            files[0][1].as_str().unwrap().lines().count(),
            3,
            "{name}: {files:?}"
        );
        assert_eq!(
            files[1],
            serde_json::json!(["requests.jsonl.1", "1048576 bytes"])
        );
        assert_eq!(
            files[9],
            serde_json::json!(["requests.jsonl.9", "archive 8\n"])
        );
        assert_eq!(linked["first_party"], true, "{name}");

        // RED ARM: the same bytes, dropped in without their declarations.
        let bare = Manifest {
            declares: Default::default(),
            ..manifest
        };
        let red_registry = dropped("red", bare, &lib);
        let red = transcript("red", &red_registry, &alias);
        assert_ne!(
            red, linked,
            "{name}: an undeclared sink must not be the same sink"
        );
        let red_files = red["files"].as_array().unwrap();
        assert!(
            !red_files
                .iter()
                .any(|f| f[1].as_str().unwrap().contains("k9b")),
            "{name}: with no destination granted, no line may be written: {red_files:?}"
        );
    }
}
