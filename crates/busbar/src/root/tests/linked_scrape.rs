// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SCRAPE SINK, BOTH DOORS, ONE ROW** — #2 rule (1) on the export axis, at the composition
//! root, for the export sink the shipped binary LINKS (K9d).
//!
//! The linked door is the real one: the build's generated [`Linked::exports`] table, stated as rows
//! by [`linked_exports`] — the rows [`dropped_from_config`] links ahead of the plugins directory's. The dropped-in door is the same
//! crate's `cdylib` (a `["cdylib", "rlib"]` crate, so this binary's target dir holds it), signed
//! first-party under the statement the linked row makes and found by the scan boot runs over
//! `plugins.dir`. Neither arm names the sink: the linked one is the table's row whose sink carries
//! the `metrics` stream, the dropped-in one the `cdylib` in the target dir that loads as an export
//! sink carrying the same streams and routes.
//!
//! [`conform`] is the proof: the two rows state the same plugin and are both first-party (what the
//! host grants), and the two opened sinks carry the same streams, claim the same routes, refuse the
//! same settings in the same words, and render the host recorder's snapshot into the same bytes —
//! which are the recorder's own. Its RED arm stays in the test: the same `cdylib` dropped in under a
//! THIRD-PARTY signature is a different row, and `conform` says so.

use super::*;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{DynExport, LoadablePlugin, PluginRegistry};

/// The settings every opened sink is handed, and the settings the refusal comparison walks.
const SETTINGS: &str = r#"{"buffer_seconds":60}"#;

/// The linked table's scrape sink: the registry the boot installs with no plugins directory, and
/// the name of the row whose sink carries the `metrics` stream — `None` when this build links no
/// such sink (a `--no-default-features` or single-plane build links no export crate at all).
fn linked_scrape_sink() -> Option<(PluginRegistry, String)> {
    let rows = linked_exports(crate::LINKED.exports).expect("the linked export sinks state rows");
    let axis = PluginRegistry::empty()
        .link(rows)
        .expect("the linked export sinks are admitted");
    let scrapes = |name: &String| {
        let sink = axis.open_export(name, SETTINGS);
        sink.is_ok_and(|s| {
            s.streams()
                .contains(&busbar_plugin_loader::ExportStream::Metrics)
        })
    };
    let names = axis.linked().iter().map(|p| p.manifest.name.clone());
    let name = names.into_iter().find(scrapes)?;
    Some((axis, name))
}

/// The `cdylib` in this target dir (uplifted or under `deps`, newest first) that loads as an export
/// sink with exactly `linked`'s streams and routes. Under CI a missing artifact is a failure.
fn dropped_in_cdylib(linked: &DynExport) -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let mut found: Vec<(std::time::SystemTime, std::path::PathBuf)> =
        [profile.to_path_buf(), profile.join("deps")]
            .iter()
            .flat_map(|dir| {
                busbar_plugin_loader::list_plugin_files(dir)
                    .into_iter()
                    .map(move |f| dir.join(f))
            })
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .collect();
    found.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    let lib = found.into_iter().find_map(|(_, p)| {
        let bytes = std::fs::read(&p).ok()?;
        let sink =
            busbar_plugin_loader::load_export_from_bytes(&bytes, SETTINGS, "probe", "export")
                .ok()?;
        let same = sink.streams() == linked.streams() && sink.routes() == linked.routes();
        same.then_some(bytes)
    });
    assert!(
        lib.is_some() || std::env::var_os("CI").is_none(),
        "the scrape sink's cdylib is not built under CI; the both-doors proof must not skip"
    );
    lib
}

/// `lib` signed by `signer` under `manifest` into a fresh `plugins/` directory, scanned under the
/// default posture holding the release key (`[31; 32]`); any other signer is allowlisted as the
/// manifest's publisher (trusted, not first-party).
fn dropped(tag: &str, manifest: Manifest, lib: &[u8], signer: &SigningKey) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-dropped-export-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[31u8; 32]);
    let publisher = (manifest.publisher.clone(), signer.verifying_key());
    let signed = sign(signer, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libexport.so", lib).unwrap();
    std::fs::write(dir.join(format!("{tag}.tar.gz")), tarball).unwrap();
    let third_party = signer.verifying_key() != release.verifying_key();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: std::iter::once(publisher).filter(|_| third_party).collect(),
        allow_unsigned: false,
        allow_third_party: third_party,
        min_versions: Default::default(),
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// What a row STATES (every manifest field but the two describing a tarball) and what the host
/// grants it.
fn statement(p: &LoadablePlugin) -> String {
    let mut m = p.manifest.clone();
    m.sha256 = String::new();
    m.signature = String::new();
    format!("{m:?} first_party={}", p.first_party())
}

/// The recorder exposition the scrape comparison renders: this process's real one (every family
/// the kernel emits here, after a few writes) — never empty, so the proof is not vacuous.
fn recorder_exposition() -> String {
    busbar_kernel::metrics::init();
    metrics::counter!("busbar_k9d_conformance_total", "note" => "a \"quoted\" \\ value")
        .increment(3);
    metrics::gauge!("busbar_k9d_conformance_gauge").set(1.5);
    metrics::histogram!("busbar_k9d_conformance_seconds").record(0.25);
    let own = busbar_kernel::metrics::render();
    assert!(own.contains("busbar_k9d_conformance_total"), "{own}");
    own
}

/// THE PROOF: `a` and `b` — the row `name` resolves to on each registry — are one plugin.
fn conform(a: &PluginRegistry, b: &PluginRegistry, name: &str, own: &str) -> Result<(), String> {
    let (ra, rb) = (a.resolve(name).ok_or("a")?, b.resolve(name).ok_or("b")?);
    if statement(ra) != statement(rb) {
        return Err(format!(
            "the rows differ:\n  {}\n  {}",
            statement(ra),
            statement(rb)
        ));
    }
    let (sa, sb) = (
        a.open_export(name, SETTINGS)?,
        b.open_export(name, SETTINGS)?,
    );
    if (sa.streams(), sa.routes()) != (sb.streams(), sb.routes()) {
        return Err("the sinks carry different streams or routes".into());
    }
    for settings in [
        serde_json::json!({ "buffer_seconds": 60 }),
        serde_json::json!({}),
        serde_json::json!({ "buffer_seconds": 60, "buffer": 1 }),
        serde_json::json!({ "buffer_seconds": "sixty" }),
    ] {
        let (va, vb) = (sa.validate("m", &settings)?, sb.validate("m", &settings)?);
        if va != vb {
            return Err(format!(
                "the sinks refuse {settings} differently: {va:?} / {vb:?}"
            ));
        }
    }
    let families = busbar_plugin_loader::scrape::snapshot(own)?;
    let (ea, eb) = (sa.scrape(families.clone())?, sb.scrape(families)?);
    if ea != eb {
        return Err("the sinks render the snapshot differently".into());
    }
    if ea.1 != own {
        return Err("the rendering is not the recorder's own bytes".into());
    }
    Ok(())
}

/// THE EXIT TEST (K9d). The linked scrape sink and the same crate dropped in are one row, one
/// sink: same statement, same grant, same streams and routes, same refusals, same bytes — the
/// recorder's. RED arm: the same library dropped in under a third-party signature is refused by
/// the same comparison.
#[test]
fn a_linked_and_a_dropped_in_scrape_sink_are_one_row_and_render_the_same_bytes() {
    // Whether THIS build links a scrape sink is the linked table's answer, not a feature name: a
    // build that links none (no export crate, or none carrying the `metrics` stream) has nothing
    // to compare and builds nothing to drop in.
    let Some((linked, name)) = linked_scrape_sink() else {
        return;
    };
    let probe = linked
        .open_export(&name, SETTINGS)
        .expect("the linked sink opens");
    let Some(lib) = dropped_in_cdylib(&probe) else {
        eprintln!("skip: the scrape sink's cdylib is not built");
        return;
    };
    let manifest = linked
        .resolve(&name)
        .expect("the linked row")
        .manifest
        .clone();
    let release = SigningKey::from_bytes(&[31u8; 32]);
    let own = recorder_exposition();

    let first_party = dropped("first-party", manifest.clone(), &lib, &release);
    assert_eq!(conform(&linked, &first_party, &name, &own), Ok(()));

    // The boot before the linked row: nothing on the axis answers the module the table links.
    let before = PluginRegistry::empty()
        .link(Vec::new())
        .expect("an empty axis");
    assert!(
        conform(&before, &first_party, &name, &own).is_err(),
        "the boot that links no export sink resolves no scrape sink"
    );

    let mut third = manifest;
    third.publisher = "acme".into();
    let third_party = dropped(
        "third-party",
        third,
        &lib,
        &SigningKey::from_bytes(&[32u8; 32]),
    );
    let refused = conform(&linked, &third_party, &name, &own);
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.starts_with("the rows differ")),
        "a dropped-in row that is not the linked one must not conform: {refused:?}"
    );
}
