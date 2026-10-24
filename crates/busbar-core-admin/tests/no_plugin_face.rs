// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN SURFACE IS NO PLUGIN (THE DESIGN §8: "Exactly three crates are compiled in and are
//! never plugins"; R6: `busbar-core-admin` stays core, "not plugins"; §6 step 3: a claimant is "a
//! plane, a plugin's inbound need, or a cleanliness crate's route (admin, oauth2)").
//!
//! Its one claim is a cleanliness crate's route on the guest list, declared as data. So the crate's
//! shipped source implements neither the plugin face nor a plane's declaration row, and names no
//! plugin kind for itself. A scan (tests excluded, comments skipped) fails, naming `file:line`, on:
//!
//! * (a) an `impl ... Plugin for` (the registry's plugin face);
//! * (b) an `impl ... PlaneMeta for` (a plane's declaration row);
//! * (c) `Kind::Plane` (the crate naming itself a plane-kind plugin).

use std::path::{Path, PathBuf};

/// A shipped-source line's verdict: which rule it breaks, if any.
fn offends(line: &str) -> Option<&'static str> {
    let code = line.trim_start();
    if code.starts_with("//") {
        return None;
    }
    if code.starts_with("impl") && (code.contains(" Plugin for ") || code.contains("::Plugin for "))
    {
        return Some("(a) the plugin face");
    }
    if code.starts_with("impl") && code.contains("PlaneMeta for ") {
        return Some("(b) a plane's declaration row");
    }
    if code.contains("Kind::Plane") {
        return Some("(c) a plane-kind name for itself");
    }
    None
}

/// Shipped source, as opposed to a fixture or a test.
fn is_shipped_source(path: &Path) -> bool {
    let rel = path.to_string_lossy().replace('\\', "/");
    !rel.contains("/tests/")
        && !rel.ends_with("/tests.rs")
        && !rel.ends_with("_test.rs")
        && !rel.ends_with("_tests.rs")
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the crate's src tree is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            walk(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

/// RED while the admin surface carried `impl Plugin for AdminPlane { fn kind() -> Kind::Plane }`
/// and `impl PlaneMeta for AdminPlane`, and the composition root registered it as "the core plane".
#[test]
fn the_admin_surface_implements_no_plugin_face() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    let shipped: Vec<&PathBuf> = files.iter().filter(|p| is_shipped_source(p)).collect();
    assert!(
        shipped
            .iter()
            .any(|p| p.ends_with("src/admin_codec/claims.rs")),
        "the scan never reached the file that declares the admin claim: {shipped:?}"
    );
    let mut offenders = Vec::new();
    for path in shipped {
        let text = std::fs::read_to_string(path).expect("a source file reads");
        for (n, line) in text.lines().enumerate() {
            if let Some(rule) = offends(line) {
                offenders.push(format!(
                    "{}:{}: {rule}: {}",
                    path.display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the admin surface presents itself as a plugin (§8, R6): {offenders:#?}"
    );
}

/// The scan sees each shape it forbids and not the crate's own traits or prose.
#[test]
fn the_plugin_face_scan_sees_what_it_forbids_and_nothing_else() {
    assert!(offends("impl Plugin for AdminPlane {").is_some());
    assert!(offends("impl busbar_contract::plugin::Plugin for AdminPlane {").is_some());
    assert!(offends("impl PlaneMeta for AdminPlane {").is_some());
    assert!(offends("        Kind::Plane").is_some());
    assert!(offends("impl AppAdmin for App {").is_none());
    assert!(offends("/// impl Plugin for X is what this rule forbids").is_none());
}
