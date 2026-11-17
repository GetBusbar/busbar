// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use busbar_kernel::appbuild::{
    load_config_from_disk, load_config_from_disk_with_document_patches, AcceptAll, LoadedConfig,
};
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::config::named_map::NamedMapSection;
use busbar_kernel::config::overlay::{OverlayDoc, OverlaySection};
use busbar_kernel::config::EnvSubst;

struct Source(std::path::PathBuf);

impl Source {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-resource-ownership-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir.join("config.yaml"))
    }

    fn load(&self, section: &str) -> LoadedConfig {
        std::fs::write(
            &self.0,
            format!("auth:\n  admin_auth: []\n{section}:\n  same:\n    module: fixture-module\n"),
        )
        .unwrap();
        load_config_from_disk(&self.0, None, true, EnvSubst::Strict).unwrap()
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
        std::fs::remove_dir(self.0.parent().unwrap()).unwrap();
    }
}

fn collision(section: &str, definition: serde_json::Value) -> OverlayDoc {
    OverlayDoc {
        root: Some(serde_json::from_value(serde_json::json!({"per_request_fee": 77})).unwrap()),
        named_maps: BTreeMap::from([(
            section.to_owned(),
            BTreeMap::from([("same".to_owned(), definition)]),
        )]),
        ..Default::default()
    }
}

#[test]
fn disk_candidate_refuses_named_collisions_before_applying_any_overlay() {
    let source = Source::new("collision");
    for section in ["identity-providers", "export"] {
        for definition in [
            serde_json::json!({"module": "other-module"}),
            serde_json::json!({"module": "fixture-module"}),
            serde_json::json!({"not_a_definition": true}),
        ] {
            let mut loaded = source.load(section);
            loaded.overlay_doc = Some(collision(section, definition));
            let error = loaded.disk_candidate().map(|_| ()).unwrap_err();
            assert!(error.contains(section) && error.contains("same"), "{error}");
            assert!(
                error.contains("base") && error.contains("overlay"),
                "{error}"
            );
            assert!(
                !error.contains("other-module"),
                "no definition contents: {error}"
            );
            assert_eq!(
                loaded.deploy.per_request_fee, 0,
                "preflight precedes root mutation"
            );
        }
    }
}

#[test]
fn disk_candidate_allows_clearing_the_conflicting_section_before_admission() {
    let source = Source::new("reset");
    let mut loaded = source.load("identity-providers");
    let mut doc = collision(
        "identity-providers",
        serde_json::json!({"module": "stored"}),
    );
    doc.clear_section(OverlaySection::NamedMap(NamedMapSection::IdentityProviders));
    loaded.overlay_doc = Some(doc);
    let candidate = loaded.disk_candidate().unwrap();
    assert_eq!(
        candidate.identity_providers["same"].module,
        "fixture-module"
    );
    assert_eq!(candidate.per_request_fee, 77);
}

#[test]
fn composed_base_names_survive_overlay_replay_without_capturing_api_resources() {
    let source = Source::new("composed");
    std::fs::write(
        &source.0,
        "auth:\n  admin_auth: []\nhooks:\n  file:\n    module: fixture-hook\n    kind: gate\ngroups:\n  file: {}\n",
    )
    .unwrap();
    let patch = DocumentPatch::from_value(serde_json::json!({
        "set": {
            "/hooks/patched": {"module": "fixture-hook", "kind": "gate"},
            "/groups/patched": {}
        }
    }))
    .unwrap();
    let mut loaded = load_config_from_disk_with_document_patches(
        &source.0,
        None,
        false,
        EnvSubst::Strict,
        &AcceptAll,
        Some(&patch),
        None,
    )
    .unwrap();
    let doc = OverlayDoc {
        hooks: std::collections::HashMap::from([(
            "api".into(),
            serde_json::from_value(serde_json::json!({
                "kind": "gate", "module": "fixture-hook"
            }))
            .unwrap(),
        )]),
        groups: BTreeMap::from([("api".into(), Default::default())]),
        ..Default::default()
    };
    loaded.overlay_doc = Some(doc.clone());
    for _ in 0..2 {
        let mut candidate = loaded.disk_candidate().unwrap();
        busbar_kernel::config::overlay::merge_into(&mut candidate, doc.clone());
        for name in ["file", "patched"] {
            assert!(loaded.resource_ownership.hook_names().contains(name));
            assert!(loaded.resource_ownership.group_names().contains(name));
            assert!(candidate.hooks.contains_key(name));
            assert!(candidate.groups.contains_key(name));
        }
        assert!(!loaded.resource_ownership.hook_names().contains("api"));
        assert!(!loaded.resource_ownership.group_names().contains("api"));
        assert!(candidate.hooks.contains_key("api"));
        assert!(candidate.groups.contains_key("api"));
    }
}

#[test]
fn api_only_named_map_replay_uses_the_original_base_ownership() {
    let source = Source::new("replay");
    let mut loaded = source.load("identity-providers");
    loaded.overlay_doc = Some(OverlayDoc {
        named_maps: BTreeMap::from([(
            "identity-providers".into(),
            BTreeMap::from([(
                "api-only".into(),
                serde_json::json!({"module": "fixture-module"}),
            )]),
        )]),
        ..Default::default()
    });
    for _ in 0..2 {
        assert!(loaded
            .disk_candidate()
            .unwrap()
            .identity_providers
            .contains_key("api-only"));
    }
}

#[test]
fn clearing_one_section_does_not_admit_a_collision_in_another() {
    let source = Source::new("remaining-collision");
    let mut loaded = source.load("export");
    let mut doc = collision("export", serde_json::json!({"module": "stored-export"}));
    doc.named_maps.insert(
        "identity-providers".into(),
        BTreeMap::from([("other".into(), serde_json::json!({"module": "stored-auth"}))]),
    );
    doc.clear_section(OverlaySection::NamedMap(NamedMapSection::IdentityProviders));
    loaded.overlay_doc = Some(doc);
    let error = loaded.disk_candidate().map(|_| ()).unwrap_err();
    assert!(error.contains("export.same"), "{error}");
    assert_eq!(loaded.deploy.per_request_fee, 0);
}
