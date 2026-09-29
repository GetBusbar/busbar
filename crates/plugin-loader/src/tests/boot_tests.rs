// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT STAGES' PROOFS: what a document uses, Select over discovered candidates (pure, RED arm
//! per class), and the one load binding each selected instance, linked and dropped, to its own log
//! file — an unselected plugin is never opened.

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::mechanism::door::{SECTION_CONSUMED, SECTION_DECLARING};
use busbar_contract::abi::mechanism::rendering::render;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::sdk::door::{abi_str, statement};

use super::*;
use crate::dispatch::NoSink;
use crate::plane_door_plugin as plug;

fn doc(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap()
}

/// A candidate of `kind` named `name`, with `aliases`, `sugar`, `verbs`, `schemes`.
fn cand(kind: KindCode, name: &str, aliases: &[&str], sugar: &[&str], verbs: &[&str]) -> Candidate {
    Candidate {
        kind,
        name: name.into(),
        aliases: aliases.iter().map(|s| s.to_string()).collect(),
        sugar: sugar.iter().map(|s| s.to_string()).collect(),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        schemes: Vec::new(),
        stated: Vec::new(),
        origin: Origin::Dropped {
            file: format!("{name}.tar.gz"),
            bytes: Arc::new(Vec::new()),
        },
    }
}

fn picked(sel: &[Selected], cands: &[Candidate]) -> Vec<(String, String)> {
    sel.iter()
        .map(|s| (cands[s.candidate].name.clone(), s.instance.clone()))
        .collect()
}

#[test]
fn uses_reads_each_class_of_root_key() {
    let u = Uses::of(&doc(r#"{
          "store": {"module": "mem"},
          "secrets": {"vaultish": {"addr": "https://v.example"}},
          "identity-providers": {"corp": {"module": "sso"}},
          "hooks": {"rank": {"module": "ranker"}},
          "export": {"metrics": {"module": "scrape"}},
          "providers": {"up": {"base_url": "wss://u.example/x", "api_key": {"envy": "K"}}},
          "tools": {}
        }"#));
    assert!(u.roots.contains("tools") && u.roots.contains("store"));
    assert_eq!(
        u.modules,
        vec![
            (KindCode::Store, "store".into(), "mem".into()),
            (KindCode::Secret, "vaultish".into(), "vaultish".into()),
            (KindCode::Auth, "corp".into(), "sso".into()),
            (KindCode::Hook, "rank".into(), "ranker".into()),
            (KindCode::Export, "metrics".into(), "scrape".into()),
        ]
    );
    assert!(
        u.refs.contains("envy"),
        "a one-key mapping is a reference: {:?}",
        u.refs
    );
    assert!(u.schemes.contains("wss") && u.schemes.contains("https"));
}

#[test]
fn select_follows_the_classes() {
    let u = Uses::of(&doc(
        r#"{"tools": {}, "export": {"metrics": {"module": "old-scrape"}, "logs": {"module": "file-sink"}},
            "providers": {"up": {"base_url": "https://u", "api_key": {"envy": "K"}}}}"#,
    ));
    let mut t = cand(KindCode::Transport, "tls-web", &[], &[], &[]);
    t.schemes = vec!["https".into()];
    let mut idle_t = cand(KindCode::Transport, "unix", &[], &[], &[]);
    idle_t.schemes = vec!["unix".into()];
    let cands = vec![
        cand(KindCode::Plane, "p-tools", &[], &[], &["tools"]),
        cand(KindCode::Plane, "p-agents", &[], &[], &["agents"]),
        cand(KindCode::Export, "scrape", &["old-scrape"], &[], &[]),
        cand(KindCode::Export, "file-sink", &[], &[], &[]),
        cand(KindCode::Export, "unused-sink", &[], &[], &[]),
        cand(KindCode::Secret, "envy-secret", &[], &["envy"], &[]),
        cand(KindCode::Secret, "filey", &[], &["filey"], &[]),
        t,
        idle_t,
    ];
    assert_eq!(
        picked(&select(&u, &cands), &cands),
        vec![
            ("p-tools".into(), "tools".into()),
            ("scrape".into(), "metrics".into()),
            ("file-sink".into(), "logs".into()),
            ("envy-secret".into(), "envy-secret".into()),
            ("tls-web".into(), "tls-web".into()),
        ]
    );
}

#[test]
fn a_module_of_another_kind_selects_nothing_and_the_first_candidate_answers() {
    let u = Uses::of(&doc(r#"{"hooks": {"h": {"module": "twin"}}}"#));
    let cands = vec![
        cand(KindCode::Export, "twin", &[], &[], &[]),
        cand(KindCode::Hook, "twin", &[], &[], &[]),
        cand(KindCode::Hook, "twin", &[], &[], &[]),
    ];
    let sel = select(&u, &cands);
    assert_eq!(
        sel,
        vec![Selected {
            candidate: 1,
            instance: "h".into()
        }]
    );
}

#[test]
fn a_candidate_reads_its_facts_off_its_rendering() {
    const REWRITES: &[busbar_contract::abi::mechanism::door::Rewrite] = &[
        busbar_contract::abi::mechanism::door::Rewrite {
            class: busbar_contract::abi::mechanism::door::REWRITE_ALIAS,
            _reserved: 0,
            from: abi_str("old"),
            to: abi_str(""),
        },
        busbar_contract::abi::mechanism::door::Rewrite {
            class: busbar_contract::abi::mechanism::door::REWRITE_SUGAR,
            _reserved: 0,
            from: abi_str("sug"),
            to: abi_str(""),
        },
    ];
    const SECTIONS: &[busbar_contract::abi::mechanism::door::Section] = &[
        busbar_contract::abi::mechanism::door::Section {
            name: abi_str("verb"),
            flags: SECTION_DECLARING,
            _reserved: 0,
        },
        busbar_contract::abi::mechanism::door::Section {
            name: abi_str("read-only"),
            flags: SECTION_CONSUMED,
            _reserved: 0,
        },
    ];
    let st = busbar_contract::abi::mechanism::door::Statement {
        kind: KindCode::Secret as u32,
        rewrites: REWRITES.as_ptr(),
        rewrites_len: REWRITES.len(),
        sections: SECTIONS.as_ptr(),
        sections_len: SECTIONS.len(),
        ..statement("the-plugin", "1.0.0", 1)
    };
    // SAFETY: the lists are `'static` arrays of their stated counts.
    let stated = unsafe { render(&st) }.unwrap();
    let c = Candidate::from_rendering(
        stated,
        Some("manifest-alias"),
        Vec::new(),
        Origin::Dropped {
            file: "f".into(),
            bytes: Arc::new(Vec::new()),
        },
    )
    .unwrap();
    assert_eq!(c.kind, KindCode::Secret);
    assert_eq!(c.name, "the-plugin");
    assert_eq!(
        c.aliases,
        vec!["old".to_string(), "manifest-alias".to_string()]
    );
    assert_eq!(c.sugar, vec!["sug".to_string()]);
    assert_eq!(c.verbs, vec!["verb".to_string()]);
    assert!(Candidate::from_rendering(
        b"not a rendering".to_vec(),
        None,
        Vec::new(),
        Origin::Dropped {
            file: "f".into(),
            bytes: Arc::new(Vec::new())
        }
    )
    .is_err());
}

fn example_cdylib(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    assert!(
        path.exists() || std::env::var_os("CI").is_none(),
        "the {name} example cdylib is not built under CI; a both-ways proof must not skip"
    );
    path.exists().then_some(path)
}

/// THE ONE LOAD, both origins: the plane door linked and the same plane dropped in (its verified
/// bytes), each selected by its verb under its own instance and bound to its own log file; an
/// unselected candidate is never opened (its bytes are not a library at all).
#[test]
fn the_one_load_binds_each_selected_instance_to_its_own_log_sink() {
    let dir = std::env::temp_dir().join(format!("busbar-boot-load-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let logs = PluginLogConfig::from_words(
        Some(dir.to_str().unwrap()),
        Some("info"),
        &Default::default(),
        None,
        None,
    )
    .unwrap();
    let linked = Candidate::linked(plug::door, Vec::new()).expect("the linked plane states itself");
    assert_eq!(linked.verbs, vec!["door".to_string()]);
    let mut cands = vec![linked.clone()];
    let mut uses = Uses::default();
    uses.roots.insert("door".into());
    if let Some(path) = example_cdylib("plane_door_plugin") {
        let mut dropped = linked.clone();
        dropped.origin = Origin::Dropped {
            file: "plane-door.tar.gz".into(),
            bytes: Arc::new(std::fs::read(path).unwrap()),
        };
        // A second instance of the same verb is taken by the first candidate: select it by hand.
        cands.push(dropped);
    }
    let mut never = cand(
        KindCode::Plane,
        "never-opened",
        &[],
        &[],
        &["not-configured"],
    );
    never.stated = linked.stated.clone();
    cands.push(never);
    let mut selected = select(&uses, &cands);
    assert_eq!(
        selected,
        vec![Selected {
            candidate: 0,
            instance: "door".into()
        }]
    );
    if cands.len() == 3 {
        selected.push(Selected {
            candidate: 1,
            instance: "door-dropped".into(),
        });
    }
    let loaded = load(&LoadRequest {
        candidates: &cands,
        selected: &selected,
        logs: &logs,
        metrics: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        max_inflight_cap: 8,
    })
    .expect("every selected instance binds");
    assert_eq!(loaded.bound.len(), selected.len());
    assert!(loaded
        .bound
        .iter()
        .all(|(_, b)| matches!(b, Bound::Plane(_))));
    for s in &selected {
        assert!(
            dir.join(format!("{}.log", s.instance)).exists(),
            "{} has its own log file",
            s.instance
        );
    }
    assert!(!dir.join("never-opened.log").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// RED: an instance that will not bind refuses the load, naming it — here a dropped plugin whose
/// stated Statement is not its door's.
#[test]
fn red_an_instance_that_will_not_bind_is_named() {
    let Some(path) = example_cdylib("plane_door_plugin") else {
        return;
    };
    let mut c = Candidate::linked(plug::door, Vec::new()).unwrap();
    c.origin = Origin::Dropped {
        file: "plane-door.tar.gz".into(),
        bytes: Arc::new(std::fs::read(path).unwrap()),
    };
    let last = c.stated.len() - 1;
    c.stated[last] ^= 1;
    let logs = PluginLogConfig::from_words(None, None, &Default::default(), None, None).unwrap();
    let err = load(&LoadRequest {
        candidates: &[c],
        selected: &[Selected {
            candidate: 0,
            instance: "door".into(),
        }],
        logs: &logs,
        metrics: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        max_inflight_cap: 8,
    })
    .unwrap_err();
    assert!(err.starts_with("door: ") && err.contains("repack"), "{err}");
}
