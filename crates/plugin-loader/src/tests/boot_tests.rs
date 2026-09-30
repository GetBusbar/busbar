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
        Origin::Dropped {
            file: "f".into(),
            bytes: Arc::new(Vec::new())
        }
    )
    .is_err());
}

/// A dropped transport is selected by the URL schemes its signed rendering claims: Discover reads
/// them off the rendering, so nothing is opened to learn them (ARCHITECT ruling 2026-09-29).
#[test]
fn a_dropped_transport_is_selected_by_the_claims_its_rendering_states() {
    const CLAIMS: &[busbar_contract::abi::mechanism::call::AbiStr] =
        &[abi_str("tele"), abi_str("teles")];
    let st = busbar_contract::abi::mechanism::door::Statement {
        kind: KindCode::Transport as u32,
        claims: CLAIMS.as_ptr(),
        claims_len: CLAIMS.len(),
        ..statement("sockets", "1.0.0", 1)
    };
    let dropped = |st: &busbar_contract::abi::mechanism::door::Statement| {
        // SAFETY: the claims are a `'static` array of their stated count.
        let stated = unsafe { render(st) }.unwrap();
        Candidate::from_rendering(
            stated,
            None,
            Origin::Dropped {
                file: "sockets.tar.gz".into(),
                bytes: Arc::new(Vec::new()),
            },
        )
        .unwrap()
    };
    let c = dropped(&st);
    assert_eq!(c.schemes, vec!["tele".to_string(), "teles".to_string()]);
    let u = Uses::of(&doc(
        r#"{"providers": {"up": {"base_url": "teles://u.example"}}}"#,
    ));
    let cands = vec![c];
    assert_eq!(
        picked(&select(&u, &cands), &cands),
        vec![("sockets".to_string(), "sockets".to_string())]
    );
    // RED: the same transport claiming nothing is not selected.
    let cands = vec![dropped(&busbar_contract::abi::mechanism::door::Statement {
        claims_len: 0,
        ..st
    })];
    assert!(select(&u, &cands).is_empty());
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
    let linked = Candidate::linked(plug::door).expect("the linked plane states itself");
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
    let mut c = Candidate::linked(plug::door).unwrap();
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

/// THE PLANE AXIS, BOTH DOORS, ONE LOAD (ARCHITECT ruling 2026-09-29): the plane door linked
/// into the build and the same plane dropped into `plugins/` (an admitted tarball whose manifest
/// states its Statement) are discovered by `open_planes` as door candidates stating the same
/// rendering, and `load_planes` binds each through the one load — the dropped one over its verified
/// bytes. A dropped plane with no Statement stays on the HOT lane, never a door candidate.
#[test]
fn a_linked_and_a_dropped_plane_door_load_through_the_same_path() {
    let Some(path) = example_cdylib("plane_door_plugin") else {
        return;
    };
    let lib = std::fs::read(path).unwrap();
    let rendering = crate::dispatch::LinkedRow::of(plug::door)
        .unwrap()
        .statement;
    let dir = std::env::temp_dir().join(format!(
        "busbar-boot-planes-{}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = crate::sign::Manifest {
        name: "plane-door".into(),
        alias: "door".into(),
        kind: "plane".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: 1,
        sha256: crate::sign::sha256_hex(&lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: Some(hex::encode(&rendering)),
    };
    let tarball = crate::tarball::package(&manifest, "lib.so", &lib).unwrap();
    std::fs::write(dir.join("plane-door.tar.gz"), tarball).unwrap();
    let policy = crate::sign::TrustPolicy {
        first_party_key: None,
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: true,
        allow_third_party: true,
        min_versions: Default::default(),
    };
    let dropped = crate::scan_and_validate(&dir.join("."), &policy).expect("the plane scans");
    let logs = PluginLogConfig::from_words(
        Some(dir.join("logs").to_str().unwrap()),
        None,
        &Default::default(),
        None,
        None,
    )
    .unwrap();
    let bind = |set: crate::boot::PlaneSet| {
        assert!(set.hot.is_empty(), "a door plane is never a HOT-lane plane");
        let stated: Vec<Vec<u8>> = set.doors.iter().map(|c| c.stated.clone()).collect();
        let bound = load_planes(&set.doors, &logs, Arc::new(NoSink), Adopter::unwatched(), 8)
            .expect("the plane binds");
        (stated, bound)
    };
    let (linked_stated, linked) = bind(
        crate::PluginRegistry::empty()
            .open_planes(&[plug::door])
            .unwrap(),
    );
    let (dropped_stated, dropped_bound) = bind(dropped.open_planes(&[]).unwrap());
    assert_eq!(linked_stated, vec![rendering.clone()]);
    assert_eq!(
        dropped_stated, linked_stated,
        "both doors state one rendering"
    );
    let shape = |b: &[(String, Plugin<crate::dispatch::kinds::plane::Plane>)]| {
        b.iter()
            .map(|(i, p)| (i.clone(), p.name().to_string(), p.kind(), p.max_inflight()))
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&linked), shape(&dropped_bound), "one load, one shape");
    assert_eq!(shape(&linked).len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plane whose Statement tail declares a rooted pin naming NO mechanism is refused at boot: the
/// tail's trust keys are judged per element when the plane binds (`open_planes` discovers it,
/// `load_planes` refuses it), exactly as the door plane's whole tail is. The plane is the fixture's
/// own door with its tail's `trust_keys` swapped for a pin that names nothing to be rooted in.
#[test]
fn a_door_plane_declaring_a_pin_with_no_mechanism_is_refused_at_boot() {
    use busbar_contract::abi::mechanism::door::{Door, KindTailHead, Statement};
    use busbar_contract::abi::plane::{PlaneTail, TrustKey, TRUST_PIN};
    use std::sync::OnceLock;

    extern "C" fn bad_door() -> *const Door {
        static BAD: OnceLock<usize> = OnceLock::new();
        let door = *BAD.get_or_init(|| {
            // SAFETY: `plug::door` answers the fixture's `'static` Door, Statement and tail.
            unsafe {
                let good = plug::door();
                let mut tail = (*(*good).statement)
                    .kind_tail
                    .cast::<PlaneTail>()
                    .read_unaligned();
                let keys: &'static [TrustKey] = Box::leak(Box::new([TrustKey {
                    key: abi_str("anchor"),
                    role: TRUST_PIN,
                    flags: 0,
                    default: abi_str(""),
                    mechanisms: std::ptr::null(),
                    mechanisms_len: 0,
                }]));
                tail.trust_keys = keys.as_ptr();
                tail.trust_keys_len = keys.len();
                let tail: &'static PlaneTail = Box::leak(Box::new(tail));
                let mut st: Statement = *(*good).statement;
                st.kind_tail = std::ptr::from_ref(tail).cast::<KindTailHead>();
                let st: &'static Statement = Box::leak(Box::new(st));
                let mut d: Door = *good;
                d.statement = st;
                std::ptr::from_ref::<Door>(Box::leak(Box::new(d))) as usize
            }
        });
        door as *const Door
    }

    let logs = PluginLogConfig::from_words(None, None, &Default::default(), None, None).unwrap();
    let set = crate::PluginRegistry::empty()
        .open_planes(&[bad_door])
        .expect("the plane states itself");
    let err = load_planes(&set.doors, &logs, Arc::new(NoSink), Adopter::unwatched(), 8)
        .expect_err("a pin naming no mechanism must refuse the boot");
    assert!(err.contains("trust_key.mechanisms"), "{err}");
    // The GREEN twin: the unmodified door binds.
    let ok = crate::PluginRegistry::empty()
        .open_planes(&[plug::door])
        .unwrap();
    load_planes(&ok.doors, &logs, Arc::new(NoSink), Adopter::unwatched(), 8)
        .expect("the well-formed plane binds");
}
