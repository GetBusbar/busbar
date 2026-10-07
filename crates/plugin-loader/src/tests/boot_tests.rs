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
        version: "1.0.0".into(),
        aliases: aliases.iter().map(|s| s.to_string()).collect(),
        sugar: sugar.iter().map(|s| s.to_string()).collect(),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        schemes: Vec::new(),
        needs: Vec::new(),
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
        conns: crate::dispatch::ConnTable::NoNeeds,
        max_inflight_cap: 8,
        opening: None,
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
        conns: crate::dispatch::ConnTable::NoNeeds,
        max_inflight_cap: 8,
        opening: None,
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
        former_names: Vec::new(),
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
        let bound = load_planes(
            &set.doors,
            &logs,
            Arc::new(NoSink),
            Adopter::unwatched(),
            8,
            crate::dispatch::ConnTable::NoNeeds,
        )
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
    let err = load_planes(
        &set.doors,
        &logs,
        Arc::new(NoSink),
        Adopter::unwatched(),
        8,
        crate::dispatch::ConnTable::NoNeeds,
    )
    .expect_err("a pin naming no mechanism must refuse the boot");
    assert!(err.contains("trust_key.mechanisms"), "{err}");
    // The GREEN twin: the unmodified door binds.
    let ok = crate::PluginRegistry::empty()
        .open_planes(&[plug::door])
        .unwrap();
    load_planes(
        &ok.doors,
        &logs,
        Arc::new(NoSink),
        Adopter::unwatched(),
        8,
        crate::dispatch::ConnTable::NoNeeds,
    )
    .expect("the well-formed plane binds");
}

// ── INBOUND: listener needs and their binds ──

fn need(direction: u32, transport: &str, target_from: &str) -> ReadNeed {
    ReadNeed {
        direction,
        egress_class: 0,
        transport: transport.into(),
        auth: String::new(),
        target_from: target_from.into(),
        trust_from: String::new(),
        details: busbar_contract::abi::mechanism::rendering::ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

fn listening(kind: KindCode, name: &str, verbs: &[&str], needs: Vec<ReadNeed>) -> Candidate {
    Candidate {
        needs,
        ..cand(kind, name, &[], &[], verbs)
    }
}

fn sel(candidate: usize, instance: &str) -> Selected {
    Selected {
        candidate,
        instance: instance.into(),
    }
}

use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;

/// Every selected instance's INBOUND need is collected with the bind its settings block states — a
/// plane's from its verb's section, an export's from its entry's `settings` — the TLS block kept raw
/// (secret references unresolved), the cap defaulted; outbound needs and unselected plugins are not.
#[test]
fn inbound_needs_are_collected_with_their_binds_from_instance_settings() {
    let d = doc(r#"{
        "agents": {"ingress": {"edge": {"listen": "127.0.0.1:9443",
            "tls": {"cert": {"ref": "c"}, "key": {"ref": "k"}}}}},
        "export": {"scrape": {"module": "sink",
            "settings": {"serve": {"listen": "0.0.0.0:9100", "max_conns": 8}}}}
    }"#);
    let cands = vec![
        listening(
            KindCode::Plane,
            "p1",
            &["agents"],
            vec![
                need(DIRECTION_OUTBOUND, "scheme-c", ""),
                need(DIRECTION_INBOUND, "scheme-a", "ingress.edge"),
            ],
        ),
        listening(
            KindCode::Export,
            "sink",
            &[],
            vec![need(DIRECTION_INBOUND, "scheme-b", "serve")],
        ),
        listening(
            KindCode::Plane,
            "unused",
            &["tools"],
            vec![need(DIRECTION_INBOUND, "scheme-b", "nowhere")],
        ),
    ];
    let got = inbound(
        &d,
        &cands,
        &[sel(0, "agents"), sel(1, "scrape")],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(
        got[0].owner,
        BindOwner::Need {
            instance: "agents".into(),
            kind: KindCode::Plane,
            need: 1,
        },
        "the need's index in its Statement"
    );
    assert_eq!(got[0].transport, "scheme-a");
    assert_eq!(got[0].at, "agents.ingress.edge");
    assert_eq!(got[0].listen, "127.0.0.1:9443".parse().unwrap());
    assert_eq!(got[0].max_conns, DEFAULT_MAX_CONNS);
    assert_eq!(
        got[0].tls,
        Some(doc(r#"{"cert": {"ref": "c"}, "key": {"ref": "k"}}"#)),
        "the TLS block stays raw: its references resolve at stage 3f"
    );
    assert_eq!(got[1].at, "export.scrape.settings.serve");
    assert_eq!(got[1].max_conns, 8);
    assert_eq!(got[1].tls, None);
}

/// RED: an inbound need with no block, no `listen`, a bad address or a bad cap is refused, naming
/// the setting.
#[test]
fn red_an_inbound_need_without_a_usable_bind_is_refused_by_its_setting() {
    let one = |settings: &str, target_from: &str| {
        let d = doc(&format!(r#"{{"agents": {settings}}}"#));
        let c = vec![listening(
            KindCode::Plane,
            "p1",
            &["agents"],
            vec![need(DIRECTION_INBOUND, "scheme-a", target_from)],
        )];
        inbound(&d, &c, &[sel(0, "agents")], Vec::new()).unwrap_err()
    };
    assert!(one("{}", "").contains("names no settings block"));
    assert_eq!(
        one("{}", "ingress"),
        "agents.ingress: not set; an inbound listener needs `listen`"
    );
    assert_eq!(
        one(r#"{"ingress": {}}"#, "ingress"),
        "agents.ingress.listen: not set"
    );
    assert_eq!(
        one(r#"{"ingress": {"listen": "localhost"}}"#, "ingress"),
        "agents.ingress.listen: `localhost` is not an ip:port address"
    );
    assert_eq!(
        one(
            r#"{"ingress": {"listen": "127.0.0.1:1", "max_conns": 0}}"#,
            "ingress"
        ),
        "agents.ingress.max_conns: not a positive whole number"
    );
}

/// RED: two listeners on one address, or a listener on an address the host's own listener takes
/// (the root `listen`), are refused before anything binds; an unspecified IP takes the port on
/// every address.
#[test]
fn red_two_listeners_on_one_address_are_refused() {
    let d = doc(r#"{
        "agents": {"a": {"listen": "0.0.0.0:9000"}, "b": {"listen": "127.0.0.1:9000"}}
    }"#);
    let c = vec![listening(
        KindCode::Plane,
        "p1",
        &["agents"],
        vec![
            need(DIRECTION_INBOUND, "scheme-a", "a"),
            need(DIRECTION_INBOUND, "scheme-b", "b"),
        ],
    )];
    assert_eq!(
        inbound(&d, &c, &[sel(0, "agents")], Vec::new()).unwrap_err(),
        "agents.b.listen: 127.0.0.1:9000 is already taken by `agents.a.listen`"
    );
    let d = doc(r#"{"agents": {"a": {"listen": "127.0.0.1:8080"}}}"#);
    let c = vec![listening(
        KindCode::Plane,
        "p1",
        &["agents"],
        vec![need(DIRECTION_INBOUND, "scheme-a", "a")],
    )];
    let root = vec![InboundBind {
        owner: BindOwner::Root,
        transport: String::new(),
        at: "listen".into(),
        listen: "0.0.0.0:8080".parse().unwrap(),
        tls: None,
        max_conns: u64::MAX,
    }];
    assert_eq!(
        inbound(&d, &c, &[sel(0, "agents")], root).unwrap_err(),
        "agents.a.listen: 127.0.0.1:8080 is already taken by `listen`"
    );
    let d = doc(r#"{"agents": {"a": {"listen": "127.0.0.1:0"}, "b": {"listen": "127.0.0.1:0"}}}"#);
    let c = vec![listening(
        KindCode::Plane,
        "p1",
        &["agents"],
        vec![
            need(DIRECTION_INBOUND, "scheme-a", "a"),
            need(DIRECTION_INBOUND, "scheme-b", "b"),
        ],
    )];
    assert_eq!(
        inbound(&d, &c, &[sel(0, "agents")], Vec::new())
            .unwrap()
            .len(),
        2,
        "port 0 asks for a free one and never collides"
    );
}

/// A Statement's needs are read off its rendering into the candidate.
#[test]
fn a_candidate_carries_its_statements_needs() {
    use busbar_contract::abi::host::conn::connector::{Need, KEEP_NAMED};
    use busbar_contract::abi::mechanism::call::Blob;
    const NEEDS: &[Need] = &[Need {
        direction: DIRECTION_INBOUND,
        egress_class: 0,
        transport: abi_str("scheme-a"),
        auth: abi_str(""),
        target_from: abi_str("ingress"),
        trust_from: abi_str(""),
        details: Blob {
            fmt: 0,
            flags: 0,
            len: 0,
            ptr: core::ptr::null(),
        },
        keep_response_headers: core::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: core::ptr::null(),
        deny_response_headers_len: 0,
    }];
    let st = busbar_contract::abi::mechanism::door::Statement {
        kind: KindCode::Plane as u32,
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        ..statement("p", "1.0.0", 1)
    };
    // SAFETY: the list is a `'static` array of its stated count.
    let stated = unsafe { render(&st) }.unwrap();
    let c = Candidate::from_rendering(
        stated,
        None,
        Origin::Dropped {
            file: "f".into(),
            bytes: Arc::new(Vec::new()),
        },
    )
    .unwrap();
    assert_eq!(
        c.needs,
        vec![need(DIRECTION_INBOUND, "scheme-a", "ingress")]
    );
}

/// The secret kind's resolver, for the boot witnesses: an `env` reference to `OIDC_SECRET`
/// resolves to the auth witness's secret; anything else does not resolve.
struct Resolver;

impl busbar_contract::secret::SecretResolve for Resolver {
    fn resolve(&self, r: &busbar_contract::secret_ref::SecretRef) -> Result<Vec<u8>, String> {
        use crate::dispatch::ready::ready_plugins::auth;
        match r.env_var() {
            Some("OIDC_SECRET") => Ok(auth::SECRET.to_vec()),
            _ => Err(format!("{} is not set", r.describe())),
        }
    }

    fn resolve_string(&self, r: &busbar_contract::secret_ref::SecretRef) -> Result<String, String> {
        self.resolve(r)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }
}

/// Boot one auth instance `oidc` of the witness `door` named `name`, its settings block `settings`
/// (JSON), through the one load with its opening: the number of instances bound, or the refusal.
fn boot_auth(door: DoorFn, name: &str, settings: &str) -> Result<usize, String> {
    use crate::dispatch::{DispatchConfig, Dispatcher};
    let d = Dispatcher::new(DispatchConfig::default());
    let c = Candidate::linked(door).expect("the auth witness states itself");
    assert_eq!(c.kind, KindCode::Auth);
    let root = kind_of(KindCode::Auth)
        .root_key()
        .expect("auth has a root key");
    let plan = doc(&format!(
        r#"{{"{root}": {{"oidc": {{"module": "{name}", "settings": {settings}}}}}}}"#
    ));
    let cands = [c];
    let selected = select(&Uses::of(&plan), &cands);
    assert_eq!(selected.len(), 1, "the auth entry selects the witness");
    let logs = PluginLogConfig::from_words(None, None, &Default::default(), None, None).unwrap();
    load(&LoadRequest {
        candidates: &cands,
        selected: &selected,
        logs: &logs,
        metrics: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
        max_inflight_cap: 8,
        opening: Some(Opening {
            doc: &plan,
            dispatcher: &d,
            secrets: &Resolver,
        }),
    })
    .map(|l| l.bound.len())
}

/// DISCOVERY AT BOOT (ARCHITECT 2026-10-02): the one load OPENS every auth instance it binds and
/// awaits its `ready` before it answers, so before any listener binds. RED: an auth door whose
/// `ready` errs refuses the boot with the plugin's own text, named by its instance (1.5.5 refused
/// the boot when discovery failed). The GREEN twin boots.
#[test]
fn red_an_auth_door_whose_ready_errs_refuses_the_boot_with_its_text() {
    use crate::dispatch::ready::ready_plugins::auth::{with_ready, NAME};
    assert_eq!(
        boot_auth(
            with_ready::door,
            NAME,
            r#""err:discovery: the issuer answered 503""#
        ),
        Err(
            "oidc: plugin 'ready-auth-witness' ready failed: discovery: the issuer answered 503"
                .to_string()
        )
    );
    assert_eq!(
        boot_auth(with_ready::door, NAME, r#""pend""#),
        Ok(1),
        "a ready that pends boots after its wake"
    );
    assert_eq!(
        boot_auth(with_ready::door, NAME, r#""ok""#),
        Ok(1),
        "the GREEN twin boots"
    );
}

/// THE DECLARED SECRETS AT AUTH OPEN (ARCHITECT 2026-10-02): an auth door that declares a secret
/// reference is handed it RESOLVED, through the secret kind, as its `OpenIn::secrets` entry — and
/// the reference is gone from its settings. RED before the resolver: it was handed an empty list
/// and its open refused. A reference that will not resolve refuses the boot, naming the key.
#[test]
fn red_an_auth_door_declaring_a_secret_ref_is_handed_it_resolved_at_open() {
    use crate::dispatch::ready::ready_plugins::auth::{with_secret, SECRET_NAME};
    assert_eq!(
        boot_auth(
            with_secret::door,
            SECRET_NAME,
            r#"{"issuer": "https://idp", "client_secret": {"env": "OIDC_SECRET"}}"#
        ),
        Ok(1)
    );
    let unresolved = boot_auth(
        with_secret::door,
        SECRET_NAME,
        r#"{"client_secret": {"env": "NOT_SET"}}"#,
    )
    .unwrap_err();
    assert!(
        unresolved.starts_with("oidc: settings.client_secret: the secret did not resolve"),
        "{unresolved}"
    );
    let unset = boot_auth(with_secret::door, SECRET_NAME, "{}").unwrap_err();
    assert_eq!(
        unset,
        "oidc: plugin 'secret-auth-witness' open failed: 1 secret(s) handed, not the resolved \
         client_secret"
    );
}

/// A door that states nothing: the linked origin of a candidate built by hand.
extern "C" fn stating_nothing() -> *const busbar_contract::abi::mechanism::door::Door {
    std::ptr::null()
}

/// `cand` at `version`, LINKED.
fn linked_cand(name: &str, version: &str) -> Candidate {
    Candidate {
        version: version.into(),
        origin: Origin::Linked(crate::dispatch::LinkedRow {
            statement: Vec::new(),
            door: stating_nothing,
        }),
        ..cand(KindCode::Hook, name, &["short"], &[], &[])
    }
}

/// `cand` at `version`, DROPPED IN as `<name>.tar.gz`.
fn dropped_cand(name: &str, version: &str) -> Candidate {
    Candidate {
        version: version.into(),
        ..cand(KindCode::Hook, name, &["short"], &[], &[])
    }
}

/// THE ONE-VERSION RULE ON AN AXIS'S CANDIDATES (ARCHITECT C'): one plugin (one Statement name)
/// linked and dropped in at ONE version is one plugin — admitted, the linked row first (it serves),
/// and named once for the log; at TWO versions the boot is refused, naming the plugin, both doors
/// and both versions. RED before: every same-name pair was skipped whatever its versions, so the
/// linked row silently won over a dropped-in copy of another version.
#[test]
fn one_plugin_by_both_doors_is_one_version_or_refused() {
    let same = [
        linked_cand("busbar-hook-x", "1.2.3"),
        dropped_cand("busbar-hook-x", "1.2.3"),
    ];
    one_owner(&same).expect("one plugin at one version");
    assert_eq!(
        both_doors(&same),
        vec![
            "plugin 'busbar-hook-x' v1.2.3 is linked and also dropped in (busbar-hook-x.tar.gz); \
             the linked build serves it"
                .to_string()
        ]
    );
    let uses = Uses {
        modules: vec![(KindCode::Hook, "h".into(), "short".into())],
        ..Uses::default()
    };
    assert_eq!(
        select(&uses, &same),
        vec![sel(0, "h")],
        "the linked row serves"
    );
    for pair in [
        [
            linked_cand("busbar-hook-x", "1.2.3"),
            dropped_cand("busbar-hook-x", "1.2.4"),
        ],
        [
            dropped_cand("busbar-hook-x", "1.2.4"),
            linked_cand("busbar-hook-x", "1.2.3"),
        ],
    ] {
        let refused = one_owner(&pair).expect_err("two versions of one plugin");
        assert_eq!(
            refused,
            "plugin 'busbar-hook-x' arrives by both doors at two versions: linked v1.2.3, dropped \
             in v1.2.4 (busbar-hook-x.tar.gz) - one version per plugin: remove one"
        );
        assert!(both_doors(&pair).is_empty());
    }
    // A Statement stating no version cannot be compared: refused, naming the plugin.
    assert_eq!(
        one_owner(&[
            linked_cand("busbar-hook-x", "1.2.3"),
            dropped_cand("busbar-hook-x", ""),
        ]),
        Err(
            "plugin 'busbar-hook-x' states no version in its Statement: the one-version rule \
             cannot compare it"
                .to_string()
        )
    );
    // Two DROPPED-IN candidates of one name are not two doors: phase 3 holds those.
    let dropped = [
        dropped_cand("busbar-hook-x", "1.2.3"),
        dropped_cand("busbar-hook-x", "1.2.4"),
    ];
    one_owner(&dropped).expect("not the one-version rule's pair");
}
