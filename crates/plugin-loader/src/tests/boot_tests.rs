// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::mechanism::rendering::render;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::kinds::codes::KindCode;
use busbar_contract::plugin_settings::sugar_words::{SECTION_CONSUMED, SECTION_DECLARING};

use super::*;

fn doc(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap()
}

fn cand(kind: KindCode, name: &str, aliases: &[&str], sugar: &[&str], verbs: &[&str]) -> Candidate {
    Candidate {
        kind,
        name: name.into(),
        version: "1.0.0".into(),
        aliases: aliases.iter().map(|s| s.to_string()).collect(),
        sugar: sugar.iter().map(|s| s.to_string()).collect(),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        selecting: Vec::new(),
        schemes: Vec::new(),
        needs: Vec::new(),
        stated: Vec::new(),
        origin: Origin::Dropped {
            file: format!("{name}.tar.gz"),
            bytes: Arc::new(Vec::new()),
        },
        disk: false,
        orders: true,
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
            class: busbar_contract::plugin_settings::sugar_words::REWRITE_ALIAS,
            _reserved: 0,
            from: abi_str("old"),
            to: abi_str(""),
        },
        busbar_contract::abi::mechanism::door::Rewrite {
            class: busbar_contract::plugin_settings::sugar_words::REWRITE_SUGAR,
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

    let cands = vec![dropped(&busbar_contract::abi::mechanism::door::Statement {
        claims_len: 0,
        ..st
    })];
    assert!(select(&u, &cands).is_empty());
}

fn example_cdylib(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary's path");
    let path = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary sits in <profile>/deps")
        .join("examples")
        .join(format!(
            "{}{name}{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    if !path.exists() {
        crate::both_ways::missing(name, crate::both_ways::BUILD_EXAMPLES);
    }
    path
}

#[test]
#[should_panic(expected = "is not built: run")]
fn red_an_absent_example_cdylib_panics_with_its_build_command() {
    example_cdylib("no_such_example");
}

#[test]
fn a_dropped_plane_is_selected_by_a_section_that_selects_it() {
    use busbar_contract::abi::mechanism::door::Section;
    use busbar_contract::plugin_settings::sugar_words::{SECTION_REQUIRED, SECTION_SELECTS};
    const SECTIONS: &[Section] = &[
        Section {
            name: abi_str("pools"),
            flags: SECTION_DECLARING,
            _reserved: 0,
        },
        Section {
            name: abi_str("providers"),
            flags: SECTION_CONSUMED | SECTION_REQUIRED,
            _reserved: 0,
        },
        Section {
            name: abi_str("models"),
            flags: SECTION_CONSUMED | SECTION_REQUIRED | SECTION_SELECTS,
            _reserved: 0,
        },
    ];
    let st = busbar_contract::abi::mechanism::door::Statement {
        kind: KindCode::Plane as u32,
        sections: SECTIONS.as_ptr(),
        sections_len: SECTIONS.len(),
        ..statement("routing-plane", "1.0.0", 1)
    };
    // SAFETY: the sections list is a `'static` array of its stated count.
    let stated = unsafe { render(&st) }.unwrap();
    let c = Candidate::from_rendering(
        stated,
        None,
        Origin::Dropped {
            file: "routing-plane.tar.gz".into(),
            bytes: Arc::new(Vec::new()),
        },
    )
    .unwrap();
    assert_eq!(c.verbs, vec!["pools".to_string()]);
    assert_eq!(c.selecting, vec!["models".to_string()]);
    let cands = vec![c];
    let direct = Uses::of(&doc(r#"{"providers": {}, "models": {}}"#));
    assert_eq!(plane_use(&direct, &cands[0]), Some("models"));
    assert_eq!(
        picked(&select(&direct, &cands), &cands),
        vec![("routing-plane".into(), "pools".into())],
        "selected by its selecting section, under its verb"
    );
    let pooled = Uses::of(&doc(r#"{"pools": {}}"#));
    assert_eq!(plane_use(&pooled, &cands[0]), Some("pools"));

    let catalog_only = Uses::of(&doc(r#"{"providers": {}}"#));
    assert_eq!(plane_use(&catalog_only, &cands[0]), None);
    assert!(select(&catalog_only, &cands).is_empty());
}

fn need(direction: u32, transport: &str, target_from: &str) -> ReadNeed {
    ReadNeed {
        direction,
        egress_class: 0,
        transport: transport.into(),
        auth: String::new(),
        target_from: target_from.into(),
        trust_from: String::new(),
        details: busbar_contract::rendering::ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::conn::codes::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
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

use busbar_contract::conn::codes::DIRECTION_OUTBOUND;

#[test]
fn inbound_needs_are_collected_with_their_binds_from_instance_settings() {
    let d = doc(r#"{
        "agents": {"ingress": {"edge": {"listen": "127.0.0.1:9443",
            "tls": {"cert": {"module":"source","settings":{"id":"c"}}, "key": {"module":"source","settings":{"id":"k"}}}}}},
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
        &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
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
        Some(serde_json::from_value(doc(r#"{"cert": {"module":"source","settings":{"id":"c"}}, "key": {"module":"source","settings":{"id":"k"}}}"#)).unwrap()),
        "TLS carries typed references which resolve at stage 3f"
    );
    assert_eq!(got[1].at, "export.scrape.settings.serve");
    assert_eq!(got[1].max_conns, 8);
    assert_eq!(got[1].tls, None);
}

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
        inbound(
            &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
            &d,
            &c,
            &[sel(0, "agents")],
            Vec::new(),
        )
        .unwrap_err()
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
        "agents.ingress.listen: not an ip:port address"
    );
    assert_eq!(
        one(
            r#"{"ingress": {"listen": "127.0.0.1:1", "max_conns": 0}}"#,
            "ingress"
        ),
        "agents.ingress.max_conns: not a positive whole number"
    );
}

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
        inbound(
            &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
            &d,
            &c,
            &[sel(0, "agents")],
            Vec::new()
        )
        .unwrap_err(),
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
        inbound(
            &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
            &d,
            &c,
            &[sel(0, "agents")],
            root
        )
        .unwrap_err(),
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
        inbound(
            &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
            &d,
            &c,
            &[sel(0, "agents")],
            Vec::new()
        )
        .unwrap()
        .len(),
        2,
        "port 0 asks for a free one and never collides"
    );
}

#[test]
fn a_candidate_carries_its_statements_needs() {
    use busbar_contract::abi::host::conn::connector::Need;
    use busbar_contract::abi::mechanism::call::Blob;
    use busbar_contract::conn::codes::KEEP_NAMED;
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

struct Resolver;

impl busbar_contract::secret::SecretResolve for Resolver {
    fn resolve(
        &self,
        r: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        let admitted: busbar_contract::secret_ref::SecretRef = serde_json::from_value(
            serde_json::json!({"module":"ready-secret-source", "settings":{"slot":"available"}}),
        )
        .unwrap();
        if r == &admitted {
            Ok(busbar_contract::redacted::Secret::new(b"s3cret".to_vec()))
        } else {
            Err(format!("{} is not set", r.describe()))
        }
    }

    fn resolve_string(
        &self,
        r: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        self.resolve(r)?
            .into_text()
            .map_err(|e| format!("{} is not text: {e:?}", r.describe()))
    }
}

#[test]
fn a_literal_at_a_wildcard_declared_secret_path_is_refused_as_an_exact_one_is() {
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    for (keys, block, at) in [
        (
            vec!["client_secret".to_string()],
            doc(r#"{"client_secret": "pasted-pw-7b"}"#),
            "settings.client_secret",
        ),
        (
            vec!["hosts.*.password".to_string()],
            doc(r#"{"hosts": [{"password": "pasted-pw-7b"}]}"#),
            "settings.hosts.0.password",
        ),
    ] {
        let block = busbar_contract::plugin_settings::ResolvedSettings::from(block);
        let Err(e) = busbar_contract::auth_calls::prepare_references(
            &block,
            &keys,
            &busbar_contract::secret_ref::Sugars::default(),
            "test-owner",
            "settings",
            &Resolver,
            &scope,
        ) else {
            panic!("a literal at {at} refuses");
        };
        assert!(
            e.starts_with(&format!("{at}: not a secret reference")),
            "{at}: {e}"
        );
        assert!(!e.contains("pasted-pw-7b"), "the value is echoed: {e}");
    }
}

#[test]
fn a_dropped_listener_binding_selects_its_exact_declared_claim_without_a_url() {
    use busbar_contract::abi::mechanism::call::Blob;
    use busbar_contract::abi::transport::listener_bindings::EXT_LISTENER_BINDINGS;
    const CLAIMS: &[busbar_contract::abi::mechanism::call::AbiStr] = &[abi_str("foreign-wire")];
    let read_candidate = |binding: &[u8]| {
        let extensions = busbar_contract::extensions::encode(&[(EXT_LISTENER_BINDINGS, binding)]);
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind: KindCode::Transport as u32,
            claims: CLAIMS.as_ptr(),
            claims_len: CLAIMS.len(),
            extensions: Blob {
                fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
                flags: 0,
                len: extensions.len(),
                ptr: extensions.as_ptr(),
            },
            ..statement("foreign-listener", "1.0.0", 1)
        };
        // SAFETY: the static claim list and extension buffer are live through rendering.
        let stated = unsafe { render(&st) }.unwrap();
        Candidate::from_rendering(
            stated,
            None,
            Origin::Dropped {
                file: "foreign-listener.tar.gz".into(),
                bytes: Arc::new(Vec::new()),
            },
        )
    };
    let candidate = read_candidate(br#"[{"slot":"listen","claim":"foreign-wire"}]"#).unwrap();
    assert!(candidate.serves(&Uses::default()));
    let candidates = [candidate];
    assert_eq!(select(&Uses::default(), &candidates).len(), 1);
    let unrelated = read_candidate(br#"[{"slot":"another-slot","claim":"foreign-wire"}]"#).unwrap();
    assert!(!unrelated.serves(&Uses::default()));
    assert!(read_candidate(br#"[{"slot":"listen","claim":"undeclared"}]"#).is_err());
    assert!(read_candidate(br#"[{"slot":"listen","claim":"foreign-wire","priority":0}]"#).is_err());
}
