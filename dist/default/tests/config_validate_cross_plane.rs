// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel::config;
use std::collections::HashMap;

#[test]
fn the_tools_section_enumerates_every_secret_reference_its_plane_declares() {
    linked::install();
    let text = "providers: {}\nmodels: {}\ntools:\n  \
        exchanged:\n    url: \"https://x.example/t\"\n    pin: { mechanism: unpinned }\n    \
        aud: \"https://x.example\"\n    token_exchange:\n      \
        token_url: \"https://as.example/token\"\n      \
        subject_token: { env: BUSBAR_TEST_SUBJECT_TOKEN }\n  \
        child:\n    transport: stdio\n    command: \"/usr/bin/true\"\n    \
        pin: { mechanism: unpinned }\n    \
        env:\n      API_KEY: { env: BUSBAR_TEST_CHILD_KEY }\n      MODE: \"plain\"\n";
    let deploy = config::deploy_from_yaml_str(text)
        .unwrap_or_else(|e| panic!("the section parses: {e}\n{text}"));
    let mut found: Vec<String> = deploy
        .plane_section("tools")
        .expect("the section is carried")
        .secret_refs()
        .into_iter()
        .map(|(at, _)| at)
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "tools.child.env.API_KEY",
            "tools.exchanged.token_exchange.subject_token",
        ],
        "every reference at the plane's declared paths, and the plain value beside one is not one"
    );
}

#[test]
fn the_agents_section_enumerates_every_secret_reference_its_plane_declares() {
    linked::install();
    let text = "providers: {}\nmodels: {}\nagents:\n  \
        leased:\n    url: \"https://a.example/rpc\"\n    pin: { mechanism: unpinned }\n    \
        upstream_credential:\n      secret: { env: BUSBAR_TEST_AGENT_LEASE }\n      \
        lease_ttl_ms: 60000\n  \
        mutual:\n    url: \"https://b.example/rpc\"\n    pin: { mechanism: unpinned }\n    \
        client_identity:\n      cert: { env: BUSBAR_TEST_AGENT_CERT }\n      \
        key: { env: BUSBAR_TEST_AGENT_KEY }\n  \
        plain:\n    url: \"https://c.example/rpc\"\n    pin: { mechanism: unpinned }\n";
    let deploy = config::deploy_from_yaml_str(text)
        .unwrap_or_else(|e| panic!("the section parses: {e}\n{text}"));
    let mut found: Vec<String> = deploy
        .plane_section("agents")
        .expect("the section is carried")
        .secret_refs()
        .into_iter()
        .map(|(at, _)| at)
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "agents.leased.upstream_credential.secret",
            "agents.mutual.client_identity.cert",
            "agents.mutual.client_identity.key",
        ],
        "every reference at the plane's declared paths, and a registration holding none adds none"
    );
}

#[test]
fn a_plane_card_silent_about_a_declared_class_refuses_at_boot() {
    linked::install();
    let planes: Vec<_> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .filter(|d| {
            d.billable_classes
                .iter()
                .any(|c| !d.fee_units.contains(&c.class))
        })
        .collect();
    assert!(
        planes.len() >= 2,
        "the rigs' two billed planes (the `tools:` and `agents:` sections) are test-linked: {:?}",
        planes.iter().map(|d| d.key).collect::<Vec<_>>()
    );
    for d in planes {
        let classes: Vec<&str> = (d.billable_classes.iter())
            .map(|c| c.class)
            .filter(|c| !d.fee_units.contains(c))
            .collect();
        let (unpriced, priced) = classes.split_last().expect("a priced class");

        let lane = format!(
            "{}:probe",
            d.scope_kinds
                .first()
                .expect("a billed door states a scope kind")
        );
        let section = |card: Option<&[&str]>| {
            let card = card.map_or(String::new(), |classes| {
                let units: Vec<String> = classes.iter().map(|c| format!("{c}: 0")).collect();
                format!(
                    "  rate_card:\n    {lane}: {{ units: {{ {} }} }}\n",
                    units.join(", ")
                )
            });
            format!(
                "store: {{ module: memory }}\nproviders: {{}}\nmodels: {{}}\n{s}:\n  \
                 fees: {{ per_request: 1 }}\n{card}  \
                 probe: {{ url: \"https://x.example/t\", pin: {{ mechanism: unpinned }} }}\n",
                s = d.config_section,
            )
        };
        let validated = |text: String| {
            let deploy = config::deploy_from_yaml_str(&text)
                .unwrap_or_else(|e| panic!("{}: the document parses: {e}\n{text}", d.key));
            let cfg = config::resolve(&deploy, &HashMap::new())
                .unwrap_or_else(|e| panic!("{}: the document resolves: {e:?}\n{text}", d.key));
            busbar_kernel::config_validate::validate(&cfg)
        };

        let errs = validated(section(Some(priced)))
            .expect_err("billing ON with a declared class unpriced must refuse (#77(5))");
        let want = format!(
            "{}.rate_card does not configure billable unit(s) {unpriced} declared by this plane; \
             add them (0 to make them free)",
            d.config_section
        );
        assert!(
            errs.contains(&want),
            "{}: the refusal names the unpriced class: {errs:?}",
            d.key
        );

        let card_refusals = |r: Result<(), Vec<String>>| -> Vec<String> {
            r.err()
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.contains("rate_card"))
                .collect()
        };
        let every = card_refusals(validated(section(Some(classes.as_slice()))));
        assert!(
            every.is_empty(),
            "{}: a card configuring every declared class (explicit 0) boots: {every:?}",
            d.key
        );
        let off = card_refusals(validated(section(None)));
        assert!(
            off.is_empty(),
            "{}: no card is billing OFF (#42) and boots: {off:?}",
            d.key
        );
    }
}
