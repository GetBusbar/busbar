// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE — the grant filter (owner ruling 2) and the dispatch-time re-validation that
//! re-reads the live pin generation on every request rather than trusting the one selection saw,
//! asserted on the resolved SETS and on the refusal each check produces.

use super::{Catalogue, DispatchRefusal};
use crate::mcp::client::catalogue::LiveSightings;
use crate::mcp::config::{
    McpPinMechanism, McpServerDefCfg, PromptAllowCfg, ResourceAllowCfg, ResourceTemplateAllowCfg,
    ServerPinCfg, ToolAllowCfg, ToolsCfg,
};

/// A registered server with `tools` approved AT a hash (so it serves) and `pending` allowed with no
/// hash (so it is catalogued and does not serve).
fn server(id: &str, tools: &[&str], pending: &[&str]) -> (String, McpServerDefCfg) {
    let mut tools_allow = indexmap::IndexMap::new();
    for t in tools {
        tools_allow.insert(
            (*t).to_string(),
            ToolAllowCfg {
                schema_hash: Some(format!("sha256:{t}")),
                description: Some(format!("<IMPORTANT>do {t}</IMPORTANT>")),
                input_schema: None,
                ask_caller: Vec::new(),
                ..ToolAllowCfg::default()
            },
        );
    }
    for t in pending {
        tools_allow.insert((*t).to_string(), ToolAllowCfg::default());
    }
    (
        id.to_string(),
        McpServerDefCfg {
            // This registration is reached over the network, so it carries none of the spawn keys.
            command: None,
            args: Vec::new(),
            env: Default::default(),
            cwd: None,
            verify_ttl: None,
            timeout: None,
            url: format!("https://{id}.internal/mcp"),
            pin: ServerPinCfg {
                mechanism: McpPinMechanism::CertSpki,
                key: Some("sha256/K=".to_string()),
            },
            tools_allow,
            prompts_allow: indexmap::IndexMap::new(),
            resources_allow: indexmap::IndexMap::new(),
            resource_templates_allow: Default::default(),
            transport: None,
            aud: None,
            grants: Default::default(),
            roots: Vec::new(),
            sampling: None,
            allow_private: false,
            token_exchange: None,
            max_input_required_rounds: None,
            max_caller_ask_rounds: None,
            upstream_credentials: None,
            hooks: Vec::new(),
        },
    )
}

/// The same registration with ONE capability of EVERY kind — a tool, a prompt, a resource and a
/// template — so the entitlement rule can be asserted on all four surfaces rather than on the one
/// that happened to have a test.
fn full_server(id: &str) -> (String, McpServerDefCfg) {
    let (name, mut def) = server(id, &["read"], &[]);
    def.prompts_allow.insert(
        "brief".to_string(),
        PromptAllowCfg {
            description: Some(format!("{id} brief")),
            template: Some("hello".to_string()),
            ..PromptAllowCfg::default()
        },
    );
    def.resources_allow.insert(
        format!("{id}://doc"),
        ResourceAllowCfg {
            text: Some("body".to_string()),
            ..ResourceAllowCfg::default()
        },
    );
    def.resource_templates_allow.insert(
        format!("{id}://logs/{{day}}"),
        ResourceTemplateAllowCfg {
            text: Some("log for {day}".to_string()),
            ..ResourceTemplateAllowCfg::default()
        },
    );
    (name, def)
}

fn cfg(servers: Vec<(String, McpServerDefCfg)>) -> ToolsCfg {
    let mut c = ToolsCfg::default();
    for (name, def) in servers {
        crate::mcp::config::validate_server(&name, &def).expect("fixture must be valid config");
        c.servers.insert(name, def);
    }
    c
}

/// A KEY carrying an explicit allow-list. The gate asks a principal now rather than a predicate, so
/// the fixture is a principal — which is the point: a test that hands the gate a closure can hand it
/// one no real key could produce.
fn grant_of(pairs: &[(&str, &str)]) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: "k1".to_string(),
        name: "k1".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: Some(
            pairs
                .iter()
                .map(|(k, v)| busbar_api::ScopeRef {
                    kind: (*k).to_string(),
                    value: (*v).to_string(),
                })
                .collect(),
        ),
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
    }
}

/// THE CALLER, as every catalogue read now takes it. The LISTING asks a different question from the
/// gate — identity and grant, and deliberately not the artifact step, because this plane CATALOGUES
/// what it will not dispatch — but it asks it of the same ordered validator, so the key, the clock
/// and the snapshot travel together instead of a bare grant closure.
fn seeing(key: &busbar_api::VirtualKey) -> crate::catalogue::Caller<'_> {
    crate::catalogue::Caller {
        key: Some(key),
        now: 0,
        generation: crate::trust::validate::Generations::at_admission(1),
    }
}

/// THE HEADLINE PROPERTY (goal item 5): two grants see two DIFFERENT lists, and a third sees NONE.
///
/// Asserted as set equality on the resolved names, not as counts — a count is satisfied by the wrong
/// members.
#[test]
fn two_grants_see_two_different_catalogues_and_a_third_sees_none() {
    let cat = Catalogue::build(&cfg(vec![
        server("fs", &["read", "write"], &[]),
        server("db", &["query"], &[]),
    ]));

    // Grant A: the whole `fs` server.
    let a = grant_of(&[
        ("mcp_server", "fs"),
        ("mcp_tool", "fs_read"),
        ("mcp_tool", "fs_write"),
    ]);
    // Grant B: ONE tool on `db`, and nothing on `fs`.
    let b = grant_of(&[("mcp_server", "db"), ("mcp_tool", "db_query")]);
    // Grant C: a grant that names a pool and nothing else — the fail-closed cross-kind case.
    let c = grant_of(&[("pool", "fast")]);

    let names = |g: &busbar_api::VirtualKey| {
        let mut n: Vec<String> = cat
            .tools_for(&seeing(g))
            .iter()
            .map(|t| t.namespaced.clone())
            .collect();
        n.sort();
        n
    };

    assert_eq!(
        names(&a),
        vec!["fs_read".to_string(), "fs_write".to_string()]
    );
    assert_eq!(names(&b), vec!["db_query".to_string()]);
    assert!(
        names(&c).is_empty(),
        "a key whose grant names only a pool reaches NO tool: cross-kind is fail-closed"
    );
    // And the three answers are genuinely three, not one repeated — the guard against a filter that
    // is accidentally constant.
    assert_ne!(names(&a), names(&b));
}

/// BOTH grants, and both are load-bearing. A caller let through the server door must not acquire
/// every capability behind it, and a caller holding a tool grant on a server it may not reach must
/// not get in sideways.
#[test]
fn the_server_grant_and_the_tool_grant_are_both_required() {
    let cat = Catalogue::build(&cfg(vec![server("fs", &["read", "write"], &[])]));

    let tool_only = grant_of(&[("mcp_tool", "fs_read")]);
    assert!(
        cat.tools_for(&seeing(&tool_only)).is_empty(),
        "a tool grant without the server grant reaches nothing"
    );

    let server_only = grant_of(&[("mcp_server", "fs")]);
    assert!(
        cat.tools_for(&seeing(&server_only)).is_empty(),
        "a server grant without a tool grant reaches nothing"
    );

    let one_tool = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let got: Vec<String> = cat
        .tools_for(&seeing(&one_tool))
        .iter()
        .map(|t| t.namespaced.clone())
        .collect();
    assert_eq!(
        got,
        vec!["fs_read".to_string()],
        "the door does not confer the room: `fs_write` stays out"
    );
}

/// A pending tool is CATALOGUED (so the approval queue is visible) and does NOT dispatch (there is
/// no approved digest to dispatch against). Both halves, because either alone is a different bug.
#[test]
fn a_tool_with_no_approved_hash_is_listed_and_refuses_to_dispatch() {
    let cat = Catalogue::build(&cfg(vec![server("fs", &["read"], &["pending"])]));
    let g = grant_of(&[
        ("mcp_server", "fs"),
        ("mcp_tool", "fs_read"),
        ("mcp_tool", "fs_pending"),
    ]);
    let mut names: Vec<String> = cat
        .tools_for(&seeing(&g))
        .iter()
        .map(|t| t.namespaced.clone())
        .collect();
    names.sort();
    assert_eq!(names, vec!["fs_pending".to_string(), "fs_read".to_string()]);

    assert!(cat
        .resolve_now(Some(&g), LiveSightings::unsighted(), "fs_read")
        .is_ok());
    assert_eq!(
        cat.resolve_now(Some(&g), LiveSightings::unsighted(), "fs_pending"),
        Err(DispatchRefusal::NotApproved("fs_pending".to_string()))
    );
}

/// An `unpinned` registration has no authenticity root — nothing the operator pinned out of band for
/// the endpoint to be checked against — so it CANNOT SERVE TRAFFIC, whatever its tools claim and
/// whatever the caller's grant says.
#[test]
fn an_unpinned_server_never_dispatches() {
    let (name, mut def) = server("dev", &["read"], &[]);
    def.pin = ServerPinCfg {
        mechanism: McpPinMechanism::Unpinned,
        key: None,
    };
    let cat = Catalogue::build(&cfg(vec![(name, def)]));
    let g = grant_of(&[("mcp_server", "dev"), ("mcp_tool", "dev_read")]);
    assert_eq!(
        cat.resolve_now(Some(&g), LiveSightings::unsighted(), "dev_read"),
        Err(DispatchRefusal::NotPinned("dev".to_string())),
        "no locked pin ⇒ pending ⇒ never served, even to a fully granted caller"
    );
}

/// A `pin.key:` that is PRESENT AND BLANK declares nothing, so the registration is `pending` and
/// serves nothing — whitespace is not out-of-band material, and a pin with nothing to verify with is
/// not a pin.
///
/// The rule is [`crate::trust::declared`]'s now, and it used to be this plane's alone: the sibling
/// plane's reader took `key.unwrap_or_default()` and would have built an artifact out of `""`. This
/// is the check that moving the rule to core did not lose it on the plane it started on.
#[test]
fn a_present_but_blank_pin_key_declares_nothing() {
    let (name, mut def) = server("dev", &["read"], &[]);
    def.pin = ServerPinCfg {
        mechanism: McpPinMechanism::CertSpki,
        key: Some("   ".to_string()),
    };
    assert!(
        crate::mcp::config::validate_server(&name, &def).is_err(),
        "boot must still refuse a rooted mechanism with no usable material"
    );
    assert_eq!(
        crate::trust::declared::declared_pin::<crate::mcp::client::catalogue::TransportPin>(
            def.pin.declaration()
        ),
        None,
        "and the reader must refuse it on its own, not by trusting that boot already did"
    );
}

/// An ungranted caller naming a real tool and a granted caller naming a fictional one must be told
/// apart INTERNALLY (the audit row needs the distinction) and answered identically on the wire.
#[test]
fn not_granted_and_unknown_are_distinct_internally() {
    let cat = Catalogue::build(&cfg(vec![server("fs", &["read"], &[])]));
    let none = grant_of(&[]);
    assert_eq!(
        cat.resolve_now(Some(&none), LiveSightings::unsighted(), "fs_read"),
        Err(DispatchRefusal::NotGranted("fs_read".to_string()))
    );
    let all = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_nope")]);
    assert_eq!(
        cat.resolve_now(Some(&all), LiveSightings::unsighted(), "fs_nope"),
        Err(DispatchRefusal::UnknownTool("fs_nope".to_string()))
    );
    // The operator gets two reasons; the caller gets one message. That is the design.
    assert_ne!(
        DispatchRefusal::NotGranted("x".into()).audit_reason(),
        DispatchRefusal::UnknownTool("x".into()).audit_reason()
    );
    assert_eq!(
        DispatchRefusal::NotGranted("fs_read".into()).to_string(),
        DispatchRefusal::UnknownTool("fs_read".into()).to_string(),
        "the wire message must not leak which of the two it was"
    );
}

/// The generation is MONOTONIC across builds, including a build whose content is identical.
///
/// Identical content matters: a generation derived from a content hash would compare EQUAL after a
/// change-and-revert, and the dispatch-time check asks whether the operator's approval was REPLACED,
/// not whether it happens to look the same.
#[test]
fn the_pin_generation_moves_on_every_build_including_an_identical_one() {
    let c = cfg(vec![server("fs", &["read"], &[])]);
    let a = Catalogue::build(&c);
    let b = Catalogue::build(&c);
    assert!(
        b.generation() > a.generation(),
        "identical content must still move the generation: {} then {}",
        a.generation(),
        b.generation()
    );
    // Even the empty catalogue of a deployment with no `tools:` takes one, so "MCP was configured
    // and then emptied" is a MOVE rather than a return to a timeless zero.
    let e = Catalogue::default();
    assert!(e.generation() > b.generation());
}

/// THE SEAM TEST, in the exact words the correction gives it: *a call whose candidate was resolved
/// under pin generation N is refused at dispatch when the live generation is N+1.*
///
/// It is assertable with no session table and no handshake, which is the whole point of the
/// restatement — the defence used to be phrased as "a pin change tombstones the sticky session", and
/// this wire revision has no sessions, so that test could never have run at all.
#[test]
fn a_call_resolved_under_generation_n_is_refused_when_the_live_generation_is_n_plus_1() {
    let c = cfg(vec![server("fs", &["read"], &[])]);
    let admitted = Catalogue::build(&c);
    let g = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let selected = admitted
        .resolve_now(Some(&g), LiveSightings::unsighted(), "fs_read")
        .unwrap()
        .clone();
    let selected_gen = admitted.generation();

    // Same snapshot: the call goes through. Without this half, the refusal below would be
    // indistinguishable from a check that refuses everything.
    assert_eq!(
        admitted.revalidate_now(
            Some(&g),
            LiveSightings::unsighted(),
            &selected,
            selected_gen
        ),
        Ok(())
    );

    // THE SWAP. The operator quarantines the tool by withdrawing its approved hash, and the new
    // snapshot takes the next generation.
    let mut quarantined = c.clone();
    quarantined
        .servers
        .get_mut("fs")
        .unwrap()
        .tools_allow
        .insert("read".to_string(), ToolAllowCfg::default());
    let live = Catalogue::build(&quarantined);

    // THE CALL IS REFUSED, AND THE REFUSAL NAMES THE QUARANTINE RATHER THAN THE MOVE.
    //
    // It used to name the move, because the generation was compared before anything else. The one
    // ordered validator in `crate::trust::validate` compares it LAST, deliberately: "something
    // moved, retry" is a worse message than "this tool's approved digest was withdrawn", and an
    // operator handed the first goes looking for a config apply they did not make. Nothing is
    // admitted that was not admitted before — both steps refuse this call — and
    // `a_revert_still_refuses_because_the_generation_is_not_content` below is the proof that the
    // generation step still closes the case only it can close.
    assert_eq!(
        live.revalidate_now(
            Some(&g),
            LiveSightings::unsighted(),
            &selected,
            selected_gen
        ),
        Err(DispatchRefusal::NotApproved("fs_read".to_string())),
        "an in-flight call cannot outlive a quarantine"
    );
}

/// The generation check refuses on a MOVE, not on a change in content — so a revert-then-re-approve
/// cannot slip a call through on an approval the operator had already revoked.
#[test]
fn a_revert_still_refuses_because_the_generation_is_not_content() {
    let c = cfg(vec![server("fs", &["read"], &[])]);
    let admitted = Catalogue::build(&c);
    let g = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let selected = admitted
        .resolve_now(Some(&g), LiveSightings::unsighted(), "fs_read")
        .unwrap()
        .clone();
    let selected_gen = admitted.generation();

    // Byte-identical content, rebuilt. A content-derived generation would compare equal here and
    // admit the call; a counter cannot.
    let live = Catalogue::build(&c);
    assert!(matches!(
        live.revalidate_now(
            Some(&g),
            LiveSightings::unsighted(),
            &selected,
            selected_gen
        ),
        Err(DispatchRefusal::GenerationMoved { .. })
    ));
}

/// The re-validation ALSO re-derives the bound identity under the LIVE grant, so a grant revoked
/// between admission and dispatch bites even where the generation happens to be unchanged. The
/// second check is deliberately redundant with the first — "the generation is the only check" is the
/// assumption a future caller that plumbs the generation wrongly would silently rely on.
#[test]
fn revalidation_also_re_derives_the_identity_under_the_live_grant() {
    let cat = Catalogue::build(&cfg(vec![server("fs", &["read"], &[])]));
    let full = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let selected = cat
        .resolve_now(Some(&full), LiveSightings::unsighted(), "fs_read")
        .unwrap()
        .clone();
    let gen = cat.generation();

    let revoked = grant_of(&[]);
    assert_eq!(
        cat.revalidate_now(Some(&revoked), LiveSightings::unsighted(), &selected, gen),
        Err(DispatchRefusal::NotGranted("fs_read".to_string())),
        "same generation, revoked grant: still refused"
    );
}

/// CROSS-TENANT ISOLATION, ON EVERY CATALOGUE SURFACE.
///
/// `two_grants_see_two_different_catalogues_and_a_third_sees_none` above proved this for TOOLS and
/// only for tools; `prompts/list`, `resources/list` and `resources/templates/list` had no
/// entitlement test of their own at all, on a plane where each of them is a separate wire verb
/// answering "what exists here". That absence is the finding this test closes: the four surfaces
/// route through one `required_grants` now, and one test asserts the property on all four, so a
/// surface cannot be added and left out of the rule.
///
/// Asserted as DISJOINTNESS and NON-EMPTINESS together: "each saw one thing" is exactly what a
/// swapped filter would also report, and "each saw nothing" is what a filter that refuses everything
/// would.
#[test]
fn no_principal_sees_another_principals_prompts_resources_or_templates() {
    let cat = Catalogue::build(&cfg(vec![full_server("fs"), full_server("db")]));

    let a = grant_of(&[
        ("mcp_server", "fs"),
        ("mcp_tool", "fs_read"),
        ("mcp_tool", "fs_brief"),
        ("mcp_tool", "fs_fs://doc"),
        ("mcp_tool", "fs_fs://logs/{day}"),
    ]);
    let b = grant_of(&[
        ("mcp_server", "db"),
        ("mcp_tool", "db_read"),
        ("mcp_tool", "db_brief"),
        ("mcp_tool", "db_db://doc"),
        ("mcp_tool", "db_db://logs/{day}"),
    ]);

    /// One catalogue SURFACE, read for one caller. A named type because the four surfaces are the
    /// point of this test: a fifth one added without a row here is a surface with no entitlement
    /// assertion, and naming the shape is what makes adding the row obvious.
    type ReadSurface = fn(&Catalogue, &crate::catalogue::Caller<'_>) -> Vec<String>;
    let surfaces: [(&str, ReadSurface); 4] = [
        ("tools", |c, k| {
            c.tools_for(k)
                .iter()
                .map(|t| t.namespaced.clone())
                .collect()
        }),
        ("prompts", |c, k| {
            c.prompts_for(k)
                .iter()
                .map(|p| p.namespaced.clone())
                .collect()
        }),
        ("resources", |c, k| {
            c.resources_for(k)
                .iter()
                .map(|r| r.namespaced.clone())
                .collect()
        }),
        ("templates", |c, k| {
            c.resource_templates_for(k)
                .iter()
                .map(|t| t.namespaced.clone())
                .collect()
        }),
    ];

    for (what, read) in surfaces {
        let mine = read(&cat, &seeing(&a));
        let theirs = read(&cat, &seeing(&b));
        assert!(
            !mine.is_empty() && !theirs.is_empty(),
            "`{what}`: both principals must see something, or the disjointness below is trivial"
        );
        assert!(
            mine.iter().all(|m| m.starts_with("fs_")),
            "`{what}`: principal A saw something that is not its own: {mine:?}"
        );
        assert!(
            theirs.iter().all(|t| t.starts_with("db_")),
            "`{what}`: principal B saw something that is not its own: {theirs:?}"
        );
        assert!(
            mine.iter().all(|m| !theirs.contains(m)),
            "`{what}`: one principal's inventory appeared in the other's"
        );
    }

    // And the two ADDRESSED reads answer the same way: a caller cannot reach across by NAMING the
    // other tenant's capability rather than listing it.
    assert!(
        cat.prompt_for(&seeing(&a), "db_brief").is_none(),
        "`prompts/get` must not reach another principal's prompt by name"
    );
    assert!(
        matches!(
            cat.resource_by_uri(&seeing(&a), "db://doc"),
            super::ResourceLookup::NotFound
        ),
        "`resources/read` must not reach another principal's resource by uri"
    );
    assert!(
        matches!(
            cat.resource_template_for(&seeing(&a), "db://logs/monday"),
            super::ResourceLookup::NotFound
        ),
        "an expanded uri must not match another principal's template"
    );
}

/// THE FAIL-CLOSED FLOOR, reached through this plane's own entry types.
///
/// `crate::catalogue` refuses an item that requires NO grant, and every MCP entry type requires two.
/// This is the plane-side half of that: a caller holding NOTHING sees nothing on any surface, which
/// is the assertion that would go red if a `required_grants` were ever emptied.
#[test]
fn a_caller_holding_no_grant_at_all_sees_nothing_on_any_surface() {
    let cat = Catalogue::build(&cfg(vec![full_server("fs")]));
    let none = grant_of(&[]);
    assert!(cat.tools_for(&seeing(&none)).is_empty());
    assert!(cat.prompts_for(&seeing(&none)).is_empty());
    assert!(cat.resources_for(&seeing(&none)).is_empty());
    assert!(cat.resource_templates_for(&seeing(&none)).is_empty());
    assert!(cat.prompt_for(&seeing(&none), "fs_brief").is_none());
    assert!(matches!(
        cat.resource_by_uri(&seeing(&none), "fs://doc"),
        super::ResourceLookup::NotFound
    ));
    assert!(matches!(
        cat.resource_template_for(&seeing(&none), "fs://logs/monday"),
        super::ResourceLookup::NotFound
    ));
}

/// THE LISTING GAINED THE IDENTITY STEP IT NEVER HAD.
///
/// Before the walk was unified the catalogue took a grant CLOSURE, which could carry the grant and
/// nothing else: a key deleted, disabled or expired between ingress and the listing still saw the
/// whole of what it had been granted. `tools/call` grew the check with the ordered validator; the
/// four listing surfaces are the other half, and this is that half.
///
/// The refusal is `identity_not_live` in the AUDIT record and identical to `unknown_tool` on the
/// wire, which is the same distinction `not_granted` already keeps.
#[test]
fn a_key_that_is_no_longer_live_sees_nothing_on_any_surface() {
    let cat = Catalogue::build(&cfg(vec![full_server("fs")]));
    let live = grant_of(&[
        ("mcp_server", "fs"),
        ("mcp_tool", "fs_read"),
        ("mcp_tool", "fs_brief"),
        ("mcp_tool", "fs_fs://doc"),
        ("mcp_tool", "fs_fs://logs/{day}"),
    ]);
    // The control: while the key is live it sees all four surfaces, or the rows below prove nothing.
    assert_eq!(cat.tools_for(&seeing(&live)).len(), 1);
    assert_eq!(cat.prompts_for(&seeing(&live)).len(), 1);
    assert_eq!(cat.resources_for(&seeing(&live)).len(), 1);
    assert_eq!(cat.resource_templates_for(&seeing(&live)).len(), 1);

    for (what, mutate) in [
        (
            "deleted",
            (|k: &mut busbar_api::VirtualKey| k.deleted_at = Some(1))
                as fn(&mut busbar_api::VirtualKey),
        ),
        ("disabled", |k: &mut busbar_api::VirtualKey| {
            k.enabled = false
        }),
        ("expired", |k: &mut busbar_api::VirtualKey| {
            k.expires_at = Some(1)
        }),
    ] {
        let mut gone = live.clone();
        mutate(&mut gone);
        let asked = crate::catalogue::Caller {
            key: Some(&gone),
            now: 100,
            generation: crate::trust::validate::Generations::at_admission(1),
        };
        assert!(cat.tools_for(&asked).is_empty(), "{what}: tools");
        assert!(cat.prompts_for(&asked).is_empty(), "{what}: prompts");
        assert!(cat.resources_for(&asked).is_empty(), "{what}: resources");
        assert!(
            cat.resource_templates_for(&asked).is_empty(),
            "{what}: templates"
        );
        assert_eq!(
            crate::catalogue::judge(cat.tools_for(&seeing(&live))[0], &asked, &(),)
                .unwrap_err()
                .audit_reason(),
            crate::audit::vocab::REASON_IDENTITY_NOT_LIVE,
            "{what}: the audit record must say the key is gone, not that it lacks a grant"
        );
    }
}
