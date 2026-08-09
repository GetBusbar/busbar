// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE — the grant filter (owner ruling 2) and the dispatch-time re-validation that
//! re-reads the live pin generation on every request rather than trusting the one selection saw,
//! asserted on the resolved SETS and on the refusal each check produces.

use super::{Catalogue, DispatchRefusal};
use crate::mcp::client::catalogue::LiveSightings;
use crate::mcp::config::{McpServerDefCfg, PinMechanism, ServerPinCfg, ToolAllowCfg, ToolsCfg};

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
            },
        );
    }
    for t in pending {
        tools_allow.insert((*t).to_string(), ToolAllowCfg::default());
    }
    (
        id.to_string(),
        McpServerDefCfg {
            url: format!("https://{id}.internal/mcp"),
            pin: ServerPinCfg {
                mechanism: PinMechanism::CertSpki,
                key: Some("sha256/K=".to_string()),
            },
            tools_allow,
            prompts_allow: indexmap::IndexMap::new(),
            resources_allow: indexmap::IndexMap::new(),
            resource_templates_allow: Default::default(),
            transport: None,
            aud: None,
            grants: Default::default(),
            allow_private: false,
            token_exchange: None,
            max_input_required_rounds: None,
            max_caller_ask_rounds: None,
            upstream_credentials: None,
            hooks: Vec::new(),
        },
    )
}

fn cfg(servers: Vec<(String, McpServerDefCfg)>) -> ToolsCfg {
    let mut c = ToolsCfg::default();
    for (name, def) in servers {
        crate::mcp::config::validate_server(&name, &def).expect("fixture must be valid config");
        c.servers.insert(name, def);
    }
    c
}

/// A grant predicate over an explicit allow-list, in the exact shape `VirtualKey::scope_allowed`
/// answers: an entry is `(kind, value)`, and anything not listed is denied.
fn grant_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str, &str) -> bool {
    move |kind, value| pairs.iter().any(|(k, v)| *k == kind && *v == value)
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

    let names = |g: &dyn Fn(&str, &str) -> bool| {
        let mut n: Vec<String> = cat
            .tools_for(g)
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
        cat.tools_for(&tool_only).is_empty(),
        "a tool grant without the server grant reaches nothing"
    );

    let server_only = grant_of(&[("mcp_server", "fs")]);
    assert!(
        cat.tools_for(&server_only).is_empty(),
        "a server grant without a tool grant reaches nothing"
    );

    let one_tool = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let got: Vec<String> = cat
        .tools_for(&one_tool)
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
        .tools_for(&g)
        .iter()
        .map(|t| t.namespaced.clone())
        .collect();
    names.sort();
    assert_eq!(names, vec!["fs_pending".to_string(), "fs_read".to_string()]);

    assert!(cat
        .resolve(&g, LiveSightings::unsighted(), "fs_read")
        .is_ok());
    assert_eq!(
        cat.resolve(&g, LiveSightings::unsighted(), "fs_pending"),
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
        mechanism: PinMechanism::Unpinned,
        key: None,
    };
    let cat = Catalogue::build(&cfg(vec![(name, def)]));
    let g = grant_of(&[("mcp_server", "dev"), ("mcp_tool", "dev_read")]);
    assert_eq!(
        cat.resolve(&g, LiveSightings::unsighted(), "dev_read"),
        Err(DispatchRefusal::NotPinned("dev".to_string())),
        "no locked pin ⇒ pending ⇒ never served, even to a fully granted caller"
    );
}

/// An ungranted caller naming a real tool and a granted caller naming a fictional one must be told
/// apart INTERNALLY (the audit row needs the distinction) and answered identically on the wire.
#[test]
fn not_granted_and_unknown_are_distinct_internally() {
    let cat = Catalogue::build(&cfg(vec![server("fs", &["read"], &[])]));
    let none = grant_of(&[]);
    assert_eq!(
        cat.resolve(&none, LiveSightings::unsighted(), "fs_read"),
        Err(DispatchRefusal::NotGranted("fs_read".to_string()))
    );
    let all = grant_of(&[("mcp_server", "fs"), ("mcp_tool", "fs_nope")]);
    assert_eq!(
        cat.resolve(&all, LiveSightings::unsighted(), "fs_nope"),
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
        .resolve(&g, LiveSightings::unsighted(), "fs_read")
        .unwrap()
        .clone();
    let selected_gen = admitted.generation();

    // Same snapshot: the call goes through. Without this half, the refusal below would be
    // indistinguishable from a check that refuses everything.
    assert_eq!(
        admitted.revalidate(&g, LiveSightings::unsighted(), &selected, selected_gen),
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

    assert_eq!(
        live.revalidate(&g, LiveSightings::unsighted(), &selected, selected_gen),
        Err(DispatchRefusal::GenerationMoved {
            selected: selected_gen,
            live: live.generation(),
        }),
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
        .resolve(&g, LiveSightings::unsighted(), "fs_read")
        .unwrap()
        .clone();
    let selected_gen = admitted.generation();

    // Byte-identical content, rebuilt. A content-derived generation would compare equal here and
    // admit the call; a counter cannot.
    let live = Catalogue::build(&c);
    assert!(matches!(
        live.revalidate(&g, LiveSightings::unsighted(), &selected, selected_gen),
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
        .resolve(&full, LiveSightings::unsighted(), "fs_read")
        .unwrap()
        .clone();
    let gen = cat.generation();

    let revoked = grant_of(&[]);
    assert_eq!(
        cat.revalidate(&revoked, LiveSightings::unsighted(), &selected, gen),
        Err(DispatchRefusal::NotGranted("fs_read".to_string())),
        "same generation, revoked grant: still refused"
    );
}
