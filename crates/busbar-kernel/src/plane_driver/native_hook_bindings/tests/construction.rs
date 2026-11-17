// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{PolicyOnError, PromptAccess, UserAccess};
use busbar_plugin_abi::kinds::hook::hook::{FB_WANTS_PROMPT, POINT_REWRITE, POINT_ROUTE};
use busbar_ports::hook::{HookCall, HookView};
use busbar_ports::CallCx;

struct Port {
    points: u32,
    facts: u64,
}
impl HookPort for Port {
    fn points(&self) -> u32 {
        self.points
    }
    fn facts(&self) -> u64 {
        self.facts
    }
    fn on<'a>(&'a self, _: CallCx, _: u32, _: &'a HookView<'a>) -> HookCall<'a> {
        panic!("assembly must not call or reopen a hook")
    }
}

fn definition() -> HookCfg {
    busbar_contract::json::parse_str(r#"{"kind":"gate","module":"image","timeout_ms":37,"prompt":"ro","user":"ro","priority":4,"on_error":"reject"}"#).unwrap()
}
fn opened(points: u32, facts: u64, words: &[&str]) -> OpenedHook {
    OpenedHook {
        port: Arc::new(Port { points, facts }),
        image: Arc::from("image"),
        words: words.iter().map(|s| Box::from(*s)).collect(),
        timeout: std::time::Duration::from_millis(89),
    }
}

#[test]
fn named_binding_preserves_the_opened_port_grants_and_error_policy() {
    let hooks = [("guard".into(), definition())].into_iter().collect();
    let ports = [(
        "guard".into(),
        opened(1 << POINT_ROUTE, FB_WANTS_PROMPT, &[]),
    )]
    .into_iter()
    .collect();
    let words = BTreeMap::new();
    let call = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    }
    .named("guard", POINT_ROUTE)
    .unwrap();
    assert!(Arc::ptr_eq(&call.port, &ports["guard"].port));
    assert_eq!(&*call.name, "guard");
    assert_eq!(call.timeout.as_millis(), 37);
    assert_eq!(call.prompt, PromptAccess::Ro);
    assert_eq!(call.user, UserAccess::Ro);
    assert_eq!(call.on_error, PolicyOnError::Reject);
    assert_eq!(call.on_empty, PolicyOnError::Reject);
    assert!(call.strategy.is_none());
}

#[test]
fn missing_port_and_missing_point_refuse_by_configured_name() {
    let hooks = [("guard".into(), definition())].into_iter().collect();
    let mut ports = BTreeMap::new();
    let words = BTreeMap::new();
    let failure = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    }
    .named("guard", POINT_ROUTE)
    .err()
    .unwrap();
    assert!(
        failure.contains("guard") && failure.contains("opened"),
        "{failure}"
    );
    ports.insert(
        "guard".into(),
        opened(1 << POINT_REWRITE, FB_WANTS_PROMPT, &[]),
    );
    let failure = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    }
    .named("guard", POINT_ROUTE)
    .err()
    .unwrap();
    assert!(
        failure.contains("guard") && failure.contains("point"),
        "{failure}"
    );
}

#[test]
fn fallbacks_preserve_every_deadline_grant_and_the_final_terminal() {
    let mut first = definition();
    first.on_error = "fallback".into();
    let mut fallback = definition();
    fallback.timeout_ms = 81;
    fallback.prompt = PromptAccess::No;
    fallback.on_error = "first".into();
    let hooks = [("guard".into(), first), ("fallback".into(), fallback)]
        .into_iter()
        .collect();
    let ports = ["guard", "fallback"]
        .into_iter()
        .map(|name| (name.into(), opened(1 << POINT_ROUTE, FB_WANTS_PROMPT, &[])))
        .collect();
    let words = BTreeMap::new();
    let call = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    }
    .named("guard", POINT_ROUTE)
    .unwrap();
    assert_eq!(call.on_error, PolicyOnError::First);
    assert_eq!(call.fallbacks.len(), 1);
    assert_eq!(&*call.fallbacks[0].name, "fallback");
    assert_eq!(call.fallbacks[0].timeout.as_millis(), 81);
    assert_eq!(call.fallbacks[0].prompt, PromptAccess::No);
    assert!(call.fallbacks[0].fallbacks.is_empty());
}

#[test]
fn fallback_cycle_and_missing_fallback_refuse() {
    let mut guard = definition();
    guard.on_error = "guard".into();
    let mut hooks = [("guard".into(), guard)]
        .into_iter()
        .collect::<HookRegistry>();
    let ports = [("guard".into(), opened(1 << POINT_ROUTE, 0, &[]))]
        .into_iter()
        .collect();
    let words = BTreeMap::new();
    assert!(Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words
    }
    .named("guard", POINT_ROUTE)
    .err()
    .unwrap()
    .contains("cycle"));
    hooks.get_mut("guard").unwrap().on_error = "absent".into();
    assert!(Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words
    }
    .named("guard", POINT_ROUTE)
    .err()
    .unwrap()
    .contains("absent"));
}

#[test]
fn strategy_uses_admitted_word_and_refuses_ambiguous_unopened_images() {
    let hooks = HookRegistry::new();
    let ports = [("rank".into(), opened(1 << POINT_ROUTE, 0, &["rank"]))]
        .into_iter()
        .collect();
    let mut words = [("image".into(), vec![Box::from("rank")])]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let call = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    }
    .strategy("rank")
    .unwrap();
    assert_eq!(call.strategy.as_deref(), Some("rank"));
    assert_eq!(call.timeout.as_millis(), 89);
    assert_eq!(call.prompt, PromptAccess::No);
    assert_eq!(call.user, UserAccess::No);
    assert!(call.signals.wants(crate::hooks::Signal::CandidateRouteCost));
    words.insert("unopened-image".into(), vec![Box::from("rank")]);
    assert!(Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words
    }
    .strategy("rank")
    .err()
    .unwrap()
    .contains("several"));
}

fn names(calls: &[Arc<Call>]) -> Vec<&str> {
    calls.iter().map(|c| c.name.as_ref()).collect()
}

#[test]
fn scope_priority_and_group_selection_are_frozen_without_candidate_scope_guessing() {
    let mut hooks = HookRegistry::new();
    for (name, priority, group) in [
        ("global", 7, None),
        ("section", 3, None),
        ("pool", 3, Some("team")),
    ] {
        let mut hook = definition();
        hook.priority = priority;
        hook.groups = group.into_iter().map(str::to_owned).collect();
        hooks.insert(name.into(), hook);
    }
    let ports = hooks
        .keys()
        .map(|name| (name.clone(), opened(1 << POINT_ROUTE, 0, &[])))
        .collect();
    let words = BTreeMap::new();
    let pool = crate::config::PoolCfg {
        gates: vec!["pool".into()],
        ..Default::default()
    };
    let tables = Tables::build(
        &Calls {
            hooks: &hooks,
            opened: &ports,
            words: &words,
        },
        &["global".into()],
        &["section".into()],
        Some(&pool),
    )
    .unwrap();
    let tree = [(
        "child".into(),
        crate::config::groups::GroupCfg {
            parent: Some("team".into()),
            ..Default::default()
        },
    )]
    .into_iter()
    .collect();
    assert_eq!(
        names(&tables.select(Some("child"), &tree, true).gates),
        ["section", "pool", "global"]
    );
    assert_eq!(
        names(&tables.select(None, &tree, true).gates),
        ["section", "global"]
    );
    assert_eq!(
        names(&tables.select(Some("child"), &tree, false).gates),
        ["section", "global"]
    );
    // Configuration mutation belongs to the next generation, never this table.
    hooks.get_mut("global").unwrap().priority = 0;
    hooks.get_mut("pool").unwrap().groups = vec!["unrelated".into()];
    assert_eq!(
        names(&tables.select(Some("child"), &tree, true).gates),
        ["section", "pool", "global"]
    );
}

#[test]
fn rewrites_keep_scope_order_and_taps_keep_declared_phases() {
    use busbar_plugin_abi::kinds::hook::hook::POINT_NOTIFY;
    let mut global = definition();
    global.prompt = PromptAccess::Rw;
    global.priority = 40;
    let mut pool_hook = definition();
    pool_hook.prompt = PromptAccess::Rw;
    pool_hook.priority = 0;
    let mut tap = definition();
    tap.kind = crate::config::HookKind::Tap;
    tap.phase = vec![crate::config::HookStage::Response];
    let hooks = [
        ("global".into(), global),
        ("pool".into(), pool_hook),
        ("tap".into(), tap),
    ]
    .into_iter()
    .collect::<HookRegistry>();
    let ports = hooks
        .keys()
        .map(|name| {
            (
                name.clone(),
                opened(
                    (1 << POINT_REWRITE) | (1 << POINT_NOTIFY),
                    FB_WANTS_PROMPT,
                    &[],
                ),
            )
        })
        .collect();
    let words = BTreeMap::new();
    let pool = crate::config::PoolCfg {
        gates: vec!["pool".into()],
        ..Default::default()
    };
    let tables = Tables::build(
        &Calls {
            hooks: &hooks,
            opened: &ports,
            words: &words,
        },
        &["global".into(), "tap".into()],
        &[],
        Some(&pool),
    )
    .unwrap();
    let picked = tables.select(None, &BTreeMap::new(), true);
    assert_eq!(names(&picked.rewrites), ["global", "pool"]);
    assert!(picked.gates.is_empty());
    assert!(picked.taps.request.is_empty());
    assert!(picked.taps.candidate.is_empty());
    assert!(picked.taps.routing.is_empty());
    assert_eq!(names(&picked.taps.response), ["tap"]);
}

#[test]
fn no_attachment_allocates_no_hook_stage_and_missing_name_does_not_disappear() {
    let hooks = HookRegistry::new();
    let ports = BTreeMap::new();
    let words = BTreeMap::new();
    let calls = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    };
    let tables = Tables::build(&calls, &[], &[], None).unwrap();
    assert!(!tables.active());
    assert!(!tables.enforcing());
    let failure = Tables::build(&calls, &[], &["missing".into()], None)
        .err()
        .unwrap();
    assert!(failure.contains("missing"));
}

#[test]
fn rewrite_without_declared_prompt_and_missing_fallback_point_refuse() {
    let mut guard = definition();
    guard.prompt = PromptAccess::Rw;
    let mut hooks = [("guard".into(), guard)]
        .into_iter()
        .collect::<HookRegistry>();
    let mut ports = [("guard".into(), opened(1 << POINT_REWRITE, 0, &[]))]
        .into_iter()
        .collect();
    let words = BTreeMap::new();
    assert!(Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words
    }
    .named("guard", POINT_REWRITE)
    .is_err());
    ports.insert(
        "guard".into(),
        opened(1 << POINT_REWRITE, FB_WANTS_PROMPT, &[]),
    );
    hooks.get_mut("guard").unwrap().on_error = "fallback".into();
    hooks.insert("fallback".into(), definition());
    ports.insert(
        "fallback".into(),
        opened(1 << POINT_ROUTE, FB_WANTS_PROMPT, &[]),
    );
    assert!(Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words
    }
    .named("guard", POINT_REWRITE)
    .err()
    .unwrap()
    .contains("fallback"));
}

#[test]
fn fallback_group_scope_is_checked_without_replacing_its_final_terminal() {
    let mut guard = definition();
    guard.on_error = "fallback".into();
    let mut fallback = definition();
    fallback.groups = vec!["team".into()];
    let hooks = [("guard".into(), guard), ("fallback".into(), fallback)]
        .into_iter()
        .collect();
    let ports = ["guard", "fallback"]
        .into_iter()
        .map(|name| (name.into(), opened(1 << POINT_ROUTE, 0, &[])))
        .collect();
    let words = BTreeMap::new();
    let tables = Tables::build(
        &Calls {
            hooks: &hooks,
            opened: &ports,
            words: &words,
        },
        &["guard".into()],
        &[],
        None,
    )
    .unwrap();
    let picked = tables.select(None, &BTreeMap::new(), false);
    assert_eq!(picked.gates[0].on_error, PolicyOnError::Reject);
    assert!(picked.gates[0].fallbacks.is_empty());
    assert_eq!(
        tables.select(Some("team"), &BTreeMap::new(), false).gates[0]
            .fallbacks
            .len(),
        1
    );
}

#[test]
fn configured_strategy_disambiguates_by_admitted_identity_and_default_does_not_override_explicit_base(
) {
    let mut hook = definition();
    hook.default = true;
    let hooks = [("rank".into(), hook)].into_iter().collect();
    let ports = [("rank".into(), opened(1 << POINT_ROUTE, 0, &["rank"]))]
        .into_iter()
        .collect();
    let words = [
        ("image".into(), vec![Box::from("rank")]),
        ("other-image".into(), vec![Box::from("rank")]),
    ]
    .into_iter()
    .collect();
    let calls = Calls {
        hooks: &hooks,
        opened: &ports,
        words: &words,
    };
    assert_eq!(
        calls.strategy("rank").unwrap().strategy.as_deref(),
        Some("rank")
    );
    let pool = crate::config::PoolCfg::default();
    assert_eq!(
        Tables::build(&calls, &[], &[], Some(&pool))
            .unwrap()
            .policy
            .unwrap()
            .call
            .strategy,
        None
    );
    let pool = crate::config::PoolCfg {
        base_named: true,
        ..pool
    };
    assert!(Tables::build(&calls, &[], &[], Some(&pool))
        .unwrap()
        .policy
        .is_none());
}
