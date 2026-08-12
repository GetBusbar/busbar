// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN READ MUST ANSWER "WHEN DOES THIS HOOK RUN".
//!
//! `phase:` and `groups:` are WRITABLE over the admin API (`POST`/`PUT /hooks` deserialize
//! `config::HookCfg` verbatim, and the spec documents that body as "a `hooks:` entry, as JSON"),
//! but `HookView` projected neither. So an operator could configure a hook's stage and caller
//! scoping through the API and then not read it back through the API.
//!
//! Worse than a missing field: the ONE stage field the view did carry, `at`, is `None` for every
//! hook written in the current top-level `hooks:` grammar, because `config::hook_cfg_from_def`
//! hard-codes `at: None` and `--migrate-config` rewrites a legacy `at:` into `phase:`. The read
//! therefore reported `at: null` for a tap pinned to a single stage, under a doc comment that said
//! `null` meant "a gate".
//!
//! These tests pin the fix at the projection: both spellings are echoed, and the RESOLVED set is
//! projected beside them through the same predicate the firing path uses.

use crate::admin::v1::service::project_hook_view;
use crate::config::{
    HookCfg, HookKind, HookStage, PromptAccess, UserAccess, ALL_HOOK_STAGES, CORE_HOOK_PHASES,
};

/// A minimal hook definition. Stage/scope fields are set per test.
fn hook() -> HookCfg {
    HookCfg {
        kind: HookKind::Tap,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// A non-empty `phase:` is authoritative, and the read says so: the list is echoed verbatim AND
/// resolved. This is the shape `--migrate-config` writes and the shape the current grammar produces,
/// so before the fix it was the shape that read back as "no stage information at all".
#[test]
fn a_phase_scoped_hook_reads_back_its_stages() {
    let cfg = HookCfg {
        phase: vec![HookStage::Response],
        ..hook()
    };
    let view = project_hook_view("audit", &cfg, &[]);

    assert_eq!(view.phase, vec!["response"], "the `phase:` list, echoed");
    assert_eq!(
        view.fires_at,
        vec!["response"],
        "and resolved: a non-empty `phase:` wins outright"
    );
    assert_eq!(
        view.at, None,
        "the legacy `at:` stays null for a phase-scoped hook, which is exactly why it cannot be \
         the field an operator reads"
    );
}

/// Precedence rung 2: `phase:` empty, legacy `at:` set. The resolved set is that one stage.
#[test]
fn a_legacy_at_hook_resolves_to_exactly_that_one_stage() {
    let cfg = HookCfg {
        at: Some(HookStage::Request),
        ..hook()
    };
    let view = project_hook_view("logger", &cfg, &[]);

    assert_eq!(view.at, Some("request"));
    assert!(
        view.phase.is_empty(),
        "no `phase:` was written, so the echo is empty; the resolved set carries the answer"
    );
    assert_eq!(view.fires_at, vec!["request"]);
}

/// Precedence rung 3: BOTH omitted. The resolved set is the four core stages, and only those,
/// never "every stage that will ever exist" (the frozen meaning of an omitted `phase:`). An empty
/// `phase` echo is therefore ambiguous on its own, which is the argument for projecting the
/// resolved set beside it rather than instead of it.
#[test]
fn an_unscoped_hook_resolves_to_the_four_core_stages() {
    let view = project_hook_view("unscoped", &hook(), &[]);

    assert!(view.phase.is_empty());
    assert_eq!(view.at, None);
    assert_eq!(
        view.fires_at,
        CORE_HOOK_PHASES
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        "an omitted `phase:` means the four core stages"
    );
}

/// The resolved set is never a guess: it is `fires_at_stage` asked once per stage. This pins the
/// two to each other so a future edit cannot make the read say one thing while the firing path
/// does another.
#[test]
fn the_resolved_set_agrees_with_the_firing_predicate_for_every_stage() {
    for cfg in [
        hook(),
        HookCfg {
            at: Some(HookStage::Routing),
            ..hook()
        },
        HookCfg {
            phase: vec![HookStage::Request, HookStage::Response],
            ..hook()
        },
        HookCfg {
            // `phase:` wins even when `at:` disagrees with it.
            at: Some(HookStage::Request),
            phase: vec![HookStage::Candidate],
            ..hook()
        },
    ] {
        let view = project_hook_view("h", &cfg, &[]);
        for stage in ALL_HOOK_STAGES {
            assert_eq!(
                view.fires_at.contains(&stage.as_str()),
                cfg.fires_at_stage(*stage),
                "projection and firing predicate disagree at {}",
                stage.as_str()
            );
        }
        assert!(
            !view.fires_at.is_empty(),
            "every hook fires somewhere; an empty resolved set would be a silently dead hook"
        );
    }
}

/// The other half of the same gap: `groups:` is writable over the API and was unreadable over it.
#[test]
fn a_group_scoped_hook_reads_back_its_caller_scope() {
    let cfg = HookCfg {
        groups: vec!["engineering".to_string()],
        ..hook()
    };
    let view = project_hook_view("pii-eng", &cfg, &[]);
    assert_eq!(view.groups, vec!["engineering".to_string()]);

    let unscoped = project_hook_view("pii-all", &hook(), &[]);
    assert!(
        unscoped.groups.is_empty(),
        "empty means ALL callers, and an operator must be able to see that it is empty"
    );
}

/// `ALL_HOOK_STAGES` is the domain the resolved set is computed over, so a stage missing from it is
/// a stage no admin read can ever report. The match below is EXHAUSTIVE with no `_` arm: a new
/// `HookStage` variant fails to compile here until it is named, which is the moment its author must
/// also add it to the constant.
///
/// It must NOT be conflated with `CORE_HOOK_PHASES`, which is frozen at the four and must never
/// grow. The two are equal today and are expected to diverge; that expected divergence is why they
/// are separate constants rather than one alias.
#[test]
fn all_hook_stages_lists_every_stage_variant() {
    for stage in ALL_HOOK_STAGES {
        let named = match stage {
            HookStage::Request => "request",
            HookStage::Candidate => "candidate",
            HookStage::Routing => "routing",
            HookStage::Response => "response",
        };
        assert_eq!(stage.as_str(), named);
    }
    for stage in CORE_HOOK_PHASES {
        assert!(
            ALL_HOOK_STAGES.contains(stage),
            "a default-set stage that is not a known stage is incoherent: {}",
            stage.as_str()
        );
    }
    assert_eq!(
        ALL_HOOK_STAGES.len(),
        4,
        "a stage was added: add it to ALL_HOOK_STAGES and bump this count, and do NOT add it to \
         CORE_HOOK_PHASES (see its FREEZE BLOCKER)"
    );
}
