// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::v1::service::project_hook_view;
use crate::v1::service::tests::hook;
use busbar_kernel::config::{HookCfg, HookKind, HookStage, ALL_HOOK_STAGES, CORE_HOOK_PHASES};

#[test]
fn a_phase_scoped_hook_reads_back_its_stages() {
    let cfg = HookCfg {
        phase: vec![HookStage::Response],
        ..hook(HookKind::Tap, false)
    };
    let view = project_hook_view("audit", &cfg, &[]);

    assert_eq!(view.phase, vec!["response"], "the `phase:` list, echoed");
    assert_eq!(
        view.fires_at,
        vec!["response"],
        "and resolved: a non-empty `phase:` wins outright"
    );
}

#[test]
fn an_unscoped_hook_resolves_to_the_four_core_stages() {
    let view = project_hook_view("unscoped", &hook(HookKind::Tap, false), &[]);

    assert!(view.phase.is_empty());
    assert_eq!(
        view.fires_at,
        CORE_HOOK_PHASES
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>(),
        "an omitted `phase:` means the four core stages"
    );
}

#[test]
fn the_resolved_set_agrees_with_the_firing_predicate_for_every_stage() {
    for cfg in [
        hook(HookKind::Tap, false),
        HookCfg {
            phase: vec![HookStage::Request, HookStage::Response],
            ..hook(HookKind::Tap, false)
        },
        HookCfg {
            phase: vec![HookStage::Candidate],
            ..hook(HookKind::Tap, false)
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

#[test]
fn a_group_scoped_hook_reads_back_its_caller_scope() {
    let cfg = HookCfg {
        groups: vec!["engineering".to_string()],
        ..hook(HookKind::Tap, false)
    };
    let view = project_hook_view("pii-eng", &cfg, &[]);
    assert_eq!(view.groups, vec!["engineering".to_string()]);

    let unscoped = project_hook_view("pii-all", &hook(HookKind::Tap, false), &[]);
    assert!(
        unscoped.groups.is_empty(),
        "empty means ALL callers, and an operator must be able to see that it is empty"
    );
}

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
