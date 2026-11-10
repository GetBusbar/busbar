// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn projected() -> Projection {
    let mut view = Projection::empty("pool".into(), "neutral".into());
    view.system = Some("instructions".into());
    view.turns = vec![("user".into(), "question".into())];
    view.message_count = 1;
    view
}

#[test]
fn text_completeness_requires_plane_assurance_and_exact_lent_projection() {
    let mut view = projected();
    let text = PromptProjection {
        system: Some("instructions".into()),
        messages: vec![("user".into(), "question".into())],
    };
    assert!(!view.complete_text_projection(&text));
    view.text_complete = true;
    assert!(view.complete_text_projection(&text));
    view.has_tools = true;
    assert!(!view.complete_text_projection(&text));
    view.has_tools = false;
    // A host cap, withheld system text or edited turn cannot retain the assurance.
    for partial in [
        PromptProjection {
            system: None,
            messages: Vec::new(),
        },
        PromptProjection {
            system: None,
            messages: text.messages.clone(),
        },
        PromptProjection {
            system: text.system.clone(),
            messages: vec![("user".into(), "other".into())],
        },
    ] {
        assert!(!view.complete_text_projection(&partial));
    }
}

#[test]
fn text_completeness_is_absent_without_a_prompt_grant() {
    let mut view = projected();
    view.text_complete = true;
    let mut requested = RequestedSignals::default();
    let ordinary = view.request(1, "pool", true, None, &requested);
    assert!(ordinary.signals.is_empty());
    requested.insert(Signal::RequestTextComplete);
    let hidden = view.request(1, "pool", false, None, &requested);
    assert!(hidden.prompt.is_none());
    assert!(hidden.signals.get(Signal::RequestTextComplete).is_none());
    view.text_complete = false;
    let unknown = view.request(1, "pool", true, None, &requested);
    assert_eq!(
        unknown.signals.get(Signal::RequestTextComplete),
        Some(&SignalValue::Bool(false))
    );
    assert_eq!(Signal::RequestTextComplete.bit(), 11);
    assert_eq!(Signal::RequestTextComplete.name(), "request_text_complete");
}
