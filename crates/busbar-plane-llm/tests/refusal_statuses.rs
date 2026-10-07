// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's stated refusal reasons name the reasons they say they name.

use busbar_contract::abi::plane::reason_of;
use busbar_plane_llm::refusal::reason;

#[test]
fn every_stated_reason_code_is_the_reason_it_is_named_for() {
    for (code, spelling) in [
        (reason::UNAUTHENTICATED, "unauthenticated"),
        (reason::OVER_BUDGET, "over_budget"),
        (reason::DESTINATION_UNREACHABLE, "destination_unreachable"),
        (reason::GROUP_FROZEN, "group_frozen"),
        (reason::NO_RATE, "no_rate"),
        (reason::NO_DESTINATION, "no_destination"),
    ] {
        assert_eq!(
            reason_of(code).map(|r| r.as_str()),
            Some(spelling),
            "code {code}"
        );
    }
}

/// A REFUSAL WITH NO UNIT WEARS THE STATUS ITS TARGET'S 1.5.5 DIALECT STATES (the plane seam's refusals,
/// l.2645-2647): the `refusal` slot renders it in [`envelope_for`]'s dialect and states that
/// dialect's row, whatever dialect the matched line carried. The lines cannot spell every 1.5.5
/// shape (an anthropic path at any depth, a gemini action under `/v1/models/`), so the status is
/// the target's, not the line's: a bad credential on a gemini action under the openai-shaped
/// `/v1/models` family is gemini's 400, on a converse path bedrock's 403, elsewhere the kernel's.
#[test]
fn a_refusal_with_no_unit_states_its_targets_dialects_status() {
    use busbar_plane_llm::exchange::arrive::envelope_for;
    use busbar_plane_llm::refusal::stated_status;
    for (target, dialect, status) in [
        ("/v1/models/gemini-pro:generateContent", "gemini", Some(400)),
        (
            "/v1beta/models/gemini-pro:generateContent",
            "gemini",
            Some(400),
        ),
        ("/model/m/converse", "bedrock", Some(403)),
        ("/model/m/converse-stream", "bedrock", Some(403)),
        ("/a/b/v1/messages", "anthropic", None),
        ("/v1/messages", "anthropic", None),
        ("/v1/chat/completions", "openai", None),
        ("/model/m/invoke", "openai", None),
        ("/definitely/unknown", "openai", None),
    ] {
        assert_eq!(envelope_for(target), dialect, "{target}");
        assert_eq!(
            stated_status(envelope_for(target), reason::UNAUTHENTICATED),
            status,
            "{target}"
        );
    }
    // The every-dialect rows hold under every envelope; the kernel's own refusals with no unit (no
    // route, wrong method, handler panic) state none, so the kernel's status stands.
    assert_eq!(stated_status("openai", reason::NO_DESTINATION), Some(404));
    assert_eq!(stated_status("bedrock", reason::OVER_BUDGET), Some(400));
    assert_eq!(stated_status("openai", reason::OVER_BUDGET), None);
    for code in [43, 44, 45, 7] {
        assert_eq!(stated_status("gemini", code), None, "code {code}");
    }
}
