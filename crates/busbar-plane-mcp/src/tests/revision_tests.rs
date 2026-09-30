// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn every_revision_round_trips_its_wire_string() {
    for r in ALL {
        assert_eq!(Revision::parse(r.wire()), Some(*r));
    }
    assert_eq!(
        Revision::parse("2025-03-26"),
        None,
        "not implemented: batched bodies"
    );
    assert_eq!(Revision::parse(""), None);
}

#[test]
fn the_stateless_revision_is_the_codec_constant() {
    assert_eq!(Revision::R2026_07_28.wire(), crate::codec::PROTOCOL_VERSION);
    assert!(!Revision::R2026_07_28.has_sessions());
    assert!(SESSION_REVISIONS.iter().all(|r| r.has_sessions()));
}

#[test]
fn initialize_echoes_an_implemented_session_revision() {
    for r in SESSION_REVISIONS {
        assert_eq!(negotiate(Some(r.wire())), *r);
    }
}

#[test]
fn initialize_offers_the_latest_session_revision_otherwise() {
    for asked in [
        None,
        Some("2025-03-26"),
        Some("1999-01-01"),
        Some("2026-07-28"),
        Some(""),
    ] {
        assert_eq!(negotiate(asked), Revision::R2025_11_25, "{asked:?}");
    }
}

#[test]
fn the_version_header_is_judged_against_the_session() {
    use HeaderCheck::*;
    let s = Revision::R2025_06_18;
    assert_eq!(check_header(s, Some("2025-06-18")), Agrees);
    assert_eq!(check_header(s, Some("2025-11-25")), Disagrees);
    assert_eq!(check_header(s, None), Missing);
    // The event-stream revision predates the header.
    assert_eq!(check_header(Revision::R2024_11_05, None), Agrees);
    assert_eq!(
        check_header(Revision::R2024_11_05, Some("2025-06-18")),
        Disagrees
    );
}

#[test]
fn the_client_ladder_falls_back_on_4xx_only() {
    use ClientStep::*;
    use StepOutcome::*;
    assert_eq!(next_step(Stateless, Refused4xx), Some(Initialize));
    assert_eq!(next_step(Initialize, Refused4xx), Some(EventStream));
    assert_eq!(next_step(EventStream, Refused4xx), None);
    for step in [Stateless, Initialize, EventStream] {
        assert_eq!(next_step(step, Answered), None);
        assert_eq!(
            next_step(step, Unreachable),
            None,
            "an outage is not a revision signal"
        );
    }
}

#[test]
fn a_client_accepts_only_session_revisions_it_implements() {
    assert_eq!(accept_offered("2025-11-25"), Some(Revision::R2025_11_25));
    assert_eq!(accept_offered("2024-11-05"), Some(Revision::R2024_11_05));
    assert_eq!(
        accept_offered("2026-07-28"),
        None,
        "no initialize in the stateless revision"
    );
    assert_eq!(accept_offered("2025-03-26"), None);
}

#[test]
fn only_the_two_2025_revisions_resume() {
    assert!(Revision::R2025_06_18.resumable());
    assert!(Revision::R2025_11_25.resumable());
    assert!(!Revision::R2024_11_05.resumable());
    assert!(!Revision::R2026_07_28.resumable());
    assert!(Revision::R2024_11_05.is_event_stream_revision());
}

#[test]
fn red_a_sessionless_get_is_told_apart_by_the_version_header() {
    use SessionlessGet::*;
    // A 2024-11-05 client sends no version header: the event stream.
    assert_eq!(sessionless_get(None), EventStream);
    // A single-endpoint revision's client: 405, as its revision says.
    for v in ["2025-06-18", "2025-11-25", "2026-07-28"] {
        assert_eq!(sessionless_get(Some(v)), NotAllowed, "{v}");
    }
    // An unknown revision reads as the latest session revision, as negotiation reads it.
    for v in ["2025-03-26", "1999-01-01", ""] {
        assert_eq!(sessionless_get(Some(v)), NotAllowed, "{v:?}");
    }
}
