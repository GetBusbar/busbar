// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-A2A-CARD-REDIRECT (ABI-MIN3-INTERFACE §14): Card fetch redirects (§12.14; K8 + C1, WBS rule 10). The
//! plane-a2a arm runs in its repo.
//!
//! W1-K8B's arms are core's redirect rule (`busbar_kernel::auth::sight_redirect`): (a) a same-origin redirect is
//! followed, (b) three are followed and a fourth is not (`too_many`), (c) a cross-origin one is not
//! (`cross_origin`, core's text byte for byte), (e) nothing outside a TGT_SIGHT session is followed. Arms (d) and
//! (f) judge the followed hop on the exchange path (W1-C1A's guard, pins and dial).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_kernel::auth::sight_redirect::{next_hop, Answered, Hop, NotFollowedReason, AUDIT_ACTION, MAX_REDIRECTS};
use url::Url;

fn url(u: &str) -> Url {
    Url::parse(u).expect("url")
}

fn answered<'a>(hop: &'a Url, status: u16, location: &'a str, followed: u32) -> Answered<'a> {
    Answered { sight: true, method: "GET", status, location: Some(location), hop, followed }
}

#[test]
fn a_same_origin_redirect_is_followed_up_to_three_times() {
    let upstream = url("https://agent.example/");
    let legacy = url("https://agent.example/.well-known/agent.json");
    for status in [301, 302, 303, 307, 308] {
        assert_eq!(
            next_hop(answered(&legacy, status, "/.well-known/agent-card.json", 0), "agent", &upstream),
            Hop::Follow(url("https://agent.example/.well-known/agent-card.json"))
        );
    }
    let third = next_hop(answered(&legacy, 301, "card.json", MAX_REDIRECTS - 1), "agent", &upstream);
    assert_eq!(third, Hop::Follow(url("https://agent.example/.well-known/card.json")), "joined per RFC 3986");
    let Hop::NotFollowed(row) = next_hop(answered(&legacy, 301, "/x", MAX_REDIRECTS), "agent", &upstream) else {
        panic!("a fourth redirect is not followed");
    };
    assert_eq!(row.reason, NotFollowedReason::TooMany);
    assert_eq!(row.reason.word(), "too_many");
}

#[test]
fn a_cross_origin_redirect_is_not_followed_and_audited_with_core_text() {
    let upstream = url("https://agent.example/");
    let hop = url("https://agent.example/.well-known/agent-card.json");
    let Hop::NotFollowed(row) = next_hop(answered(&hop, 302, "https://cdn.example:8443/card", 0), "agent", &upstream)
    else {
        panic!("another origin is never followed");
    };
    assert_eq!(AUDIT_ACTION, "upstream_redirect_not_followed");
    assert_eq!(row.reason.word(), "cross_origin");
    assert_eq!(&*row.upstream, "agent");
    assert_eq!(
        row.text(),
        "redirect from https://agent.example to https://cdn.example:8443 not followed: busbar 1.6 follows only \
         same-origin redirects when fetching an agent card; set `upstreams.agent.url` to the card's origin"
    );
    let http = next_hop(answered(&hop, 301, "http://agent.example/card", 0), "agent", &upstream);
    assert!(matches!(http, Hop::NotFollowed(r) if r.reason == NotFollowedReason::CrossOrigin), "scheme is origin");
}

#[test]
fn only_a_get_in_a_sight_session_follows() {
    let upstream = url("https://agent.example/");
    let hop = url("https://agent.example/a2a");
    let delegation = Answered { sight: false, ..answered(&hop, 302, "/elsewhere", 0) };
    assert_eq!(next_hop(delegation, "agent", &upstream), Hop::Deliver, "(e) a delegation's 302 is delivered");
    let post = Answered { method: "POST", ..answered(&hop, 307, "/elsewhere", 0) };
    assert_eq!(next_hop(post, "agent", &upstream), Hop::Deliver);
    assert_eq!(next_hop(answered(&hop, 200, "/x", 0), "agent", &upstream), Hop::Deliver);
    let no_location = Answered { location: None, ..answered(&hop, 301, "", 0) };
    assert_eq!(next_hop(no_location, "agent", &upstream), Hop::Deliver);
}

#[test]
#[ignore = "owner: W1-K8B (arms (d), (f): the followed hop judged on the exchange path, needs W1-C1A)"]
fn card_redirect_core_arms() {
    todo!("owner: W1-K8B (C-A2A-CARD-REDIRECT (d), (f); W1-C1A's exchange path)")
}
