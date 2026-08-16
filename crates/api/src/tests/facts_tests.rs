// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Layer 1 view's pins. The property under test is GENERALITY: the same trait must be
//! implementable by a plane that speaks a chat IR and by one that speaks no IR at all. If only the
//! first is expressible, the contract has the closed-enum problem in a different costume.

use super::*;

/// A chat-family request — the shape `IrRequest` has.
struct ChatLike {
    turns: usize,
    text: String,
    max_tokens: Option<u32>,
    user: Option<String>,
}

impl PlaneFacts for ChatLike {
    fn verb(&self) -> &str {
        "chat"
    }
    fn wants_stream(&self) -> bool {
        true
    }
    fn end_user(&self) -> Option<&str> {
        self.user.as_deref()
    }
    fn magnitude(&self) -> Magnitude {
        Magnitude {
            unit: "tokens",
            amount: self.text.len() as u64 / 4,
            caller_cap: self.max_tokens.map(u64::from),
        }
    }
    fn screenable(&self) -> Vec<Screenable<'_>> {
        vec![Screenable::Text {
            label: "message",
            text: std::borrow::Cow::Borrowed(&self.text),
        }]
    }
}

/// A SESSION-ORIENTED plane with NO IR — no messages, no tools, no turns, no request/response.
///
/// **This is the case that matters, and it is not hypothetical: A2A is in this position in
/// production today, with its own types and no `IrReq` variant at all.** If the Layer 1 view cannot
/// express it, the contract can only ever carry the LLM family.
struct SessionLike {
    peer: String,
    bytes_pending: u64,
}

impl PlaneFacts for SessionLike {
    fn verb(&self) -> &str {
        "session.open"
    }
    fn wants_stream(&self) -> bool {
        // Duplex forever. `true` means "continuously" here, which is the honest reading.
        true
    }
    fn end_user(&self) -> Option<&str> {
        Some(&self.peer)
    }
    fn magnitude(&self) -> Magnitude {
        // Bytes, not tokens — and the trait does not care which.
        Magnitude {
            unit: "bytes",
            amount: self.bytes_pending,
            // No caller-declared cap concept exists for a session. `None` is a fact about the
            // protocol, and the trait lets it say so rather than forcing a fabricated number.
            caller_cap: None,
        }
    }
    fn screenable(&self) -> Vec<Screenable<'_>> {
        // Payload bytes are not screenable material. Saying so explicitly is better than returning
        // an empty vec that reads as "nothing to see" — a consumer can tell the difference between
        // "no content" and "content withheld".
        vec![Screenable::Opaque {
            label: "packet",
            marker: "[encrypted payload]",
        }]
    }
}

/// THE HEADLINE. One trait, two planes with nothing in common — and core reads both the same way.
/// Neither implementation names a type from the other's world.
#[test]
fn the_layer_one_view_is_implementable_by_a_plane_with_no_ir_at_all() {
    let chat = ChatLike {
        turns: 3,
        text: "summarise the incident report".to_string(),
        max_tokens: Some(4096),
        user: Some("u-1".to_string()),
    };
    let session = SessionLike {
        peer: "peer-7".to_string(),
        bytes_pending: 1_400,
    };

    // Core reads both through the same seam, with no `match` on which family it holds.
    fn admit(f: &dyn PlaneFacts) -> (String, String, u64) {
        let m = f.magnitude();
        (f.verb().to_string(), m.unit.to_string(), m.amount)
    }

    assert_eq!(admit(&chat).1, "tokens");
    assert_eq!(admit(&session).1, "bytes");
    assert_eq!(admit(&session).0, "session.open");
    // The chat plane's caller cap survives; the session plane honestly reports it has no such
    // concept rather than fabricating one.
    assert_eq!(chat.magnitude().caller_cap, Some(4096));
    assert_eq!(session.magnitude().caller_cap, None);
    let _ = chat.turns;
}

/// WITHHELD IS NOT THE SAME AS ABSENT. A consumer must be able to tell "this plane has no screenable
/// content" from "this plane has content it will not show you" — collapsing them is how an audit
/// record silently becomes a claim that nothing happened.
#[test]
fn opaque_content_is_distinguishable_from_no_content() {
    let session = SessionLike {
        peer: "p".to_string(),
        bytes_pending: 1,
    };
    let items = session.screenable();
    assert_eq!(items.len(), 1, "withheld content is still an ITEM");
    match &items[0] {
        Screenable::Opaque { marker, .. } => assert!(!marker.is_empty()),
        other => panic!("expected withheld content, got {other:?}"),
    }
}
