// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_store_reply_keeps_inline_and_owned_texts_across_other_ticket_answers() {
    let kept: Replies<Vec<Box<Text>>> = Replies::default();
    let first_key = ReplyKey::of(Ticket {
        slot: 1,
        generation: 1,
    });
    let other_key = ReplyKey::of(Ticket {
        slot: 2,
        generation: 1,
    });
    let first = RefCell::new(Vec::new());
    let named = reply_text(Text::render(format_args!("original {}", 1)), &first);
    for i in 0..64 {
        reply_text(Text::Owned(format!("same answer {i}")), &first);
    }
    kept.insert(first_key, first.into_inner());
    for i in 0..=TEXT_RING {
        let mut old = kept.take(other_key).unwrap_or_default();
        old.clear();
        let answer = RefCell::new(old);
        reply_text(Text::render(format_args!("other {i}")), &answer);
        kept.insert(other_key, answer.into_inner());
    }
    // Inspect current owners only. No assertion reads an old raw pointer on a RED keeper.
    assert_eq!(
        kept.with(first_key, |texts| texts[0].as_str().to_owned()),
        Some("original 1".into())
    );
    assert_eq!(
        kept.with(first_key, |texts| (texts[0].as_str().as_ptr(), texts.len())),
        Some((named.ptr, 65))
    );
}
