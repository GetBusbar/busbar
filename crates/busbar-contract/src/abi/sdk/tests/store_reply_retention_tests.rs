// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_store_reply_keeps_inline_and_owned_texts_across_other_ticket_answers() {
    let kept: Replies<ReplyTexts> = Replies::default();
    let first_key = ReplyKey::of(Ticket {
        slot: 1,
        generation: 1,
    });
    let other_key = ReplyKey::of(Ticket {
        slot: 2,
        generation: 1,
    });
    let first = RefCell::new(ReplyTexts::default());
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
        kept.with(first_key, |texts| texts.texts[0].as_str().to_owned()),
        Some("original 1".into())
    );
    assert_eq!(
        kept.with(first_key, |texts| (
            texts.texts[0].as_str().as_ptr(),
            texts.used
        )),
        Some((named.ptr, 65))
    );
}

#[test]
fn a_consumed_store_reply_reuses_stable_text_slots_without_retaining_its_old_errors() {
    let held = RefCell::new(ReplyTexts::default());
    reply_text(Text::Owned("old owned error".into()), &held);
    reply_text(Text::render(format_args!("old rendered {}", 2)), &held);
    let addresses: Vec<*const Text> = held
        .borrow()
        .texts
        .iter()
        .map(|text| text.as_ref() as *const Text)
        .collect();

    held.borrow_mut().clear();
    assert_eq!(held.borrow().used, 0);
    assert!(held
        .borrow()
        .texts
        .iter()
        .all(|text| text.as_str().is_empty()));
    let first = reply_text(Text::render(format_args!("new rendered {}", 1)), &held);
    reply_text(Text::Owned("new owned error".into()), &held);
    let kept = held.borrow();
    assert_eq!(kept.used, 2);
    assert_eq!(kept.texts.len(), 2);
    for (text, address) in kept.texts.iter().zip(addresses) {
        assert_eq!(text.as_ref() as *const Text, address);
    }
    assert_eq!(kept.texts[0].as_str(), "new rendered 1");
    assert_eq!(kept.texts[1].as_str(), "new owned error");
    assert_eq!(first.ptr, kept.texts[0].as_str().as_ptr());
}
