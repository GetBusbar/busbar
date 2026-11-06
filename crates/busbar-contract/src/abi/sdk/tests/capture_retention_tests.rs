// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn truncated_message_never_admits_a_later_field_into_the_event_prefix() {
    let slot = CaptureSlot::new();
    let message = format!("{}🦀", "a".repeat(MAX_TEXT - 3));
    tracing::dispatcher::with_default(&slot.dispatch(), || {
        tracing::info!(target: "", answer = 42, "{message}");
    });
    let captured = slot.capture().unwrap().take();
    assert_eq!(captured.records.len(), 1);
    assert_eq!(
        captured.records[0].text,
        format!(": {}", "a".repeat(MAX_TEXT - 3))
    );
    assert_eq!(captured.records[0].text.len(), MAX_TEXT - 1);
}

#[test]
fn returned_logs_survive_other_tickets_and_crossing_threads() {
    let retained = Arc::new(CaptureRetention::default());
    let host = HostCtx { handle: 71 };
    let first = Ticket {
        slot: 3,
        generation: 1,
    };
    let mut slot = CaptureSlot::new();
    for (ticket, text) in [
        (first, "first"),
        (
            Ticket {
                slot: 4,
                generation: 1,
            },
            "other",
        ),
    ] {
        let mut reply = retained.begin(host, std::ptr::null_mut(), ticket);
        slot.capture().unwrap().lock().records.push(Captured {
            severity: SEVERITY_INFO,
            text: text.into(),
        });
        let mut envelope = Envelope::ZERO;
        // SAFETY: the input envelope is empty; the reply owns all generated diagnostics.
        unsafe { slot.seal(&mut envelope, &mut reply.reply) };
        retained.keep(reply, false, None);
    }
    let other_thread = Arc::clone(&retained);
    let copied = std::thread::spawn(move || {
        other_thread
            .owner(Owner::Host(host.handle))
            .with(ReplyKey::of(first), |r| r.texts[0].to_vec())
    })
    .join()
    .unwrap();
    assert_eq!(copied, Some(b"first".to_vec()));
    let recycled = Ticket {
        slot: first.slot,
        generation: 2,
    };
    let reply = retained.begin(host, std::ptr::null_mut(), recycled);
    assert!(retained
        .owner(Owner::Host(host.handle))
        .with(ReplyKey::of(first), |_| ())
        .is_none());
    retained.keep(reply, true, None);
    assert!(
        !retained
            .owners
            .lock()
            .unwrap()
            .contains_key(&Owner::Host(host.handle)),
        "close retires the instance outside any callback"
    );
}
