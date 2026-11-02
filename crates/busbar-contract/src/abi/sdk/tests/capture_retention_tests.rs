// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

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
