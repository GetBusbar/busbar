// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn an_append_wakes_nobody_and_a_pull_takes_everything_in_order() {
    let wake = Arc::new(Notify::new());
    let outbox = CoreOutbox::new(wake.clone());
    let first = outbox.append(1u32);
    let second = outbox.append(2);
    assert!(first < second);
    let mut woken = Box::pin(wake.notified());
    assert!(
        futures::poll!(woken.as_mut()).is_pending(),
        "an ordinary append never wakes the flusher"
    );
    let drained = outbox.drain();
    assert_eq!(drained.items, vec![1, 2]);
    assert_eq!(drained.through, 2);
    assert_eq!(outbox.held(), 0);
    assert_eq!(
        outbox.held.lock().unwrap().items.capacity(),
        0,
        "the pull releases the buffer; the next append makes a new one"
    );
    assert!(outbox.drain().items.is_empty());
}

#[tokio::test]
async fn only_an_asked_append_wakes_the_flusher_and_waits_for_its_commit() {
    let wake = Arc::new(Notify::new());
    let outbox = Arc::new(CoreOutbox::new(wake.clone()));
    outbox.append("read");
    let change = outbox.append_and_ask("change");
    tokio::time::timeout(std::time::Duration::from_secs(1), wake.notified())
        .await
        .expect("the change asked for a pull");
    let waiting = tokio::spawn({
        let outbox = outbox.clone();
        async move { outbox.committed(change).await }
    });
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished(), "nothing is committed before the pull");
    let drained = outbox.drain();
    outbox.settled(drained.through - 1);
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished(), "a commit below its ticket does not release it");
    outbox.settled(drained.through);
    tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
        .await
        .expect("released by the commit that holds it")
        .unwrap();
    assert!(outbox.is_committed(change));
}
