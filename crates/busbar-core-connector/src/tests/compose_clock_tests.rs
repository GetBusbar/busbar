// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DRIVE'S CLOCK (TRANSPORT-TLS T10): a drive reads the clock at most once, and only when a
//! deadline is compared or armed; a deadline armed inside a drive still fires on time.

use super::*;
use crate::compose::clock_reads;

/// T10: every drive of a whole exchange, from the dial through its answer, reads the clock at most
/// once; once no deadline is set, a drive reads it not at all.
#[test]
fn drive_reads_clock_once() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let _ = clock_reads::take();
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).expect("dials");
        let waker = std::task::Waker::noop();
        c.write(
            b"first",
            true,
            false,
            &mut std::task::Context::from_waker(waker),
        )
        .unwrap();
        assert_eq!(gather(&mut c, 5).await, b"first");
        let counted = clock_reads::take();
        assert!(counted.drives > 0, "the exchange was driven: {counted:?}");
        assert!(
            counted.reads > 0,
            "the open deadline was compared while connecting: {counted:?}"
        );
        assert!(
            counted.most_in_one_drive <= 1,
            "at most one clock read per drive: {counted:?}"
        );

        c.write(
            b"second",
            true,
            false,
            &mut std::task::Context::from_waker(waker),
        )
        .unwrap();
        assert_eq!(gather(&mut c, 6).await, b"second");
        let counted = clock_reads::take();
        assert!(counted.drives > 0, "the second ask was driven: {counted:?}");
        assert!(
            counted.most_in_one_drive <= 1,
            "at most one clock read per drive: {counted:?}"
        );
        if c.open_deadline.is_none() && c.framer_deadline.is_none() && c.tunnel.is_none() {
            assert_eq!(
                counted.reads, 0,
                "no deadline is set, so no drive reads the clock: {counted:?}"
            );
        }
        c.close();
    });
}

/// T10: the framer's deadline is armed inside the drive that connects (after that drive compared
/// the open deadline): it is still kept, and fires at its time, not before and not never.
#[test]
fn deadline_armed_mid_drive_still_fires() {
    worker().block_on(async {
        let far = silent().await;
        let door = Arc::new(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                silence: Some(Duration::from_millis(300)),
                ..Knobs::default()
            },
        ));
        let _ = clock_reads::take();
        let start = Instant::now();
        let mut c = Connection::dial(door.clone(), &crate::support::via(), dial(&far)).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(10), next(&mut c))
            .await
            .expect("the deadline armed mid-drive fires; the connection does not hang");
        assert_eq!(r, Err(Failure::Timeout));
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(300),
            "not before the deadline: {took:?}"
        );
        assert!(took < Duration::from_secs(5), "at the deadline: {took:?}");
        assert!(
            door.count("timer") >= 1,
            "the deadline reached the framer as `timer`"
        );
        let counted = clock_reads::take();
        assert!(
            counted.most_in_one_drive <= 1,
            "at most one clock read per drive: {counted:?}"
        );
    });
}
