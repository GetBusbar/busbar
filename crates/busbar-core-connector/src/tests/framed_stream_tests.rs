// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
mod stream_holds {
    use super::super::{
        StreamHolds, STREAM_STALL_DEFAULT_MS, STREAM_STALL_MAX_MS, STREAM_STALL_MIN_MS,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn a_held_stream_stalls_only_at_its_deadline_and_siblings_are_untouched() {
        let t0 = Instant::now();
        let mut holds = StreamHolds::new(Some(5_000));
        holds.hold(3, t0);
        assert!(holds.is_held(3));
        assert!(!holds.is_held(5));
        assert_eq!(
            holds.next_deadline(),
            Some(t0 + Duration::from_millis(5_000))
        );
        assert!(holds
            .take_stalled(t0 + Duration::from_millis(4_999))
            .is_empty());
        assert_eq!(
            holds.take_stalled(t0 + Duration::from_millis(5_000)),
            vec![3]
        );
        // Reset streams leave the set: never reported twice.
        assert!(holds.is_empty());
        assert!(holds.take_stalled(t0 + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn a_repeated_full_does_not_push_the_deadline_out() {
        let t0 = Instant::now();
        let mut holds = StreamHolds::new(Some(2_000));
        holds.hold(1, t0);
        holds.hold(1, t0 + Duration::from_millis(1_500));
        assert_eq!(holds.len(), 1);
        assert_eq!(
            holds.take_stalled(t0 + Duration::from_millis(2_000)),
            vec![1]
        );
    }

    #[test]
    fn writable_releases_and_the_stream_never_stalls() {
        let t0 = Instant::now();
        let mut holds = StreamHolds::new(None);
        holds.hold(7, t0);
        assert!(holds.release(7));
        assert!(!holds.release(7), "already released");
        assert_eq!(holds.next_deadline(), None);
        assert!(holds
            .take_stalled(t0 + Duration::from_secs(3_600))
            .is_empty());
    }

    #[test]
    fn the_stall_window_is_clamped_and_defaults_to_sixty_seconds() {
        let t0 = Instant::now();
        let at = |ms: Option<u32>| {
            let mut h = StreamHolds::new(ms);
            h.hold(1, t0);
            h.next_deadline().expect("held") - t0
        };
        assert_eq!(
            at(None),
            Duration::from_millis(u64::from(STREAM_STALL_DEFAULT_MS))
        );
        assert_eq!(STREAM_STALL_DEFAULT_MS, 60_000);
        assert_eq!(
            at(Some(0)),
            Duration::from_millis(u64::from(STREAM_STALL_MIN_MS))
        );
        assert_eq!(
            at(Some(u32::MAX)),
            Duration::from_millis(u64::from(STREAM_STALL_MAX_MS))
        );
    }

    #[test]
    fn several_stalled_streams_come_back_ascending() {
        let t0 = Instant::now();
        let mut holds = StreamHolds::new(Some(1_000));
        holds.hold(9, t0);
        holds.hold(2, t0);
        holds.hold(4, t0 + Duration::from_secs(10));
        assert_eq!(holds.take_stalled(t0 + Duration::from_secs(1)), vec![2, 9]);
        assert!(holds.is_held(4));
    }
}
