// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R1: one upstream attempt crosses its framer's `locate` once. The answer the
//! head's completion located (`locate_head`) is the one the open dials (`open_located`), on a
//! fresh dial and on a pooled line alike; a carried answer for any other target is never trusted.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

/// One attempt the way the kernel's far end makes it: complete the head at `located_at`, then
/// open `far` with the answer that completion carried, and read the exchange to its end. Returns
/// what it read and how often `locate` crossed.
async fn located_attempt(c: &Connector, far: &str, located_at: &str) -> (Exchanged, u32) {
    let scope = Scope::open();
    let (_, located) = c
        .locate_head(OWNER, NeedId(0), located_at, 0)
        .expect("the head completes");
    let id = c
        .open_located(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: far,
                body: busbar_contract::conn::Bytes::copy_from_slice(b"ask"),
                ..OpenDesc::default()
            },
            false,
            located.as_deref(),
        )
        .expect("opens");
    let mut buf = [0_u8; 64];
    let mut got = Vec::new();
    let mut whole = false;
    let mut failed = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match c.read(OWNER, id, 7, &mut buf) {
            Ok(p) if p.kind == PieceKind::Completion => {
                whole = true;
                break;
            }
            Ok(p) => got.extend_from_slice(&buf[..p.len]),
            Err(ConnError::Pending) => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    let _ = c.close(OWNER, id);
    ((got, whole, failed), scope.count(Derive::Locate))
}

#[test]
fn upstream_locate_once_per_attempt() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(std::time::Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages")
            .expect("a served scheme declares");
        let whole = (b"x".to_vec(), true, None);

        assert_eq!(
            located_attempt(&c, &far, &far).await,
            (whole.clone(), 1),
            "a fresh dial locates once: the head's answer is the one it dials"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        assert_eq!(
            located_attempt(&c, &far, &far).await,
            (whole.clone(), 1),
            "a pooled reuse locates once too"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "control: the second attempt rode the kept line"
        );

        let scope = Scope::open();
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &far, b"ask", true).await,
            whole,
            "a plugin caller's open carries no answer and is served as before"
        );
        assert_eq!(
            scope.count(Derive::Locate),
            1,
            "a plugin caller's open locates once, as it always has"
        );
    });
}

#[test]
fn a_carried_answer_for_another_target_is_located_afresh() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let (elsewhere, elsewhere_accepted, _) = keeping_far_end().await;
        let c = pooled_messages(std::time::Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages")
            .expect("a served scheme declares");

        assert_eq!(
            located_attempt(&c, &far, &elsewhere).await,
            ((b"x".to_vec(), true, None), 2),
            "an answer located for another target is not trusted: the open locates afresh"
        );
        assert_eq!(
            (
                accepted.load(Ordering::SeqCst),
                elsewhere_accepted.load(Ordering::SeqCst)
            ),
            (1, 0),
            "the dial went where the fresh answer said, never where the carried one did"
        );
    });
}
