// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WEBRTC-ICE-RESTART (ABI-MIN3-INTERFACE §14): a session's deterministic `random_into` records every draw
//! (round 18). The transport-webrtc arms run in its repo.
//!
//! A session task draws its local ICE terms from a recording fill at session start and again on each re-offer
//! (an ICE restart), the way transport-webrtc's P-builder draws from `Host::random_into`. The fill here is the
//! recorder the arm checks the terms against; with it not installed the draw panics and the panic is the FAULT
//! (the forks never produce a value). The session runs on a current-thread runtime over an in-memory pipe (the
//! engine's MemIo, which this arm first ran on, was cut with the labelled output model: WIRE-022, E-MEMIO).

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

const UFRAG: usize = 8;
const PWD: usize = 24;

/// A deterministic fill that records every draw, in order (a counter through splitmix64).
struct Fill {
    state: Mutex<(u64, Vec<Vec<u8>>)>,
}
impl Fill {
    fn new() -> Arc<Self> {
        Arc::new(Fill {
            state: Mutex::new((0x9E37_79B9_7F4A_7C15, Vec::new())),
        })
    }
    fn random_into(&self, buf: &mut [u8]) {
        let mut st = self.state.lock().unwrap();
        for b in buf.iter_mut() {
            st.0 = st.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = st.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)) as u8;
        }
        st.1.push(buf.to_vec());
    }
    fn draws(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().1.clone()
    }
}

type Terms = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;

/// The session: ICE terms at start, then new terms for every re-offer read from `io`, until EOF.
fn spawn_session(mut io: DuplexStream, fill: Option<Arc<Fill>>, terms: Terms) -> JoinHandle<()> {
    tokio::spawn(async move {
        let draw = |terms: &Terms| {
            let fill = fill.as_ref().expect("random fill not installed");
            let (mut u, mut p) = (vec![0u8; UFRAG], vec![0u8; PWD]);
            fill.random_into(&mut u);
            fill.random_into(&mut p);
            terms.lock().unwrap().push((u, p));
        };
        draw(&terms);
        let mut raw = [0u8; 64];
        loop {
            if io.read(&mut raw).await.unwrap() == 0 {
                return;
            }
            draw(&terms);
        }
    })
}

/// Lets the session task run until it parks on its read.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_session_records_every_draw() {
    let fill = Fill::new();
    let terms: Terms = Arc::default();
    let (mut far, near) = tokio::io::duplex(64);
    let session = spawn_session(near, Some(fill.clone()), terms.clone());

    // (a) session start: the terms are bytes of the recorded draws.
    settle().await;
    let first = terms.lock().unwrap()[0].clone();
    let rec = fill.draws();
    assert_eq!(rec.len(), 2);
    assert_eq!(
        (first.0.as_slice(), first.1.as_slice()),
        (rec[0].as_slice(), rec[1].as_slice())
    );

    // (b) a re-offer with new credentials: new terms, drawn from the fill, differing from the old.
    far.write_all(b"re-offer").await.unwrap();
    settle().await;
    let all = terms.lock().unwrap().clone();
    assert_eq!(all.len(), 2);
    let rec = fill.draws();
    assert_eq!(rec.len(), 4);
    assert_eq!(
        (all[1].0.as_slice(), all[1].1.as_slice()),
        (rec[2].as_slice(), rec[3].as_slice())
    );
    assert_ne!(all[0].0, all[1].0);
    assert_ne!(all[0].1, all[1].1);

    // The session ends on EOF and nothing was drawn that the record does not hold.
    drop(far);
    session.await.unwrap();
    assert_eq!(fill.draws().len(), 4);
}

#[tokio::test(flavor = "current_thread")]
async fn a_session_without_a_fill_panics_and_yields_no_terms() {
    // (c) the fill not installed: the forks panic (the shim's catch is the FAULT), never produce a value.
    let terms: Terms = Arc::default();
    let (_far, near) = tokio::io::duplex(64);
    let caught = spawn_session(near, None, terms.clone()).await;
    assert!(caught.is_err_and(|e| e.is_panic()));
    assert!(terms.lock().unwrap().is_empty());
}
