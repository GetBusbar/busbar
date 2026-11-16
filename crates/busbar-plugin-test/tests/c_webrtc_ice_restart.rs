// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WEBRTC-ICE-RESTART (ABI-MIN3-INTERFACE §14): MemIo's deterministic `random_into` records every draw (round
//! 18). The transport-webrtc arms run in its repo.
//!
//! W1-A12 lands the MemIo arm: a session task on a real `MemIo` draws its local ICE terms from a recording fill at
//! session start and again on each re-offer (an ICE restart), the way transport-webrtc's P-builder draws from
//! `Host::random_into`. The fill here is the recorder the arm checks the terms against; with it not installed the
//! draw panics and the panic is the FAULT (the forks never produce a value).

use std::future::poll_fn;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use busbar_plugin_abi::memio::{MemIo, Ran};
use hyper::rt::{Read, ReadBuf};

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

/// The session: ICE terms at start, then new terms for every re-offer fed to the conn.
fn spawn_session(m: &mut MemIo, fill: Option<Arc<Fill>>, terms: Terms) {
    let mut io = m.io();
    m.spawn(async move {
        let draw = |terms: &Terms| {
            let fill = fill.as_ref().expect("random fill not installed");
            let (mut u, mut p) = (vec![0u8; UFRAG], vec![0u8; PWD]);
            fill.random_into(&mut u);
            fill.random_into(&mut p);
            terms.lock().unwrap().push((u, p));
        };
        draw(&terms);
        loop {
            let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 64];
            let mut rb = ReadBuf::uninit(&mut raw);
            poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled()))
                .await
                .unwrap();
            if rb.filled().is_empty() {
                return;
            }
            draw(&terms);
        }
    });
}

#[test]
fn memio_records_every_draw() {
    let fill = Fill::new();
    let terms: Terms = Arc::default();
    let mut m = MemIo::new();
    spawn_session(&mut m, Some(fill.clone()), terms.clone());

    // (a) session start: the terms are bytes of the recorded draws.
    assert_eq!(m.run(0, 256), Ran::Idle);
    let first = terms.lock().unwrap()[0].clone();
    let rec = fill.draws();
    assert_eq!(rec.len(), 2);
    assert_eq!(
        (first.0.as_slice(), first.1.as_slice()),
        (rec[0].as_slice(), rec[1].as_slice())
    );

    // (b) a re-offer with new credentials: new terms, drawn from the fill, differing from the old.
    m.feed(b"re-offer");
    assert_eq!(m.run(1, 256), Ran::Idle);
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
    m.feed(&[]);
    assert_eq!(m.run(2, 256), Ran::Closed);
    assert_eq!(fill.draws().len(), 4);
}

#[test]
fn memio_without_a_fill_panics_and_yields_no_terms() {
    // (c) the fill not installed: the forks panic (the shim's catch is the FAULT), never produce a value.
    let terms: Terms = Arc::default();
    let mut m = MemIo::new();
    spawn_session(&mut m, None, terms.clone());
    let caught = catch_unwind(AssertUnwindSafe(|| m.run(0, 256)));
    assert!(caught.is_err());
    assert!(terms.lock().unwrap().is_empty());
}
