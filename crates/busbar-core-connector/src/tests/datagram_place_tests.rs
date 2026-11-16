// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W4 §8 `rendezvous_swap_relocates_and_pins`: a datagram need's declared target is
//! placed through its RENDEZVOUS door. When `finalize_boot_metadata` swaps that door, the kept
//! place is not the new door's, so the next datagram open locates again and its dial and
//! authority pin follow the new door's answer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use busbar_contract::conn::{ConnError, Conns as _, InstanceId, NeedId, OpenDesc};

use super::{dialling, p, Scripted, Sink, St, HOST_PWD, HOST_UFRAG};
use crate::framer::DoorFacts;
use crate::registry::{Entry, Transports};
use crate::support::{Knobs as DoorKnobs, TestDoor};

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);

/// The `bytes` rendezvous framer, locating every target at `authority`.
fn rendezvous(authority: &'static str) -> Arc<TestDoor> {
    Arc::new(TestDoor::new(
        "bytes",
        &["bytes"],
        &[],
        DoorKnobs {
            authority: Some(authority),
            ..DoorKnobs::default()
        },
    ))
}

/// The view: the dialling datagram framer `dg`, the `bytes` rendezvous framer, and a carrier.
fn view(dg: &Arc<Scripted>, exchange: &Arc<TestDoor>) -> Transports {
    Transports::new(vec![
        Entry {
            door: Arc::clone(dg) as Arc<dyn crate::framer::FramerDoor>,
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::clone(exchange) as Arc<dyn crate::framer::FramerDoor>,
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::new(TestDoor::identity("carrier")),
            alpn: Vec::new(),
        },
    ])
    .unwrap()
}

/// A datagram open of the need's declared target (empty target) for a fresh paired `unit`.
fn open(c: &crate::Connector, unit: u64) -> Result<busbar_contract::conn::ConnId, ConnError> {
    let pairing = crate::datagram::Pairing::new(Arc::new(Sink::default()), p("127.0.0.1:3478"));
    c.pair(unit, pairing).unwrap();
    c.open(
        OWNER,
        NEED,
        &OpenDesc {
            target: "",
            unit,
            ..OpenDesc::default()
        },
    )
}

#[test]
fn rendezvous_swap_relocates_and_pins() {
    crate::support::worker().block_on(async {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at: &'static str =
            Box::leak(listener.local_addr().unwrap().to_string().into_boxed_str());
        let dg = Arc::new(Scripted {
            facts: DoorFacts {
                dials: true,
                name: "dg".into(),
                claims: vec!["dg"],
                ..super::scripted(dialling()).facts.clone()
            },
            knobs: dialling(),
            st: Mutex::new(St {
                local: (HOST_UFRAG, HOST_PWD),
                begin: VecDeque::from([(0, b"offer".to_vec(), 0), (0, b"offer".to_vec(), 0)]),
                ..St::default()
            }),
            park: Mutex::new(None),
        });
        let first = rendezvous(at);
        let c = crate::Connector::serving(
            view(&dg, &first),
            crate::tests::loopback_literals(),
            None,
            Arc::new(|_, _| {}),
        );
        c.declare_need_to(
            OWNER,
            NEED,
            "dg",
            crate::DEFAULT_CLASS,
            &format!("bytes://{at}/v1/realtime/calls"),
        )
        .unwrap();

        let conn = open(&c, 7).expect("the first datagram open dials the rendezvous");
        assert_eq!(
            first.count("locate"),
            1,
            "the first open fills the place through the first door"
        );
        c.close(OWNER, conn).unwrap();

        // A door whose Locate names an authority the destination guard refuses (link-local).
        let second = rendezvous("169.254.169.254:9");
        c.finalize_boot_metadata(view(&dg, &second), &[], crate::pool::PoolPosture::NONE);
        assert_eq!(
            open(&c, 8),
            Err(ConnError::Refused),
            "the open follows the new door's place and is refused on its authority"
        );
        assert_eq!(
            second.count("locate"),
            1,
            "the swapped rendezvous door is located again, not served the old door's place"
        );
        assert_eq!(
            first.count("locate"),
            1,
            "the old door is never asked again"
        );
    });
}
