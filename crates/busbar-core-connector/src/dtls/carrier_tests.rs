// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The datagram carrier on real loopback sockets over a scripted transport: one shared media port, many
//! rendezvous, routed by the local ufrag a check names (C-ICE).

use super::*;
use crate::dtls::session::Live;
use crate::dtls::tests::{check, creds};
use busbar_plugin_abi::kinds::transport::transport as wire;
use busbar_ports::transport::{ConnIn, TransportEvent, TransportOut};
use busbar_ports::PortError;
use std::collections::VecDeque;

const REMOTE_PWD: &str = "remote-password-0123456789";

type Told = Arc<Mutex<Vec<(&'static str, u32)>>>;

/// Opens one scripted session per call, each with the next ufrag and pwd.
struct Many {
    next: Mutex<VecDeque<(&'static str, &'static str)>>,
    told: Told,
    local: Mutex<Vec<String>>,
}

struct Tag {
    name: &'static str,
    told: Told,
}

impl Opener for Many {
    fn begin(
        &self,
        conn: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<Box<dyn Live>, PortError> {
        self.local.lock().unwrap().push(String::from(conn.local));
        let (ufrag, pwd) = self.next.lock().unwrap().pop_front().unwrap();
        sink(TransportOut::IceTerms {
            controlling: false,
            local_ufrag: ufrag,
            local_pwd: pwd.as_bytes(),
            remote_ufrag: "rfrag",
            remote_pwd: REMOTE_PWD.as_bytes(),
        });
        Ok(Box::new(Tag {
            name: ufrag,
            told: Arc::clone(&self.told),
        }))
    }
}

impl Live for Tag {
    fn event(
        &mut self,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        match ev {
            TransportEvent::Rendezvous(_) => sink(TransportOut::Rendezvous("answer")),
            TransportEvent::Path { flags, .. } => {
                self.told.lock().unwrap().push((self.name, flags))
            }
            TransportEvent::Keying { .. } => {}
        }
        Ok(())
    }

    fn datagram(
        &mut self,
        _path: u32,
        _secured: bool,
        _bytes: &[u8],
        _sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn timer(&mut self, _sink: &mut dyn FnMut(TransportOut<'_>)) -> Result<(), PortError> {
        Ok(())
    }
}

struct Loopback;

impl MediaListeners for Loopback {
    fn listener(&self, _route: u32) -> Option<MediaRoute> {
        Some(MediaRoute {
            bind: "127.0.0.1:0".parse().unwrap(),
            class: 0,
        })
    }
}

fn carrier(ufrags: &[(&'static str, &'static str)]) -> (DatagramCarrier, Arc<Many>) {
    let many = Arc::new(Many {
        next: Mutex::new(ufrags.iter().copied().collect()),
        told: Arc::default(),
        local: Mutex::default(),
    });
    let judge = |dest: &str,
                 _class: u32,
                 _done: crate::Judged|
     -> Option<Result<SocketAddr, u64>> { dest.parse().ok().map(Ok) };
    let judge: Arc<dyn DialJudge> = Arc::new(judge);
    let carrier = DatagramCarrier::over(
        Arc::clone(&many) as Arc<dyn Opener>,
        Arc::new(Loopback),
        judge,
        Arc::new(LogAudit),
    )
    .unwrap();
    (carrier, many)
}

/// Wait (bounded) until `told` holds `n` entries.
async fn until(told: &Told, n: usize) {
    for _ in 0..150 {
        if told.lock().unwrap().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn two_rendezvous_on_one_media_port_are_routed_by_ufrag() {
    crate::support::worker().block_on(async {
        let (carrier, many) = carrier(&[
            ("afrag", "a-password-0123456789012"),
            ("bfrag", "b-password-0123456789012"),
        ]);
        let first = carrier.accept(7, "offer a").await;
        let second = carrier.accept(7, "offer b").await;
        let (Ok((answer_a, _leg_a)), Ok((answer_b, _leg_b))) = (first, second) else {
            panic!("both rendezvous are accepted");
        };
        assert_eq!((&*answer_a, &*answer_b), ("answer", "answer"));
        let locals = many.local.lock().unwrap().clone();
        assert_eq!(locals[0], locals[1], "one shared port");
        let port: SocketAddr = locals[0].parse().unwrap();

        // An honest check for the second session only reaches the second session.
        let far = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let honest = check(
            &creds("bfrag", "b-password-0123456789012"),
            "rfrag",
            "b-password-0123456789012",
        );
        far.send_to(&honest, port).unwrap();
        until(&many.told, 1).await;
        assert_eq!(
            *many.told.lock().unwrap(),
            vec![("bfrag", wire::PATH_NEW | wire::PATH_VERIFIED)]
        );

        // A check for the first session with the second's password is nobody's path.
        let forged = check(
            &creds("afrag", "a-password-0123456789012"),
            "rfrag",
            "b-password-0123456789012",
        );
        far.send_to(&forged, port).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            many.told.lock().unwrap().len(),
            1,
            "the forged check was not heard"
        );
    });
}

#[test]
fn a_ufrag_already_live_on_the_port_is_refused() {
    crate::support::worker().block_on(async {
        let (carrier, _many) = carrier(&[
            ("same", "p-password-0123456789012"),
            ("same", "q-password-0123456789012"),
        ]);
        let first = carrier.accept(7, "offer").await;
        assert!(first.is_ok());
        let second = carrier.accept(7, "offer").await;
        assert!(matches!(second, Err(RecordsDenied::Unavailable)));
        drop(first);
    });
}

/// THE RELEASE PROOF FOR A PORT'S READER BUFFER (owner's ruling on allocation, addendum; GROUP-storage R2.5
/// item 1, B5: `udp::MAX_DATAGRAM` bytes, read into for the port's life). A carrier binds its listener's port on
/// the first accept; when the leg and the carrier let the port go, the reader ends on its next tick and frees the
/// buffer. After one warm carrier (the runtime's driver), five carriers that accepted once and were dropped
/// leave less than one reader buffer held.
#[test]
fn a_port_let_go_returns_its_reader_buffer() {
    crate::support::worker().block_on(async {
        let cycle = || async {
            let (carrier, _many) = carrier(&[("rfrag", "r-password-0123456789012")]);
            let accepted = carrier.accept(7, "offer").await;
            assert!(accepted.is_ok(), "the rendezvous is accepted");
            drop(accepted);
            drop(carrier);
            tokio::time::sleep(TICK * 5).await;
        };
        cycle().await;
        let start = crate::support::held_bytes();
        for _ in 0..5 {
            cycle().await;
        }
        let held = crate::support::held_bytes() - start;
        assert!(
            held < isize::try_from(crate::udp::MAX_DATAGRAM).unwrap(),
            "five carriers let go still hold {held} bytes"
        );
    });
}
