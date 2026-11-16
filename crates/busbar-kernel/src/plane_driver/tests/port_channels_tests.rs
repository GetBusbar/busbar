// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §12.19, §12.23 (PLANE-DRIVER slice 7): CHANNEL and CH_READY intents against a channel host, the
//! sessionless `demux`, and the ADMIN_TICK answer (PUSH and EMIT), through a scripted plane.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    tag as t, ChanAttach, DemuxRec, EmitRec, PushRec, CARRIER_STDIO, DX_OUTSTANDING, FROM_CORE,
    P_CHANNEL, P_ERROR,
};
use busbar_plugin_abi::records::{tag as g, Records, Reply, Writer};
use busbar_plugin_loader::ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_plugin_loader::ports::{CallCx, PortError};

use super::{decode_tick, demux, Attached, ChannelAttach, ChannelHost, Held};
use crate::plane_driver::port_intents::Resolver;
use crate::plane_driver::port_session::{Calls, Effects, Task};
use crate::plugin_records::RecordsDenied;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

/// The plane's session calls: a request answer with the scripted items, then one answer per piece.
struct Live;

enum It {
    Channel { exchange: u32, key: &'static str },
    ChReady { exchange: u32, tail: &'static [u8] },
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        match it {
            It::Channel { exchange, key } => sink(PlaneOut::Channel {
                exchange: *exchange,
                carrier: CARRIER_STDIO,
                flags: 0,
                framing: 1,
                key,
                head: Records::new(&[]),
            }),
            It::ChReady { exchange, tail } => sink(PlaneOut::ChReady {
                exchange: *exchange,
                tail,
            }),
        }
    }
}

#[derive(Default)]
struct Script {
    request: Vec<It>,
    answers: Mutex<VecDeque<Vec<It>>>,
    pieces: Mutex<Vec<(u32, u32, u32, Vec<u8>)>>,
}

impl Calls for Script {
    type Session = Live;

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        play(&self.request, sink);
        Ok(Live)
    }

    fn piece(
        &self,
        _: &mut Live,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.pieces
            .lock()
            .unwrap()
            .push((from, exchange, flags, bytes.to_vec()));
        let items = self.answers.lock().unwrap().pop_front().unwrap_or_default();
        play(&items, sink);
        Ok(())
    }

    fn rewrite(
        &self,
        _: &mut Live,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn end(&self, _: Live, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Ok(())
    }

    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<Live, PortError> {
        Err(refused())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }

    fn upstream(
        &self,
        _: &mut Live,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
}

struct NoStore;

impl crate::plane_driver::port_intents::IntentHost for NoStore {
    fn lookup(
        &self,
        _: crate::plugin_records::Scope,
        _: u32,
        _: u32,
        _: &[u8],
    ) -> Result<crate::plane_driver::port_intents::Looked, RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn store(
        &self,
        _: crate::plugin_records::Scope,
        _: u32,
        _: u64,
        _: &[u8],
        _: &[u8],
    ) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn delete(&self, _: crate::plugin_records::Scope, _: &[u8]) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn commit(
        &self,
        _: crate::plugin_records::Scope,
        _: &[crate::plugin_records::CommitOp<'_>],
    ) -> Result<crate::plugin_records::CommitOutcome, RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn push(&self, _: u64, _: &[u8]) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

/// A held channel that records what the session told it.
struct Wire(Arc<Mutex<Vec<String>>>);

impl Held for Wire {
    fn send(&mut self, message: &[u8], ask: bool) -> Result<(), RecordsDenied> {
        self.0.lock().unwrap().push(format!(
            "send {} ask={ask}",
            String::from_utf8_lossy(message)
        ));
        Ok(())
    }

    fn ready(&mut self, tail: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push(format!("ready {}", String::from_utf8_lossy(tail)));
    }
}

struct Channels {
    wire: Arc<Mutex<Vec<String>>>,
    seen: Mutex<Vec<(u32, String, u32)>>,
    deny: bool,
}

impl ChannelHost for Channels {
    fn attach(&self, a: &ChannelAttach<'_>) -> Result<Attached, RecordsDenied> {
        self.seen
            .lock()
            .unwrap()
            .push((a.exchange, a.key.to_owned(), a.carrier));
        if self.deny {
            return Err(RecordsDenied::Unavailable);
        }
        Ok(Attached {
            generation: 3,
            slot: 11,
            greet: true,
            ready_tail: b"tail".to_vec(),
            held: Box::new(Wire(Arc::clone(&self.wire))),
        })
    }
}

fn req() -> PlaneIn<'static> {
    PlaneIn {
        route: 1,
        flags: 0,
        auth: 1,
        method: "POST",
        path: "/x",
        query: "",
        headers: &[],
        identity: &[],
        request_id: 1,
        carrier: 0,
        work: "",
        ticket_record: &[],
    }
}

fn channels(deny: bool) -> Channels {
    Channels {
        wire: Arc::default(),
        seen: Mutex::default(),
        deny,
    }
}

#[test]
fn an_attached_channel_is_a_p_channel_piece_on_its_exchange_carrying_the_attachment() {
    let script = Script {
        request: vec![It::Channel {
            exchange: 4,
            key: "mcp",
        }],
        ..Script::default()
    };
    let host = channels(false);
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    task.resolve(
        first,
        &Resolver::new(&NoStore, None).with_channels(&host),
        &Quiet,
    )
    .unwrap();
    assert_eq!(
        *host.seen.lock().unwrap(),
        vec![(4, "mcp".to_owned(), CARRIER_STDIO)]
    );
    let got = script.pieces.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0, got[0].1, got[0].2), (FROM_CORE, 4, P_CHANNEL));
    let rec = Records::new(&got[0].3).next().unwrap().unwrap();
    assert_eq!(rec.tag, t::CH_ATTACH);
    let (attach, tail) = rec.pod_tail::<ChanAttach>().unwrap();
    assert_eq!((attach.generation, attach.slot, attach.greet), (3, 11, 1));
    assert_eq!(tail, b"tail");
}

#[test]
fn a_channel_that_cannot_attach_is_a_p_error_with_a_refusal_on_that_exchange() {
    for with_host in [true, false] {
        let script = Script {
            request: vec![It::Channel {
                exchange: 2,
                key: "k",
            }],
            ..Script::default()
        };
        let host = channels(true);
        let resolver = Resolver::new(&NoStore, None);
        let resolver = if with_host {
            resolver.with_channels(&host)
        } else {
            resolver
        };
        let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
        task.resolve(first, &resolver, &Quiet).unwrap();
        let got = script.pieces.lock().unwrap().clone();
        assert_eq!((got[0].1, got[0].2), (2, P_ERROR));
        let rec = Records::new(&got[0].3).next().unwrap().unwrap();
        assert_eq!(
            rec.tag,
            t::REFUSAL,
            "one REFUSAL record to render in-stream"
        );
    }
}

#[test]
fn ch_ready_reaches_the_held_channel_of_that_exchange_and_an_unheld_one_is_dropped() {
    let script = Script {
        request: vec![It::Channel {
            exchange: 4,
            key: "mcp",
        }],
        ..Script::default()
    };
    // The piece answer is the greeting session's CH_READY, and one for an exchange nobody holds.
    *script.answers.lock().unwrap() = VecDeque::from([vec![
        It::ChReady {
            exchange: 4,
            tail: b"caps",
        },
        It::ChReady {
            exchange: 9,
            tail: b"lost",
        },
    ]]);
    let host = channels(false);
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    task.resolve(
        first,
        &Resolver::new(&NoStore, None).with_channels(&host),
        &Quiet,
    )
    .unwrap();
    assert_eq!(*host.wire.lock().unwrap(), vec!["ready caps".to_owned()]);
}

#[test]
fn a_held_channel_is_written_to_through_the_task_and_dropped_with_it() {
    let script = Script {
        request: vec![It::Channel {
            exchange: 4,
            key: "mcp",
        }],
        ..Script::default()
    };
    let host = channels(false);
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    task.resolve(
        first,
        &Resolver::new(&NoStore, None).with_channels(&host),
        &Quiet,
    )
    .unwrap();
    assert!(task.send_channel(4, b"hello", true).unwrap());
    assert!(
        !task.send_channel(5, b"x", false).unwrap(),
        "no channel on exchange 5"
    );
    assert_eq!(
        *host.wire.lock().unwrap(),
        vec!["send hello ask=true".to_owned()]
    );
}

/// A plane that answers `demux` and `admin` with scripted bytes; it has no sessions.
struct FakePort {
    demux: Vec<u8>,
    tick: Vec<u8>,
}

impl PlanePort for FakePort {
    fn routes(&self) -> &[RouteInfo] {
        &[]
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
    }
    fn facts(&self) -> u64 {
        0
    }
    fn tick_s(&self) -> Option<u64> {
        Some(5)
    }
    fn admin_openapi(&self) -> Option<&str> {
        None
    }
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn upstream(
        &self,
        _: &mut PlaneSession,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn piece(
        &self,
        _: &mut PlaneSession,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn rewrite(
        &self,
        _: &mut PlaneSession,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn demux(
        &self,
        _: &str,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        for rec in Records::new(&self.demux) {
            let rec = rec.unwrap();
            let (dx, tail) = rec.pod_tail::<DemuxRec>().unwrap();
            sink(PlaneOut::Demux {
                slot: dx.slot,
                flags: dx.flags,
                tail,
            });
        }
        Ok(())
    }
    fn admin<'a>(
        &'a self,
        _: CallCx,
        _: u32,
        _: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        Box::pin(async move { Ok(self.tick.clone()) })
    }
}

#[test]
fn demux_answers_the_slot_flags_and_tail_and_no_record_is_slot_zero() {
    let mut r = Reply::new();
    r.put_pod_tail(
        t::DEMUX,
        &DemuxRec {
            slot: 0,
            flags: DX_OUTSTANDING,
            _r: 0,
        },
        b"fallback",
    )
    .unwrap();
    let port = FakePort {
        demux: r.as_bytes().to_vec(),
        tick: Vec::new(),
    };
    let d = demux(&port, "mcp", b"{}").unwrap().unwrap();
    assert_eq!(
        (d.slot, d.flags, &d.tail[..]),
        (0, DX_OUTSTANDING, &b"fallback"[..])
    );
    let none = FakePort {
        demux: Vec::new(),
        tick: Vec::new(),
    };
    assert!(demux(&none, "mcp", b"{}").unwrap().is_none());
}

#[test]
fn a_tick_answer_is_pushes_and_emits_in_order() {
    let mut nested = Reply::new();
    nested.put_text(g::H_METHOD, "POST").unwrap();
    let mut r = Reply::new();
    r.put_pod_tail(t::PUSH, &PushRec { ttl_s: 60 }, nested.as_bytes())
        .unwrap();
    r.put_pod_tail(t::EMIT, &EmitRec { carrier: 7 }, b"line one")
        .unwrap();
    let out = decode_tick(r.as_bytes()).unwrap();
    assert_eq!(out.pushes.len(), 1);
    assert_eq!(out.pushes[0].0, 60);
    assert_eq!(out.pushes[0].1, nested.as_bytes());
    assert_eq!(out.emits, vec![(7, b"line one".to_vec())]);
    assert!(decode_tick(&[]).unwrap().pushes.is_empty());
}
