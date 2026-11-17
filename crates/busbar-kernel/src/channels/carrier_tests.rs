// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.19 (PLANE-CARRIER): the channel carrier driver over fake wires. A "child" is the far end of an in-memory
//! duplex: the test writes what the child writes and reads what core wrote to it. The plane's `demux` is a script
//! over the message text: `r<slot>|..` replies to a slot, `f<slot>|..` is that slot's final reply, `o|<tail>` is
//! DX_OUTSTANDING with that fallback tail, `b|<key>` is DX_BROADCAST under that key; anything else has no DEMUX.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    CARRIER_HTTP, CARRIER_STDIO, CH_FRAME_NDJSON, CH_PER_CALLER, CH_SERIAL, DX_BROADCAST, DX_FINAL,
    DX_OUTSTANDING, DX_RESIGHT, P_SIGNAL, P_TEXT,
};
use busbar_plugin_abi::records::Records;
use tokio::io::{
    duplex, split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf,
    WriteHalf,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::carrier::{ChannelDriver, Demuxer, Events, Wire, Wires};
use super::{Attachment, ChannelMsg, ChannelReq, SessionSignals, UpstreamChannels};
use crate::plane_driver::port_channels::Demuxed;
use crate::plane_driver::port_intents::Namespace;
use crate::plugin_records::RecordsDenied;
use crate::upstreams::{ProgramPin, StdioCommand, UpstreamDef, UpstreamTls};

const WAIT: Duration = Duration::from_secs(3);
const SHORT: Duration = Duration::from_millis(60);
const INSTANCE: u64 = 7;

/// The far end of one wire.
struct Remote {
    stdin: BufReader<ReadHalf<DuplexStream>>,
    stdout: WriteHalf<DuplexStream>,
    gone: Arc<AtomicBool>,
}

impl Remote {
    async fn line(&mut self) -> String {
        let mut line = String::new();
        timeout(WAIT, self.stdin.read_line(&mut line))
            .await
            .expect("core wrote a line")
            .unwrap();
        line
    }

    async fn says(&mut self, text: &str) {
        self.stdout.write_all(text.as_bytes()).await.unwrap();
        self.stdout.write_all(b"\n").await.unwrap();
        self.stdout.flush().await.unwrap();
    }

    /// The child exits: both its ends close.
    fn exits(self) {
        drop(self);
    }

    async fn nothing_written(&mut self) -> bool {
        let mut line = String::new();
        timeout(SHORT, self.stdin.read_line(&mut line))
            .await
            .is_err()
    }
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct FakeWires {
    remotes: mpsc::UnboundedSender<Remote>,
    opened: AtomicUsize,
    fail: AtomicBool,
}

impl Wires for FakeWires {
    fn open<'a>(
        &'a self,
        _upstream: &'a UpstreamDef,
        req: &'a ChannelReq<'a>,
    ) -> BoxFut<'a, Result<Wire, RecordsDenied>> {
        Box::pin(async move {
            self.opened.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(RecordsDenied::Unavailable);
            }
            let (ours, theirs) = duplex(1 << 16);
            let (read, write) = split(ours);
            let (stdin, stdout) = split(theirs);
            let gone = Arc::new(AtomicBool::new(false));
            let _ = self.remotes.send(Remote {
                stdin: BufReader::new(stdin),
                stdout,
                gone: Arc::clone(&gone),
            });
            Ok(Wire {
                read: Box::new(read),
                write: (req.carrier == CARRIER_STDIO)
                    .then(|| Box::new(write) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>),
                hold: Box::new(DropFlag(gone)),
            })
        })
    }
}

struct Script;

impl Demuxer for Script {
    fn demux(&self, _key: &str, message: &[u8]) -> Option<Demuxed> {
        let text = std::str::from_utf8(message).ok()?;
        let (head, tail) = text.split_once('|')?;
        let slot = |n: &str| n.parse::<u64>().unwrap();
        let (kind, rest) = head.split_at(1);
        match kind {
            "r" => Some(Demuxed {
                slot: slot(rest),
                flags: 0,
                tail: Vec::new(),
            }),
            "f" => Some(Demuxed {
                slot: slot(rest),
                flags: DX_FINAL,
                tail: Vec::new(),
            }),
            "o" => Some(Demuxed {
                slot: 0,
                flags: DX_OUTSTANDING,
                tail: tail.as_bytes().to_vec(),
            }),
            "b" => Some(Demuxed {
                slot: 0,
                flags: DX_BROADCAST,
                tail: tail.as_bytes().to_vec(),
            }),
            "s" => Some(Demuxed {
                slot: slot(rest),
                flags: DX_RESIGHT,
                tail: Vec::new(),
            }),
            _ => None,
        }
    }
}

/// One recorded signal: instance, key, subject, flags, payload.
type SignalRow = (u64, Vec<u8>, Option<[u8; 32]>, u32, Vec<u8>);

#[derive(Default)]
struct Signals(Mutex<Vec<SignalRow>>);

impl SessionSignals for Signals {
    fn signal(
        &self,
        instance: u64,
        key: &[u8],
        subject: Option<[u8; 32]>,
        flags: u32,
        bytes: &[u8],
    ) -> u32 {
        self.0
            .lock()
            .unwrap()
            .push((instance, key.to_vec(), subject, flags, bytes.to_vec()));
        1
    }
}

#[derive(Default)]
struct Told {
    tripped: Mutex<Vec<String>>,
    resighted: Mutex<Vec<String>>,
}

impl Events for Told {
    fn tripped(&self, upstream: &str) {
        self.tripped.lock().unwrap().push(upstream.to_owned());
    }

    fn resight(&self, upstream: &str) {
        self.resighted.lock().unwrap().push(upstream.to_owned());
    }
}

struct Fixture {
    budget: super::budget::UnitBudget,
    driver: ChannelDriver,
    remotes: mpsc::UnboundedReceiver<Remote>,
    wires: Arc<FakeWires>,
    signals: Arc<Signals>,
    told: Arc<Told>,
    who: Namespace,
}

fn fixture() -> Fixture {
    let (tx, remotes) = mpsc::unbounded_channel();
    let wires = Arc::new(FakeWires {
        remotes: tx,
        opened: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
    });
    let signals = Arc::new(Signals::default());
    let told = Arc::new(Told::default());
    let budget = super::budget::ChannelBudget::new().instance();
    let unit = budget.unit();
    let driver = ChannelDriver::new(
        INSTANCE,
        budget,
        Arc::clone(&wires) as Arc<dyn Wires>,
        Arc::new(Script),
        Arc::clone(&signals) as Arc<dyn SessionSignals>,
        Arc::clone(&told) as Arc<dyn Events>,
    );
    Fixture {
        budget: unit,
        driver,
        remotes,
        wires,
        signals,
        told,
        who: Namespace {
            plugin: "plane-x".into(),
            name: "x".into(),
            instance: INSTANCE,
            slot: 0,
        },
    }
}

fn upstream(idle_s: u64) -> UpstreamDef {
    UpstreamDef {
        resource: None,
        allow_private: false,
        name: "member".into(),
        url: None,
        command: Some(StdioCommand {
            argv: vec!["/bin/member".into()],
            env: Vec::new(),
            cwd: None,
            pin: ProgramPin::Unpinned,
            idle_s,
        }),
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth: None,
    }
}

fn req<'a>(
    budget: &'a super::budget::UnitBudget,
    exchange: u32,
    key: &'a str,
    flags: u32,
) -> ChannelReq<'a> {
    ChannelReq {
        budget,
        exchange,
        carrier: CARRIER_STDIO,
        flags,
        framing: CH_FRAME_NDJSON,
        key,
        subject: None,
        head: Records::new(&[]),
    }
}

async fn attach(
    f: &Fixture,
    up: &UpstreamDef,
    r: ChannelReq<'_>,
) -> Result<Attachment, RecordsDenied> {
    let caller = f.who.caller();
    f.driver.attach(&caller, up, r).await
}

async fn message(a: &mut Attachment) -> String {
    match timeout(WAIT, a.recv()).await.expect("a message") {
        Some(ChannelMsg::Message(bytes)) => String::from_utf8(bytes.into_vec()).unwrap(),
        Some(ChannelMsg::Ended) => "<ended>".to_owned(),
        None => "<none>".to_owned(),
    }
}

#[tokio::test]
async fn the_first_attach_of_a_generation_greets_and_the_next_waits_for_its_ready() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    assert!(a.greet, "the first attach runs the greeting");
    assert_eq!(a.generation, 1);
    let caller = f.who.caller();
    let mut waiting = f.driver.attach(&caller, &up, req(&f.budget, 2, "k", 0));
    assert!(
        timeout(SHORT, &mut waiting).await.is_err(),
        "no other session is released before CH_READY"
    );
    a.ready(b"caps");
    let b = timeout(WAIT, waiting).await.unwrap().unwrap();
    assert!(!b.greet);
    assert_eq!(&*b.ready_tail, b"caps");
    assert_eq!(
        (b.generation, a.generation),
        (1, 1),
        "one child serves both"
    );
    assert_ne!(a.slot, b.slot);
    assert!(f.remotes.try_recv().is_ok(), "one child was spawned");
    assert!(f.remotes.try_recv().is_err());
    assert_eq!(f.wires.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_greeter_that_leaves_without_ready_hands_the_greeting_to_the_next() {
    let f = fixture();
    let up = upstream(300);
    let a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    let caller = f.who.caller();
    let mut waiting = f.driver.attach(&caller, &up, req(&f.budget, 2, "k", 0));
    assert!(timeout(SHORT, &mut waiting).await.is_err());
    drop(a);
    let b = timeout(WAIT, waiting).await.unwrap().unwrap();
    assert!(b.greet, "it never readied, so the next session greets");
    assert_eq!(b.generation, 1);
}

#[tokio::test]
async fn messages_are_written_framed_and_a_final_reply_releases_the_next_serial_ask() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", CH_SERIAL))
        .await
        .unwrap();
    a.ready(b"");
    let mut b = attach(&f, &up, req(&f.budget, 2, "k", CH_SERIAL))
        .await
        .unwrap();
    let mut child = f.remotes.recv().await.unwrap();
    a.send(b"ask-a", true).await.unwrap();
    b.send(b"ask-b", true).await.unwrap();
    assert_eq!(
        child.line().await,
        "ask-a\n",
        "an NDJSON write ends in one newline"
    );
    assert!(child.nothing_written().await, "b waits behind a's ask");
    child.says(&format!("f{}|reply-a", a.slot)).await;
    assert_eq!(message(&mut a).await, format!("f{}|reply-a", a.slot));
    assert_eq!(child.line().await, "ask-b\n", "the final reply released b");
    child.says(&format!("r{}|reply-b", b.slot)).await;
    assert_eq!(message(&mut b).await, format!("r{}|reply-b", b.slot));
}

#[tokio::test]
async fn a_message_that_is_not_an_ask_is_written_at_once_even_behind_a_serial_ask() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", CH_SERIAL))
        .await
        .unwrap();
    a.ready(b"");
    let mut b = attach(&f, &up, req(&f.budget, 2, "k", CH_SERIAL))
        .await
        .unwrap();
    let mut child = f.remotes.recv().await.unwrap();
    a.send(b"ask-a", true).await.unwrap();
    assert_eq!(child.line().await, "ask-a\n");
    b.send(b"answer-to-the-members-own-ask", false)
        .await
        .unwrap();
    assert_eq!(child.line().await, "answer-to-the-members-own-ask\n");
}

#[tokio::test]
async fn an_unbidden_message_goes_to_the_head_of_the_ask_line_and_leaves_its_ask_open() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", CH_SERIAL))
        .await
        .unwrap();
    a.ready(b"");
    let mut child = f.remotes.recv().await.unwrap();
    a.send(b"ask-a", true).await.unwrap();
    assert_eq!(child.line().await, "ask-a\n");
    child.says("o|fallback-not-used").await;
    assert_eq!(message(&mut a).await, "o|fallback-not-used");
    child.says(&format!("f{}|done", a.slot)).await;
    assert_eq!(
        message(&mut a).await,
        format!("f{}|done", a.slot),
        "its ask was still open"
    );
}

#[tokio::test]
async fn an_unbidden_message_with_no_ask_open_writes_the_planes_fallback_or_is_counted() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    a.ready(b"");
    let mut child = f.remotes.recv().await.unwrap();
    child.says("o|{\"error\":\"no\"}").await;
    assert_eq!(
        child.line().await,
        "{\"error\":\"no\"}\n",
        "the fallback, framed"
    );
    assert_eq!(f.driver.counts().unattributed(), 0);
    child.says("o|").await;
    for _ in 0..100 {
        if f.driver.counts().unattributed() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        f.driver.counts().unattributed(),
        1,
        "no fallback: dropped and counted"
    );
}

#[tokio::test]
async fn a_broadcast_goes_to_the_signal_registry_with_the_key_and_the_channels_subject() {
    let mut f = fixture();
    let up = upstream(300);
    let subject = [9u8; 32];
    let mut r = req(&f.budget, 1, "k", CH_PER_CALLER);
    r.subject = Some(subject);
    let mut a = attach(&f, &up, r).await.unwrap();
    a.ready(b"");
    let mut child = f.remotes.recv().await.unwrap();
    child.says("b|resources/updated").await;
    for _ in 0..100 {
        if !f.signals.0.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen = f.signals.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        [(
            INSTANCE,
            b"resources/updated".to_vec(),
            Some(subject),
            P_SIGNAL | P_TEXT,
            b"b|resources/updated".to_vec()
        )]
    );
}

#[tokio::test]
async fn a_resight_flag_asks_for_a_sighting_of_the_upstream() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    a.ready(b"");
    let mut child = f.remotes.recv().await.unwrap();
    child.says(&format!("s{}|changed", a.slot)).await;
    assert_eq!(message(&mut a).await, format!("s{}|changed", a.slot));
    assert_eq!(*f.told.resighted.lock().unwrap(), ["member"]);
}

#[tokio::test]
async fn a_message_with_no_demux_is_dropped_and_the_next_still_arrives() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    a.ready(b"");
    let mut child = f.remotes.recv().await.unwrap();
    child.says("noise").await;
    child.says(&format!("r{}|real", a.slot)).await;
    assert_eq!(message(&mut a).await, format!("r{}|real", a.slot));
}

#[tokio::test]
async fn a_child_that_exits_ends_the_generation_for_every_session_and_the_next_attach_respawns_after_100_ms(
) {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    a.ready(b"");
    let mut b = attach(&f, &up, req(&f.budget, 2, "k", 0)).await.unwrap();
    let child = f.remotes.recv().await.unwrap();
    let gone = Arc::clone(&child.gone);
    child.exits();
    assert_eq!(message(&mut a).await, "<ended>");
    assert_eq!(message(&mut b).await, "<ended>");
    for _ in 0..100 {
        if gone.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        gone.load(Ordering::SeqCst),
        "the ended generation's wire was dropped (the child is killed)"
    );
    let started = Instant::now();
    let c = attach(&f, &up, req(&f.budget, 3, "k", 0)).await.unwrap();
    assert!(c.greet, "a new generation greets again");
    assert_eq!(c.generation, 2);
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "the first respawn waits 100 ms"
    );
    assert!(f.remotes.try_recv().is_ok());
}

#[tokio::test]
async fn generation_end_joins_a_blocked_writer_before_notifying_attachments() {
    let mut f = fixture();
    let up = upstream(300);
    let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    a.ready(b"");
    let mut child = f.remotes.recv().await.unwrap();
    // Exceeds the wire's 64 KiB capacity while staying within general (non-protected) output.
    let bytes = vec![b'x'; 1 << 20];
    a.send(&bytes, false).await.unwrap();
    let mut first = [0; 1];
    child.stdin.read_exact(&mut first).await.unwrap();
    assert_eq!(first, [b'x']);
    assert_eq!(f.budget.used().messages, 1);
    child.exits();
    assert_eq!(message(&mut a).await, "<ended>");
    assert_eq!(
        f.budget.used().messages,
        0,
        "end notification follows writer destruction"
    );
    assert_eq!(f.budget.used().bytes, 0);
}

#[tokio::test]
async fn the_fifth_end_inside_a_minute_trips_the_channel_and_audits_it_once() {
    let mut f = fixture();
    let up = upstream(300);
    for end in 1..=5 {
        let mut a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
        a.ready(b"");
        let child = f.remotes.recv().await.unwrap();
        child.exits();
        assert_eq!(message(&mut a).await, "<ended>", "end {end}");
        // The generation is recorded as ended before the next attach looks.
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(matches!(
        attach(&f, &up, req(&f.budget, 1, "k", 0)).await,
        Err(RecordsDenied::Unavailable)
    ));
    assert_eq!(*f.told.tripped.lock().unwrap(), ["member"]);
    assert_eq!(
        f.wires.opened.load(Ordering::SeqCst),
        5,
        "a tripped channel spawns nothing"
    );
    f.driver.redeclared("member").await;
    let again = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    assert!(again.greet, "declared anew, the channel spawns again");
}

#[tokio::test]
async fn a_wire_that_cannot_open_is_unavailable_and_counts_as_an_end() {
    let f = fixture();
    let up = upstream(300);
    f.wires.fail.store(true, Ordering::SeqCst);
    for _ in 0..5 {
        assert!(matches!(
            attach(&f, &up, req(&f.budget, 1, "k", 0)).await,
            Err(RecordsDenied::Unavailable)
        ));
    }
    assert_eq!(
        *f.told.tripped.lock().unwrap(),
        ["member"],
        "the fifth failure trips"
    );
}

#[tokio::test]
async fn a_generation_nothing_is_attached_to_closes_after_the_idle_time_without_counting_as_an_end()
{
    let mut f = fixture();
    let up = upstream(1);
    let a = attach(&f, &up, req(&f.budget, 1, "k", 0)).await.unwrap();
    let child = f.remotes.recv().await.unwrap();
    drop(a);
    let started = Instant::now();
    while !child.gone.load(Ordering::SeqCst) {
        assert!(started.elapsed() < Duration::from_secs(5), "idle close");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let started = Instant::now();
    let b = attach(&f, &up, req(&f.budget, 2, "k", 0)).await.unwrap();
    assert_eq!(b.generation, 2);
    assert!(
        started.elapsed() < Duration::from_millis(80),
        "an idle close is not an end: no respawn delay"
    );
}

#[tokio::test]
async fn a_per_caller_channel_is_one_generation_per_subject() {
    let mut f = fixture();
    let up = upstream(300);
    let with = |subject: u8| {
        let mut r = req(&f.budget, 1, "k", CH_PER_CALLER);
        r.subject = Some([subject; 32]);
        r
    };
    let a = attach(&f, &up, with(1)).await.unwrap();
    let b = attach(&f, &up, with(2)).await.unwrap();
    assert!(a.greet && b.greet, "each subject's channel greets");
    assert!(f.remotes.try_recv().is_ok() && f.remotes.try_recv().is_ok());
    let c = attach(&f, &up, with(1));
    let mut c = Box::pin(c);
    assert!(
        timeout(SHORT, &mut c).await.is_err(),
        "the same subject shares the first channel and waits for its greeting"
    );
}

#[tokio::test]
async fn a_request_core_cannot_serve_is_invalid() {
    let f = fixture();
    let up = upstream(300);
    let mut framing = req(&f.budget, 1, "k", 0);
    framing.framing = 9;
    let mut carrier = req(&f.budget, 1, "k", 0);
    carrier.carrier = 99;
    let no_subject = req(&f.budget, 1, "k", CH_PER_CALLER);
    let long = "x".repeat(129);
    let mut other = f.who.clone();
    other.instance = INSTANCE + 1;
    for bad in [framing, carrier, no_subject, req(&f.budget, 1, &long, 0)] {
        assert!(matches!(
            attach(&f, &up, bad).await,
            Err(RecordsDenied::Invalid)
        ));
    }
    let caller = other.caller();
    assert!(
        matches!(
            f.driver
                .attach(&caller, &up, req(&f.budget, 1, "k", 0))
                .await,
            Err(RecordsDenied::Invalid)
        ),
        "another plane instance's driver is not this one"
    );
    assert_eq!(f.wires.opened.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_held_request_streams_in_and_takes_no_writes() {
    let mut f = fixture();
    let up = upstream(300);
    let mut r = req(&f.budget, 1, "k", 0);
    r.carrier = CARRIER_HTTP;
    r.framing = busbar_plugin_abi::plane::CH_FRAME_SSE;
    let mut a = attach(&f, &up, r).await.unwrap();
    a.ready(b"");
    let mut held = f.remotes.recv().await.unwrap();
    held.stdout
        .write_all(b"event: endpoint\ndata: /m?s=1\n\n")
        .await
        .unwrap();
    held.stdout
        .write_all(format!("data: r{}|x\n\n", a.slot).as_bytes())
        .await
        .unwrap();
    assert_eq!(
        message(&mut a).await,
        format!("r{}|x", a.slot),
        "the endpoint event had no DEMUX"
    );
    tokio::time::sleep(SHORT).await;
    assert!(
        a.send(b"x", false).await.is_err(),
        "a held GET has nothing to write to"
    );
}
