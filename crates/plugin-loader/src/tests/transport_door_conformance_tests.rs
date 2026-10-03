// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: transport`, BOTH WAYS, THROUGH THE ONE DISPATCHER, OVER THE REAL `tcp` DOOR** (TODO
//! ABI-b4 for the transport kind; M6/contract: exact crossing counts).
//!
//! The subject is the shipped plugin, `busbar-transport-tcp`, not a fixture: its door LINKED (the
//! `linked::door` a busbar build holds, reached by KIND through the both-ways table's `transport`
//! row) and DROPPED IN (the pinned `busbar-transport-tcp-plugin` cdylib, found by
//! [`both_ways::cdylib`], the same lookup every extracted plugin's dropped leg uses). One script of
//! the kind's whole table is driven through the dispatcher's crossing against each: `validate` and
//! `open`; `locate` over a bare authority, a `tcp://` one and three it refuses; every carrier op
//! (REFUSED, the socket being the host's); a framing begun, written to and read through a TIGHT
//! sink (so every op answers `YIELD_MORE` and is re-driven), ended, encoded over, refused over,
//! detached and adopted; `finish` twice; `ingest` on a framing nobody began; and `close`.
//!
//! Two things are compared. The TRANSCRIPTS (outcome, error text, wire bytes, frame bytes, pieces,
//! yield flags, framing token, line for line), and the CROSSINGS: the dispatcher counts every
//! crossing it actually made ([`Plugin::crossings`]), and on BOTH legs that count must equal the
//! number of ops the script issued, which must equal [`CROSSINGS`], the number the script's own
//! arithmetic gives. "Greater than zero" would pass a leg that swallowed or duplicated an op.
//!
//! RED ARMS, KEPT: the door asked for as another kind is refused on both legs
//! ([`the_tcp_door_asked_for_as_another_kind_is_refused_both_ways`]); a transcript that drops one
//! crossing, or a count that is off by one, is seen ([`a_miscount_is_seen`]).

use std::mem::zeroed;

use busbar_contract::abi::mechanism::call::{AbiStr, Field, OutHead};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn, SIDE_ACCEPT,
    SIDE_DIAL, YIELD_ENDED, YIELD_MORE,
};

use super::door_both_ways::{self as both, close, input, line, octets, open, output, same};
use crate::both_ways::{cdylib, transport_fixture};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::kinds::transport::{Transport, TransportFacts};
use crate::dispatch::{
    load_dropped, load_linked, Frame, InFrame, LinkedRow, LoadError, OutFrame, Plugin,
};
use std::sync::atomic::Ordering;

/// The shipped plugin's cdylib crate, by its Cargo name.
const CDYLIB: &str = "busbar_transport_tcp_plugin";

/// THE CROSSINGS THE SCRIPT MAKES, counted by hand from [`script`]:
///
/// | step | ops |
/// |---|---|
/// | `validate`, `open` | 2 |
/// | `locate` x5 | 5 |
/// | the eight carrier ops | 8 |
/// | `begin` (dial) | 1 |
/// | `emit` of 15 bytes through a 4-byte wire | 4 |
/// | `ingest` of 17 bytes through a 3-byte frame | 6 |
/// | `ingest` of the end | 1 |
/// | `encode` x3 | 3 |
/// | `begin`, `refuse` of 7 bytes (2), `timer`, `detach` | 5 |
/// | `begin`, `ingest` of 15 bytes (1), `detach` through a 3-byte frame (4) | 6 |
/// | `adopt` of 7 bytes, `timer` x2 | 3 |
/// | `finish` x2, `ingest` on no framing | 3 |
/// | `close` | 1 |
const CROSSINGS: u64 = 48;

/// The host's buffers for one framer op: a TIGHT sink, so a framer that answers more than fits is
/// asked again.
struct Bufs {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
}

impl Bufs {
    fn tight() -> Self {
        Self {
            wire: vec![0; 4],
            frame: vec![0; 3],
            // SAFETY: `FramePiece` is plain integers; all-zero is a valid value.
            pieces: vec![unsafe { zeroed() }; 1],
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// What the op just answered wrote into the sink.
    fn seen(&self, o: &FramerOut) -> String {
        let wire = &self.wire[..o.yielded.wire_len as usize];
        let frame = &self.frame[..o.yielded.frame_len as usize];
        let pieces: Vec<(u64, u64, u16, u32)> = self.pieces[..o.yielded.pieces_len as usize]
            .iter()
            .map(|p| (p.offset, p.len, p.flags, p.code))
            .collect();
        format!(
            "wire={:?} frame={:?} pieces={pieces:?} flags={} framing={}",
            String::from_utf8_lossy(wire),
            String::from_utf8_lossy(frame),
            o.yielded.flags,
            o.framing
        )
    }
}

/// One leg's run: the transcript, and how many ops the script issued.
struct Run<'a> {
    p: &'a Plugin<Transport>,
    lines: Vec<String>,
    ops: u64,
}

impl Run<'_> {
    /// One crossing of slot `s` over `i`: its transcript line is `label` and the host's answer.
    fn cross<I: InFrame, O: OutFrame>(
        &mut self,
        label: &str,
        s: u32,
        i: I,
    ) -> (crate::dispatch::Called, O) {
        let mut f = Frame::new(i, output::<O>());
        let c = self.p.call(s, &mut f);
        self.ops += 1;
        self.lines.push(line(label, &c));
        (c, f.out)
    }

    /// A framer op over `bytes` (`end` for an `ingest`'s far-side end): its line carries the sink.
    fn framer(
        &mut self,
        label: &str,
        b: &mut Bufs,
        s: u32,
        framing: u64,
        bytes: &[u8],
        end: bool,
    ) -> FramerOut {
        let sink = b.sink();
        let at = self.lines.len();
        let out = match s {
            slot::EMIT => {
                let mut i: EmitIn = input();
                (i.framing, i.bytes, i.len, i.sink) = (framing, bytes.as_ptr(), bytes.len(), sink);
                self.cross::<_, FramerOut>(label, s, i).1
            }
            slot::INGEST => {
                let mut i: IngestIn = input();
                (i.framing, i.bytes, i.len, i.end, i.sink) =
                    (framing, bytes.as_ptr(), bytes.len(), u32::from(end), sink);
                self.cross::<_, FramerOut>(label, s, i).1
            }
            slot::REFUSE => {
                let mut i: RefuseIn = input();
                (i.framing, i.bytes, i.len, i.sink) = (framing, bytes.as_ptr(), bytes.len(), sink);
                self.cross::<_, FramerOut>(label, s, i).1
            }
            slot::FINISH => {
                let mut i: FinishIn = input();
                (i.framing, i.sink) = (framing, sink);
                self.cross::<_, FramerOut>(label, s, i).1
            }
            _ => {
                // `timer` and `detach` share `FramingIn`.
                let mut i: FramingIn = input();
                (i.framing, i.sink) = (framing, sink);
                self.cross::<_, FramerOut>(label, s, i).1
            }
        };
        let seen = b.seen(&out);
        self.lines[at] = format!("{} {seen}", self.lines[at]);
        out
    }

    /// `framer`, then the same op again with no new bytes for as long as the sink was too tight
    /// (`YIELD_MORE`): the host's own re-drive. Answers the last yield's flags.
    fn pump(
        &mut self,
        label: &str,
        b: &mut Bufs,
        s: u32,
        framing: u64,
        bytes: &[u8],
        end: bool,
    ) -> u32 {
        let mut o = self.framer(label, b, s, framing, bytes, end);
        while o.yielded.flags & YIELD_MORE != 0 {
            o = self.framer(label, b, s, framing, &[], end);
        }
        o.yielded.flags
    }

    fn begin(&mut self, label: &str, b: &mut Bufs, side: u32) -> u64 {
        let mut i: BeginIn = input();
        (i.side, i.sink) = (side, b.sink());
        let at = self.lines.len();
        let (_, o) = self.cross::<_, FramerOut>(label, slot::BEGIN, i);
        self.lines[at] = format!("{} framing={}", self.lines[at], o.framing);
        o.framing
    }

    /// `locate` of `target` with an authority buffer of `cap` bytes.
    fn locate(&mut self, target: &[u8], cap: usize) {
        let (mut authority, mut name, mut alpn) = (vec![0_u8; cap], vec![0_u8; 8], vec![0_u8; 8]);
        let mut i: LocateIn = input();
        i.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
        (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
        (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
        (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
        let at = self.lines.len();
        let (_, o) = self.cross::<_, LocateOut>("locate", slot::LOCATE, i);
        self.lines[at] = format!(
            "{} target={:?} authority={:?} needed={} secure={} has_name={}",
            self.lines[at],
            String::from_utf8_lossy(target),
            String::from_utf8_lossy(&authority[..(o.authority_written as usize).min(cap)]),
            o.authority_needed,
            o.secure,
            o.has_name
        );
    }
}

/// THE SCRIPT: the transport kind's whole table, one line per crossing.
fn script(p: &Plugin<Transport>) -> Run<'_> {
    let mut r = Run {
        p,
        lines: Vec::new(),
        ops: 0,
    };

    // ── lifecycle ──
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = octets(b"{}");
    r.lines
        .push(line("validate", &p.call(life::VALIDATE, &mut v)));
    r.ops += 1;
    r.lines.push(line("open", &open(p, b"{}")));
    r.ops += 1;

    // ── locate: two it reads, three it refuses (a path, nothing, a buffer too small) ──
    r.locate(b"tcp://example.test:80", 64);
    r.locate(b"example.test:80", 64);
    r.locate(b"http://example.test/path", 64);
    r.locate(b"", 64);
    r.locate(b"example.test:80", 3);

    // ── the carrier ops: the socket is the host's, so each is REFUSED ──
    r.cross::<_, ListenOut>("listen", slot::LISTEN, input::<ListenIn>());
    r.cross::<_, AcceptOut>("accept", slot::ACCEPT, input::<AcceptIn>());
    r.cross::<_, ConnOut>("dial", slot::DIAL, input::<DialIn>());
    r.cross::<_, IoOut>("read", slot::READ, input::<ReadIn>());
    r.cross::<_, IoOut>("write", slot::WRITE, input::<WriteIn>());
    r.cross::<_, IoOut>("flush", slot::FLUSH, input::<ConnIn>());
    r.cross::<_, IoOut>("shut", slot::SHUT, input::<ShutIn>());
    r.cross::<_, ArrivalOut>("arrival", slot::ARRIVAL, input::<ArrivalIn>());

    // ── a dialled framing: out, in, the far side's end ──
    let mut b = Bufs::tight();
    let dial = r.begin("begin dial", &mut b, SIDE_DIAL);
    r.pump("emit", &mut b, slot::EMIT, dial, b"to the far side", false);
    r.pump(
        "ingest",
        &mut b,
        slot::INGEST,
        dial,
        b"from the far side",
        false,
    );
    let ended = r.pump("ingest end", &mut b, slot::INGEST, dial, b"", true);
    assert_eq!(ended, YIELD_ENDED, "the far side's end ends the connection");

    // ── encode: a body alone, a body the wire cannot hold, a head field a byte stream has no room for ──
    let wire = |b: &mut Bufs, body: &[u8], fields: &[Field], label: &str, r: &mut Run<'_>| {
        let mut i: EncodeIn = input();
        (i.body, i.body_len, i.sink) = (body.as_ptr(), body.len(), b.sink());
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        let at = r.lines.len();
        let (_, o) = r.cross::<_, FramerOut>(label, slot::ENCODE, i);
        let seen = b.seen(&o);
        r.lines[at] = format!("{} {seen}", r.lines[at]);
    };
    wire(&mut b, b"body", &[], "encode", &mut r);
    wire(&mut b, b"too long", &[], "encode too long", &mut r);
    let field = Field {
        name: AbiStr {
            ptr: b"a".as_ptr(),
            len: 1,
        },
        value: AbiStr {
            ptr: b"b".as_ptr(),
            len: 1,
        },
    };
    wire(&mut b, b"body", &[field], "encode with a field", &mut r);

    // ── a refusal's bytes are the wire; a timer owes nothing more; nothing unread detaches ──
    let refused = r.begin("begin refuse", &mut b, SIDE_ACCEPT);
    r.pump("refuse", &mut b, slot::REFUSE, refused, b"refused", false);
    r.pump("timer", &mut b, slot::TIMER, refused, b"", false);
    r.pump("detach empty", &mut b, slot::DETACH, refused, b"", false);

    // ── an upgrade: what was ingested and not answered is handed back, and adopted ──
    let accepted = r.begin("begin accept", &mut b, SIDE_ACCEPT);
    r.framer(
        "ingest left over",
        &mut b,
        slot::INGEST,
        accepted,
        b"left over bytes",
        false,
    );
    let flags = r.pump("detach", &mut b, slot::DETACH, accepted, b"", false);
    assert_eq!(flags, YIELD_ENDED, "a drained detach forgets the framing");
    let mut a: AdoptIn = input();
    (a.side, a.leftover, a.leftover_len, a.sink) = (SIDE_ACCEPT, b"adopted".as_ptr(), 7, b.sink());
    let at = r.lines.len();
    let (_, adopted) = r.cross::<_, FramerOut>("adopt", slot::ADOPT, a);
    let seen = b.seen(&adopted);
    r.lines[at] = format!("{} {seen}", r.lines[at]);
    let token = adopted.framing;
    let mut o = adopted;
    while o.yielded.flags & YIELD_MORE != 0 {
        o = r.framer("timer after adopt", &mut b, slot::TIMER, token, b"", false);
    }

    // ── finish, finish again, and an ingest on a framing nobody began ──
    r.framer("finish", &mut b, slot::FINISH, token, b"", false);
    r.framer("finish again", &mut b, slot::FINISH, token, b"", false);
    r.framer(
        "ingest on no framing",
        &mut b,
        slot::INGEST,
        999,
        b"x",
        false,
    );

    // ── close ──
    r.lines.push(line("close", &close(p)));
    r.ops += 1;
    r
}

/// What a leg's script left behind: the transcript, and the crossings the dispatcher counted.
fn crossings(p: &Plugin<Transport>) -> u64 {
    p.inner.crossings.load(Ordering::Relaxed)
}

/// THE COUNT RULE: the dispatcher's crossings, the script's ops and its lines are one number, and it
/// is `expected`.
fn exact(who: &str, r: &Run<'_>, counted: u64, expected: u64) -> Result<(), String> {
    for (what, n) in [
        ("the dispatcher's crossings", counted),
        ("the script's ops", r.ops),
        ("the transcript's lines", r.lines.len() as u64),
    ] {
        if n != expected {
            return Err(format!(
                "{who}: {what} are {n}, expected exactly {expected}"
            ));
        }
    }
    Ok(())
}

#[test]
fn a_linked_and_a_dropped_in_tcp_door_frame_identically() {
    let door = transport_fixture::linked::door;
    let linked = both::linked::<Transport>(door);
    let path = cdylib(CDYLIB).unwrap_or_else(|| {
        panic!("the {CDYLIB} cdylib is not built: this is the dropped-in door's proof")
    });
    let dropped = both::dropped_from::<Transport>(door, &path);

    // The Statement each leg's registry view reads: the same claims, the same role.
    let facts = |p: &Plugin<Transport>| p.context::<TransportFacts>().cloned().expect("its tail");
    assert_eq!(facts(&linked.plugin), facts(&dropped.plugin));
    assert_eq!(
        facts(&linked.plugin).claims,
        [transport_fixture::linked::KEY]
    );
    assert_eq!(linked.plugin.name(), dropped.plugin.name());

    let a = script(&linked.plugin);
    let b = script(&dropped.plugin);
    same(&a.lines, &b.lines);
    exact("linked", &a, crossings(&linked.plugin), CROSSINGS).unwrap();
    exact("dropped in", &b, crossings(&dropped.plugin), CROSSINGS).unwrap();

    // The script reached every answer it names: equal empty transcripts would prove nothing.
    let at = |label: &str| {
        a.lines
            .iter()
            .filter(|l| l.starts_with(&format!("{label}:")))
            .cloned()
            .collect::<Vec<_>>()
    };
    let located = at("locate");
    assert!(located[0].contains("Ready") && located[0].contains("authority=\"example.test:80\""));
    assert!(located[1].contains("Ready") && located[1].contains("authority=\"example.test:80\""));
    assert!(located[2].contains("Failed"), "{}", located[2]);
    assert!(located[3].contains("Failed"), "{}", located[3]);
    assert!(
        located[4].contains("Failed") && located[4].contains("needed=15"),
        "{}",
        located[4]
    );
    for carrier in [
        "listen", "accept", "dial", "read", "write", "flush", "shut", "arrival",
    ] {
        assert!(
            at(carrier)[0].contains("Refused"),
            "{carrier}: {}",
            at(carrier)[0]
        );
    }
    let emitted: String = at("emit")
        .iter()
        .map(|l| {
            l.split("wire=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        emitted, "to the far side",
        "emit is the wire, byte for byte"
    );
    assert_eq!(at("emit").len(), 4);
    assert_eq!(at("ingest").len(), 6, "17 bytes through a 3-byte frame");
    assert!(at("encode")[0].contains("Ready") && at("encode")[0].contains("wire=\"body\""));
    assert!(at("encode too long")[0].contains("Failed"));
    assert!(at("encode with a field")[0].contains("Failed"));
    assert!(at("finish")[0].contains("Ready"));
    assert!(at("finish again")[0].contains("Failed"));
    assert!(at("ingest on no framing")[0].contains("Failed"));
    assert!(at("close")[0].contains("Ready"));
}

/// THE RED ARM, KEPT: the count rule is not vacuous. A leg one crossing short, or a count one off,
/// is refused with the number it saw.
#[test]
fn a_miscount_is_seen() {
    let linked = both::linked::<Transport>(transport_fixture::linked::door);
    let r = script(&linked.plugin);
    let counted = crossings(&linked.plugin);
    assert_eq!(counted, CROSSINGS);
    assert!(exact("linked", &r, counted, CROSSINGS).is_ok());
    assert!(
        exact("linked", &r, counted, CROSSINGS + 1).is_err(),
        "one more expected than made"
    );
    assert!(
        exact("linked", &r, counted - 1, CROSSINGS).is_err(),
        "a leg that swallowed a crossing"
    );
    let mut short = Run {
        p: r.p,
        lines: r.lines.clone(),
        ops: r.ops,
    };
    short.lines.pop();
    assert!(
        exact("linked", &short, counted, CROSSINGS).is_err(),
        "a transcript missing a line"
    );
    let mut other = r.lines.clone();
    other[10].push('!');
    assert!(
        std::panic::catch_unwind(|| same(&r.lines, &other)).is_err(),
        "a divergent line is seen"
    );
}

/// THE RED ARM, KEPT: the tcp door is a transport. Asked for as a hook it is refused, linked (by the
/// door's own kind) and dropped in (by the stated kind, before the library is opened).
#[test]
fn the_tcp_door_asked_for_as_another_kind_is_refused_both_ways() {
    let door = transport_fixture::linked::door;
    let want = (KindCode::Transport, KindCode::Hook);
    let row = LinkedRow::of(door).expect("the door states itself");
    let linked = both::linked::<Transport>(door);
    match load_linked::<Hook>(&row, both::bind(&linked.dispatcher)) {
        Err(LoadError::WrongKind { door, want: asked }) => assert_eq!((door, asked), want),
        other => panic!("the linked door loaded as a hook: {:?}", other.err()),
    }
    let path = cdylib(CDYLIB).unwrap_or_else(|| panic!("the {CDYLIB} cdylib is not built"));
    match load_dropped::<Hook>(&path, &row.statement, both::bind(&linked.dispatcher)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the dropped-in door loaded as a hook: {:?}", other.err()),
    }
}
