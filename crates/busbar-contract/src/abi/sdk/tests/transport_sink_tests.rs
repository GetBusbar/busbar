// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sink fill: wire bytes first, then pieces as far as the sink holds (a piece that does not fit
//! whole is split, its end-of-frame on its last part), head words in their slots, then the yield
//! flags; and a field block is cut only where a continuation extends a value.

use super::*;
use crate::abi::sdk::test_support::zeroed;

/// A framing that owes `wire` and `pieces`, over `Vec<u8>` frames.
#[derive(Default)]
struct Framing {
    wire: Vec<u8>,
    pieces: VecDeque<Piece<Vec<u8>>>,
    deadline: Option<u64>,
    ended: bool,
}

impl Owed<Vec<u8>> for Framing {
    fn wire_into(&mut self, into: &mut HostBuf<'_, u8>) {
        let n = into.stream(&self.wire);
        self.wire.drain(..n);
    }
    fn wire_pending(&self) -> bool {
        !self.wire.is_empty()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece<Vec<u8>>> {
        &mut self.pieces
    }
    fn next_deadline(&self) -> Option<u64> {
        self.deadline
    }
    fn ended(&self) -> bool {
        self.ended
    }
    fn rest(bytes: &mut Vec<u8>, at: usize) {
        bytes.drain(..at);
    }
}

/// What one `fill` handed: the wire bytes, the frame bytes, the pieces, the head slots, the yield.
struct Filled {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    yielded: crate::abi::transport::FramerYield,
}

/// `fill` `f` into a sink of `wire`, `frame`, `pieces` and `heads` capacities.
fn fill_into(f: &mut Framing, wire: usize, frame: usize, pieces: usize, heads: usize) -> Filled {
    let (mut w, mut fr) = (vec![0_u8; wire], vec![0_u8; frame]);
    let mut ps: Vec<FramePiece> = (0..pieces).map(|_| zeroed()).collect();
    let mut hs = vec![HeadSlots::default(); heads];
    let mut sink: FramerSink = zeroed();
    sink.wire = w.as_mut_ptr();
    sink.wire_cap = w.len();
    sink.frame = fr.as_mut_ptr();
    sink.frame_cap = fr.len();
    sink.pieces = ps.as_mut_ptr();
    sink.pieces_cap = ps.len();
    sink.heads = hs.as_mut_ptr();
    sink.heads_cap = hs.len();
    let mut out: FramerOut = zeroed();
    // SAFETY: every buffer the sink names is a live `Vec` of its stated capacity, borrowed for the
    // call.
    let lent = unsafe { Lent::new(&sink) };
    fill::<Vec<u8>, _>(
        f,
        lent,
        &mut Out::new(&mut out),
        |code| u8::try_from(code / 100).unwrap_or(0),
        |_| 0,
    );
    let y = out.yielded;
    let len = |n: u64| usize::try_from(n).expect("a length");
    w.truncate(len(y.wire_len));
    fr.truncate(len(y.frame_len));
    ps.truncate(len(u64::from(y.pieces_len)));
    hs.truncate(len(u64::from(y.heads_len)));
    Filled {
        wire: w,
        frame: fr,
        pieces: ps,
        heads: hs,
        yielded: y,
    }
}

/// Wire bytes go first, as far as the wire holds; what is left is owed (`YIELD_MORE`).
#[test]
fn wire_bytes_go_first_and_the_rest_is_owed() {
    let mut f = Framing {
        wire: b"GET / HTTP/1.1\r\n".to_vec(),
        ..Framing::default()
    };
    let got = fill_into(&mut f, 4, 16, 4, 0);
    assert_eq!(got.wire, b"GET ");
    assert_eq!(got.yielded.flags & YIELD_MORE, YIELD_MORE);
    let got = fill_into(&mut f, 64, 16, 4, 0);
    assert_eq!(got.wire, b"/ HTTP/1.1\r\n");
    assert_eq!(got.yielded.flags & YIELD_MORE, 0);
}

/// A piece that does not fit whole is split: its first part ends no frame, its last part does,
/// and only the last part of a failure says the stream failed.
#[test]
fn a_piece_that_does_not_fit_is_split_its_end_on_its_last_part() {
    let mut f = Framing::default();
    f.pieces.push_back(Piece::failure(3, "far end reset"));
    let got = fill_into(&mut f, 0, 8, 4, 0);
    assert_eq!(got.frame, b"far end ");
    assert_eq!(got.pieces.len(), 1);
    assert_eq!(got.pieces[0].flags & PIECE_END_OF_FRAME, 0);
    assert_eq!(got.pieces[0].flags & PIECE_STREAM_FAILED, 0);
    assert_eq!(got.yielded.flags & YIELD_MORE, YIELD_MORE);
    let got = fill_into(&mut f, 0, 8, 4, 0);
    assert_eq!(got.frame, b"reset");
    assert_eq!(
        got.pieces[0].flags,
        PIECE_END_OF_FRAME | PIECE_STREAM_FAILED
    );
    assert!(f.pieces.is_empty());
}

/// A status maps to its class and its fault; the end and the writable signal are said, never
/// inferred; an ended connection with nothing owed says so, and its deadline rides the yield.
#[test]
fn the_flags_say_what_each_piece_carries() {
    let mut f = Framing {
        deadline: Some(42),
        ended: true,
        ..Framing::default()
    };
    f.pieces.push_back(Piece {
        status: Some(503),
        retry_after_secs: Some(9),
        declared_len: Some(4),
        ..Piece::fields(1, b"x-a: 1\r\n".to_vec())
    });
    f.pieces.push_back(Piece::end(1));
    f.pieces.push_back(Piece::writable(2));
    let got = fill_into(&mut f, 0, 64, 4, 0);
    assert_eq!(got.pieces.len(), 3);
    let head = got.pieces[0];
    assert_eq!(
        head.flags,
        PIECE_END_OF_FRAME
            | PIECE_FIELDS
            | PIECE_HAS_CODE
            | PIECE_HAS_RETRY_AFTER
            | PIECE_HAS_DECLARED_LEN
    );
    assert_eq!(
        (
            head.code,
            head.status_class,
            head.retry_after_secs,
            head.declared_len
        ),
        (503, 5, 9, 4)
    );
    assert_eq!(got.pieces[1].flags, PIECE_END_OF_FRAME | PIECE_END);
    assert_eq!(got.pieces[2].flags, PIECE_WRITABLE);
    assert_eq!(got.yielded.flags, YIELD_HAS_DEADLINE | YIELD_ENDED);
    assert_eq!(got.yielded.next_deadline_ns, 42);
}

/// A head's words ride its stream's head slots, their bytes in the frame ahead of the piece's; a
/// host that takes no slots is not handed them.
#[test]
fn head_words_ride_the_head_slots_ahead_of_the_head() {
    let words = HeadWords {
        method: b"GET".to_vec(),
        target: b"/a".to_vec(),
        ..HeadWords::default()
    };
    let mut f = Framing::default();
    f.pieces.push_back(Piece {
        head: Some(words.clone()),
        ..Piece::fields(5, b"x: 1\r\n".to_vec())
    });
    let got = fill_into(&mut f, 0, 64, 4, 1);
    assert_eq!(got.frame, b"GET/ax: 1\r\n");
    assert_eq!(got.heads.len(), 1);
    let slots = got.heads[0];
    assert_eq!(slots.stream, 5);
    assert_eq!((slots.method.offset, slots.method.len), (0, 3));
    assert_eq!((slots.target.offset, slots.target.len), (3, 2));
    assert_eq!((slots.reason.offset, slots.reason.len), (0, 0));
    assert_eq!(got.pieces[0].offset, 5);

    let mut f = Framing::default();
    f.pieces.push_back(Piece {
        head: Some(words),
        ..Piece::fields(5, b"x: 1\r\n".to_vec())
    });
    let got = fill_into(&mut f, 0, 64, 4, 0);
    assert_eq!(got.frame, b"x: 1\r\n");
    assert!(got.heads.is_empty());
}

/// A field block is cut only at a line's start or inside a value, never inside a name: the host
/// refuses any continuation that does not extend a value.
#[test]
fn a_field_block_is_cut_only_where_a_continuation_extends_a_value() {
    let block = b"date: Mon\r\nx-a: 1\r\n";
    assert_eq!(field_cut(block, 64, false), block.len());
    // Inside "date": back to the start; just past the colon: a value.
    assert_eq!(field_cut(block, 3, false), 0);
    assert_eq!(field_cut(block, 5, false), 5);
    // Inside "x-a" on the second line: back to the line's start.
    assert_eq!(field_cut(block, 13, false), 11);
    // Opening inside a value, every byte up to the next name may go.
    assert_eq!(field_cut(b"on\r\nx: 1\r\n", 5, true), 4);
}

/// A field block split mid-value opens its rest as a continuation.
#[test]
fn a_split_field_block_continues_its_value() {
    let mut f = Framing::default();
    f.pieces
        .push_back(Piece::fields(1, b"x-a: 12345\r\nx-b: 6\r\n".to_vec()));
    let got = fill_into(&mut f, 0, 8, 4, 0);
    assert_eq!(got.frame, b"x-a: 123");
    assert_eq!(got.pieces[0].flags, PIECE_FIELDS);
    let got = fill_into(&mut f, 0, 64, 4, 0);
    assert_eq!(got.frame, b"45\r\nx-b: 6\r\n");
    assert_eq!(
        got.pieces[0].flags,
        PIECE_END_OF_FRAME | PIECE_FIELDS | PIECE_CONTINUED
    );
}

/// `mark_stream_full` sets `YIELD_STREAM_FULL` on what `fill` answered, and nothing else.
#[test]
fn a_full_stream_is_marked_after_the_fill() {
    let mut out: FramerOut = zeroed();
    mark_stream_full(&mut Out::new(&mut out));
    assert_eq!(out.yielded.flags, YIELD_STREAM_FULL);
}
