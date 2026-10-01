// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tcp` DOOR'S BOTH-WAYS WITNESS: the linked door and this crate's own dropped-in image
//! (the `tcp_door` example, the door behind the one `export_door!`), each admitted
//! through the loader's ONE door validation and driven through the ONE dispatcher's crossing, give
//! the same Statement and the same answers, byte for byte.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::transport::{
    slot, BeginIn, EmitIn, FramePiece, FramerOut, FramerSink, IngestIn, PIECE_END_OF_FRAME,
    SIDE_DIAL, YIELD_ENDED,
};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    ManifestFacts, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This crate's dropped-in image, the `tcp_door` example `cargo test` builds. A missing artifact
/// is a failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let examples = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>")
        .join("examples");
    let file = busbar_plugin_loader::plugin_library_filename("tcp_door");
    [examples.join(&file), examples.join("deps").join(&file)]
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("the tcp_door example ({file}) is not built"))
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
    }
}

fn open(p: &Plugin<Transport>) {
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    };
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(life::OPEN, &mut f).outcome, Outcome::Ready);
}

/// What one script saw: the wire bytes, the frame bytes with their pieces' flags, the last flags.
type Script = (Vec<u8>, Vec<(Vec<u8>, u8)>, u32);

/// One scripted exchange through the dispatcher: begin, emit, ingest (tight sink), ingest the end.
/// What comes back: the wire bytes, the frame bytes with their pieces' flags, the last flags.
fn script(p: &Plugin<Transport>) -> Script {
    let mut wire = vec![0_u8; 4];
    let mut frame = vec![0_u8; 3];
    let mut pieces: Vec<FramePiece> = vec![z(); 1];
    let base = FramerSink {
        wire: wire.as_mut_ptr(),
        wire_cap: wire.len(),
        frame: frame.as_mut_ptr(),
        frame_cap: frame.len(),
        pieces: pieces.as_mut_ptr(),
        pieces_cap: pieces.len(),
        now_monotonic_ns: 1,
        now_unix_ns: 1,
    };
    let sink = || base;
    let mut i: BeginIn = z();
    i.head = in_head();
    i.side = SIDE_DIAL;
    i.sink = sink();
    let mut o: FramerOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(slot::BEGIN, &mut f).outcome, Outcome::Ready);
    let framing = f.out.framing;

    let (mut wire_log, mut frames, mut flags) = (Vec::new(), Vec::new(), 0);
    let steps: [(u32, &[u8], bool); 3] = [
        (slot::EMIT, b"to the far side", false),
        (slot::INGEST, b"from the far side", false),
        (slot::INGEST, b"", true),
    ];
    for (op, bytes, end) in steps {
        let mut first = true;
        loop {
            let give: &[u8] = if first { bytes } else { &[] };
            first = false;
            let (outcome, o) = if op == slot::EMIT {
                let mut i: EmitIn = z();
                i.head = in_head();
                i.framing = framing;
                i.bytes = give.as_ptr();
                i.len = give.len();
                i.sink = sink();
                let mut o: FramerOut = z();
                o.head = out_head();
                let mut f = Frame::new(i, o);
                (p.call(op, &mut f).outcome, f.out)
            } else {
                let mut i: IngestIn = z();
                i.head = in_head();
                i.framing = framing;
                i.bytes = give.as_ptr();
                i.len = give.len();
                i.end = u32::from(end);
                i.sink = sink();
                let mut o: FramerOut = z();
                o.head = out_head();
                let mut f = Frame::new(i, o);
                (p.call(op, &mut f).outcome, f.out)
            };
            assert_eq!(outcome, Outcome::Ready);
            wire_log.extend_from_slice(&wire[..o.yielded.wire_len as usize]);
            for piece in &pieces[..o.yielded.pieces_len as usize] {
                let at = piece.offset as usize;
                frames.push((frame[at..at + piece.len as usize].to_vec(), piece.flags));
            }
            flags = o.yielded.flags;
            if flags & busbar_contract::abi::transport::YIELD_MORE == 0 {
                break;
            }
        }
    }
    (wire_log, frames, flags)
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_framer() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked: Plugin<Transport> =
        load_linked(busbar_transport_tcp::linked::door, bind(&d)).expect("the linked door loads");
    let facts = ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind: KindCode::Transport,
        kind_abi: KindCode::Transport.abi_version(),
    };
    let dropped: Plugin<Transport> =
        load_dropped(&cdylib(), &facts, bind(&d)).expect("the dropped-in door loads");
    assert_eq!(linked.name(), "tcp");
    assert_eq!(dropped.name(), linked.name());
    open(&linked);
    open(&dropped);

    let a = script(&linked);
    let b = script(&dropped);
    assert_eq!(a.0, b"to the far side", "emit is the wire, byte for byte");
    let frame: Vec<u8> = a.1.iter().flat_map(|(bytes, _)| bytes.clone()).collect();
    assert_eq!(frame, b"from the far side");
    assert_eq!(
        a.1.iter()
            .filter(|(_, f)| f & PIECE_END_OF_FRAME != 0)
            .count(),
        1,
        "one read is one frame"
    );
    assert_eq!(a.2, YIELD_ENDED, "the far side's end ends the connection");
    assert_eq!(a, b, "both doors answer alike");
}
