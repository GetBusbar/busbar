//! What one downlink audio frame is allowed to allocate, and what it must still say.
//!
//! A call carries fifty audio frames a second in each direction, so anything the downlink renderer
//! does per frame is done fifty times a second per call. Building a document to describe a fixed
//! three-member envelope, a string to hold the payload, and then serializing the document, is three
//! allocations to reach bytes that could have been appended to a buffer already held. That cost is
//! too small for a stopwatch to find on a shared runner and too frequent to leave alone. An
//! allocation COUNT finds it, and is the same number on every machine, so it can be pinned.
//!
//! The first test below is the one that matters most: the bytes are unchanged. A renderer that got
//! faster and moved a byte would have broken every client of this dialect, so the count is only
//! allowed to fall on the far side of a byte-for-byte comparison against the serializer that used
//! to produce it.

use busbar_plane_voice::twilio;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations made by THIS thread since the counter was last read.
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting.
struct Counting;

// SAFETY: every call is forwarded verbatim to the system allocator; the counter is a thread-local
// `Cell` of a plain integer, touched only on the allocating thread, and never reads or writes the
// memory being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// How many allocations one call made on this thread.
fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = ALLOCS.with(Cell::get);
    f();
    ALLOCS.with(Cell::get) - before
}

/// The identifier a `start` event binds, in the shape this dialect mints them.
const SID: &str = "MZ18ad3ab5a668481ce02b83e7395059f0";

/// One 20 ms µ-law frame at eight kilohertz.
fn frame_bytes() -> Vec<u8> {
    (0..160u16).map(|i| (i % 251) as u8).collect()
}

/// The bytes the serializer produced, restated as the reference the renderer is held to.
///
/// The member ORDER is the serializer's, not a preference: this document's members are written in
/// the order a JSON object's keys sort in, because that is the order the old renderer emitted and
/// every recorded conformance answer was taken against it.
fn reference(stream_sid: &str, mulaw: &[u8]) -> Vec<u8> {
    let doc = serde_json::json!({
        "event": "media",
        "streamSid": stream_sid,
        "media": { "payload": base64(mulaw) },
    });
    serde_json::to_vec(&doc).expect("the document serializes")
}

/// Standard base64, spelled out here so the reference owes the renderer nothing.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The rendered envelope is the serializer's, byte for byte.
#[test]
fn the_rendered_envelope_is_the_one_the_serializer_produced() {
    // Every length class the payload can end on, because base64 pads three of the four differently,
    // plus the empty frame and an identifier the serializer would have had to escape.
    let payloads: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x7f],
        vec![0x7f, 0x00],
        vec![0x7f, 0x00, 0xff],
        frame_bytes(),
    ];
    for sid in [SID, "", "a\"b\\c", "sid with spaces", "sid-ünïcode"] {
        for payload in &payloads {
            let mut out = Vec::new();
            twilio::encode_media_into(&mut out, sid, payload);
            assert_eq!(
                out,
                reference(sid, payload),
                "the envelope for {sid:?} with {} payload bytes moved",
                payload.len()
            );
            assert_eq!(
                twilio::encode_media(sid, payload),
                out,
                "the owning form and the rendering form disagree for {sid:?}"
            );
        }
    }
}

/// COMMITTED BASELINE — the exact allocation count of rendering ONE downlink audio frame into a
/// buffer that has already carried one.
///
/// Zero. The envelope is fixed, the buffer is the caller's, and the only two things that vary from
/// frame to frame — the payload and the identifier — are appended, not built.
const RENDER_ALLOCS: u64 = 0;

#[test]
fn rendering_a_downlink_frame_into_a_held_buffer_allocates_nothing() {
    let mulaw = frame_bytes();
    let mut out = Vec::new();

    // One warm call outside the window: the buffer takes its capacity here, which is the whole
    // point of handing the same one back frame after frame.
    twilio::encode_media_into(&mut out, SID, &mulaw);
    let expected = out.clone();

    let count = allocations_of(|| {
        twilio::encode_media_into(&mut out, SID, &mulaw);
    });

    // The serializer route, measured rather than remembered. `reference` is the renderer this
    // replaced, restated line for line above, so the pair of numbers printed here is the whole
    // claim: the same bytes, for this much less.
    let mut serialized = None;
    let before = allocations_of(|| serialized = Some(reference(SID, &mulaw)));
    println!("downlink render allocations: {count} (serializer route: {before})");

    assert_eq!(
        out, expected,
        "a reused buffer renders the same bytes a fresh one does"
    );
    assert_eq!(
        serialized.expect("the reference ran"),
        out,
        "the two routes disagree about the bytes"
    );
    assert_eq!(
        count, RENDER_ALLOCS,
        "rendering one downlink frame allocated {count} times, not {RENDER_ALLOCS}: it is building \
         something per frame that does not change from frame to frame"
    );
    assert!(
        before > count,
        "the serializer route allocated {before} times and the renderer {count}: the renderer \
         exists to cost less than it, so a renderer that does not is not worth having"
    );
}
