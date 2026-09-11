//! THE SAME 4 KIB AT HOUR ONE.
//!
//! `bounded.rs` says of the per-unit arena that it "is reset per frame on the relay path of an
//! open unit", and the kernel's own arena module says what that buys: "a session that relays for
//! an hour uses the same 4 KiB it used at its first frame". Nothing in this tree tested it, and
//! nothing could: every implementor of the trait was a test double that handed out `Box::leak`ed
//! bytes, so the property under test was false in every arena a test could reach and the claim was
//! carried by prose alone.
//!
//! This is the measurement. One recorded request shape per data plane in this tree is replayed a
//! hundred times through one buffer — the plane's own declared pointers scanned by the production span resolver, then the
//! two allocations a decode step makes — and the buffer is asked, after every pass, the two
//! questions the claim answers: how many bytes did this pass need, and has the most this buffer
//! ever held moved. A buffer that is genuinely reused answers the same number to the first every
//! time and never moves the second after pass one. A buffer that is quietly re-allocated per frame
//! — which is what leaking is — cannot answer either.
//!
//! Every body below is bytes this tree has on disk, cited to the file it was taken from, so the
//! shapes are the ones the planes actually decode rather than shapes chosen to fit the arena.

use busbar_kernel::arena::{span_slab, Arena, ArenaBuf};

/// One recorded request shape, and the pointers a plane declares over it.
///
/// Labelled and cited BY SHAPE rather than by the plane it came from, and one recorded body's
/// instance name is blanked to a stand-in: the kind boundaries forbid this crate a plane's
/// instance vocabulary, and the matrix that enforces them counts OCCURRENCES of the needle, so a
/// same-length substitution would not flatten a single cell. The stand-in is the same length all
/// the same, for a different reason: the assertions below are byte-sensitive — the arena's cursor
/// and its high-water are counts of bytes, and the pointer spans the resolver hands back are byte
/// offsets into this body — so a substitution of a different width would move every number the
/// cell compares and the recording would stop being the thing measured.
struct Replay {
    /// What shape of request this is.
    shape: &'static str,
    /// The bytes.
    body: &'static [u8],
    /// The pointers the plane declares, as the span resolver is handed them.
    pointers: &'static [&'static str],
    /// Where the bytes came from.
    cite: &'static str,
}

/// How many times each request is replayed through the one buffer.
///
/// A hundred, because the failure this is written against is cumulative: an arena that grows by
/// one allocation per frame passes any test that runs it twice.
const PASSES: u64 = 100;

const REPLAYS: &[Replay] = &[
    Replay {
        shape: "chat-completion",
        body: br#"{"max_tokens":64,"messages":[{"content":"ping","role":"user"}],"model":"m-dialect-1"}"#,
        pointers: &["/model", "/messages", "/max_tokens", "/stream"],
        cite: "testing/shadow-oracle/golden/1.5.5/cells, the recorded chat request",
    },
    Replay {
        shape: "error-envelope",
        body: br#"{"error":{"code":"invalid_request","message":"malformed If-Match"}}"#,
        pointers: &["/error/code", "/error/message"],
        cite: "testing/shadow-oracle/golden/1.5.5/cells, the recorded control-surface refusal",
    },
    Replay {
        shape: "rpc-scalar-id",
        body: br#"{"jsonrpc":"2.0","id":9,"method":"tasks/get","params":{"id":"t1"}}"#,
        pointers: &["/jsonrpc", "/id", "/method", "/params"],
        cite: "the JSON-RPC call one of the tree's conformance rigs drives",
    },
    Replay {
        shape: "rpc-string-id",
        body: br#"{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user"}}}"#,
        pointers: &["/jsonrpc", "/id", "/method", "/params/message/role"],
        cite: "the JSON-RPC call with a string id and a nested member",
    },
    Replay {
        shape: "media-frame",
        body: br#"{"event":"media","media":{"payload":"UklGRg=="}}"#,
        pointers: &["/event", "/media/payload"],
        cite: "the streaming media frame a session transport relays",
    },
];

/// One pass: the plane's scan, then the two allocations a decode makes. Returns what it took.
fn one_pass(buf: &mut ArenaBuf, replay: &Replay) -> usize {
    let mut slab = span_slab();
    let arena = buf.lease(&mut slab[..]);
    let table = busbar_contract::spans::resolve(replay.body, replay.pointers, &arena)
        .expect("the declared pointers of one recorded request fit the arena");
    assert!(
        !table.is_empty(),
        "{}: the recorded body carries at least one declared pointer",
        replay.shape
    );
    arena
        .alloc_bytes(replay.body)
        .expect("one recorded body fits the arena");
    arena
        .alloc_str(replay.shape)
        .expect("one shape key fits the arena");
    arena.used()
}

/// A hundred replays of one recorded request shape take the same bytes every time, and the
/// buffer's high-water never moves after the first.
#[test]
fn a_hundred_replays_of_every_recorded_shape_reuse_the_one_buffer() {
    for replay in REPLAYS {
        let mut buf = ArenaBuf::new();
        let first = one_pass(&mut buf, replay);
        let first_high = buf.high_water();
        assert_eq!(
            buf.resets(),
            1,
            "{}: one frame, one reset ({})",
            replay.shape,
            replay.cite
        );
        assert!(
            first > 0 && first <= busbar_kernel::arena::ARENA_BYTES,
            "{}: a recorded request takes some of the arena and not more than all of it",
            replay.shape
        );

        for pass in 2..=PASSES {
            let used = one_pass(&mut buf, replay);
            assert_eq!(
                used, first,
                "{}: pass {pass} took {used} bytes where pass 1 took {first} — the cursor did not \
                 go back to the start ({})",
                replay.shape, replay.cite
            );
            assert_eq!(
                buf.high_water(),
                first_high,
                "{}: the most this buffer ever held moved on pass {pass}, so the bytes pass 1 used \
                 were never given back ({})",
                replay.shape,
                replay.cite
            );
            assert_eq!(
                buf.resets(),
                pass,
                "{}: every pass is one reset of the one buffer",
                replay.shape
            );
        }
    }
}

/// The bytes a later pass is handed are the bytes it wrote, never the bytes the pass before wrote.
///
/// The other half of reuse, and the one that would be a leak of one request into another's answer
/// rather than a leak of memory: reuse over a bump cursor means pass two is standing on pass one's
/// ground, so an allocation that is handed back short of what it asked for could read the previous
/// request straight out of the remainder.
#[test]
fn a_replay_never_reads_the_replay_before_it() {
    let mut buf = ArenaBuf::new();
    {
        let mut slab = span_slab();
        let arena = buf.lease(&mut slab[..]);
        arena
            .alloc_bytes(b"the-first-request-secret")
            .expect("room");
    }
    let mut slab = span_slab();
    let arena = buf.lease(&mut slab[..]);
    assert_eq!(
        arena.remaining(),
        busbar_kernel::arena::ARENA_BYTES,
        "the second lease starts at the front of the same buffer"
    );
    let second = arena.alloc_bytes(b"aa").expect("room");
    assert_eq!(
        second.as_slice(),
        b"aa",
        "a short allocation standing on the first request's ground reads its own two bytes and \
         carries no remainder of what was there — the trait hands back only what it copied in"
    );
}

/// The arena refuses past its declared size rather than growing, and says how much was left.
#[test]
fn the_arena_refuses_past_the_declared_ceiling() {
    let mut buf = ArenaBuf::new();
    let mut slab = span_slab();
    let arena = buf.lease(&mut slab[..]);
    let whole = vec![0u8; busbar_kernel::arena::ARENA_BYTES];
    arena
        .alloc_bytes(&whole)
        .expect("the whole arena fits once");
    assert_eq!(arena.remaining(), 0);
    let refused = arena
        .alloc_bytes(b"one more")
        .expect_err("nothing fits after the whole arena is spent");
    assert_eq!(refused.wanted, 8);
    assert_eq!(refused.remaining, 0);
}
