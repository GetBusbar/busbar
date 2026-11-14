// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SSE FRAMER HOT-PATH GATE (DEPENDENCY-LADDER §0, row C17): the baseline the sseer swap is
//! measured against, recorded on the hand terminator search first.
//!
//! `busbar_contract::protocol::SseFrames` runs per streamed frame. The bench feeds an OpenAI-,
//! an Anthropic- and a Gemini-shaped event stream in 1-byte, 1 KiB and 16 KiB pieces and drains
//! every frame; the swap commit is red if any case's median or p99 is slower than this baseline
//! by more than CI's run-to-run noise (the larger of 2% and three times the baseline spread).
//!
//! The allocation witness asserts what the framer promises today: once its buffer is warm, framing
//! allocates nothing. A counting `#[global_allocator]` is armed only around a second pass of each
//! stream; `BUSBAR_ALLOC_INJECT` allocates inside the armed window to prove it can go red.
//!
//! ```text
//! cargo bench -p busbar-contract --bench sse_frames
//! ```

use busbar_contract::protocol::SseFrames;
use criterion::{criterion_group, criterion_main, Criterion};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAlloc;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System`, the process's real allocator; the only added behaviour
// is a relaxed counter bump when the armed flag is set, which allocates nothing itself.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// An OpenAI chat-completions stream: `data:` lines, LF terminators, a `[DONE]` sentinel.
fn openai_stream() -> Vec<u8> {
    let mut s = Vec::new();
    for i in 0..400 {
        s.extend_from_slice(
            format!(
                "data: {{\"id\":\"chatcmpl-9x\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\
                 \"model\":\"gpt-4o-mini\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"tok{i} \"}},\
                 \"finish_reason\":null}}]}}\n\n"
            )
            .as_bytes(),
        );
    }
    s.extend_from_slice(b"data: [DONE]\n\n");
    s
}

/// An Anthropic messages stream: `event:` and `data:` lines, pings as comments.
fn anthropic_stream() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(
        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\
          \"role\":\"assistant\",\"model\":\"claude\",\"usage\":{\"input_tokens\":25}}}\n\n",
    );
    for i in 0..400 {
        if i % 50 == 0 {
            s.extend_from_slice(b": ping\n\n");
        }
        s.extend_from_slice(
            format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\
                 \"delta\":{{\"type\":\"text_delta\",\"text\":\"tok{i} \"}}}}\n\n"
            )
            .as_bytes(),
        );
    }
    s.extend_from_slice(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    s
}

/// A Gemini `alt=sse` stream: CRLF terminators.
fn gemini_stream() -> Vec<u8> {
    let mut s = Vec::new();
    for i in 0..400 {
        s.extend_from_slice(
            format!(
                "data: {{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"tok{i} \"}}],\
                 \"role\":\"model\"}},\"index\":0}}]}}\r\n\r\n"
            )
            .as_bytes(),
        );
    }
    s
}

const PIECES: &[(&str, usize)] = &[("1b", 1), ("1kib", 1024), ("16kib", 16 * 1024)];

/// Push `stream` in `piece`-byte chunks, draining every frame; the bytes framed.
fn frame_all(frames: &mut SseFrames, stream: &[u8], piece: usize) -> usize {
    let mut framed = 0;
    for chunk in stream.chunks(piece) {
        frames.push(chunk);
        while let Some(frame) = frames.next_frame() {
            framed += black_box(frame).len();
        }
    }
    framed
}

fn assert_warm_framing_allocates_nothing(streams: &[(&str, Vec<u8>)]) {
    let inject = std::env::var_os("BUSBAR_ALLOC_INJECT").is_some();
    for (name, stream) in streams {
        for &(size, piece) in PIECES {
            let mut frames = SseFrames::new();
            assert_eq!(frame_all(&mut frames, stream, piece), stream.len());
            ALLOC_COUNT.store(0, Ordering::Relaxed);
            ARMED.store(true, Ordering::Relaxed);
            let framed = frame_all(&mut frames, stream, piece);
            if inject {
                let v: Vec<u8> = Vec::with_capacity(16);
                black_box(v);
            }
            ARMED.store(false, Ordering::Relaxed);
            assert_eq!(framed, stream.len());
            let allocations = ALLOC_COUNT.load(Ordering::Relaxed);
            assert_eq!(
                allocations, 0,
                "SSE FRAMER ALLOC ({name}, {size} pieces): a warm framer performed {allocations} \
                 allocation(s); it must perform 0"
            );
        }
    }
}

fn sse_frames(c: &mut Criterion) {
    let streams = [
        ("openai", openai_stream()),
        ("anthropic", anthropic_stream()),
        ("gemini", gemini_stream()),
    ];
    let mut group = c.benchmark_group("sse_frames");
    for (name, stream) in &streams {
        for &(size, piece) in PIECES {
            let mut frames = SseFrames::new();
            group.bench_function(format!("{name}/{size}"), |b| {
                b.iter(|| frame_all(&mut frames, black_box(stream), piece));
            });
        }
    }
    group.finish();
    assert_warm_framing_allocates_nothing(&streams);
}

criterion_group!(sse_frames_benches, sse_frames);
criterion_main!(sse_frames_benches);
