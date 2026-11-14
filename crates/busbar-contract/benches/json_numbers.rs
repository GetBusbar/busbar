// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SERDE-NUMBERS B1: the JSON number paths that serde_json's `arbitrary_precision` feature
//! touches, measured before and after the flag is dropped.
//!
//! # What is measured
//!
//! - `spans::parse_value` (every plane-llm and plane-mcp body) on OpenAI chat requests of 1 KiB,
//!   8 KiB and 100 KiB, plus an 8 KiB number-dense body (a logprobs array).
//! - `Observation::encode`/`decode` with four classes (two whole, two fractional).
//! - Persistence `encode`/`decode` of a `BTreeMap<String, Count>` with eight entries.
//! - `select_json` on a 4 KiB Vault reply, and on the same reply with a selected object 64 deep.
//!
//! Each case also reports its allocations per call, counted by a `#[global_allocator]` that is
//! armed only around one call outside criterion's timing loop.
//!
//! # Running it
//!
//! ```text
//! cargo bench -p busbar-contract --bench json_numbers
//! ```

use busbar_contract::abi::sdk::cred::{select_json, Held, SelectedJson};
use busbar_contract::abi::sdk::plane::observation::Observation;
use busbar_contract::spans::parse_value;
use busbar_contract::Count;
use criterion::{criterion_group, criterion_main, Criterion};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAlloc;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System`, the process's real allocator; the only added behaviour
// is a relaxed counter bump while armed, which allocates nothing itself.
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
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc_zeroed(layout)
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

/// Run `op` once with the counter armed and report its allocations.
fn report_allocs<R>(name: &str, op: impl FnOnce() -> R) {
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::SeqCst);
    let out = op();
    ARMED.store(false, Ordering::SeqCst);
    let allocs = ALLOC_COUNT.load(Ordering::Relaxed);
    drop(black_box(out));
    println!("json_numbers allocs_per_call {name} {allocs}");
}

/// An OpenAI chat request of about `size` bytes: sampling numbers, a tool, and user turns.
fn openai_chat_request(size: usize) -> Vec<u8> {
    let mut body = String::from(
        r#"{"model":"gpt-4o","temperature":0.7,"top_p":0.95,"max_tokens":1024,"seed":42,"#,
    );
    body.push_str(
        r#""presence_penalty":0.0,"frequency_penalty":0.25,"logit_bias":{"1734":-100,"9906":5},"#,
    );
    body.push_str(r#""tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object","properties":{"lat":{"type":"number","minimum":-90,"maximum":90},"lon":{"type":"number","minimum":-180,"maximum":180}},"required":["lat","lon"]}}}],"#);
    body.push_str(r#""messages":[{"role":"system","content":"You are a helpful assistant."}"#);
    let mut turn = 0usize;
    while body.len() + 256 < size {
        body.push_str(&format!(
            r#",{{"role":"user","content":[{{"type":"text","text":"Turn {turn}: what is the weather at 51.5072, -0.1276 today, and how many degrees above 12.5 is it?"}}]}}"#
        ));
        turn += 1;
    }
    body.push_str("]}");
    body.into_bytes()
}

/// An 8 KiB number-dense body: a chat response with a logprobs array.
fn number_dense_body() -> Vec<u8> {
    let mut body = String::from(
        r#"{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"logprobs":{"content":["#,
    );
    let mut i = 0u32;
    while body.len() < 8 * 1024 - 160 {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            r#"{{"token":"t","logprob":-{}.{:06},"bytes":[116],"top_logprobs":[{{"token":"u","logprob":-{}.{:06}}}]}}"#,
            i % 7,
            (i * 7919) % 1_000_000,
            i % 5 + 1,
            (i * 104_729) % 1_000_000
        ));
        i += 1;
    }
    body.push_str(
        r#"]},"finish_reason":"stop"}],"usage":{"prompt_tokens":1234,"completion_tokens":567}}"#,
    );
    body.into_bytes()
}

/// A Vault KV v2 reply of about 4 KiB. With `deep`, the selected object nests 64 levels.
fn vault_reply(deep: bool) -> Vec<u8> {
    let mut secret = String::from(
        r#"{"password":"hunter2-correct-horse","port":5432,"ratio":0.125,"serial":184467440737095516160000"#,
    );
    if deep {
        secret.push_str(r#","nested":"#);
        secret.push_str(&"{\"k\":".repeat(63));
        secret.push_str("{\"leaf\":27.5}");
        secret.push_str(&"}".repeat(63));
    }
    secret.push('}');
    let mut body = format!(
        r#"{{"request_id":"7c2f6f2e-1b9b-4a52-9d1c-6f0f4c7f8a11","lease_id":"","renewable":false,"lease_duration":0,"data":{{"data":{secret},"metadata":{{"created_time":"2026-11-14T09:00:00.000000Z","custom_metadata":{{"#
    );
    let mut i = 0u32;
    while body.len() < 4 * 1024 - 120 {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            r#""label_{i}":"value number {i} for the vault metadata""#
        ));
        i += 1;
    }
    body.push_str(r#"},"deletion_time":"","destroyed":false,"version":3}},"wrap_info":null,"warnings":null,"auth":null}"#);
    body.into_bytes()
}

fn bench_parse_value(c: &mut Criterion) {
    let cases = [
        ("parse_value/openai_chat_1k", openai_chat_request(1024)),
        ("parse_value/openai_chat_8k", openai_chat_request(8 * 1024)),
        (
            "parse_value/openai_chat_100k",
            openai_chat_request(100 * 1024),
        ),
        ("parse_value/number_dense_8k", number_dense_body()),
    ];
    for (name, body) in &cases {
        assert!(parse_value(body).is_ok(), "{name} parses");
        report_allocs(name, || parse_value(body));
        c.bench_function(name, |b| b.iter(|| parse_value(black_box(body))));
    }
}

fn counts() -> [Count; 4] {
    ["1234", "567", "27.5", "1234567890123.456789"].map(|n| Count::parse(n).expect("count"))
}

fn bench_observation(c: &mut Criterion) {
    let mut observation = Observation::new([7; 32], b"event-1".to_vec(), b"component".to_vec());
    for (class, count) in counts().into_iter().enumerate() {
        observation = observation
            .count(class as u32, count)
            .expect("unique class");
    }
    let encoded = observation.encode().expect("encode");
    assert_eq!(Observation::decode(&encoded).expect("decode"), observation);
    report_allocs("observation/encode", || observation.encode());
    report_allocs("observation/decode", || Observation::decode(&encoded));
    c.bench_function("observation/encode", |b| {
        b.iter(|| black_box(&observation).encode())
    });
    c.bench_function("observation/decode", |b| {
        b.iter(|| Observation::decode(black_box(&encoded)))
    });
}

fn bench_persistence(c: &mut Criterion) {
    let map: BTreeMap<String, Count> = [
        "input",
        "output",
        "cache_read",
        "cache_write",
        "reasoning",
        "audio_input",
        "search_units",
        "unitemized_tokens",
    ]
    .iter()
    .zip(counts().into_iter().cycle())
    .map(|(class, count)| ((*class).to_owned(), count))
    .collect();
    let encoded = serde_json::to_vec(&map).expect("encode");
    let decoded: BTreeMap<String, Count> = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded, map);
    report_allocs("persistence/encode", || serde_json::to_vec(&map));
    report_allocs("persistence/decode", || {
        serde_json::from_slice::<BTreeMap<String, Count>>(&encoded)
    });
    c.bench_function("persistence/encode", |b| {
        b.iter(|| serde_json::to_vec(black_box(&map)))
    });
    c.bench_function("persistence/decode", |b| {
        b.iter(|| serde_json::from_slice::<BTreeMap<String, Count>>(black_box(&encoded)))
    });
}

fn select(body: &[u8]) -> bool {
    matches!(
        select_json(Held::new(body.to_vec()), &["data", "data"]),
        Ok(SelectedJson::Value(_))
    )
}

fn bench_select_json(c: &mut Criterion) {
    for (name, body) in [
        ("select_json/vault_4k", vault_reply(false)),
        ("select_json/vault_4k_deep64", vault_reply(true)),
    ] {
        assert!(select(&body), "{name} selects");
        report_allocs(name, || select(&body));
        c.bench_function(name, |b| b.iter(|| select(black_box(&body))));
    }
}

criterion_group!(
    benches,
    bench_parse_value,
    bench_observation,
    bench_persistence,
    bench_select_json
);
criterion_main!(benches);
