// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CODEC READS ONLY THE HOST IT IS HANDED (coordinator ruling 2026-10-14, contract-ABI: the
//! contract holds no host service; a codec is handed a `CodecHost`). A writer that mints an id draws
//! it from the handle's entropy and stamps the handle's clock, and with a handle that has neither it
//! mints from nothing: there is no other source left for it to reach. (The compile half of the same
//! rule is the contract's `compile_fail` doctest on `CodecHost`: the free ports are gone.)

use busbar_contract::codec::CodecHost;

/// A host whose entropy is one repeated byte and whose clock is one fixed second.
struct Fixed;

impl CodecHost for Fixed {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        out.fill(0x2A);
        true
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(1_700_000_000)
    }
}

/// A host with no entropy and no clock.
struct Silent;

impl CodecHost for Silent {
    fn fill_entropy(&self, _out: &mut [u8]) -> bool {
        false
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

/// An answer with no id and no creation time, written as an OpenAI chat completion through `host`.
fn written(host: &dyn CodecHost) -> serde_json::Value {
    let writer = crate::codec::proto_codec::Protocol::openai();
    writer
        .writer()
        .write_response(host, &crate::codec::ir::IrResponse::default())
}

fn token(v: &serde_json::Value) -> String {
    let id = v["id"].as_str().expect("an id is always written");
    id.strip_prefix("chatcmpl-")
        .expect("the native id prefix")
        .to_string()
}

#[test]
fn the_minted_id_and_the_stamped_time_are_the_handed_hosts() {
    let v = written(&Fixed);
    let t = token(&v);
    let first = t.chars().next().expect("a non-empty token");
    assert!(
        t.chars().all(|c| c == first) && first != '0',
        "every byte of the token came from the handed host's entropy, got {t:?}"
    );
    assert_eq!(v["created"], 1_700_000_000, "the handed host's clock");
}

#[test]
fn a_host_with_nothing_to_give_mints_from_nothing() {
    let v = written(&Silent);
    let t = token(&v);
    assert!(
        t.chars().all(|c| c == '0'),
        "no entropy was handed, so none was drawn from anywhere else: {t:?}"
    );
    assert_eq!(
        v["created"], 0,
        "no clock was handed, so the unstamped time"
    );
}
