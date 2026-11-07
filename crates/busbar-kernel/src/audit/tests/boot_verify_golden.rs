// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::store::plane_view::decode;
use busbar_contract::records::RecordStoreResult;

/// The one field this golden reads back off a frozen scoped-stream body — the tail digest. Decoded
/// through a NEUTRAL local shape (matching the on-disk field name) so this core test names no stream
/// record type: the frozen bytes are opaque persisted evidence, and all the golden asserts of them is
/// that the digest the past build sealed is still the one they carry.
#[derive(serde::Deserialize)]
struct FrozenTailDigest {
    hash: String,
}

const SCOPED_1: &[u8] = br#"{"seq":1,"prev_hash":"","hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","content":[0,0,0,0,0,0,0,8,0,0,0,0,101,83,241,0,0,0,0,0,0,0,0,3,115,114,118,0,0,0,0,0,0,0,8,115,114,118,95,116,111,111,108,0,0,0,0,0,0,0,10,100,105,115,112,97,116,99,104,101,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6,97,98,99,49,50,51,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,7]}"#;
const SCOPED_2: &[u8] = br#"{"seq":2,"prev_hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","hash":"721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a","content":[0,0,0,0,0,0,0,8,0,0,0,0,101,83,241,60,0,0,0,0,0,0,0,3,115,114,118,0,0,0,0,0,0,0,9,115,114,118,95,111,116,104,101,114,0,0,0,0,0,0,0,7,114,101,102,117,115,101,100,0,0,0,0,0,0,0,11,110,111,116,95,103,114,97,110,116,101,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,0,0,0,0,7]}"#;

pub(in crate::audit) const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
pub(in crate::audit) const AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

const SCOPED_TAIL_HASH: &str = "721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a";
pub(in crate::audit) const AD_TAIL_HASH: &str =
    "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

const KIND_SCOPED: &str = "scoped_golden";

const FROZEN_SCOPE: &str = "vk_alice";

fn scoped_reframe(
    scope: &str,
    body: &[u8],
) -> RecordStoreResult<crate::audit::stream_registry::StreamRecord> {
    let b: crate::audit::journal::NeutralBody = decode(body)?;
    Ok(crate::audit::stream_registry::StreamRecord::from_parts(
        scope.to_string(),
        b.seq,
        b.prev_hash,
        b.hash,
        b.content,
        crate::audit::Framing::LengthPrefixed,
        true,
    ))
}

#[test]
fn scoped_chain_boot_verifies_from_frozen_bytes() {
    use crate::audit::stream_registry;

    let bodies = vec![SCOPED_1.to_vec(), SCOPED_2.to_vec()];
    let kind_id = crate::audit::auditlog::fresh_test_kind_id();
    stream_registry::register(
        kind_id,
        KIND_SCOPED.to_string(),
        crate::audit::Framing::LengthPrefixed,
        true,
        stream_registry::Decode::Native(scoped_reframe),
        usize::MAX,
    );
    let broke = stream_registry::seed(kind_id, FROZEN_SCOPE, &bodies).expect("the bodies decode");
    assert!(
        !broke,
        "a persisted length-prefixed scoped chain reported TAMPERED means the digest drifted"
    );

    let tail: FrozenTailDigest = decode(SCOPED_2).unwrap();
    assert_eq!(tail.hash, SCOPED_TAIL_HASH);
    use crate::audit::ChainedRecord;
    let records: Vec<_> = bodies
        .iter()
        .map(|body| scoped_reframe(FROZEN_SCOPE, body).unwrap())
        .collect();
    let mut chain = crate::audit::Chain::from_persisted(&records).unwrap();
    let next = chain.append(
        FROZEN_SCOPE,
        stream_registry::StreamInput::new(
            b"next".to_vec(),
            crate::audit::Framing::LengthPrefixed,
            true,
        ),
    );
    let (seq, prev_hash) = (next.seq(), next.prev_hash());

    assert_eq!(
        (seq, prev_hash),
        (3, SCOPED_TAIL_HASH),
        "the chain resumes after its frozen tail"
    );
}
