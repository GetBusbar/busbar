// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which operation a request target names, one claimed target at a time.
//!
//! The operation class is what PRICES a unit, and it is read from the request target alone. Several
//! of the classes are named by more than one target — one vendor's embedding surface and another's
//! are the same operation — so the resolution is a chain of disjunctions, and a disjunction whose
//! alternatives are never each exercised on their own is a chain that can quietly become a
//! conjunction: every one of those targets then falls through to the conversation class, and the
//! whole non-chat surface is billed as chat.
//!
//! So every target the ladder actually claims is decoded here, and each is asserted to name its own
//! class. The classes this plane declares but whose targets belong to another plane's ladder
//! (spoken audio, transcription of it) are not reachable through this plane's own claims and are
//! not asserted here; what is asserted is that every class this walk DID produce is one the plane
//! declares.

mod harness;

use busbar_contract::bounded::{FactValue, Labels};
use busbar_contract::ids::OpClassId;
use busbar_contract::plane::{Ingress, Plane, PlaneMeta};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{meta, LlmPlane};

/// A body in each dialect's own shape, so the codec's own reader accepts it.
const ANTHROPIC: &str =
    r#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#;
const OPENAI: &str = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
const GEMINI: &str = r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;
const COHERE: &str = r#"{"model":"command-r","messages":[{"role":"user","content":"hi"}]}"#;
const RESPONSES: &str = r#"{"model":"gpt-4o-mini","input":"hi"}"#;

/// Decode one request at one target and report the class the draft was priced as.
///
/// The fact map and the draft's own `op` are read together: they are two statements of one answer,
/// and a step after the decode reads the fact while the ledger reads the class.
fn class_at(path: &'static str, body: &str) -> OpClassId {
    let plane = LlmPlane::EMPTY;
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(path, &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(body.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .unwrap_or_else(|e| panic!("{path}: the body is this dialect's shape: {e:?}"))
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("{path}: a whole request body decodes as one unit, got {other:?}"),
    };
    assert_eq!(
        draft.facts.get(meta::FACT_OPERATION),
        Some(FactValue::Str(draft.op.as_str())),
        "{path}: the operation fact and the priced class disagree"
    );
    draft.op
}

/// Every target the ladder claims names the operation it is, and only requests that name none of
/// the non-chat surfaces are conversations.
///
/// Each row is one alternative of one of the resolver's disjunctions, so each is what says that
/// alternative is still live on its own. A conjunction in place of any of the `or`s sends that
/// row's target to the conversation class — priced, billed and audited as a chat.
#[test]
fn every_claimed_target_names_its_own_operation() {
    let rows: &[(&'static str, &str, &str)] = &[
        // The embedding surfaces: four targets, three vendors, one operation.
        ("/v1/embeddings", OPENAI, "embeddings"),
        ("/openai/v1/embeddings", OPENAI, "embeddings"),
        ("/v2/embed", COHERE, "embeddings"),
        (
            "/v1beta/models/text-embedding:embedContent",
            GEMINI,
            "embeddings",
        ),
        (
            "/v1beta/models/text-embedding:batchEmbedContents",
            GEMINI,
            "embeddings",
        ),
        // The one moderation surface.
        ("/v1/moderations", OPENAI, "moderation"),
        // The one reranking surface.
        ("/v2/rerank", COHERE, "rerank"),
        // The image surfaces: a path segment for one vendor, an action suffix for another.
        ("/v1/images/generations", OPENAI, "image"),
        ("/v1/images/edits", OPENAI, "image"),
        ("/v1beta/models/imagen:predict", GEMINI, "image"),
        // The one audio surface this plane's ladder claims. Its sibling paths are the voice
        // plane's, by name, which is why only this one is reachable here.
        ("/v1/audio/translations", OPENAI, "transcription"),
        // And everything else is a conversation, in each of the dialects that has one.
        ("/v1/chat/completions", OPENAI, "chat"),
        ("/v1/responses", RESPONSES, "chat"),
        ("/v2/chat", COHERE, "chat"),
        ("/v1/messages", ANTHROPIC, "chat"),
        (
            "/v1beta/models/gemini-2.0-flash:generateContent",
            GEMINI,
            "chat",
        ),
    ];

    let declared = <LlmPlane as PlaneMeta>::OP_CLASSES;
    for (path, body, expected) in rows {
        let class = class_at(path, body);
        assert_eq!(
            class,
            OpClassId::new(expected),
            "{path} was priced as {} and not as {expected}",
            class.as_str()
        );
        assert!(
            declared.contains(&class),
            "{path} was priced as {}, which this plane never declared",
            class.as_str()
        );
    }
}

/// A target that names an embedding surface is not a conversation, and vice versa.
///
/// The counterpart of the walk above, stated as the difference it protects: two targets that differ
/// only in their tail are two different priced operations. A resolver stuck on one answer passes
/// every row of a table that expects that answer somewhere.
#[test]
fn two_targets_that_differ_only_in_their_tail_are_two_operations() {
    assert_ne!(
        class_at("/v1/embeddings", OPENAI),
        class_at("/v1/chat/completions", OPENAI)
    );
    assert_ne!(
        class_at("/v2/embed", COHERE),
        class_at("/v2/rerank", COHERE)
    );
    assert_ne!(
        class_at("/v1beta/models/imagen:predict", GEMINI),
        class_at("/v1beta/models/text-embedding:embedContent", GEMINI)
    );
}
