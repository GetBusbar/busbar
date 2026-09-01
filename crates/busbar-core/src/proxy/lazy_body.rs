// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAZY request-body DOM.
//!
//! The dominant same-protocol passthrough request never needs the full `serde_json::Value` tree it
//! used to pay for on every ingress: the pristine short-circuit re-emits the ORIGINAL bytes, and the
//! only body reads on that path are a handful of TOP-LEVEL point reads (`model`, `stream`, the
//! affinity `system` key, the router shim keys). Building — and recursively dropping — a full DOM
//! (one allocation per JSON node) purely to answer those reads was the single biggest remaining
//! per-request CPU cost.
//!
//! [`LazyBody`] replaces the eager parse with:
//!   1. ONE validating scan over the bytes ([`LazyBody::parse`]) that PRESERVES the malformed-body
//!      400 contract exactly (it goes through `crate::json::parse`, so the depth security floor and
//!      the accept/reject set are unchanged — every byte is still parsed; uncaptured values are
//!      scanned via `serde::de::IgnoredAny` instead of allocated into a tree), and
//!   2. a tiny HEAD projection of exactly the top-level fields the pristine path reads, captured
//!      during that same scan, plus
//!   3. on-demand materialization of the full `Value` ([`LazyBody::ensure_dom`] /
//!      [`LazyBody::into_value`]) for every path that genuinely needs the tree (cross-protocol
//!      translation, rewrite hooks, taps, gates/routing policies, failover hops 2+), plus
//!   4. on-demand materialization of the request IR ([`LazyBody::ensure_ir`]) — the PROTOCOL's parse
//!      of the body, as opposed to the JSON parse above — for the hook seam. Built at most once per
//!      request and only when the deployment grants some hook access to prompt content
//!      (`App::any_content_hook`); a deployment with no content hook never reaches it.
//!
//! SAFETY CONTRACT for [`LazyBody::probe`]: the head projection answers top-level reads ONLY for
//! the keys in [`captured_head_keys`] (`model`, `stream`, `system`, and every registered protocol's
//! array-stream shim key). Every consumer that point-reads the request body on the pre-materialized
//! path (`OperationHandler::wants_stream` / `body_affinity_key` — chat reads `stream`/`system`;
//! `ProtocolWriter::wants_array_stream` — gemini reads its shim key; the ingress `model` resolution)
//! reads ONLY those keys. If a future operation/writer override reads a NEW top-level key through
//! `probe()`, that key MUST be added to `captured_head_keys` (or the call site must materialize via
//! `ensure_dom`) — see `head_matches_dom_for_captured_keys` below, which pins the equivalence.

use super::*;

/// The top-level keys the head projection captures — the COMPLETE set of body point-reads on the
/// pre-materialized path, DECLARED by the protocols rather than hardcoded here.
///
/// This was the third `OnceLock` sweep: four keys spelled in this file, unioned with a second sweep
/// (`proto::array_stream_shim_keys()`) that built a `Protocol` per known name to read one constant
/// off its writer. Both halves are now `ProtocolDecl` fields — `head_keys` and
/// `array_stream_shim_key` — folded into one registry aggregate at boot, so the set this function
/// returns is the set the protocols declared and there is nowhere else to state it.
fn captured_head_keys() -> &'static [&'static str] {
    crate::proto::registry::registry().head_keys()
}

/// A top-level map key classified against [`captured_head_keys`] WITHOUT allocating: the serde
/// visitor borrows the key transiently and resolves it to the interned `&'static str` (or `None`
/// for a key the head does not capture, whose value is then scanned via `IgnoredAny`).
struct HeadKey(Option<&'static str>);

impl<'de> serde::Deserialize<'de> for HeadKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl serde::de::Visitor<'_> for KeyVisitor {
            type Value = HeadKey;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object key")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<HeadKey, E> {
                Ok(HeadKey(
                    captured_head_keys().iter().copied().find(|k| *k == s),
                ))
            }
        }
        d.deserialize_str(KeyVisitor)
    }
}

/// The head projection: `Value::Object` holding ONLY the captured top-level keys when the body's
/// top level is a JSON object; `Value::Null` for every non-object body (whose top-level `.get()`
/// reads all resolve to `None` — exactly what they resolve to on the full DOM, since `Value::get`
/// on a non-object is `None` too). Duplicate captured keys keep the LAST occurrence, matching
/// `serde_json::Map` insert semantics on the full parse.
struct Head(Value);

impl<'de> serde::Deserialize<'de> for Head {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct HeadVisitor;
        impl<'de> serde::de::Visitor<'de> for HeadVisitor {
            type Value = Head;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            // Non-object top levels: the whole body is still parsed/validated by the driving
            // deserializer; the head is Null (all point reads -> None, same as the DOM's `.get`).
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Head, A::Error> {
                // Consume (and thereby VALIDATE) every element without building values.
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Head(Value::Null))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Head, A::Error> {
                let mut mini = serde_json::Map::new();
                while let Some(HeadKey(k)) = map.next_key::<HeadKey>()? {
                    match k {
                        // A captured key: keep its (small) value. `insert` overwrites on duplicate
                        // keys — last-wins, byte-for-byte the full-DOM behavior.
                        Some(name) => {
                            let v: Value = map.next_value()?;
                            mini.insert(name.to_string(), v);
                        }
                        // Any other key: scan/validate the value without allocating a tree.
                        None => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Head(Value::Object(mini)))
            }
        }
        d.deserialize_any(HeadVisitor)
    }
}

/// How much of the body has been materialized so far.
enum Body {
    /// Validated JSON bytes + top-level head projection; no DOM built yet.
    Head { bytes: Bytes, head: Value },
    /// The full DOM — materialized on demand, or supplied eagerly by a caller that already parsed
    /// (path-model ingress routes, failover re-parse, tests).
    Dom(Value),
}

/// The request body as the forward engine carries it: validated pristine bytes + the head
/// projection, with the full DOM materialized ONLY on the paths that need it, and the parsed IR
/// materialized ONLY when a hook is granted the request's content. See the module docs.
pub struct LazyBody {
    body: Body,
    /// The request facts, projected from the DOM by the ingress operation's reader (through the
    /// neutral [`crate::handlers::TranslateCodec::read_facts_value`] entrypoint) and memoized here so
    /// one request costs one read. Held behind the [`crate::ir::facts::IrFacts`] projection, NOT the
    /// concrete IR, so this seam never names the LLM plane's representation. `None` until
    /// [`Self::ensure_ir`] is called and successful, and dropped again whenever [`Self::ensure_dom`]
    /// hands out a mutable body — see that method for why that invalidation is the invariant rather
    /// than a precaution.
    ir: Option<Box<dyn crate::ir::facts::IrFacts + Send + Sync>>,
}

impl LazyBody {
    /// Validate `bytes` as JSON and capture the head projection — WITHOUT building a DOM. Goes
    /// through `crate::json::parse` so the depth security floor and the malformed-body reject set
    /// are IDENTICAL to the old eager `parse::<Value>` (same guard, same parser, full-body scan).
    /// `Err` ⇒ the caller takes its existing malformed-body 400 path, exactly as before.
    pub fn parse(bytes: &Bytes) -> Result<Self, sonic_rs::Error> {
        let head: Head = crate::json::parse(bytes)?;
        Ok(LazyBody {
            body: Body::Head {
                bytes: bytes.clone(), // refcount bump — the engine retains the same pristine bytes
                head: head.0,
            },
            ir: None,
        })
    }

    /// Wrap an ALREADY-parsed body (path-model ingress routes that injected shim keys, tests). The
    /// DOM is present from the start; every read sees it directly.
    pub(crate) fn from_value(v: Value) -> Self {
        LazyBody {
            body: Body::Dom(v),
            ir: None,
        }
    }

    /// Top-level POINT-READ view: the DOM when materialized (always authoritative — it may have
    /// been mutated by rewrite hooks), else the head projection. ONLY valid for reads of the
    /// [`captured_head_keys`] — any other key must go through [`Self::ensure_dom`].
    pub(crate) fn probe(&self) -> &Value {
        match &self.body {
            Body::Dom(v) => v,
            Body::Head { head, .. } => head,
        }
    }

    /// Materialize (memoized) the full DOM and return it mutably. The parse is infallible in
    /// practice — `Self::parse` already validated these exact bytes — but the `Err` is surfaced so
    /// callers keep their existing unreachable-parse-failure guards instead of unwrapping on the
    /// request path.
    ///
    /// Handing out `&mut Value` DROPS any memoized IR. This is the invariant that keeps the two
    /// views of one body from disagreeing: a rewrite hook mutating the tree through this handle
    /// would otherwise leave a stale IR behind for the next reader, which is precisely the
    /// "screened one view, forwarded another" class the IR exists to close. The cost is paid only
    /// by callers that asked to mutate, and the next [`Self::ensure_ir`] re-reads the body as it now
    /// stands.
    pub(crate) fn ensure_dom(&mut self) -> Result<&mut Value, ()> {
        self.ir = None;
        if let Body::Head { bytes, .. } = &self.body {
            let v: Value = crate::json::parse(bytes).map_err(|_| ())?;
            self.body = Body::Dom(v);
        }
        match &mut self.body {
            Body::Dom(v) => Ok(v),
            // Unreachable: the Head arm above either converted to Dom or returned Err.
            Body::Head { .. } => Err(()),
        }
    }

    /// Materialize (memoized) the request FACTS — the parse the PROTOCOL performs, as distinct from
    /// the JSON parse [`Self::ensure_dom`] performs — projected to the neutral
    /// [`crate::ir::facts::IrFacts`], and return it.
    ///
    /// The facts are read by the ingress operation's own handler through the single
    /// [`crate::handlers::TranslateCodec::read_facts_value`] entrypoint, so it is the SAME parse the
    /// cross-protocol translate path and the hook seam perform, not a second reading of the wire.
    /// `None` when the body cannot be materialized or the ingress protocol/operation has no handler or
    /// rejects the body: a caller that cannot get the facts falls back to what it does today, never to
    /// a guess.
    ///
    /// COST: the caller decides whether to call this at all, and the deployment-wide answer is
    /// `App::any_content_hook`. This method deliberately does NOT consult that flag itself — a
    /// method that silently no-ops on a config bit is a method whose contract depends on config.
    pub(crate) fn ensure_ir(
        &mut self,
        ingress_protocol: &str,
        op: crate::handlers::Op,
    ) -> Option<&(dyn crate::ir::facts::IrFacts + Send + Sync)> {
        use crate::handlers::TranslateCodec;
        if self.ir.is_none() {
            let handler = crate::handlers::request_handler(ingress_protocol)
                .and_then(|rh| rh.operation_handler(op.operation))?;
            // `ensure_dom` clears the memo, so read the facts from the materialized tree and only then
            // install them — the order matters and is the reason this is not two statements.
            let dom = self.ensure_dom().ok()?;
            self.ir = handler.read_facts_value(dom).ok();
        }
        self.ir.as_deref()
    }

    /// Consume into the full DOM (memoized parse if not yet materialized). Same infallibility note
    /// as [`Self::ensure_dom`].
    pub(crate) fn into_value(self) -> Result<Value, ()> {
        match self.body {
            Body::Dom(v) => Ok(v),
            Body::Head { bytes, .. } => crate::json::parse(&bytes).map_err(|_| ()),
        }
    }
}

/// HEAD-LEVEL mirror of `translate_request_cross_protocol`'s SAME-PROTOCOL invalidator set (#1-#4
/// of the request short-circuit contract, plus the Vertex-Anthropic body transform), evaluated on
/// top-level point reads only — so hop 1 of a same-protocol dispatch can re-emit the retained bytes
/// WITHOUT ever materializing the DOM.
///
/// SOUNDNESS (one-sided by design): this returns `true` ONLY when the full translate path would
/// provably leave the body pristine (and therefore re-emit the retained bytes itself). Any doubt
/// returns `false`, which sends the request down the unchanged materialize-and-translate path —
/// a slower CORRECT answer, never a wrong relay. Concretely:
///   - #1: any registered array-stream shim key present at the top level → not pristine.
///   - #2: `stream` present and the egress (== ingress) is path-model → not pristine.
///   - #3: modeled on the DEFAULT `rewrite_model_if_needed` (no change iff the body's top-level
///     `model` is exactly the lane's wire model string). `BedrockWriter`'s no-op override can only
///     make FEWER changes than the default, so treating every writer as the default is sound — a
///     Bedrock body without `model` reads "would change" here and takes the full path, where the
///     real no-op override still yields the byte short-circuit inside translate.
///   - Vertex-Anthropic (`path_base` on an anthropic lane) always mutates an object body.
///   - #4: same-protocol path-model with a body `model` → stripped → not pristine.
///
/// A NON-OBJECT top level is pristine: every invalidator no-ops (`as_object_mut` fails), exactly
/// as the full path concludes.
///
/// The parity test `head_pristine_matches_translate_output` pins this mirror against the real
/// translate seam so the two cannot silently drift.
pub(crate) fn head_provably_pristine(app: &App, i: usize, probe: &Value) -> bool {
    let Some(obj) = probe.as_object() else {
        return true;
    };
    // #1: never-native router shim keys are stripped on every branch.
    if crate::proto::array_stream_shim_keys()
        .iter()
        .any(|k| obj.contains_key(*k))
    {
        return false;
    }
    let lane = &app.engine_tables().lanes()[i];
    let model_in_url = crate::proto::decl_for(lane.protocol).is_some_and(|d| d.has_model_in_url);
    // #2: `stream` is a path shim for a path-model egress (same-proto ⇒ egress == this lane).
    if model_in_url && obj.contains_key("stream") {
        return false;
    }
    // #3: the default model rewrite is a no-op only when the body already carries exactly the
    // lane's wire model as a string (missing / non-string / different ⇒ the rewrite would fire).
    if obj.get("model").and_then(|m| m.as_str()) != Some(lane.wire_model()) {
        return false;
    }
    // A dialect that reshapes its body at a path-model URL always mutates an object body, so such
    // a request can never be a pristine passthrough. Asked of the WRITER before any DOM exists.
    if lane.path_base.is_some()
        && crate::proto::decl_for(lane.protocol).is_some_and(|d| d.reshapes_body_at_path_base)
    {
        return false;
    }
    // #4: a same-protocol path-model body `model` is stripped after the rewrite.
    if model_in_url && obj.contains_key("model") {
        return false;
    }
    true
}

#[cfg(test)]
#[path = "tests/lazy_body_tests.rs"]
mod lazy_body_tests;
