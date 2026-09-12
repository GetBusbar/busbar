// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen` — THE PLANE'S HALF: every frame a held subscription writes, and the
//! phase machine that decides which one is owed next.
//!
//! PLAN LINE 9. `busbar-mcp`'s own `subscribe.rs` built all of this inline, beside the poll loop
//! that feeds it: the acknowledgement's narrowing, the three list-changed notifications, the
//! resource-update relay's frame, the graceful close and the refusal. Every one of those is a
//! statement about THIS WIRE — an SSE `message` event carrying a JSON-RPC envelope, tagged in
//! `params._meta` — and this crate is the one place that wire is named, so this is where they live.
//!
//! ## WHAT STAYED ON THE ENGINE, AND WHY EACH ONE HAD TO
//!
//! Three things, and none of them is a frame. The CLOCK and the bound (`MAX_LIFETIME`,
//! `POLL_INTERVAL`, `KEEPALIVE_INTERVAL`) — this crate reads no clock but the one its context hands
//! it, and a held stream's context hands it none. The STANDING RE-ASK
//! (`busbar_substrate::trust::validate::Standing::still_permitted`, through the
//! `EngineHost::principal_standing` seam) — a principal re-resolved against the live governance
//! registry is the engine's own read, and the re-ask is the security property the engine's own
//! class test pins in place. The CATALOGUE WALK that turns a snapshot into three change keys, and
//! the grant read that judges an upstream's announcement — both are reads of the caller's grant
//! against a live registry, which is the same thing.
//!
//! What crosses is [`Poll`]: the ANSWER to those reads, in the contract's own closed words. The
//! verdict is a [`busbar_contract::counterparty::Verdict`] and not a substrate `Lapsed`, which is
//! the whole of plan line 9's verdict read — a refusal this side renders names the step that
//! refused because the word came WITH the answer, rather than because a second match here agreed
//! with the first.
//!
//! ## THE ACKNOWLEDGEMENT IS A NARROWING
//!
//! [`accept`] answers the ACCEPTED subset, never the requested one, and
//! `notifications/subscriptions/acknowledged` carries that subset as its body. A server that echoed
//! the request back would tell a client it was subscribed to things that will never arrive, and the
//! client would wait rather than fall back.
//!
//! ## THE ORDER IS THE PROPERTY
//!
//! The acknowledgement is owed FIRST and [`Phase`] is a phase rather than a flag so that "the
//! acknowledgement has not been sent yet" cannot be confused with "nothing has changed yet": the
//! first of those is a MUST about ordering and the second is ordinary quiet. And ENDED IS ENDED —
//! a stream whose standing has lapsed writes ONE closing frame and then closes, because a refusal
//! re-emitted on every poll for ever is a connection a client cannot tell from a working one.

use busbar_contract::counterparty::Verdict;
use serde_json::Value;

/// The `_meta` key the revision tags a subscription's frames with.
///
/// Spelled here because the SDK holds it privately (`SUBSCRIPTION_ID_META_KEY`, not `pub`) and the
/// codec crate does not carry it; PINNED against the SDK's own
/// `SubscriptionsListenResultMeta::new` by a cell in `busbar-mcp`, which is the crate that can name
/// both. A copy that is checked is not a second opinion.
pub const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// `notifications/subscriptions/acknowledged` — the accepted-subset frame.
pub const METHOD_ACKNOWLEDGED: &str = "notifications/subscriptions/acknowledged";

/// `notifications/prompts/list_changed`.
pub const METHOD_PROMPTS_LIST_CHANGED: &str = "notifications/prompts/list_changed";

/// `notifications/resources/list_changed`.
pub const METHOD_RESOURCES_LIST_CHANGED: &str = "notifications/resources/list_changed";

/// THE IDLE BYTES. An SSE comment — no `data:`, so every reader drops it — and not a protocol
/// message: what it stops is an idle proxy between busbar and its caller reclaiming a connection
/// that is working correctly. WHEN it is written is the engine's, because that is a clock read; WHAT
/// is written is this crate's, because it is bytes on this wire.
pub const KEEPALIVE: &str = ": keepalive\n\n";

/// The catalogue kinds busbar can observe changing BY COMPARISON, and the notification each one
/// becomes.
///
/// A closed set of the change-key categories. `resourceSubscriptions` is deliberately not a fourth
/// arm: it is uri-scoped rather than boolean, and its changes arrive as recorded upstream EVENTS
/// rather than as a catalogue slice to compare — [`Poll::Allowed`]'s `updates` is its whole delivery
/// path, and a `Kind` for it would be a boolean that means nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// `tools/list` moved.
    Tools,
    /// `prompts/list` moved.
    Prompts,
    /// `resources/list` moved.
    Resources,
}

impl Kind {
    /// Every kind, IN CHANGE-KEY ORDER, so a new arm cannot be added without appearing in the loop
    /// that emits and in the key array that feeds it.
    pub const ALL: [Kind; 3] = [Kind::Tools, Kind::Prompts, Kind::Resources];

    /// The wire method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Kind::Tools => busbar_mcp_codec::codec::METHOD_NOTIFY_TOOLS_LIST_CHANGED,
            Kind::Prompts => METHOD_PROMPTS_LIST_CHANGED,
            Kind::Resources => METHOD_RESOURCES_LIST_CHANGED,
        }
    }

    /// Whether the ACCEPTED filter opted this kind in.
    #[must_use]
    pub fn wanted(self, filter: &Filter) -> bool {
        let f = match self {
            Kind::Tools => filter.tools_list_changed,
            Kind::Prompts => filter.prompts_list_changed,
            Kind::Resources => filter.resources_list_changed,
        };
        f == Some(true)
    }
}

/// THE CATEGORIES A SUBSCRIPTION NAMES — requested on the way in, accepted on the way out.
///
/// `Option<bool>` per category rather than `bool`, because the wire distinguishes three states and
/// two of them are not the same statement: absent ("I said nothing about this category") and
/// `false` ("I do not want it") both mean nothing is delivered, and only the first is what an
/// acknowledgement may omit. The engine parses the caller's request through the SDK's own filter
/// type — that parse IS the acceptance test for the wire shape — and hands the result here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// `toolsListChanged`.
    pub tools_list_changed: Option<bool>,
    /// `promptsListChanged`.
    pub prompts_list_changed: Option<bool>,
    /// `resourcesListChanged`.
    pub resources_list_changed: Option<bool>,
    /// `resourceSubscriptions` — the uris, never an empty list. See [`accept`].
    pub resource_subscriptions: Option<Vec<String>>,
}

impl Filter {
    /// The filter AS THE ACKNOWLEDGEMENT CARRIES IT: the four members in the wire's own spelling,
    /// each omitted where this filter says nothing about it.
    ///
    /// Byte-identical to the SDK filter type's own encoding, and PINNED against it by a cell in
    /// `busbar-mcp` — the omissions are the load-bearing part, because an emitted `null` reads as a
    /// category the server took a position on.
    #[must_use]
    pub fn wire(&self) -> Value {
        let mut obj = serde_json::Map::new();
        for (key, flag) in [
            ("toolsListChanged", self.tools_list_changed),
            ("promptsListChanged", self.prompts_list_changed),
            ("resourcesListChanged", self.resources_list_changed),
        ] {
            if let Some(flag) = flag {
                obj.insert(key.to_string(), Value::Bool(flag));
            }
        }
        if let Some(uris) = &self.resource_subscriptions {
            obj.insert(
                "resourceSubscriptions".to_string(),
                Value::Array(uris.iter().map(|u| Value::String(u.clone())).collect()),
            );
        }
        Value::Object(obj)
    }

    /// Whether this filter can deliver NOTHING AT ALL.
    ///
    /// A stream that can deliver nothing is not a narrower stream, it is a connection held open to
    /// say nothing, and a client waiting on one waits for ever. The REFUSAL is the engine's — it is
    /// a JSON-RPC error envelope on a request that has not become a stream yet — but the question
    /// is this filter's, because the categories are.
    #[must_use]
    pub fn delivers_nothing(&self) -> bool {
        !Kind::ALL.into_iter().any(|k| k.wanted(self)) && self.resource_subscriptions.is_none()
    }
}

/// Narrow a requested filter to what busbar will actually deliver FOR THIS CALLER.
///
/// Written as an explicit construction rather than as an intersection with a constant, because what
/// busbar can deliver is not a fixed value to intersect against: it is a statement per category,
/// and `resourceSubscriptions` is narrowed for a different reason than an unrequested list-changed
/// is. Two reasons that read the same in a diff is how one of them gets quietly changed.
///
/// `entitled` answers "does THIS caller's grant reach a resource at this uri" — the same ordered
/// gate `resources/read` asks, threaded in as a predicate because the answer needs the catalogue
/// and the caller, and this function deliberately holds neither. A uri the caller cannot see is
/// dropped HERE, at open, so the acknowledgement never names another tenant's inventory — and the
/// entitlement is re-asked per poll at delivery, so a grant that narrows mid-stream bites there
/// too. The narrowed list is left `None` when nothing survives rather than set to an empty list: an
/// empty list is "you subscribed to no resources", which is a different statement from "this
/// category has nothing for you".
#[must_use]
pub fn accept(requested: &Filter, entitled: impl Fn(&str) -> bool) -> Filter {
    Filter {
        tools_list_changed: requested.tools_list_changed.filter(|v| *v),
        prompts_list_changed: requested.prompts_list_changed.filter(|v| *v),
        resources_list_changed: requested.resources_list_changed.filter(|v| *v),
        resource_subscriptions: requested
            .resource_subscriptions
            .as_ref()
            .map(|uris| {
                uris.iter()
                    .filter(|u| entitled(u))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|kept| !kept.is_empty()),
    }
}

/// The `params._meta` every frame on this stream carries.
///
/// THE SUBSCRIPTION ID IS THE LISTEN REQUEST'S OWN JSON-RPC ID: under a revision with no sessions,
/// the request that opened the stream is the only durable name the stream has, and minting a second
/// identifier would give a client two names for one thing and no way to relate them.
///
/// An id that is not a JSON-RPC id — neither a string nor a number — yields an EMPTY object rather
/// than a tag naming something that cannot be correlated, which is what the SDK's own result type
/// does when it refuses to build.
#[must_use]
pub fn subscription_meta(id: &Value) -> Value {
    if id.is_string() || id.is_number() {
        serde_json::json!({ META_SUBSCRIPTION_ID: id.clone() })
    } else {
        serde_json::json!({})
    }
}

/// One JSON-RPC notification envelope, tagged with the subscription it belongs to.
///
/// **No `id`, ever.** JSON-RPC 2.0 section 4.1 makes the absence of `id` the definition of a
/// notification, and an id here would oblige a client to answer something busbar is not waiting
/// for. The tag goes in `params._meta`, which is where the revision's own scenario looks for it.
#[must_use]
pub fn notification(method: &str, meta: &Value, extra: Value) -> Value {
    let mut params = match extra {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    params.insert("_meta".to_string(), meta.clone());
    serde_json::json!({
        "jsonrpc": crate::jsonrpc::VERSION,
        "method": method,
        "params": Value::Object(params),
    })
}

/// One SSE `message` event. One spelling of the framing, because two spellings of an event frame
/// is two places for the blank-line terminator to be forgotten.
#[must_use]
pub fn event(value: &Value) -> String {
    format!(
        "event: message\ndata: {}\n\n",
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
    )
}

/// WHAT ONE POLL OF A HELD SUBSCRIPTION FOUND — the engine's reads, answered in the contract's own
/// words.
///
/// Three arms and not a `Result`, because the two ways a stream ends are not one thing: a bound
/// reached is a GRACEFUL end and the revision has a word for it, and a lapsed standing is a
/// REFUSAL that names which step refused. A stream that ended by simply closing the socket is one
/// a client cannot tell from a dropped connection, which is why anything is written at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll<'a> {
    /// The standing still allows ([`Verdict::Allow`]), and this is what the snapshot it was
    /// re-asked against says.
    Allowed {
        /// The catalogue generation in force for this frame.
        generation: u64,
        /// One change key per [`Kind`], in [`Kind::ALL`] order: two polls with the same value saw
        /// the same list, and a different value means the client should re-read.
        keys: [u64; 3],
        /// The uris to relay, already judged against this poll's live grant and against the
        /// announcing server's ownership of them. Empty on the ordinary quiet poll.
        updates: &'a [String],
    },
    /// The standing no longer stands, and the verdict is the step that refused.
    Refused {
        /// Which step, in the one closed vocabulary both a client and an operator read.
        verdict: Verdict,
        /// The sentence the refusing side wrote. Rendered as the error's `message`; the stable word
        /// under `data.reason` comes off the verdict, never off this text.
        sentence: &'a str,
    },
    /// THE BOUND WAS REACHED. Not a failure and not a refusal: a long-lived response with no end is
    /// one a client cannot tell from a hung one.
    Complete,
}

/// What the stream is doing between polls. An explicit phase rather than a flag — see the module
/// header.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing has been written. The acknowledgement is owed, and it is owed FIRST.
    Acknowledge,
    /// Acknowledged; watching the generation.
    Watch {
        /// The generation the last comparison was made against.
        generation: u64,
        /// The change keys at that generation.
        seen: [u64; 3],
    },
    /// The final frame has been written. The next poll ends the stream.
    Ended,
}

/// ONE HELD SUBSCRIPTION'S COMPOSER: the accepted filter, the tag every frame carries, and the
/// phase.
///
/// It holds no host, no clock and no cursor — see the module header for what stayed on the engine
/// and why. Everything it needs per frame arrives as a [`Poll`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    accepted: Filter,
    meta: Value,
    id: Value,
    phase: Phase,
}

impl Listen {
    /// OPEN one subscription over an ALREADY-NARROWED filter.
    ///
    /// `accepted` is [`accept`]'s answer and not the caller's request, and the type does not
    /// distinguish them, so the call site is where that is stated — it is stated at both of them.
    #[must_use]
    pub fn opened(id: Value, accepted: Filter) -> Self {
        Self {
            meta: subscription_meta(&id),
            accepted,
            id,
            phase: Phase::Acknowledge,
        }
    }

    /// The accepted filter, for a caller that has to decide what to READ before it polls.
    #[must_use]
    pub fn accepted(&self) -> &Filter {
        &self.accepted
    }

    /// The uris this subscription asked for, or `None` where it asked for none — which is the
    /// engine's cue not to read the announcement ring at all.
    #[must_use]
    pub fn subscribed(&self) -> Option<&[String]> {
        self.accepted.resource_subscriptions.as_deref()
    }

    /// Whether the final frame has been written. ENDED IS ENDED: see the module header.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.phase == Phase::Ended
    }

    /// PRODUCE THE NEXT CHUNK: the frames this poll owes, `Some("")` for "nothing to say yet" — the
    /// ordinary case, which the engine turns into a [`KEEPALIVE`] once it has been quiet long
    /// enough — or `None` to close the stream.
    ///
    /// The verdict is read BEFORE the phase, and that ordering is the fix a sibling cell pins: a
    /// standing that lapsed while the acknowledgement was still owed closes the stream instead of
    /// acknowledging a subscription that will never deliver.
    #[must_use]
    pub fn step(&mut self, poll: Poll<'_>) -> Option<String> {
        if self.phase == Phase::Ended {
            return None;
        }
        let (generation, keys, updates) = match poll {
            Poll::Complete => {
                self.phase = Phase::Ended;
                return Some(self.complete_frame());
            }
            Poll::Refused { verdict, sentence } => {
                self.phase = Phase::Ended;
                return Some(self.refusal_frame(verdict, sentence));
            }
            Poll::Allowed {
                generation,
                keys,
                updates,
            } => (generation, keys, updates),
        };
        match &mut self.phase {
            Phase::Acknowledge => {
                let frame = event(&notification(
                    METHOD_ACKNOWLEDGED,
                    &self.meta,
                    serde_json::json!({ "notifications": self.accepted.wire() }),
                ));
                self.phase = Phase::Watch {
                    generation,
                    seen: keys,
                };
                Some(frame)
            }
            Phase::Watch {
                generation: watched,
                seen,
            } => {
                let mut out = String::new();
                // THE GENERATION IS THE GATE ON THE COMPARISON, not on the delivery: a snapshot
                // that has not moved cannot have changed a list, so the keys are not even read.
                if generation != *watched {
                    *watched = generation;
                    for (index, kind) in Kind::ALL.into_iter().enumerate() {
                        if keys[index] == seen[index] || !kind.wanted(&self.accepted) {
                            continue;
                        }
                        out.push_str(&event(&notification(
                            kind.method(),
                            &self.meta,
                            serde_json::json!({}),
                        )));
                    }
                    *seen = keys;
                }
                // THE RESOURCE-UPDATE RELAY. What is judged is the engine's — the subscriber's live
                // grant, and the announcing server's ownership of the uri — and what is WRITTEN is
                // one frame per surviving uri, in the order the announcements were recorded.
                for uri in updates {
                    out.push_str(&event(&notification(
                        busbar_mcp_codec::codec::METHOD_NOTIFY_RESOURCES_UPDATED,
                        &self.meta,
                        serde_json::json!({ "uri": uri }),
                    )));
                }
                Some(out)
            }
            Phase::Ended => None,
        }
    }

    /// The revision's own "this subscription ended gracefully" answer, correlated to the request
    /// that opened the stream.
    ///
    /// An id that cannot be a subscription tag yields the `resultType` alone rather than a `_meta`
    /// naming nothing — the same omission [`subscription_meta`] makes, for the same reason.
    fn complete_frame(&self) -> String {
        let meta = subscription_meta(&self.id);
        let result = if meta.as_object().is_some_and(|m| m.is_empty()) {
            serde_json::json!({ "resultType": crate::jsonrpc::RESULT_TYPE_COMPLETE })
        } else {
            serde_json::json!({
                "resultType": crate::jsonrpc::RESULT_TYPE_COMPLETE,
                "_meta": meta,
            })
        };
        event(&serde_json::json!({
            "jsonrpc": crate::jsonrpc::VERSION,
            "id": self.id,
            "result": result,
        }))
    }

    /// A LAPSED STANDING IS A REFUSAL AND SAYS WHICH ONE, in the contract's own closed word, so a
    /// client and an operator reading the same `reason` mean the same thing.
    ///
    /// The base protocol's own "invalid request" code, because what has become invalid is the
    /// request this stream IS — the standing it was admitted under no longer stands.
    ///
    /// [`Verdict::Allow`] has no reason word ([`Verdict::reason`] says so) and cannot reach here;
    /// were it to, the member is OMITTED rather than filled with a guess, because a `reason` nobody
    /// decided is worse than no `reason` at all.
    fn refusal_frame(&self, verdict: Verdict, sentence: &str) -> String {
        let mut error = serde_json::Map::new();
        error.insert(
            "code".to_string(),
            Value::from(crate::jsonrpc::CODE_INVALID_REQUEST),
        );
        error.insert("message".to_string(), Value::from(sentence));
        if let Some(reason) = verdict.reason() {
            error.insert("data".to_string(), serde_json::json!({ "reason": reason }));
        }
        event(&serde_json::json!({
            "jsonrpc": crate::jsonrpc::VERSION,
            "id": self.id,
            "error": Value::Object(error),
        }))
    }
}

#[cfg(test)]
#[path = "tests/subscribe.rs"]
mod tests;
