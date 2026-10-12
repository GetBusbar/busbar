// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE UPSTREAM CALL, NEGOTIATED: the client ladder as a sans-I/O state machine (OWNER 2026-09-29
//! compat scope, both directions).
//!
//! busbar builds every request in the stateless `2026-07-28` shape. [`Negotiator`] carries ONE such
//! request to an upstream whose revision busbar may not know, and says, one [`Action`] at a time,
//! what the driver must put on the wire: the stateless request itself; on a refusal an `initialize`
//! and `notifications/initialized` and then the request lowered into the session revision the
//! upstream chose; and on a refusal of `initialize`, the `2024-11-05` event stream, with the
//! request POSTed to the address the stream names and its answer read off the stream.
//!
//! THE ADAPTER CONTRACT, which is all a driver implements (the engine's legacy client leg today,
//! the plane driver's far end at the flip):
//!
//! - [`Action::Send`]: send the request with its verb; feed the answer to [`Negotiator::on_answer`]
//!   as a [`HopAnswer`] (status, the response head's kept fields, body), or `None` when there was no
//!   answer at all. The only head field read is [`super::compat::H_SESSION`], which the plane
//!   declares in `keep_response_headers`.
//! - [`Action::OpenStream`]: open a GET stream; feed its head to [`Negotiator::on_answer`] (body
//!   empty), then every event read off it to [`Negotiator::on_event`] until the machine finishes.
//!   Close the stream when it does.
//! - [`Action::AwaitEvent`]: read the next event off the open stream.
//! - [`Action::Finish`]: the answer to hand back, in the shape the stateless request would have
//!   had it; [`Negotiator::remembered`] is what to keep for the next call to this upstream.
//! - [`Action::Fail`]: stop; nothing more is sent.
//!
//! Nothing here opens a connection, reads a clock or holds anything across calls but the value.

use serde_json::Value;

use super::compat::{
    initialize_request, initialized_notification, lower_request, offered_revision, probe_outcome,
    EventStreamLink, LinkEffect, StreamEvent, H_SESSION,
};
use super::jsonrpc::OutboundRequest;
use crate::revision::{self, Revision, StepOutcome};
use crate::tool_sessions::Remembered;

/// The verb a hop is sent with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    /// A JSON-RPC message.
    Post,
    /// The end of a session.
    Delete,
}

/// What came back from one hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopAnswer {
    /// The response status.
    pub status: u16,
    /// The response head's kept fields, lower-case names.
    pub fields: Vec<(String, String)>,
    /// The body (the last JSON-RPC message of an event-stream answer, as the engine reads it).
    pub body: Vec<u8>,
}

impl HopAnswer {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    const fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Why a negotiated call stopped without an answer to hand back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The upstream could not be reached, or answered 5xx, on a step whose failure says nothing
    /// about its revision. The last answer, if any, is carried.
    Unreachable(Option<HopAnswer>),
    /// Every rung of the ladder was refused: the upstream speaks no revision this plane carries.
    NoCommonRevision,
    /// The upstream's `initialize` answer named a revision this plane cannot carry; the spec's rule
    /// is to disconnect.
    OfferedUnsupported,
    /// The `2024-11-05` stream named a message address on another origin, or none busbar can read.
    AddressRefused,
    /// The stream ended, or refused a POST, before the answer arrived.
    StreamLost,
}

/// The next thing the driver does.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Send `request` with `verb`, then call [`Negotiator::on_answer`].
    Send {
        /// The verb.
        verb: Verb,
        /// The request.
        request: OutboundRequest,
    },
    /// Open a GET event stream with `request`'s address and credential, then call
    /// [`Negotiator::on_answer`] with its head.
    OpenStream {
        /// The stream request (its body is empty).
        request: OutboundRequest,
    },
    /// Read the next event off the open stream and call [`Negotiator::on_event`].
    AwaitEvent,
    /// The answer to hand back.
    Finish(HopAnswer),
    /// Stop.
    Fail(Refusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Probe,
    Initialize,
    Initialized {
        revision: Revision,
        session: Option<String>,
    },
    InSession {
        revision: Revision,
        session: Option<String>,
    },
    StreamOpening,
    StreamWaitAddress,
    StreamInitPosted,
    StreamInitialized,
    StreamCallPosted,
    Done,
}

/// How many requests one `2024-11-05` link waits on at once: `initialize` and the call itself.
const LINK_WAITING: usize = 2;
/// The id busbar's own `initialize` carries. Its own request ids come from
/// [`super::jsonrpc::dispatch_request_id`], which never reaches this value.
const INITIALIZE_ID: u64 = u64::MAX;

/// ONE CALL'S NEGOTIATION. See the module header for the driver's side.
#[derive(Debug)]
pub struct Negotiator {
    original: OutboundRequest,
    original_id: Option<Value>,
    client_version: String,
    phase: Phase,
    remembered: Option<Remembered>,
    reinitialized: bool,
    link: Option<EventStreamLink>,
}

impl Negotiator {
    /// Carries `original` (a stateless request) to its upstream, starting from what busbar
    /// `remembered` about that upstream. `client_version` names busbar in `initialize`.
    #[must_use]
    pub fn new(
        original: OutboundRequest,
        remembered: Option<Remembered>,
        client_version: &str,
    ) -> Self {
        let original_id = serde_json::from_slice::<Value>(&original.body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .filter(|v| !v.is_null());
        Self {
            original,
            original_id,
            client_version: client_version.to_string(),
            phase: Phase::Probe,
            remembered,
            reinitialized: false,
            link: None,
        }
    }

    /// What to keep for the next call to this upstream: the negotiated revision and, on a
    /// session revision, its session. `None` means forget (nothing was learnt, or it was lost).
    #[must_use]
    pub fn remembered(&self) -> Option<Remembered> {
        self.remembered.clone()
    }

    /// The first action.
    pub fn start(&mut self) -> Action {
        match self.remembered.clone() {
            None => self.send(Phase::Probe, self.original.clone()),
            Some(r) if r.revision == Revision::R2026_07_28 => {
                self.send(Phase::Probe, self.original.clone())
            }
            Some(r) if r.revision.is_event_stream_revision() => self.open_stream(),
            Some(r) => self.in_session(r.revision, r.session),
        }
    }

    fn send(&mut self, phase: Phase, request: OutboundRequest) -> Action {
        self.phase = phase;
        Action::Send {
            verb: Verb::Post,
            request,
        }
    }

    fn in_session(&mut self, revision: Revision, session: Option<String>) -> Action {
        let url = self.original.url.clone();
        let request = lower_request(&self.original, &url, revision, session.as_deref());
        self.send(Phase::InSession { revision, session }, request)
    }

    fn initialize(&mut self) -> Action {
        let request = initialize_request(
            &self.original,
            &self.original.url,
            revision::SESSION_REVISIONS[0],
            INITIALIZE_ID,
            &self.client_version,
        );
        self.send(Phase::Initialize, request)
    }

    fn open_stream(&mut self) -> Action {
        self.phase = Phase::StreamOpening;
        let mut request = lower_request(
            &self.original,
            &self.original.url,
            Revision::R2024_11_05,
            None,
        );
        request.body = Vec::new();
        request
            .headers
            .retain(|(k, _)| k != "content-type" && k != "accept");
        request
            .headers
            .push(("accept".to_string(), "text/event-stream".to_string()));
        self.link = Some(EventStreamLink::new(&self.original.url, LINK_WAITING));
        Action::OpenStream { request }
    }

    fn finish(&mut self, answer: HopAnswer) -> Action {
        self.phase = Phase::Done;
        Action::Finish(answer)
    }

    fn fail(&mut self, refusal: Refusal) -> Action {
        self.phase = Phase::Done;
        Action::Fail(refusal)
    }

    /// Feeds the answer to the last [`Action::Send`] or [`Action::OpenStream`]; `None` when there
    /// was no answer at all.
    pub fn on_answer(&mut self, answer: Option<HopAnswer>) -> Action {
        let Some(answer) = answer else {
            return self.fail(Refusal::Unreachable(None));
        };
        match self.phase.clone() {
            Phase::Probe => match probe_outcome(answer.status, &answer.body) {
                StepOutcome::Answered => {
                    self.remembered = Some(Remembered {
                        revision: Revision::R2026_07_28,
                        session: None,
                        message_address: None,
                    });
                    self.finish(answer)
                }
                StepOutcome::Unreachable => self.fail(Refusal::Unreachable(Some(answer))),
                StepOutcome::Refused4xx => {
                    // A remembered stateless upstream that now refuses is renegotiated once.
                    self.remembered = None;
                    self.initialize()
                }
            },
            Phase::Initialize => {
                if answer.ok() {
                    if let Some(r) = offered_revision(&answer.body) {
                        if r.is_event_stream_revision() {
                            return self.fail(Refusal::OfferedUnsupported);
                        }
                        let session = answer.field(H_SESSION).map(str::to_string);
                        let url = self.original.url.clone();
                        let request =
                            initialized_notification(&self.original, &url, r, session.as_deref());
                        return self.send(
                            Phase::Initialized {
                                revision: r,
                                session,
                            },
                            request,
                        );
                    }
                }
                match probe_outcome(answer.status, &answer.body) {
                    StepOutcome::Unreachable => self.fail(Refusal::Unreachable(Some(answer))),
                    StepOutcome::Refused4xx => self.open_stream(),
                    StepOutcome::Answered => self.fail(Refusal::OfferedUnsupported),
                }
            }
            Phase::Initialized { revision, session } => {
                if !answer.ok() {
                    return self.fail(Refusal::Unreachable(Some(answer)));
                }
                self.remembered = Some(Remembered {
                    revision,
                    session: session.clone(),
                    message_address: None,
                });
                self.in_session(revision, session)
            }
            Phase::InSession { session, .. } => {
                if answer.status == 404 && session.is_some() && !self.reinitialized {
                    // The upstream's session is gone (ended, expired, or another replica): the
                    // spec's recovery is a fresh `initialize`, once.
                    self.reinitialized = true;
                    self.remembered = None;
                    return self.initialize();
                }
                self.finish(answer)
            }
            Phase::StreamOpening => {
                if answer.ok() {
                    self.phase = Phase::StreamWaitAddress;
                    Action::AwaitEvent
                } else if (400..500).contains(&answer.status) {
                    self.remembered = None;
                    self.fail(Refusal::NoCommonRevision)
                } else {
                    self.fail(Refusal::Unreachable(Some(answer)))
                }
            }
            Phase::StreamInitPosted | Phase::StreamCallPosted => {
                if answer.ok() {
                    Action::AwaitEvent
                } else {
                    self.fail(Refusal::StreamLost)
                }
            }
            Phase::StreamInitialized => {
                if !answer.ok() {
                    return self.fail(Refusal::StreamLost);
                }
                self.post_call_on_stream()
            }
            Phase::StreamWaitAddress | Phase::Done => Action::AwaitEvent,
        }
    }

    fn post_call_on_stream(&mut self) -> Action {
        let Some(address) = self
            .link
            .as_ref()
            .and_then(|l| l.address().map(str::to_string))
        else {
            return self.fail(Refusal::StreamLost);
        };
        let request = lower_request(&self.original, &address, Revision::R2024_11_05, None);
        match self.original_id.clone() {
            Some(id) => {
                if let Some(link) = self.link.as_mut() {
                    link.expect(&id);
                }
                self.send(Phase::StreamCallPosted, request)
            }
            // A notification has no answer on the stream: its POST's status is the whole of it.
            None => self.send(Phase::StreamCallPosted, request),
        }
    }

    /// Feeds one event read off the open stream.
    pub fn on_event(&mut self, event: &StreamEvent) -> Action {
        let Some(link) = self.link.as_mut() else {
            return self.fail(Refusal::StreamLost);
        };
        match (self.phase.clone(), link.on_event(event)) {
            (Phase::StreamWaitAddress, LinkEffect::Ready(address)) => {
                link.expect(&Value::from(INITIALIZE_ID));
                let request = initialize_request(
                    &self.original,
                    &address,
                    Revision::R2024_11_05,
                    INITIALIZE_ID,
                    &self.client_version,
                );
                self.send(Phase::StreamInitPosted, request)
            }
            (_, LinkEffect::Refused(_)) => self.fail(Refusal::AddressRefused),
            (Phase::StreamInitPosted, LinkEffect::Answer { body, .. }) => {
                if offered_revision(&body) != Some(Revision::R2024_11_05) {
                    return self.fail(Refusal::OfferedUnsupported);
                }
                let address = link.address().unwrap_or_default().to_string();
                self.remembered = Some(Remembered {
                    revision: Revision::R2024_11_05,
                    session: None,
                    message_address: None,
                });
                let request =
                    initialized_notification(&self.original, &address, Revision::R2024_11_05, None);
                self.send(Phase::StreamInitialized, request)
            }
            (Phase::StreamCallPosted, LinkEffect::Answer { body, .. }) => self.finish(HopAnswer {
                status: 200,
                fields: Vec::new(),
                body,
            }),
            _ => Action::AwaitEvent,
        }
    }

    /// Whether a notification's call is complete: a notification POSTed on the stream is finished
    /// by its POST's status, which [`Self::on_answer`] reports as [`Action::AwaitEvent`]; the driver
    /// asks this instead of waiting for an answer that never comes.
    #[must_use]
    pub fn expects_no_answer(&self) -> bool {
        self.phase == Phase::StreamCallPosted && self.original_id.is_none()
    }
}

#[cfg(test)]
#[path = "tests/negotiate_tests.rs"]
mod tests;
