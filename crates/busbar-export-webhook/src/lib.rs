// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

//! The built-in **`request-log-webhook`** export sink: frame one already-serialized request-log
//! line as one `POST` at one operator-configured target, and say what came back of it.
//!
//! # What this crate is, and what it deliberately is not
//!
//! It is a sink of kind `export`. It takes a payload and states the delivery that carries it. It
//! does not open the socket — a connection pool, a certificate posture and a runtime are properties of the
//! process this sink was loaded into, not of the sink — it does not decide whether there is room
//! for the delivery (its composer sheds for it against the capacity the operator configured), and
//! it does not build the payload: the projection that bounds what may be in the line is resolved
//! from the operator's config long before it gets here, so by the time one reaches
//! [`WebhookSink::delivery`] an ungranted field is already absent.
//!
//! It also does not EMIT and does not VALIDATE. A recorder and a diagnostics registry belong to the
//! process; the SSRF guard that decides whether a target may be POSTed to AT ALL is a boot-time
//! judgement on the operator's document, made once by whoever resolves that document — a sink asked
//! to re-decide it per delivery would be deciding it in the wrong place and at the wrong time. What
//! this sink cannot say for itself it REPORTS ([`Event`], [`Report`]), and its composer turns a
//! report into whatever that process spells a warning with.
//!
//! # Why the URL this sink carries for its reports is not the URL it POSTs to
//!
//! An operator may embed credentials in a webhook URL (RFC 3986 §3.2.1 allows `user:password@` in
//! the authority). The target must therefore be carried twice: the URL the request is addressed to,
//! and a SAFE-TO-LOG spelling of it that the composer masked before ever handing it over
//! ([`WebhookSink::new`]'s `display_url`). Every [`Event`] this crate raises carries the second one
//! and this crate never has an opportunity to mix them up, because it holds no masker and could not
//! produce the first from the second if it tried.

use busbar_contract::{
    AbiVersion, Ack, Delivery, Export, ExportHost, ExportItem, Kind, Plugin, RouteStatement,
    ServeRequest, Served, EXPORT_ABI,
};
use std::sync::Arc;
use std::time::Duration;

/// The operator's `module:` token for this sink.
pub const MODULE: &str = "request-log-webhook";

/// The label this sink's composer names its capacity gate with on the shared
/// `busbar_admission_denied_total{gate="..."}` series. Stated by the sink so the label is never a
/// string the fan-out invented about an instance it is shedding for.
pub const GATE: &str = "webhook";

/// The one media type a request-log line is ever framed as, and the header it rides on. A JSONL
/// line is JSON; there is no setting here and no negotiation, so it is a constant of the sink
/// rather than of its composer.
const CONTENT_TYPE: (&str, &str) = ("content-type", "application/json");

/// Something one delivery did that the sink cannot act on itself, handed to whoever composed it.
///
/// Both variants mean THIS LOG WAS DROPPED — a request-log webhook is fire-and-forget and never
/// retries, because a retry queue in front of a telemetry sink is a memory leak with a deadline.
/// The `url` on each is the SAFE-TO-LOG spelling supplied at construction; see the crate docs.
pub enum Event<'a> {
    /// The target answered, and the answer was not a success status.
    Non2xx {
        /// The masked target URL, safe to put in a log line.
        url: &'a str,
        /// The status the target answered with.
        status: u16,
    },
    /// The delivery never got an answer: the connection failed, timed out, or the target URL could
    /// not be framed as a request at all.
    TransportError {
        /// The masked target URL, safe to put in a log line.
        url: &'a str,
        /// A URL-FREE description of what went wrong. The composer supplies these from its own
        /// transport, which does not carry the target in its error type.
        error: &'a str,
    },
}

/// What this process does with what a delivery reports. One method, so a composer that adds a
/// counter to one arm cannot silently leave the sibling arm unrecorded.
pub trait Report: Send + Sync {
    /// Handle one report. Called on the delivery's own task, never on the request path.
    fn report(&self, event: Event<'_>);
}

/// A [`Report`] that drops every event — for a composer that wants the framing and nothing else,
/// and for tests that are not about reporting.
pub struct Silent;

impl Report for Silent {
    fn report(&self, _event: Event<'_>) {}
}

/// One configured webhook target: where a line goes, what may be said about it in a log, the header
/// the operator wants on it, and how long any one delivery may take.
pub struct WebhookSink {
    url: String,
    display_url: String,
    auth: Option<(String, String)>,
    timeout: Duration,
    report: Arc<dyn Report>,
}

impl WebhookSink {
    /// Build a sink over an ALREADY-VALIDATED target.
    ///
    /// `url` is the address deliveries are sent to and `display_url` its masked spelling, the only
    /// one this crate will ever put in an [`Event`]. `auth` is the optional `{name, value}` header
    /// pair the operator configured; a pair that is not a legal header is DROPPED from the request
    /// rather than failing the delivery, which is what the in-engine sink this replaces did.
    /// `timeout` is this instance's own per-delivery deadline — the composer applies it, since the
    /// clock belongs to whoever runs the send.
    pub fn new(
        url: String,
        display_url: String,
        auth: Option<(String, String)>,
        timeout: Duration,
        report: Arc<dyn Report>,
    ) -> Self {
        Self {
            url,
            display_url,
            auth,
            timeout,
            report,
        }
    }

    /// This instance's own per-delivery deadline.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The masked target, for a composer that wants to name the sink in something of its own.
    pub fn display_url(&self) -> &str {
        &self.display_url
    }

    /// State ONE delivery: where this already-serialized request-log line goes, what rides with it,
    /// and the bytes themselves — the whole of what this sink decides about a delivery.
    ///
    /// The method is a POST and is not stated, because there is no other thing this sink does and a
    /// field that can only hold one value is a field a composer can get wrong. A header pair the
    /// host's wire refuses is the host's to drop; this sink states what the operator asked for.
    ///
    /// PRIVATE: the only way into this sink is [`Export::receive`]. A framing a composer could
    /// reach around the face to call is a second entry point, and two entry points are two
    /// behaviours a month later.
    fn delivery(&self, payload: &str) -> Delivery {
        let mut headers = vec![(CONTENT_TYPE.0.to_string(), CONTENT_TYPE.1.to_string())];
        if let Some((name, value)) = &self.auth {
            headers.push((name.clone(), value.clone()));
        }
        Delivery {
            target: self.url.clone(),
            headers,
            body: payload.as_bytes().to_vec(),
        }
    }

    /// What came back of one delivery. `Ok` carries the answered status, `Err` a URL-free cause.
    /// A success status is the only outcome that reports nothing.
    pub fn observe(&self, outcome: Result<u16, String>) {
        match outcome {
            Ok(status) if (200..300).contains(&status) => {}
            Ok(status) => self.report.report(Event::Non2xx {
                url: &self.display_url,
                status,
            }),
            Err(error) => self.report.report(Event::TransportError {
                url: &self.display_url,
                error: &error,
            }),
        }
    }
}

impl Plugin for WebhookSink {
    fn key(&self) -> &'static str {
        MODULE
    }
    fn kind(&self) -> Kind {
        Kind::Export
    }
    fn abi(&self) -> AbiVersion {
        EXPORT_ABI
    }
}

/// THE FACE. What this sink carries, what it does with a record of it, and — because it is a PUSH
/// sink and is delivered to rather than scraped — the two halves of the face that say so by being
/// empty.
impl Export for WebhookSink {
    /// The per-request operational record, in the frozen export vocabulary's own token. Stated by
    /// the sink, so a composer routes nothing to it that it never said it would take.
    fn streams(&self) -> &'static [&'static str] {
        &["logs"]
    }

    /// Frame one record as this instance's POST and put it on the wire the HOST lends for the
    /// length of this call. The framing is this sink's and the socket is the host's, which is the
    /// same division the composer made by hand before the face existed — a connection pool on the
    /// open-web posture is a property of the process, and a crate of kind `export` may not name one.
    ///
    /// The ACK is what actually happened. [`Ack::Received`] means the host's wire took the framed
    /// delivery: this sink never learns whether it landed, so `Durable` is a word it may never say.
    /// [`Ack::Retry`] means the host took it nowhere.
    fn receive(&self, item: ExportItem<'_>, host: &dyn ExportHost) -> Ack {
        let Ok(payload) = std::str::from_utf8(item.bytes) else {
            return Ack::Retry;
        };
        if host.send(self.delivery(payload)) {
            Ack::Received
        } else {
            Ack::Retry
        }
    }

    /// None. A push sink is delivered to; it is not scraped, and it claims no path on this
    /// process's front door.
    fn routes(&self) -> &'static [RouteStatement] {
        &[]
    }

    /// Unreachable: a host only dispatches to a route the sink declared, and this sink declares
    /// none. Answered rather than panicked, because a sink is not the party that decides what a
    /// host does with a request nobody claimed.
    fn serve(&self, _req: &ServeRequest<'_>, _host: &dyn ExportHost) -> Served {
        Served {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
