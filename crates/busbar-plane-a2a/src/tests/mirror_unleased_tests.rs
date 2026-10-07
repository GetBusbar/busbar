// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REQUEST BUSBAR ORIGINATES WHOSE CREDENTIAL IS UNAVAILABLE (the engine's
//! `originate.rs` `originate`, origin/predev `crates/busbar-a2a/src/a2a/originate.rs:80-86`: a lease
//! that could not be minted is logged `A2A_OUTBOUND_CRED_UNLEASED` and the hop is not made, for the
//! push-config mirror and the `ListTasks` refresh alike, `:235-244` and `:352-361`). The host names
//! that refusal by its own cause (`ConnFailure::CredentialUnavailable`), so the door can log it as
//! the engine did and make no further hop.

use super::*;
use busbar_contract::abi::sdk::conn::ConnFailure;

/// A warn capture: every WARN event's fields, rendered, sent down a channel (the door holds no
/// subscriber dependency, so the `tracing` trait is implemented by hand).
struct WarnCapture(std::sync::mpsc::Sender<String>);

struct Render<'a>(&'a mut String);

impl tracing::field::Visit for Render<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = String::new();
        event.record(&mut Render(&mut line));
        let _ = self.0.send(line);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// What `answer` lands as for the agent `planner`, and every WARN line it logged. Landed twice:
/// a warn callsite's interest is cached process-wide, so a concurrent test's dispatcher can hide the
/// first emission from this scoped subscriber.
fn landing(
    answer: impl Fn() -> Result<busbar_contract::abi::sdk::exchange::ExchangeResponse, ConnFailure>,
) -> (Result<Option<(u16, Vec<u8>)>, Unleased>, Vec<String>) {
    let (sent, heard) = std::sync::mpsc::channel();
    let landed = tracing::subscriber::with_default(WarnCapture(sent), || {
        let first = landed(Binding::JsonRpc, "planner", LIST_TASKS, answer());
        let _ = landed(Binding::JsonRpc, "planner", LIST_TASKS, answer());
        first
    });
    (landed, heard.try_iter().collect())
}

/// A request the host refused for an unavailable credential lands [`Unleased`] and is logged with
/// the engine's diagnostic, naming the agent. RED arm: the host's plain refusal lands as a request
/// that was not answered (`None`) and logs nothing.
#[test]
fn an_unavailable_credential_lands_unleased_and_is_logged_as_the_engine_logged_it() {
    let banner = crate::diagnostics::A2A_OUTBOUND_CRED_UNLEASED
        .banner()
        .to_string();

    let (landed, seen) = landing(|| Err(ConnFailure::CredentialUnavailable));
    assert_eq!(landed, Err(Unleased));
    assert!(
        seen.iter().any(|l| l.contains(&banner)
            && l.contains("planner")
            && l.contains("the outbound credential could not be leased")),
        "the unleased request carries diag={banner} and the agent; captured: {seen:?}"
    );

    let (landed, seen) = landing(|| Err(ConnFailure::Refused("the connection was refused".into())));
    assert_eq!(
        landed,
        Ok(None),
        "a plain refusal is a request not answered"
    );
    assert!(
        !seen.iter().any(|l| l.contains(&banner)),
        "a plain refusal is not an unleased credential; captured: {seen:?}"
    );
}

/// An answered request lands its status and body, as [`answered`] reads them.
#[test]
fn an_answered_request_lands_its_status_and_body() {
    let (landed, _) = landing(|| {
        Ok(busbar_contract::abi::sdk::exchange::ExchangeResponse {
            status: 200,
            reason: None,
            fields: Vec::new(),
            body: b"{}".to_vec(),
        })
    });
    assert_eq!(landed, Ok(Some((200, b"{}".to_vec()))));
}

fn read_flight() -> Flight {
    Flight {
        stage: Stage::Mirror,
        method: method::GET_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: Value::Null,
        hop: Originated {
            agent: "planner".into(),
            url: "https://agent.example".into(),
            allow_private: false,
            binding: Binding::JsonRpc,
            version: "1.0",
            seq: 0,
            exchange: None,
        },
    }
}

/// An UNLEASED read ends the mirror: no re-arm is issued, as the engine's `mirror_push_config`
/// returned before its first request when `originate` gave `None` (origin/predev
/// `originate.rs:235-244`). RED arm: the same read not answered re-arms.
#[test]
fn an_unleased_read_ends_the_mirror_without_a_rearm() {
    let mut unleased = read_flight();
    unleased.land(Err(Unleased));
    assert_eq!(unleased.stage, Stage::Done);

    let mut unanswered = read_flight();
    unanswered.land(Ok(None));
    assert_eq!(
        unanswered.stage,
        Stage::Rearm,
        "a read the agent did not answer still reconciles"
    );
    let mut rearming = read_flight();
    rearming.land(Ok(None));
    rearming.land(Err(Unleased));
    assert_eq!(
        rearming.stage,
        Stage::Done,
        "an unleased re-arm ends it too"
    );
}
