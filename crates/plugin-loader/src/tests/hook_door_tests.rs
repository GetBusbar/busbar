// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{CLASS_GATE, PROMPT_NO, USER_NO};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::hook_calls::{Answered, HookAxis, HookFacts};
use busbar_contract::hooks::{RoutingContext, RoutingRequest};
use busbar_contract::SignalBag;
use serde_json::json;

use super::HookRows;
use crate::boot::{Candidate, Origin};
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};

use crate::hook_door_conformance_tests::hook_door_plugin;

use hook_door_plugin::{
    BROKEN_NAME, MAX_INFLIGHT, NAME, PANICKING_NAME, REJECT_STATUS, UNTAILED_NAME,
};

#[path = "../../tests/fixtures/hook_checkpoint_plugin.rs"]
mod checkpoint_plugin;

#[path = "hook_checkpoint_cancellation_tests.rs"]
mod checkpoint_cancellation;

#[path = "hook_recovery_backoff_tests.rs"]
mod recovery_backoff;

fn checkpoint_instance(
    way: Way,
    mode: &str,
) -> (super::HookInstance, Arc<std::sync::atomic::AtomicUsize>) {
    use crate::dispatch::{ConnTable, NoSink};
    let axis = rows(checkpoint_plugin::door, "hook_checkpoint_door", way);
    let candidate = axis.find(checkpoint_plugin::NAME).unwrap().clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let binds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bind = {
        let dispatcher = Arc::clone(&dispatcher);
        let binds = Arc::clone(&binds);
        move || {
            binds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            HookRows::bind(
                &candidate,
                &dispatcher,
                "hooks.checkpoint",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let settings = json!({"reject_over_messages": 3, "checkpoint_mode": mode}).to_string();
    (
        super::HookInstance::open(bind().unwrap(), dispatcher, settings.as_bytes(), bind).unwrap(),
        binds,
    )
}

fn regenerate(instance: &super::HookInstance) {
    let retired = {
        let mut state = instance.inner.lock();
        std::mem::replace(
            &mut *state,
            super::State::Quarantined {
                trial_at: std::time::Instant::now(),
                window: super::QUARANTINE_FIRST,
            },
        )
    };
    if let super::State::Live(plugin) = retired {
        super::close(&plugin);
    }
}

#[tokio::test]
async fn complete_configure_checkpoints_survive_partial_pushes_through_both_doors() {
    use busbar_contract::hook_calls::HookCalls;
    for way in [Way::Linked, Way::Dropped] {
        let (instance, binds) = checkpoint_instance(way, "valid");
        regenerate(&instance);
        let initial = instance.decide(frame(2), BUDGET).await;
        assert!(matches!(initial, Answered::Answer { out, .. } if out.reject_status == 0));
        instance
            .configure("checkpoint", r#"{"reject_over_messages":1}"#, 2, BUDGET)
            .await
            .unwrap();
        for (settings, version) in [
            ("{}", 3),
            (r#"{"reject_over_messages":null}"#, 3),
            (r#"{"reject_over_messages":8}"#, 1),
        ] {
            instance
                .configure("checkpoint", settings, version, BUDGET)
                .await
                .unwrap();
            let live = instance.decide(frame(2), BUDGET).await;
            assert!(
                matches!(live, Answered::Answer { out, .. } if out.reject_status == REJECT_STATUS),
                "{way:?}: live partial push changed effective state"
            );
        }
        assert!(instance
            .configure(
                "checkpoint",
                r#"{"reject_over_messages":"invalid"}"#,
                4,
                BUDGET
            )
            .await
            .is_err());
        for _ in 0..3 {
            regenerate(&instance);
            let reopened = instance.decide(frame(2), BUDGET).await;
            assert!(
                matches!(reopened, Answered::Answer { out, .. } if out.reject_status == REJECT_STATUS),
                "{way:?}: regenerated instance lost acknowledged state: {}",
                decided(2, &reopened)
            );
        }
        assert_eq!(binds.load(std::sync::atomic::Ordering::SeqCst), 5);
    }
}

#[tokio::test]
async fn missing_or_malformed_checkpoints_never_reopen_silently_stale_through_both_doors() {
    use busbar_contract::hook_calls::HookCalls;
    for way in [Way::Linked, Way::Dropped] {
        for mode in ["none", "malformed"] {
            let (instance, _) = checkpoint_instance(way, mode);
            let ack = instance
                .configure("checkpoint", r#"{"reject_over_messages":1}"#, 2, BUDGET)
                .await;
            assert_eq!(ack.is_ok(), mode == "none");
            let live = instance.decide(frame(2), BUDGET).await;
            assert!(
                matches!(live, Answered::Answer { out, .. } if out.reject_status == REJECT_STATUS)
            );
            regenerate(&instance);
            let reopened = instance.decide(frame(2), BUDGET).await;
            assert!(
                matches!(reopened, Answered::Broken(_)),
                "{way:?}/{mode}: recovery guessed opaque settings"
            );
            assert!(instance.quarantined());
        }
    }
}

#[tokio::test]
async fn notified_hook_replies_release_their_leases_through_both_doors() {
    use busbar_contract::hook_calls::HookCalls;
    for way in [Way::Linked, Way::Dropped] {
        let (instance, _) = checkpoint_instance(way, "valid");
        for _ in 0..3 {
            instance
                .notify(
                    busbar_contract::abi::host::hook::NotifyFrame::build(&request(1), None, false),
                    BUDGET,
                )
                .await;
            let status = instance.status(BUDGET).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&status).unwrap()["held"],
                0,
                "{way:?}: notify retained its reply lease"
            );
        }
    }
}

fn complete_checkpoint(
    revision: u64,
    version: u64,
    limit: u64,
) -> busbar_contract::abi::sdk::hook::ConfigureCheckpoint {
    busbar_contract::abi::sdk::hook::ConfigureCheckpoint::new(
        revision,
        version,
        json!({"reject_over_messages":limit})
            .to_string()
            .into_bytes(),
    )
    .unwrap()
}

#[tokio::test]
async fn delayed_equal_version_and_retired_instance_acks_cannot_roll_back_recovery() {
    use busbar_contract::hook_calls::HookCalls;
    let (instance, _) = checkpoint_instance(Way::Linked, "valid");
    let original = match &*instance.inner.lock() {
        super::State::Live(p) => Arc::clone(p),
        _ => panic!("opened"),
    };
    instance
        .inner
        .acknowledged(
            &original,
            "checkpoint",
            3,
            Ok(Some(complete_checkpoint(2, 3, 1))),
        )
        .unwrap();
    instance
        .inner
        .acknowledged(
            &original,
            "checkpoint",
            3,
            Ok(Some(complete_checkpoint(1, 3, 8))),
        )
        .unwrap();
    regenerate(&instance);
    let answer = instance.decide(frame(2), BUDGET).await;
    assert!(matches!(answer, Answered::Answer {out, ..} if out.reject_status == REJECT_STATUS));
    assert!(instance
        .inner
        .acknowledged(
            &original,
            "checkpoint",
            99,
            Ok(Some(complete_checkpoint(99, 99, 8)))
        )
        .is_err());
    regenerate(&instance);
    let answer = instance.decide(frame(2), BUDGET).await;
    assert!(matches!(answer, Answered::Answer {out, ..} if out.reject_status == REJECT_STATUS));
}

#[tokio::test]
async fn an_ack_racing_the_replay_is_restored_before_the_trial_is_published() {
    use busbar_contract::hook_calls::HookCalls;
    let (instance, _) = checkpoint_instance(Way::Linked, "block_replay");
    instance
        .configure("checkpoint", r#"{"reject_over_messages":2}"#, 2, BUDGET)
        .await
        .unwrap();
    let original = match &*instance.inner.lock() {
        super::State::Live(p) => Arc::clone(p),
        _ => panic!("opened"),
    };
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    *checkpoint_plugin::BLOCK_CONFIGURE.lock().unwrap() = Some((entered, released));
    regenerate(&instance);
    let deciding = instance.decide(frame(2), BUDGET);
    let trial = tokio::spawn(async move {
        matches!(deciding.await, Answered::Answer {out, ..} if out.reject_status == REJECT_STATUS)
    });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(BUDGET).unwrap())
        .await
        .unwrap();

    instance
        .inner
        .acknowledged(
            &original,
            "checkpoint",
            3,
            Ok(Some(complete_checkpoint(2, 3, 1))),
        )
        .unwrap();
    release.send(()).unwrap();
    assert!(trial.await.unwrap());
    assert!(!instance.quarantined());
}

#[tokio::test]
async fn a_missing_checkpoint_cannot_be_repaired_by_an_older_delayed_reply() {
    use busbar_contract::hook_calls::HookCalls;
    let (instance, _) = checkpoint_instance(Way::Linked, "valid");
    let original = match &*instance.inner.lock() {
        super::State::Live(p) => Arc::clone(p),
        _ => panic!("opened"),
    };
    instance
        .inner
        .acknowledged(&original, "checkpoint", 3, Ok(None))
        .unwrap();
    instance
        .inner
        .acknowledged(
            &original,
            "checkpoint",
            2,
            Ok(Some(complete_checkpoint(1, 2, 1))),
        )
        .unwrap();
    regenerate(&instance);
    assert!(matches!(
        instance.decide(frame(2), BUDGET).await,
        Answered::Broken(_)
    ));
}

mod sdk_refresh {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::task::Poll;

    use busbar_contract::abi::hook::{self, DecideIn, DecideOut, NotifyIn, TransformOut};
    use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_NAMED};
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, OutHead, Outcome};
    use busbar_contract::abi::mechanism::door::Statement;
    use busbar_contract::abi::mechanism::lifecycle::{self as lc, CancelIn, CancelOut, RefreshIn};
    use busbar_contract::abi::mechanism::rendering::ReadNeed;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::cred::Cred;
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::sdk::exchange::{Op, Request};
    use busbar_contract::abi::sdk::hook::{
        Decoded, DecodedTap, Hook, HookOpen, RewriteVerdict, Verdict,
    };
    use busbar_contract::conn::{
        ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
        PieceKind,
    };
    use busbar_contract::ids::StreamId;
    use busbar_contract::transport::ConnFacts;
    use zeroize::Zeroizing;

    use crate::dispatch::kinds::hook::Hook as HookKind;
    use crate::dispatch::{
        load_linked, Called, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, Plugin,
    };
    use crate::door_both_ways::{bind, close, input, octets, open, output};

    const OLD: &str = "old-hook-credential-CANARY";
    const NEW: &str = "new-hook-credential-CANARY";

    #[derive(Default)]
    struct Probe {
        old_dropped: AtomicUsize,
        calls: Mutex<Vec<String>>,
    }

    fn probes() -> &'static Mutex<HashMap<u64, Arc<Probe>>> {
        static PROBES: OnceLock<Mutex<HashMap<u64, Arc<Probe>>>> = OnceLock::new();
        PROBES.get_or_init(Mutex::default)
    }

    struct Forwarder {
        probe: Arc<Probe>,
        secret: String,
        cred: Cred,
    }

    impl Drop for Forwarder {
        fn drop(&mut self) {
            if self.secret == OLD {
                self.probe.old_dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    impl Forwarder {
        fn exchange(&self, op: &Op<'_>) -> Poll<String> {
            self.probe.calls.lock().unwrap().push(self.secret.clone());
            op.exchange_sealed(0, Some("http://hook.example"), || {
                Ok((
                    {
                        let mut request = Request::default();
                        request.method = b"POST".to_vec();
                        request.target = b"/hook".to_vec();
                        request
                    },
                    vec![(0, b"authorization".to_vec(), self.cred.field())],
                ))
            })
            .map(|reply| {
                let reply = reply.expect("the scripted reply completes");
                let reason =
                    String::from_utf8(reply.reason.expect("the peer's canary reason")).unwrap();
                reason.replace(&self.secret, "<redacted>")
            })
        }
    }

    impl Hook for Forwarder {
        fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            self.exchange(op).map(Verdict::Failed)
        }
        fn transform(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
            self.exchange(op).map(RewriteVerdict::Failed)
        }
        fn notify(&self, _: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
            self.exchange(op)
                .map(|reason| assert_eq!(reason, "<redacted>"))
        }
    }

    struct Open;
    impl HookOpen for Open {
        fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
            let settings: serde_json::Value = serde_json::from_str(settings).unwrap();
            let secret = settings["secret"].as_str().unwrap().to_string();
            Ok(Box::new(Forwarder {
                probe: Arc::clone(&probes().lock().unwrap()[&settings["scope"].as_u64().unwrap()]),
                cred: Cred::captured(Zeroizing::new(secret.as_bytes().to_vec())),
                secret,
            }))
        }
    }

    const NEEDS: [Need; 1] = [Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: abi_str("http"),
        auth: AbiStr::ZERO,
        target_from: AbiStr::ZERO,
        trust_from: AbiStr::ZERO,
        details: Blob::ABSENT,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }];

    const TAIL: hook::Tail =
        busbar_contract::abi::sdk::hook::tail(hook::CLASS_GATE, hook::PROMPT_NO, hook::USER_NO);

    busbar_contract::hook_door! {
        open: Open,
        statement: Statement {
            needs: NEEDS.as_ptr(), needs_len: NEEDS.len(),
            ..busbar_contract::abi::sdk::hook::statement_with_tail(statement("refreshing-hook-sdk", "1", 64), &TAIL)
        },
    }

    #[derive(Default)]
    struct Peer {
        slab: ConnSlab<Mutex<(String, bool)>>,
        released: AtomicBool,
        credentials: Mutex<Vec<String>>,
        closed: AtomicUsize,
    }
    impl DeclaredConns for Peer {
        fn declare(
            &self,
            owner: InstanceId,
            need: NeedId,
            _: &ReadNeed,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(), ConnError> {
            self.slab.declare(owner, need);
            Ok(())
        }
        fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
            self.slab.check_need(owner, need).ok().map(Ok)
        }
        fn framed(&self, _: InstanceId, _: NeedId) -> bool {
            true
        }
        fn serves_scheme(&self, scheme: &str) -> bool {
            scheme == "http"
        }
    }
    impl Conns for Peer {
        fn open(
            &self,
            owner: InstanceId,
            need: NeedId,
            desc: &OpenDesc<'_>,
        ) -> Result<ConnId, ConnError> {
            let credential = String::from_utf8(
                desc.fields
                    .iter()
                    .find(|(name, _)| *name == "authorization")
                    .unwrap()
                    .1
                    .to_vec(),
            )
            .unwrap();
            self.credentials.lock().unwrap().push(credential.clone());
            self.slab
                .insert(owner, need, Mutex::new((credential, false)))
        }
        fn write(
            &self,
            _: InstanceId,
            _: ConnId,
            bytes: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            Ok(bytes.len())
        }
        fn read(
            &self,
            owner: InstanceId,
            conn: ConnId,
            _: u64,
            buf: &mut [u8],
        ) -> Result<Piece, ConnError> {
            if !self.released.load(Ordering::SeqCst) {
                return Err(ConnError::Pending);
            }
            let (_, state) = self.slab.get(owner, conn)?;
            let mut state = state.lock().unwrap();
            let first = !state.1;
            state.1 = true;
            if first {
                buf[..state.0.len()].copy_from_slice(state.0.as_bytes());
            }
            Ok(Piece {
                kind: if first {
                    PieceKind::Fields
                } else {
                    PieceKind::Completion
                },
                stream: StreamId(0),
                len: 0,
                end: true,
                status: None,
                status_code: first.then_some(503),
                status_namespace: None,
                retry_after_secs: None,
                fault: None,
                reason: first.then_some(0..state.0.len()),
                declared_len: None,
            })
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
            Err(ConnError::Pending)
        }
        fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
            Ok(ConnFacts::default())
        }
        fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
            self.slab.remove(owner, conn)?;
            self.closed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct Loaded {
        scope: u64,
        plugin: Plugin<HookKind>,
        dispatcher: Dispatcher,
        peer: Arc<Peer>,
        probe: Arc<Probe>,
    }
    impl Loaded {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let scope = NEXT.fetch_add(1, Ordering::SeqCst);
            let probe = Arc::new(Probe::default());
            probes().lock().unwrap().insert(scope, Arc::clone(&probe));
            let dispatcher = Dispatcher::new(DispatchConfig::default());
            let peer = Arc::new(Peer::default());
            let mut binding = bind(&dispatcher);
            binding.conns = ConnTable::Host(peer.clone());
            let plugin = load_linked::<HookKind>(&LinkedRow::of(door).unwrap(), binding).unwrap();
            let loaded = Self {
                scope,
                plugin,
                dispatcher,
                peer,
                probe,
            };
            assert_eq!(
                open(&loaded.plugin, &loaded.settings(OLD)).outcome,
                Outcome::Ready
            );
            loaded
        }
        fn settings(&self, secret: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({"scope": self.scope, "secret": secret})).unwrap()
        }
        fn refresh(&self) {
            let settings = self.settings(NEW);
            let mut f: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
            f.input.settings = octets(&settings);
            f.input.generation = 2;
            assert_eq!(
                self.plugin.call(lc::slot::REFRESH, &mut f).outcome,
                Outcome::Ready
            );
        }
        fn cancel(&self, ticket: Ticket) {
            let mut f: Frame<CancelIn, CancelOut> = Frame::new(input(), output());
            f.input.ticket = ticket;
            assert_eq!(
                self.plugin.call(lc::slot::CANCEL, &mut f).outcome,
                Outcome::Ready
            );
            assert_eq!(f.out.disposition, hook::cancel::ABORTED);
        }
        fn call(&self, slot: u32, ticket: Ticket, resume: bool, malformed: bool) -> Called {
            if slot == hook::slot::NOTIFY {
                let mut f: Frame<NotifyIn, OutHead> = Frame::new(input(), output());
                if malformed {
                    f.input.present = u32::MAX;
                }
                self.plugin.call_inline(ticket, resume, slot, &mut f)
            } else {
                let mut i: DecideIn = input();
                if malformed {
                    i.present = hook::VIEW_HAS_PROMPT;
                    i.prompt.message_count = 1;
                }
                if slot == hook::slot::DECIDE {
                    self.plugin.call_inline(
                        ticket,
                        resume,
                        slot,
                        &mut Frame::<_, DecideOut>::new(i, output()),
                    )
                } else {
                    self.plugin.call_inline(
                        ticket,
                        resume,
                        slot,
                        &mut Frame::<_, TransformOut>::new(i, output()),
                    )
                }
            }
        }
    }
    impl Drop for Loaded {
        fn drop(&mut self) {
            close(&self.plugin);
            probes().lock().unwrap().remove(&self.scope);
        }
    }

    #[test]
    fn loaded_hook_sdk_pending_operations_keep_their_credential_across_refresh() {
        for slot in [
            hook::slot::DECIDE,
            hook::slot::TRANSFORM,
            hook::slot::NOTIFY,
        ] {
            let h = Loaded::new();
            let old = h.dispatcher.inline_ticket().unwrap();
            assert_eq!(
                h.call(slot, old.ticket(), false, false).outcome,
                Outcome::Pending
            );
            h.refresh();
            assert_eq!(
                h.probe.old_dropped.load(Ordering::SeqCst),
                0,
                "refresh must retain the pending Hook"
            );
            let fresh = h.dispatcher.inline_ticket().unwrap();
            assert_eq!(
                h.call(slot, fresh.ticket(), false, false).outcome,
                Outcome::Pending
            );
            assert_eq!(*h.peer.credentials.lock().unwrap(), [OLD, NEW]);
            h.cancel(fresh.ticket());
            h.peer.released.store(true, Ordering::SeqCst);
            let answer = h.call(slot, old.ticket(), true, false);
            assert_eq!(
                answer.outcome,
                if slot == hook::slot::NOTIFY {
                    Outcome::Ready
                } else {
                    Outcome::Failed
                }
            );
            if slot != hook::slot::NOTIFY {
                assert_eq!(answer.error.as_deref(), Some(b"<redacted>".as_slice()));
            }
            assert_eq!(*h.probe.calls.lock().unwrap(), [OLD, NEW, OLD]);
            assert_eq!(
                h.probe.old_dropped.load(Ordering::SeqCst),
                1,
                "terminal answer releases the original Hook"
            );
            assert_eq!(h.peer.closed.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn loaded_hook_sdk_cancel_fault_and_fresh_entry_release_the_pending_hook() {
        for slot in [
            hook::slot::DECIDE,
            hook::slot::TRANSFORM,
            hook::slot::NOTIFY,
        ] {
            for cleanup in ["cancel", "fault", "fresh"] {
                let h = Loaded::new();
                let ticket = h.dispatcher.inline_ticket().unwrap();
                assert_eq!(
                    h.call(slot, ticket.ticket(), false, false).outcome,
                    Outcome::Pending
                );
                h.refresh();
                assert_eq!(h.probe.old_dropped.load(Ordering::SeqCst), 0);
                match cleanup {
                    "cancel" => h.cancel(ticket.ticket()),
                    "fault" => assert_eq!(
                        h.call(slot, ticket.ticket(), true, true).outcome,
                        Outcome::Fault
                    ),
                    _ => {
                        assert_eq!(
                            h.call(slot, ticket.ticket(), false, false).outcome,
                            Outcome::Pending
                        );
                        assert_eq!(*h.peer.credentials.lock().unwrap(), [OLD, NEW]);
                        h.cancel(ticket.ticket());
                    }
                }
                assert_eq!(
                    h.probe.old_dropped.load(Ordering::SeqCst),
                    1,
                    "{cleanup} must release the original Hook"
                );
                assert_eq!(
                    h.peer.closed.load(Ordering::SeqCst),
                    if cleanup == "fresh" { 2 } else { 1 }
                );
            }
        }
    }
}

const BUDGET: Duration = Duration::from_secs(5);

fn serve_request() -> busbar_contract::abi::mechanism::endpoint::EndpointRequest {
    busbar_contract::abi::mechanism::endpoint::EndpointRequest {
        method: "POST".into(),
        path: hook_door_plugin::ROUTE_PATH.into(),
        query: "kind=feedback".into(),
        headers: vec![("content-type".into(), "text/plain".into())],
        body: b"received".to_vec(),
    }
}

#[tokio::test]
async fn hook_routes_serve_leased_responses_through_both_doors_and_refused_stubs_fail() {
    for way in [Way::Linked, Way::Dropped] {
        let axis = rows(hook_door_plugin::conforming::door, "hook_door", way);
        let calls = axis
            .open(
                NAME,
                "receiver",
                &json!({"reject_over_messages": 3}),
                BUDGET,
            )
            .unwrap();
        assert_eq!(calls.routes().len(), 1);
        assert_eq!(calls.routes()[0].path, hook_door_plugin::ROUTE_PATH);
        let response = calls.serve(serve_request(), BUDGET).await.unwrap();
        assert_eq!(response.status, 202);
        assert_eq!(
            response.headers,
            vec![("x-fixture".into(), "present".into())]
        );
        assert_eq!(
            response.body,
            b"POST /hooks/receiver/feedback?kind=feedback\nreceived"
        );

        assert_eq!(
            calls.serve(serve_request(), BUDGET).await.unwrap().body,
            response.body
        );
        let stub = rows(hook_door_plugin::broken::door, "hook_broken_door", way);
        let calls = stub
            .open(
                BROKEN_NAME,
                "receiver",
                &json!({"reject_over_messages": 3}),
                BUDGET,
            )
            .unwrap();
        assert_eq!(calls.routes().len(), 1);
        assert!(calls.serve(serve_request(), BUDGET).await.is_err());
    }
}

#[tokio::test]
async fn malformed_hook_serve_headers_are_refused_and_the_answer_lease_is_released() {
    for way in [Way::Linked, Way::Dropped] {
        for mode in ["odd", "null", "overlong", "utf8"] {
            let axis = rows(hook_door_plugin::conforming::door, "hook_door", way);
            let calls = axis
                .open(
                    NAME,
                    "receiver",
                    &json!({
                        "reject_over_messages": 3, "serve_headers": mode,
                    }),
                    BUDGET,
                )
                .unwrap();
            let error = calls
                .serve(serve_request(), BUDGET)
                .await
                .expect_err("the actual hook answer must fail header validation");
            assert!(error.contains("response header"), "{way:?}/{mode}: {error}");
            let mut count = serve_request();
            count.query = "lease-count".into();
            assert_eq!(
                calls.serve(count, BUDGET).await.unwrap().body,
                b"0",
                "{way:?}/{mode}: rejected answers must not retain their leased body"
            );
        }
    }
}

#[tokio::test]
async fn a_slow_hook_serve_is_bounded_by_its_budget_through_both_doors() {
    for way in [Way::Linked, Way::Dropped] {
        let axis = rows(hook_door_plugin::conforming::door, "hook_door", way);
        let calls = axis
            .open(
                NAME,
                "receiver",
                &json!({"reject_over_messages": 3, "sleep_ms": 100}),
                BUDGET,
            )
            .unwrap();
        assert!(calls
            .serve(serve_request(), Duration::from_millis(10))
            .await
            .is_err());

        assert_eq!(
            calls.serve(serve_request(), BUDGET).await.unwrap().status,
            202
        );
    }
}

fn request(messages: usize) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 7,
        pool: "p",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: messages,
        tool_count: 0,
        has_tools: false,
        total_chars: 11,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: SignalBag::new(),
        session: None,
    }
}

fn frame(messages: usize) -> Arc<DecideFrame> {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    DecideFrame::first(DecideView::build(&request(messages), &[], &ctx))
}

/// How a row reaches the axis.
#[derive(Debug, Clone, Copy)]
enum Way {
    Linked,
    Dropped,
}

fn rows(door: DoorFn, example: &str, way: Way) -> HookRows {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    match way {
        Way::Linked => HookRows::new(&[door], None, dispatcher).expect("the linked row"),
        Way::Dropped => {
            let path = crate::both_ways::example_cdylib(example);
            let bytes = std::fs::read(&path).expect("the example cdylib reads");
            let row = Candidate::from_rendering(
                rendering_of(door).expect("the door renders its Statement"),
                None,
                Origin::Dropped {
                    file: format!("{example}.tar.gz"),
                    bytes: Arc::new(bytes),
                },
            )
            .expect("the rendering states a candidate");
            HookRows::of(vec![row], dispatcher)
        }
    }
}

fn decided(messages: usize, a: &Answered<busbar_contract::abi::hook::DecideOut>) -> String {
    match a {
        Answered::Answer {
            outcome,
            out,
            error,
            ..
        } => format!(
            "decide {messages}: {outcome:?} verbs={:#x} reject_status={} error={error:?}",
            out.verbs, out.reject_status
        ),
        Answered::TimedOut => format!("decide {messages}: timed out"),
        Answered::Broken(why) => format!("decide {messages}: broken ({why})"),
    }
}

async fn script(rows: &HookRows, module: &str) -> Vec<String> {
    let probed = |settings: serde_json::Value| rows.probe(module, "gate", &settings);
    let mut lines = vec![
        format!(
            "probe bad: {:?}",
            probed(json!({"reject_over_messages": "three"}))
        ),
        format!(
            "probe good: {:?}",
            probed(json!({"reject_over_messages": 3}))
        ),
        format!(
            "probe nobody: {:?}",
            rows.probe("nobody", "gate", &json!({}))
        ),
    ];
    let calls = rows
        .open(
            module,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .expect("the hook opens through the axis");
    lines.push(format!("name: {}", calls.name()));
    for messages in [2, 5] {
        lines.push(decided(
            messages,
            &calls.decide(frame(messages), BUDGET).await,
        ));
    }
    lines.push(format!("status: {:?}", calls.status(BUDGET).await));
    lines.push(format!(
        "configure: {:?}",
        calls.configure("gate", "{}", 2, BUDGET).await
    ));
    lines
}

#[tokio::test]
async fn a_linked_and_a_dropped_in_hook_open_through_the_axis_and_decide_identically() {
    let door = hook_door_plugin::conforming::door;
    let linked_rows = rows(door, "hook_door", Way::Linked);
    let linked = script(&linked_rows, NAME).await;
    let dropped_rows = rows(door, "hook_door", Way::Dropped);
    let dropped = script(&dropped_rows, NAME).await;
    assert_eq!(linked, dropped, "the same table, whichever door");

    let facts = HookFacts {
        name: NAME.to_string(),
        class: CLASS_GATE,
        prompt: PROMPT_NO,
        user: USER_NO,
        infallible: false,
        words: Vec::new(),
    };
    assert!(
        linked[0].contains(&format!("{facts:?}")) && linked[0].contains("must be a number"),
        "{}",
        linked[0]
    );
    assert!(linked[1].ends_with("[]))"), "{}", linked[1]);
    assert_eq!(linked[2], "probe nobody: None");
    assert_eq!(linked[3], format!("name: {NAME}"));
    assert!(
        linked[4].contains("Ready") && linked[4].contains("verbs=0x2 "),
        "{}",
        linked[4]
    );
    assert!(
        linked[5].contains("Ready")
            && linked[5].contains("verbs=0x14 ")
            && linked[5].contains(&format!("reject_status={REJECT_STATUS}")),
        "{}",
        linked[5]
    );
    assert_eq!(linked[6], "status: None", "the fixture refuses `status`");
    assert!(linked[7].starts_with("configure: Err("), "{}", linked[7]);
}

#[tokio::test]
async fn a_hook_that_breaks_the_kind_contract_is_broken_through_both_doors() {
    let run = |rows: HookRows| async move {
        let calls = rows
            .open(
                BROKEN_NAME,
                "hooks.gate",
                &json!({"reject_over_messages": 3}),
                BUDGET,
            )
            .expect("the broken hook still opens");
        decided(2, &calls.decide(frame(2), BUDGET).await)
    };
    let broken = hook_door_plugin::broken::door;
    let linked = run(rows(broken, "hook_broken_door", Way::Linked)).await;
    assert!(
        linked.contains("broken (") && linked.contains("FAULT"),
        "{linked}"
    );

    let refused = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked)
        .open(BROKEN_NAME, "hooks.gate", &json!({}), BUDGET)
        .err();
    assert!(
        refused.is_some_and(|e| e.contains(BROKEN_NAME)),
        "an unknown module is refused, named"
    );
    let dropped_rows = rows(broken, "hook_broken_door", Way::Dropped);
    assert_eq!(
        linked,
        run(dropped_rows).await,
        "the same refusal, whichever door"
    );
}

#[tokio::test]
async fn a_panicking_hook_is_broken_through_the_axis_never_a_verdict() {
    let axis = rows(hook_door_plugin::panicking::door, "hook_door", Way::Linked);
    let calls = axis
        .open(
            PANICKING_NAME,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .expect("the panicking hook opens: only its decide panics");
    let started = std::time::Instant::now();
    let answered = decided(2, &calls.decide(frame(2), BUDGET).await);
    assert!(
        answered.contains("broken (") && answered.contains("FAULT"),
        "{answered}"
    );
    assert!(
        started.elapsed() < BUDGET,
        "a caught panic answers at once, not on the call's budget"
    );
}

#[test]
fn a_linked_row_is_linked_and_first_party_and_a_dropped_in_unsigned_row_is_neither() {
    let door = hook_door_plugin::conforming::door;
    let linked = rows(door, "hook_door", Way::Linked);
    assert!(linked.linked(NAME) && linked.first_party(NAME));
    assert!(!linked.linked("nobody") && !linked.first_party("nobody"));
    let dropped = rows(door, "hook_door", Way::Dropped);
    assert!(!dropped.linked(NAME) && !dropped.first_party(NAME));
}

#[test]
fn a_hook_statement_without_its_kind_tail_is_refused_at_load() {
    let untailed = rows(hook_door_plugin::untailed::door, "hook_door", Way::Linked);
    assert_eq!(
        untailed.probe(UNTAILED_NAME, "gate", &json!({"reject_over_messages": 3})),
        Some((None, Vec::new())),
        "an untailed hook states no facts"
    );
    let refused = untailed
        .open(
            UNTAILED_NAME,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .err()
        .expect("an untailed hook is refused at load");
    assert!(
        refused.contains(crate::dispatch::kinds::hook::NO_TAIL) && refused.contains(UNTAILED_NAME),
        "{refused}"
    );
    let tailed = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked).open(
        NAME,
        "hooks.gate",
        &json!({"reject_over_messages": 3}),
        BUDGET,
    );
    assert!(tailed.is_ok(), "the tailed door opens");
}

#[test]
fn a_dropped_in_1_5_5_json_hook_plugin_is_refused_naming_the_rebuild() {
    let abi = *crate::supported_abi("hook")
        .iter()
        .min()
        .expect("a hook payload schema");
    let registry = crate::both_ways::dropped(
        "json-hook",
        crate::both_ways::statement("hook", "json-hook", "json-hook", abi),
        b"a 1.5.5 JSON hook library",
    );
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let refused = HookRows::new(&[], Some(&registry), dispatcher)
        .expect_err("a 1.5.5 JSON hook plugin is refused");
    assert!(
        refused.contains(super::JSON_HOOK_REFUSED) && refused.contains("json-hook"),
        "{refused}"
    );
}

#[tokio::test]
async fn a_hook_reads_the_request_session_through_both_doors() {
    let run = |rows: HookRows| async move {
        let calls = rows
            .open(
                NAME,
                "hooks.gate",
                &json!({"reject_over_messages": 3, "reject_session": "ctx-7"}),
                BUDGET,
            )
            .expect("the hook opens");
        let ctx = RoutingContext {
            pool: "p",
            budget_remaining: None,
            budget: &[],
        };
        let mut lines = Vec::new();
        for session in [Some(&b"ctx-7"[..]), Some(&b"ctx-8"[..]), None] {
            let mut req = request(2);
            req.session = session;
            let frame = DecideFrame::first(DecideView::build(&req, &[], &ctx));
            lines.push(decided(2, &calls.decide(frame, BUDGET).await));
        }
        lines
    };
    let door = hook_door_plugin::conforming::door;
    let linked = run(rows(door, "hook_door", Way::Linked)).await;
    assert!(
        linked[0].contains("verbs=0x14 ")
            && linked[0].contains(&format!("reject_status={REJECT_STATUS}")),
        "the named session is refused: {}",
        linked[0]
    );
    assert!(linked[1].contains("verbs=0x2 "), "{}", linked[1]);
    assert!(linked[2].contains("verbs=0x2 "), "{}", linked[2]);
    let dropped_rows = rows(door, "hook_door", Way::Dropped);
    assert_eq!(
        linked,
        run(dropped_rows).await,
        "the same answers, whichever door"
    );
}

#[tokio::test]
async fn a_slow_hook_is_cut_off_at_its_budget_through_the_axis() {
    let axis = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let calls = axis
        .open(
            NAME,
            "hooks.slow",
            &json!({"reject_over_messages": 3, "sleep_ms": 2_000}),
            BUDGET,
        )
        .expect("the slow gate opens");
    let started = std::time::Instant::now();
    let answered = calls.decide(frame(2), Duration::from_millis(100)).await;
    assert!(
        matches!(answered, Answered::TimedOut),
        "a slow gate must exceed the deadline: {}",
        decided(2, &answered)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the deadline must cut off promptly, not wait out the sleep"
    );
}

#[tokio::test]
async fn a_call_refused_at_the_cap_as_the_watchdog_faults_the_instance_waits_for_its_trial() {
    for configuring in [false, true] {
        let axis = rows(
            hook_door_plugin::configurable::door,
            "hook_door",
            Way::Linked,
        );

        let wedged: Arc<dyn busbar_contract::hook_calls::HookCalls> = axis
            .open(
                hook_door_plugin::CONFIGURABLE_NAME,
                "hooks.wedged-race",
                &json!({"reject_over_messages": 3, "sleep_ms": 1_501}),
                BUDGET,
            )
            .expect("the wedged gate opens");
        *crate::hook_door::HOLD_REFUSED_UNTIL_FAULTED_FOR_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(b"\"sleep_ms\":1501".to_vec());
        let mut inflight = Vec::with_capacity(MAX_INFLIGHT as usize);
        for _ in 0..MAX_INFLIGHT {
            let wedged = Arc::clone(&wedged);
            inflight.push(tokio::spawn(async move {
                let _ = wedged.decide(frame(2), Duration::from_millis(50)).await;
            }));
        }
        for h in inflight {
            let _ = h.await;
        }

        let (ready, detail) = if configuring {
            let answer = wedged
                .configure("wedged-race", r#"{"reject_over_messages":1}"#, 2, BUDGET)
                .await;
            (answer.is_ok(), format!("{answer:?}"))
        } else {
            let answer = wedged.decide(frame(2), BUDGET).await;
            (
                matches!(
                    answer,
                    Answered::Answer {
                        outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                        ..
                    }
                ),
                decided(2, &answer),
            )
        };
        *crate::hook_door::HOLD_REFUSED_UNTIL_FAULTED_FOR_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        assert!(
            ready,
            "a cap-refused call waits for its fresh trial (configure={configuring}): {detail}"
        );
    }
}

#[tokio::test]
async fn the_inflight_cap_saturates_and_fails_on_the_caller_deadline_through_the_axis() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
        workers: MAX_INFLIGHT,
        ..DispatchConfig::default()
    }));
    let axis = HookRows::new(
        &[hook_door_plugin::conforming::door],
        None,
        dispatcher.clone(),
    )
    .expect("the linked row");
    let wedged: Arc<dyn busbar_contract::hook_calls::HookCalls> = axis
        .open(
            NAME,
            "hooks.wedged",
            &json!({"reject_over_messages": 3, "hold_for_cap_test": true}),
            BUDGET,
        )
        .expect("the controlled gate opens");
    let blocked = hook_door_plugin::BlockedCalls::hold();
    let kept = frame(2);
    let mut inflight = Vec::with_capacity(MAX_INFLIGHT as usize);
    for i in 0..MAX_INFLIGHT {
        let wedged = Arc::clone(&wedged);
        let frame = if i == 0 { Arc::clone(&kept) } else { frame(2) };
        inflight.push(tokio::spawn(async move {
            let _ = wedged.decide(frame, BUDGET).await;
        }));
    }
    tokio::time::timeout(BUDGET, async {
        while blocked.entered() != MAX_INFLIGHT {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("every slot has an executing crossing");
    for h in &inflight {
        h.abort();
    }
    for h in inflight {
        assert!(h.await.expect_err("the caller is abandoned").is_cancelled());
    }

    assert!(kept.try_lend().is_none());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kept.order(1))).is_err());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kept.answer_decide(&busbar_contract::abi::sdk::hook::Verdict::Abstain)
    }))
    .is_err());
    assert!(matches!(
        wedged.decide(Arc::clone(&kept), BUDGET).await,
        Answered::Broken(why) if why.contains("buffers are already in use")
    ));
    let start = std::time::Instant::now();
    let saturated = wedged.decide(frame(2), Duration::from_millis(150)).await;
    let elapsed = start.elapsed();
    blocked.release();
    tokio::time::timeout(BUDGET, async {
        while kept.try_lend().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled crossing releases its buffers after returning");
    let (_, out) = kept.answer_decide(&busbar_contract::abi::sdk::hook::Verdict::Prefer(vec![0]));
    assert_eq!(kept.order(out.order_written), vec![0]);
    assert!(
        matches!(saturated, Answered::TimedOut),
        "with every slot held, a further caller must reach its deadline: {}",
        decided(2, &saturated)
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the wait must be bounded by the caller's own deadline, not by the held plugin"
    );
    let resumed = wedged.decide(frame(2), BUDGET).await;
    assert!(
        matches!(
            resumed,
            Answered::Answer {
                outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                ..
            }
        ),
        "a freed slot must let the next call through: {}",
        decided(2, &resumed)
    );
    assert_eq!(
        dispatcher.stats().quarantined,
        0,
        "capacity is tested without a watchdog breach"
    );
}

#[test]
fn a_1_5_5_hook_name_opens_the_1_6_0_hook_both_ways() {
    const OLD: &str = "busbar-webrequest";
    let door = hook_door_plugin::conforming::door;
    let settings = json!({"reject_over_messages": 3});
    let opens = |rows: &HookRows| rows.open(OLD, "hooks.wr", &settings, BUDGET).is_ok();
    let dispatcher = || Arc::new(Dispatcher::new(DispatchConfig::default()));

    let former_of = |w: &str| {
        if w == NAME {
            vec![OLD.to_string()]
        } else {
            Vec::new()
        }
    };
    let linked = HookRows::new(&[door], None, dispatcher())
        .expect("the linked row")
        .with_former_names(former_of)
        .expect("no other plugin claims the name");
    assert!(opens(&linked), "linked: '{OLD}' opens the hook");
    assert!(linked.linked(OLD) && linked.first_party(OLD));
    let bare = HookRows::new(&[door], None, dispatcher()).expect("the linked row");
    assert!(!opens(&bare), "RED: a linked row without its former name");

    let path = crate::both_ways::example_cdylib("hook_door");
    let lib = std::fs::read(path).expect("the example cdylib reads");
    let abi = crate::supported_abi("hook")[0];
    let stated = hex::encode(rendering_of(door).expect("the door renders its Statement"));
    let manifest = |former: &[&str]| {
        let mut m =
            crate::both_ways::statement("hook", "busbar-hook-webrequest", "webrequest", abi);
        m.statement = Some(stated.clone());
        m.former_names = former.iter().map(|s| s.to_string()).collect();
        m
    };
    let registry = crate::both_ways::dropped("former-hook", manifest(&[OLD]), &lib);
    assert!(registry.answers(OLD, "hook"), "preflight resolves '{OLD}'");
    let dropped = HookRows::new(&[], Some(&registry), dispatcher()).expect("the dropped row");
    assert!(opens(&dropped), "dropped in: '{OLD}' opens the hook");
    let registry = crate::both_ways::dropped("bare-hook", manifest(&[]), &lib);
    let bare = HookRows::new(&[], Some(&registry), dispatcher()).expect("the dropped row");
    assert!(
        !opens(&bare),
        "RED: a dropped-in hook without its former name"
    );
    assert!(!registry.answers(OLD, "hook"));
}

#[test]
fn a_former_name_two_hooks_claim_is_refused_on_the_axis() {
    let rows = HookRows::new(
        &[
            hook_door_plugin::conforming::door,
            hook_door_plugin::broken::door,
        ],
        None,
        Arc::new(Dispatcher::new(DispatchConfig::default())),
    )
    .expect("two distinct linked hooks");
    let refused = rows
        .with_former_names(|w| {
            if w == NAME {
                vec![BROKEN_NAME.to_string()]
            } else {
                Vec::new()
            }
        })
        .expect_err("a former name that is another hook's name is refused");
    assert!(
        refused.contains(&format!("'{BROKEN_NAME}'")) && refused.contains(NAME),
        "{refused}"
    );
}

#[test]
fn a_linked_hook_and_a_different_dropped_in_hook_claiming_one_word_are_refused() {
    let abi = crate::supported_abi("hook")[0];
    let stated = hex::encode(
        rendering_of(hook_door_plugin::broken::door).expect("the door renders its Statement"),
    );
    let dropped = |alias: &str| {
        let mut m = crate::both_ways::statement("hook", "acme-hook-other", alias, abi);
        m.statement = Some(stated.clone());
        crate::both_ways::dropped(&format!("claim-{alias}"), m, b"a hook library")
    };
    let rows = |registry: &crate::PluginRegistry| {
        HookRows::new(
            &[hook_door_plugin::conforming::door],
            Some(registry),
            Arc::new(Dispatcher::new(DispatchConfig::default())),
        )
    };
    let refused = rows(&dropped(NAME)).expect_err("a word two hooks claim is refused");
    assert!(
        refused.contains(&format!("'{NAME}'")) && refused.contains(BROKEN_NAME),
        "{refused}"
    );
    assert!(
        rows(&dropped("acme-other")).is_ok(),
        "distinct words coexist"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_trial_holds_no_other_caller() {
    use super::{HookInstance, State};
    use crate::dispatch::{ConnTable, NoSink};
    use busbar_contract::hook_calls::HookCalls;
    use std::sync::mpsc;
    let axis = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let c = axis.find(NAME).expect("the linked row").clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let bind = {
        let (c, dispatcher) = (c.clone(), Arc::clone(&dispatcher));
        move || {
            HookRows::bind(
                &c,
                &dispatcher,
                "hooks.trial",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let (entered_tx, entered) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let gate = std::sync::Mutex::new(Some((entered_tx, released)));
    let first = bind().expect("the hook binds");
    let instance = Arc::new(
        HookInstance::open(
            first,
            Arc::clone(&dispatcher),
            br#"{"reject_over_messages": 3}"#,
            move || {
                if let Some((entered, released)) = gate.lock().unwrap().take() {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                }
                bind()
            },
        )
        .expect("the hook opens"),
    );

    *instance.inner.lock() = State::Quarantined {
        trial_at: std::time::Instant::now(),
        window: super::QUARANTINE_FIRST,
    };
    let trial = {
        let instance = Arc::clone(&instance);
        tokio::spawn(async move {
            let a = instance.decide(frame(2), BUDGET).await;
            let ready = matches!(
                a,
                Answered::Answer {
                    outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
                    ..
                }
            );
            (ready, decided(2, &a))
        })
    };
    tokio::task::spawn_blocking(move || entered.recv().unwrap())
        .await
        .unwrap();
    let (asked_tx, asked) = mpsc::channel();
    {
        let instance = Arc::clone(&instance);
        std::thread::spawn(move || {
            let _ = asked_tx.send(instance.quarantined());
        });
    }
    let answered = tokio::task::spawn_blocking(move || asked.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    release.send(()).unwrap();
    assert_eq!(
        answered,
        Ok(true),
        "a wedged trial held another caller behind the hook's state lock"
    );
    let (ready, served) = trial.await.unwrap();
    assert!(ready, "the trial's fresh instance serves: {served}");
    assert!(!instance.quarantined());
}

#[tokio::test]
async fn a_trial_keeps_the_settings_the_hook_acknowledged() {
    use super::{HookInstance, State};
    use crate::dispatch::{ConnTable, NoSink};
    use busbar_contract::hook_calls::HookCalls;
    let axis = rows(checkpoint_plugin::door, "hook_checkpoint_door", Way::Linked);
    let c = axis
        .find(checkpoint_plugin::NAME)
        .expect("the linked row")
        .clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let bind = {
        let (c, dispatcher) = (c.clone(), Arc::clone(&dispatcher));
        move || {
            HookRows::bind(
                &c,
                &dispatcher,
                "hooks.tuned",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let instance = HookInstance::open(
        bind().expect("the hook binds"),
        Arc::clone(&dispatcher),
        br#"{"reject_over_messages": 3}"#,
        bind,
    )
    .expect("the hook opens");
    let rejects = |a: &Answered<busbar_contract::abi::hook::DecideOut>| matches!(a, Answered::Answer { out, .. } if out.reject_status == REJECT_STATUS);
    assert!(!rejects(&instance.decide(frame(2), BUDGET).await));
    instance
        .configure("tuned", r#"{"reject_over_messages": 1}"#, 2, BUDGET)
        .await
        .expect("the hook acknowledges version 2");
    let a = instance.decide(frame(2), BUDGET).await;
    assert!(
        rejects(&a),
        "the acknowledged settings gate: {}",
        decided(2, &a)
    );

    *instance.inner.lock() = State::Quarantined {
        trial_at: std::time::Instant::now(),
        window: super::QUARANTINE_FIRST,
    };
    let a = instance.decide(frame(2), BUDGET).await;
    assert!(
        rejects(&a),
        "the trial's instance lost the acknowledged settings: {}",
        decided(2, &a)
    );
    assert!(!instance.quarantined());
}

#[tokio::test]
async fn a_configure_refusal_is_named_by_the_host() {
    use super::HookInstance;
    use crate::dispatch::{ConnTable, NoSink};
    use busbar_contract::hook_calls::HookCalls;
    let axis = rows(
        hook_door_plugin::configurable::door,
        "hook_door",
        Way::Linked,
    );
    let c = axis
        .find(hook_door_plugin::CONFIGURABLE_NAME)
        .expect("the linked row")
        .clone();
    let dispatcher = Arc::clone(&axis.dispatcher);
    let bind = {
        let (c, dispatcher) = (c.clone(), Arc::clone(&dispatcher));
        move || {
            HookRows::bind(
                &c,
                &dispatcher,
                "hooks.tuned",
                Arc::new(NoSink),
                ConnTable::NoNeeds,
            )
        }
    };
    let instance = HookInstance::open(
        bind().expect("the hook binds"),
        Arc::clone(&dispatcher),
        br#"{"reject_over_messages": 3}"#,
        bind,
    )
    .expect("the hook opens");
    assert_eq!(
        instance
            .configure("tuned", r#"{"reject_over_messages": "x"}"#, 2, BUDGET)
            .await,
        Err(format!(
            "hook '{}': settings: `reject_over_messages` must be a number",
            hook_door_plugin::CONFIGURABLE_NAME
        ))
    );
}

#[test]
fn an_instance_debug_never_shows_its_settings() {
    let rows = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked);
    let c = rows.find(NAME).expect("the fixture's row").clone();
    let bind = {
        let (c, dispatcher) = (c.clone(), Arc::clone(&rows.dispatcher));
        move || {
            HookRows::bind(
                &c,
                &dispatcher,
                "hooks.gate",
                Arc::new(super::NoSink),
                super::ConnTable::NoNeeds,
            )
        }
    };
    let settings = br#"{"reject_over_messages": 3}"#;
    let opened = super::HookInstance::open(
        bind().expect("the fixture binds"),
        Arc::clone(&rows.dispatcher),
        settings,
        bind,
    )
    .expect("the fixture opens over its settings");
    let shown = format!("{opened:?}");
    assert!(shown.contains(NAME), "the name names the instance: {shown}");
    for leak in ["reject_over_messages", "3}"] {
        assert!(!shown.contains(leak), "`{leak}` printed: {shown}");
    }
}

#[tokio::test]
async fn red_a_hook_that_declared_no_orders_is_refused_when_it_orders() {
    let open = |door: DoorFn, orders: bool| {
        let mut axis = rows(door, "hook_door", Way::Linked);
        for c in &mut axis.candidates {
            c.orders = orders;
        }
        let name = axis.candidates[0].name.clone();
        axis.open(
            &name,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .expect("the hook opens")
    };
    let ordering = hook_door_plugin::ordering::door;
    let undeclared = decided(2, &open(ordering, true).decide(frame(2), BUDGET).await);
    assert!(
        undeclared.contains("Ready") && undeclared.contains("verbs=0x1 "),
        "a hook that never declared `orders: false` may order: {undeclared}"
    );
    let declared = decided(2, &open(ordering, false).decide(frame(2), BUDGET).await);
    assert!(
        declared.contains("broken") && declared.contains("`hook.orders: false`"),
        "a hook that declared `orders: false` and ordered was not refused: {declared}"
    );
    let abstains = decided(
        2,
        &open(hook_door_plugin::conforming::door, false)
            .decide(frame(2), BUDGET)
            .await,
    );
    assert!(
        abstains.contains("Ready") && abstains.contains("verbs=0x2 "),
        "a hook that declared `orders: false` and abstains is served: {abstains}"
    );
}

#[tokio::test]
async fn an_unrepresentable_call_budget_is_broken_without_poisoning_either_hook_door() {
    for way in [Way::Linked, Way::Dropped] {
        let axis = rows(hook_door_plugin::conforming::door, "hook_door", way);
        let calls = axis
            .open(
                NAME,
                "hooks.gate",
                &json!({"reject_over_messages": 3}),
                BUDGET,
            )
            .unwrap();
        let answer = calls.decide(frame(2), Duration::MAX).await;
        assert!(
            matches!(answer, Answered::Broken(ref why) if why.contains("clock range")),
            "{way:?}: {answer:?}"
        );
        let recovered = calls.decide(frame(2), BUDGET).await;
        assert!(
            matches!(recovered, Answered::Answer { .. }),
            "{way:?}: {recovered:?}"
        );
    }
}
