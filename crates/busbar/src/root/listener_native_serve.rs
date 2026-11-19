// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One supervisor retains the accepted socket, original inputs, and response owners.

use std::collections::VecDeque;
use std::sync::Arc;

use busbar_core_connector::framed_stream::session::{self, Inbound, Wiring};
use busbar_core_connector::listen::{Admits, Admitted};
use busbar_kernel::inbound::native::StreamOwner;
use busbar_plugin_abi::transport::{CR_DRAIN, CR_NORMAL};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use super::{InputError, NativeListener, OpenedConnection, ReadyInput};
use crate::root::durability::core_audit::CoreAudit;
use crate::root::listener::{ConnBalancer, ConnCountGuard};
use crate::root::plane_node::Node;

enum ResponseFinished {
    Delivered(super::delivery::CompletedResponse),
}

/// Observation of this original carrier's completed driver and retired actual writer.
/// Only the supervisor below constructs this; a dropped waiter or stream number cannot.
pub(crate) struct NativeCarrierRetired {
    owner: Arc<StreamOwner>,
}
impl NativeCarrierRetired {
    pub(crate) fn owner(&self) -> &Arc<StreamOwner> {
        &self.owner
    }
}

pub(crate) async fn serve_admitted(
    mut admits: impl Admits,
    native: Arc<NativeListener>,
    security: Option<Arc<dyn busbar_contract::transport::wire::ConnectionSecurity>>,
    node: Arc<Node>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    mut balancer: Option<ConnBalancer>,
) -> std::io::Result<()> {
    // This core's audit state: made when its listener loop starts, handed to each connection on
    // it, released by the flusher's first pull after the loop and its connections let it go.
    let core = node.core_audit();
    let (stop, stopped) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut task_failure = None;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (admitted, guard) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            finished = connections.join_next(), if !connections.is_empty() => {
                // The connection has already retired its original owners before returning.
                if let Some(Err(error)) = finished {
                    task_failure = Some(std::io::Error::other(error));
                    break;
                }
                continue;
            },
            handed = async { balancer.as_mut().expect("guarded receiver").rx.recv().await },
                if balancer.is_some() && connections.len() < native.limits.max_connections => {
                let Some(admitted) = handed else { break };
                (admitted, balancer.as_ref().map(ConnBalancer::adopt))
            },
            admitted = admits.admit(), if connections.len() < native.limits.max_connections => match balancer.as_ref() {
                Some(balance) => match balance.try_hand_off(admitted) {
                    None => continue,
                    Some(admitted) => (admitted, Some(balance.place_local())),
                },
                None => (admitted, None),
            },
        };
        connections.spawn(accepted(
            admitted,
            guard,
            native.clone(),
            security.clone(),
            node.clone(),
            Arc::clone(&core),
            stopped.clone(),
        ));
    }
    drop(admits);
    if let Some(mut balance) = balancer.take() {
        while let Ok(admitted) = balance.rx.try_recv() {
            connections.spawn(accepted(
                admitted,
                Some(balance.adopt()),
                native.clone(),
                security.clone(),
                node.clone(),
                Arc::clone(&core),
                stopped.clone(),
            ));
        }
    }
    let _ = stop.send(true);
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            task_failure.get_or_insert_with(|| std::io::Error::other(error));
        }
    }
    match task_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn accepted(
    admitted: Admitted,
    _count: Option<ConnCountGuard>,
    native: Arc<NativeListener>,
    security: Option<Arc<dyn busbar_contract::transport::wire::ConnectionSecurity>>,
    node: Arc<Node>,
    core: Arc<CoreAudit>,
    stopped: watch::Receiver<bool>,
) -> Result<(), InputError> {
    // The original connector connection permit lives through every terminal join.
    let _hold = admitted.hold;
    let listener = Arc::clone(&native);
    let ended = async {
        let stream = tokio::net::TcpStream::from_std(admitted.stream).map_err(InputError::Io)?;
        let opened = native.accepted(stream, security.as_deref()).await?;
        supervise(opened, native, node, core, stopped).await
    }
    .await;
    if let Err(stop) = &ended {
        ended_with(&listener, stop);
    }
    ended
}

/// A connection that ends with a failure used to end in silence: the listener loop joins its task
/// and reads only a panic, so the failure itself was dropped. Say which listener it was on and
/// what stopped it, so a request closed with nothing written names its layer: an arrival refusal,
/// the transport's grammar, the response intent, or a delivery stop (`Integrity` is an answer that
/// carried no output authority). A caller that went away is not a failure of this side.
fn ended_with(native: &NativeListener, stop: &InputError) {
    use busbar_contract::response_delivery::ResponseStop;
    if matches!(stop, InputError::Delivery(ResponseStop::Cancelled)) {
        return;
    }
    tracing::warn!(
        listener = %native.slot,
        admin = native.admin.is_some(),
        stop = %stop,
        "a native connection ended with a failure"
    );
}

/// The caller's side of an adopted connection, as the supervisor holds it.
struct AdoptedSide {
    /// Where the caller's events go: the plane session's side of the upgraded request.
    to_plane: mpsc::Sender<busbar_kernel::plane_driver::port_duplex::ClientEvent>,
    /// The one event read from the adopted session and not yet taken by the plane session.
    held: Option<busbar_kernel::plane_driver::port_duplex::ClientEvent>,
}

struct Waiting {
    stream: u64,
    ready: Option<ReadyInput>,
}

fn next_ready(waiting: &mut VecDeque<Waiting>) -> Option<ReadyInput> {
    if waiting.front().is_some_and(|entry| entry.ready.is_some()) {
        waiting.pop_front().and_then(|entry| entry.ready)
    } else {
        None
    }
}

fn stop_connection(
    ingress: &super::NativeIngress,
    waiting: &mut VecDeque<Waiting>,
    close: &mut Option<oneshot::Sender<u32>>,
    reason: u32,
) {
    waiting.clear();
    for slot in &ingress.slots {
        ingress.connection.cancel(&slot.owner);
    }
    if let Some(close) = close.take() {
        let _ = close.send(reason);
    }
}

async fn supervise(
    opened: OpenedConnection,
    native: Arc<NativeListener>,
    node: Arc<Node>,
    core: Arc<CoreAudit>,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), InputError> {
    let OpenedConnection {
        mut ingress,
        conn,
        io,
        progress,
        delivery,
    } = opened;
    // Heads waiting their turn, in order: empty until the first head (allocation ruling); each head
    // is bounded by its own admission, not by a fixed queue.
    let mut waiting = VecDeque::new();
    let connection = Arc::new(
        node.response_intents()
            .ok_or(InputError::Invalid)?
            .connection(core)
            .map_err(InputError::FinalIntent)?,
    );
    let (mut registrations, registered) = mpsc::channel(1);
    let (mut feeds, fed) = mpsc::channel(1);
    let (inbound, mut inputs) = mpsc::channel(1);
    let (close, closed) = oneshot::channel();
    let mut close = Some(close);
    let driver = session::drive(
        conn,
        io,
        progress,
        Wiring {
            delivery,
            registrations: registered,
            feeds: fed,
            inbound,
            close: closed,
            write_timeout: native.limits.write_timeout,
            drain_grace: native.limits.drain_grace,
            counters: Arc::default(),
            // No housekeeping tick walks a listener's read blocks yet (the usage flush tick runs
            // in the kernel's budget flusher, started in main.rs): until it does, a read block,
            // once made, is kept until its connection ends.
            read_holders: None,
        },
    );
    let mut driver = std::pin::pin!(driver);
    let mut driver_done = false;
    let mut input_open = true;
    let mut preparing = JoinSet::new();
    let mut responses = JoinSet::new();
    let mut failure = None;
    // The connection after a committed upgrade's hand-over (`listener_native_handover.rs`): the
    // websocket transport's session is driven in the HTTP session's place, and what it hands up is
    // the caller's side of the one upgraded session, not a new request.
    let mut adopted: Option<AdoptedSide> = None;
    loop {
        if driver_done {
            for slot in &mut ingress.slots {
                if !slot.carrier_reported {
                    if let Some(handle) = &slot.node {
                        if let Err(error) = handle.carrier_retired(NativeCarrierRetired {
                            owner: slot.owner.clone(),
                        }) {
                            failure.get_or_insert(error);
                        }
                        slot.carrier_reported = true;
                    }
                }
            }
        }
        if let Some(ready) = preparing
            .is_empty()
            .then(|| next_ready(&mut waiting))
            .flatten()
        {
            let (native, node, connection, registrations) = (
                native.clone(),
                node.clone(),
                connection.clone(),
                registrations.clone(),
            );
            preparing.spawn(async move {
                let owner = ready.owner.clone();
                let result =
                    super::dispatch::prepare(ready, native, node, connection, registrations).await;
                (owner, result)
            });
        }
        if driver_done && preparing.is_empty() && responses.is_empty() {
            break;
        }
        let request_deadline = ingress
            .slots
            .iter()
            .filter_map(super::InputSlot::next_deadline)
            .min();
        tokio::select! {
            biased;
            () = async {
                match request_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending().await,
                }
            }, if close.is_some() => {
                failure.get_or_insert(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Deadline));
                input_open = false;
                stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
            },
            changed = stopped.changed(), if close.is_some() => {
                if changed.is_err() || *stopped.borrow() {
                    input_open = false;
                    stop_connection(&ingress, &mut waiting, &mut close, CR_DRAIN);
                }
            },
            outcome = &mut driver, if !driver_done => {
                // §12.27 step 3: the HTTP transport answered UPGRADE to a committed upgrade's 101.
                // The connection, its counters, its progress reader and the upgraded answer go to
                // the websocket transport; this supervisor goes on with them.
                let outcome = match outcome {
                    session::Outcome::Upgraded(upgrade) => {
                        let owners: Vec<Arc<StreamOwner>> =
                            ingress.slots.iter().map(|slot| slot.owner.clone()).collect();
                        match super::handover::adopt(
                            upgrade,
                            &owners,
                            ingress.connection.facts(),
                            &native.limits,
                        ) {
                            Ok(next) => {
                                driver.set(session::drive(next.conn, next.io, next.progress, next.wiring));
                                inputs = next.inputs;
                                close = Some(next.close);
                                registrations = next.registrations;
                                feeds = next.feeds;
                                adopted = Some(AdoptedSide { to_plane: next.to_plane, held: None });
                                // No further request arrives on an adopted connection.
                                waiting.clear();
                                continue;
                            }
                            // Not adopted: nothing was written for the 101, the writer is retired,
                            // and the request ends cancelled (its unit settles as a cut answer).
                            Err(error) => {
                                failure.get_or_insert(error);
                                None
                            }
                        }
                    }
                    outcome => Some(outcome),
                };
                // The caller's side of an adopted session is over with its connection.
                adopted = None;
                driver_done = true;
                input_open = false;
                inputs.close();
                waiting.clear();
                for slot in &ingress.slots {
                    ingress.connection.cancel(&slot.owner);
                    // A committed upgrade whose connection ended before its hand-over is let go:
                    // its plane session is told the caller is gone.
                    super::handover::forget(&slot.owner);
                }
                if outcome.as_ref().is_some_and(|outcome| !matches!(outcome, session::Outcome::Closed | session::Outcome::PeerClosed | session::Outcome::CoreClosed(_))) {
                    failure.get_or_insert(InputError::Invalid);
                }
                if let Some(outcome) = outcome {
                    outcome.retire();
                }
            },
            prepared = preparing.join_next(), if !preparing.is_empty() => {
                match prepared {
                    Some(Ok((owner, Ok(prepared)))) => {
                        if let Some(slot) = ingress.slots.iter_mut().find(|slot| Arc::ptr_eq(&slot.owner, &owner)) {
                            slot.node = prepared.native_node_handle();
                        }
                        let feeds = feeds.clone();
                        responses.spawn(async move {
                            ResponseFinished::Delivered(prepared.send(&feeds).await)
                        });
                    },
                    Some(Ok((owner, Err(error)))) => {
                        ingress.connection.cancel(&owner);
                        let (error, handle) = match error {
                            super::data::DataPrepareError::Input(error) => (error, None),
                            super::data::DataPrepareError::HeldNode { error, handle } => (error, Some(handle)),
                        };
                        let slot = ingress.slots.iter_mut().find(|slot| Arc::ptr_eq(&slot.owner, &owner))
                            .expect("preparing request retains its original input slot");
                        slot.node = handle;
                        failure.get_or_insert(error);
                        input_open = false;
                        stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                    },
                    Some(Err(error)) => {
                        failure.get_or_insert(InputError::Io(std::io::Error::other(error)));
                        input_open = false;
                        stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                    },
                    None => {},
                }
            },
            completed = responses.join_next(), if !responses.is_empty() => {
                match completed {
                    Some(Ok(ResponseFinished::Delivered(completed))) => {
                        if let Err(error) = ingress.retire(&completed.owner) {
                            failure.get_or_insert(error);
                            input_open = false;
                            stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                        }
                        if let Err(error) = completed.result { failure.get_or_insert(error); }
                    },
                    Some(Err(error)) => {
                        failure.get_or_insert(InputError::Io(std::io::Error::other(error)));
                        input_open = false;
                        stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                    },
                    None => {},
                }
            },
            // One event of the caller is held for the plane session at a time: the adopted session
            // is not read further until the plane has taken it (that is the back-pressure).
            permit = async {
                adopted.as_ref().expect("guarded").to_plane.clone().reserve_owned().await
            }, if adopted.as_ref().is_some_and(|side| side.held.is_some()) => {
                match (permit, adopted.as_mut().and_then(|side| side.held.take())) {
                    (Ok(permit), Some(event)) => { permit.send(event); },
                    // The plane session is over: nothing more of the caller is wanted.
                    _ => {},
                }
            },
            input = inputs.recv(), if input_open && adopted.as_ref().is_none_or(|side| side.held.is_none()) => {
                let Some(input) = input else { input_open = false; continue };
                if let Some(side) = adopted.as_mut() {
                    // After the hand-over: a message of the caller, its close, or its loss.
                    side.held = Some(super::handover::event_of(input));
                    continue;
                }
                if let Inbound::Head { stream, .. } = &input {
                    waiting.push_back(Waiting { stream: *stream, ready: None });
                }
                let reset = match &input {
                    Inbound::Reset { stream, .. } | Inbound::Stalled(stream) => Some(*stream),
                    _ => None,
                };
                // The arrival's one monotonic reading: its deadline is derived from it and every
                // call made for the request is handed it.
                let Some(arrival) = busbar_kernel::inbound::native::Arrival::at(
                    busbar_kernel::store::monotonic_ns(),
                    native.limits.request_timeout,
                ) else {
                    failure.get_or_insert(InputError::Capacity);
                    input_open = false;
                    stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                    continue;
                };
                match ingress.accept(input, Some(arrival)) {
                    Ok(Some(ready)) => {
                        let stream = ready.request.binding().stream();
                        if let Some(entry) = waiting.iter_mut().find(|entry| entry.stream == stream) {
                            entry.ready = Some(ready);
                        } else {
                            failure.get_or_insert(InputError::Invalid);
                            input_open = false;
                            stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                        }
                    },
                    Ok(None) => {},
                    Err(error) => {
                        failure.get_or_insert(error);
                        input_open = false;
                        stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                    },
                }
                if let Some(stream) = reset {
                    if let Some(index) = waiting.iter().position(|entry| entry.stream == stream) {
                        waiting.remove(index);
                        if let Some(owner) = ingress.slots.iter().find(|slot| slot.stream == stream).map(|slot| slot.owner.clone()) {
                            if let Err(error) = ingress.retire(&owner) {
                                failure.get_or_insert(error);
                                input_open = false;
                                stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                            }
                        }
                    }
                }
            },
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn later_input_eof_cannot_overtake_original_head_registration() {
        let (mut ingress, source) = super::super::tests::ingress_fixture().await;
        assert!(ingress
            .accept(super::super::tests::public_head(&source, 1, false), None)
            .unwrap()
            .is_none());
        let second = ingress
            .accept(super::super::tests::public_head(&source, 2, true), None)
            .unwrap()
            .unwrap();
        let mut waiting = VecDeque::from([
            Waiting {
                stream: 1,
                ready: None,
            },
            Waiting {
                stream: 2,
                ready: Some(second),
            },
        ]);
        assert!(next_ready(&mut waiting).is_none());
        assert_eq!(waiting.len(), 2);
        waiting.front_mut().unwrap().ready = ingress.accept(Inbound::End(1), None).unwrap();
        let first = next_ready(&mut waiting).unwrap();
        assert_eq!(first.request.binding().stream(), 1);
        assert!(first.request.binding().owns_stream(&first.owner));
        let second = next_ready(&mut waiting).unwrap();
        assert_eq!(second.request.binding().stream(), 2);
        assert!(second.request.binding().owns_stream(&second.owner));
        assert!(next_ready(&mut waiting).is_none());
    }
}
