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

use super::{InputError, NativeListener, OpenedConnection, ReadyInput, LIVE_RESPONSES};
use crate::root::listener::{ConnBalancer, ConnCountGuard};
use crate::root::plane_node::Node;

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
    stopped: watch::Receiver<bool>,
) -> Result<(), InputError> {
    // The original connector connection permit lives through every terminal join.
    let _hold = admitted.hold;
    let stream = tokio::net::TcpStream::from_std(admitted.stream).map_err(InputError::Io)?;
    let opened = native.accepted(stream, security.as_deref()).await?;
    supervise(opened, native, node, stopped).await
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
    mut stopped: watch::Receiver<bool>,
) -> Result<(), InputError> {
    let OpenedConnection {
        mut ingress,
        conn,
        first,
        io,
        progress,
        delivery,
    } = opened;
    let source = conn.storage().clone();
    let _queue_credit = source
        .try_reserve(
            LIVE_RESPONSES
                .checked_mul(std::mem::size_of::<Waiting>())
                .ok_or(InputError::Capacity)?,
        )
        .map_err(|_| InputError::Capacity)?;
    let mut waiting = VecDeque::new();
    waiting
        .try_reserve_exact(LIVE_RESPONSES)
        .map_err(|_| InputError::Capacity)?;
    if waiting.capacity() > LIVE_RESPONSES {
        return Err(InputError::Capacity);
    }
    let connection = Arc::new(
        node.response_intents()
            .ok_or(InputError::Invalid)?
            .connection()
            .map_err(InputError::FinalIntent)?,
    );
    let (registrations, registered) = mpsc::channel(1);
    let (feeds, fed) = mpsc::channel(1);
    let (inbound, mut inputs) = mpsc::channel(1);
    let (close, closed) = oneshot::channel();
    let mut close = Some(close);
    let driver = session::drive(
        conn,
        first,
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
        },
    );
    let mut driver = std::pin::pin!(driver);
    let mut driver_done = false;
    let mut input_open = true;
    let mut preparing = JoinSet::new();
    let mut responses = JoinSet::new();
    let mut failure = None;
    loop {
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
        let request_deadline = ingress.slots.iter().filter_map(|slot| slot.deadline).min();
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
                driver_done = true;
                input_open = false;
                inputs.close();
                waiting.clear();
                for slot in &ingress.slots { ingress.connection.cancel(&slot.owner); }
                if !matches!(outcome, session::Outcome::Closed | session::Outcome::PeerClosed | session::Outcome::CoreClosed(_)) {
                    failure.get_or_insert(InputError::Invalid);
                }
                outcome.retire();
                for slot in &ingress.slots {
                    node.native_carrier_retired(NativeCarrierRetired { owner: slot.owner.clone() });
                }
            },
            prepared = preparing.join_next(), if !preparing.is_empty() => {
                match prepared {
                    Some(Ok((_owner, Ok(prepared)))) => {
                        let (feeds, node) = (feeds.clone(), node.clone());
                        responses.spawn(async move {
                            prepared.send(&feeds, &node).await
                        });
                    },
                    Some(Ok((owner, Err(error)))) => {
                        ingress.connection.cancel(&owner);
                        // Before driver retirement keep this original slot available for the
                        // actual writer-retired observation, including failed registration.
                        if driver_done {
                            node.native_carrier_retired(NativeCarrierRetired { owner: owner.clone() });
                            if let Err(error) = ingress.retire(&owner) { failure.get_or_insert(error); }
                        }
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
                    Some(Ok(completed)) => {
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
            input = inputs.recv(), if input_open => {
                let Some(input) = input else { input_open = false; continue };
                if let Inbound::Head { stream, .. } = &input {
                    if waiting.len() == LIVE_RESPONSES {
                        failure.get_or_insert(InputError::Capacity);
                        input_open = false;
                        stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                        continue;
                    }
                    waiting.push_back(Waiting { stream: *stream, ready: None });
                }
                let reset = match &input {
                    Inbound::Reset { stream, .. } | Inbound::Stalled(stream) => Some(*stream),
                    _ => None,
                };
                let Some(deadline) = std::time::Instant::now().checked_add(native.limits.request_timeout) else {
                    failure.get_or_insert(InputError::Capacity);
                    input_open = false;
                    stop_connection(&ingress, &mut waiting, &mut close, CR_NORMAL);
                    continue;
                };
                match ingress.accept(input, Some(deadline)) {
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
