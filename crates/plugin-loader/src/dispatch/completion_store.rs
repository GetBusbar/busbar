// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::completion_retirement::{Acknowledgement, Capability, Domain};

impl ServiceStore {
    pub(crate) fn retirement_input(
        &self,
        caller: usize,
        owner: HostCtx,
        ticket: Ticket,
    ) -> Option<Capability> {
        if !self.held.tracks(ticket) {
            return None;
        }
        let mut map = self.lock(ticket);
        let held = map.entry(ticket).or_insert_with(|| Held {
            epoch: self.epochs.fetch_add(1, Ordering::Relaxed) + 1,
            entries: HashMap::new(),
            inspections: HashMap::new(),
            conditionals: HashMap::new(),
            conditional_units: HashMap::new(),
            retirement: HashMap::new(),
        });
        let (known_owner, nonce, acknowledged) =
            *held.retirement.entry(caller).or_insert_with(|| {
                (
                    owner,
                    self.epochs.fetch_add(1, Ordering::Relaxed) + 1,
                    [0; 32],
                )
            });
        if known_owner != owner {
            return None;
        }
        Some(Capability {
            owner,
            ticket,
            epoch: held.epoch,
            nonce,
            acknowledged,
        })
    }

    pub(crate) fn retire_results(
        &self,
        wake: &'static InstanceWake,
        ack: &Acknowledgement,
    ) -> Result<(), ()> {
        let caller = std::ptr::from_ref(wake) as usize;
        let capability = ack.capability;
        let digest =
            busbar_contract::abi::sdk::completion_retirement::ack_digest(ack).map_err(|_| ())?;
        let ticket = capability.ticket;
        let mut removed = Vec::with_capacity(ack.handles.len());
        let retired_conns = {
            let mut map = self.lock(ticket);
            let held = map
                .get_mut(&ticket)
                .filter(|h| {
                    h.epoch == capability.epoch
                        && h.retirement.get(&caller)
                            == Some(&(capability.owner, capability.nonce, capability.acknowledged))
                })
                .ok_or(())?;
            for handle in &ack.handles {
                let entry = held.entries.get(&Issue {
                    caller,
                    seq: handle.seq,
                });
                match handle.domain {
                    Domain::Host
                        if !matches!(
                            entry,
                            Some((
                                _,
                                Entry::Done {
                                    delivered: true,
                                    ..
                                }
                            ))
                        ) =>
                    {
                        return Err(())
                    }
                    Domain::Connector if entry.is_some() => return Err(()),
                    _ => {}
                }
            }
            wake.conn_state.retire(ticket, &ack.handles, || {
                self.held.retire(ticket, caller, &ack.handles, || {
                    for handle in ack.handles.iter().filter(|h| h.domain == Domain::Host) {
                        removed.push(
                            held.entries
                                .remove(&Issue {
                                    caller,
                                    seq: handle.seq,
                                })
                                .expect("validated service result"),
                        );
                    }
                    let receipt = held
                        .retirement
                        .get_mut(&caller)
                        .expect("validated owner nonce");
                    receipt.1 = self.epochs.fetch_add(1, Ordering::Relaxed) + 1;
                    receipt.2 = digest;
                })
            })?
        };
        drop((removed, retired_conns));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::sdk::completion_retirement::Handle;

    fn rig() -> (ServiceStore, &'static InstanceWake, Capability) {
        let store = ServiceStore::default();
        let wake = Box::leak(Box::<InstanceWake>::default());
        let ticket = Ticket {
            slot: 1,
            generation: 7,
        };
        store.held.track(ticket);
        let cap = store
            .retirement_input(
                std::ptr::from_ref(wake) as usize,
                HostCtx { handle: 9 },
                ticket,
            )
            .unwrap();
        (store, wake, cap)
    }

    fn issue(store: &ServiceStore, wake: &InstanceWake, cap: Capability, seq: u32, entry: Entry) {
        let caller = std::ptr::from_ref(wake) as usize;
        let pending = matches!(entry, Entry::Running { .. });
        store
            .lock(cap.ticket)
            .get_mut(&cap.ticket)
            .unwrap()
            .entries
            .insert(Issue { caller, seq }, (Bound { op: 1, req: 3 }, entry));
        let handle = CompletionHandle {
            ticket: cap.ticket,
            seq,
            ..CompletionHandle::ZERO
        };
        assert!(store.held.call(caller, Domain::Host, handle));
        store.held.answered(caller, Domain::Host, handle, pending);
    }

    #[test]
    fn batch_preserves_all_entries_until_every_named_result_was_delivered() {
        let (store, wake, cap) = rig();
        let done = || Entry::Done {
            invocation: 90,
            stored: Stored::ready(1),
            shorts: 0,
            delivered: true,
        };
        issue(&store, wake, cap, 1, done());
        issue(&store, wake, cap, 2, Entry::Running { invocation: 91 });
        let caller = std::ptr::from_ref(wake) as usize;
        let ack = Acknowledgement {
            capability: cap,
            handles: vec![
                Handle {
                    domain: Domain::Host,
                    seq: 1,
                },
                Handle {
                    domain: Domain::Host,
                    seq: 2,
                },
            ],
        };
        assert_eq!(store.retire_results(wake, &ack), Err(()));
        assert_eq!(store.held(), 2);
        let handle = CompletionHandle {
            ticket: cap.ticket,
            seq: 2,
            ..CompletionHandle::ZERO
        };
        assert!(store.complete(
            handle,
            Issue { caller, seq: 2 },
            cap.epoch,
            91,
            Stored::ready(2)
        ));
        assert_eq!(
            store.retire_results(wake, &ack),
            Err(()),
            "completed but never delivered"
        );
        {
            let mut map = store.lock(cap.ticket);
            let entry = &mut map
                .get_mut(&cap.ticket)
                .unwrap()
                .entries
                .get_mut(&Issue { caller, seq: 2 })
                .unwrap()
                .1;
            // SAFETY: the put callback writes no borrowed memory.
            let answer = unsafe { redeem(entry, |_| Ok(Answered::ready(2, 0))) };
            store.held.answered(
                caller,
                Domain::Host,
                handle,
                answer.outcome == Outcome::Pending,
            );
        }
        let other = Box::leak(Box::<InstanceWake>::default());
        issue(&store, other, cap, 2, Entry::Running { invocation: 92 });
        store.retire_results(wake, &ack).unwrap();
        assert_eq!(store.held(), 1);
        assert_eq!(
            store.held.held(cap.ticket),
            1,
            "another caller's same seq remains pending"
        );
        assert_eq!(
            store.retire_results(wake, &ack),
            Err(()),
            "old nonce is not reusable"
        );
    }

    #[test]
    fn stale_completion_cannot_complete_a_reused_sequence_in_the_same_epoch() {
        let (store, wake, cap) = rig();
        let caller = std::ptr::from_ref(wake) as usize;
        issue(
            &store,
            wake,
            cap,
            4,
            Entry::Done {
                invocation: 101,
                stored: Stored::ready(1),
                shorts: 0,
                delivered: true,
            },
        );
        store
            .retire_results(
                wake,
                &Acknowledgement {
                    capability: cap,
                    handles: vec![Handle {
                        domain: Domain::Host,
                        seq: 4,
                    }],
                },
            )
            .unwrap();
        issue(&store, wake, cap, 4, Entry::Running { invocation: 102 });
        let handle = CompletionHandle {
            ticket: cap.ticket,
            seq: 4,
            ..CompletionHandle::ZERO
        };
        assert!(!store.complete(
            handle,
            Issue { caller, seq: 4 },
            cap.epoch,
            101,
            Stored::ready(7)
        ));
        assert!(store.complete(
            handle,
            Issue { caller, seq: 4 },
            cap.epoch,
            102,
            Stored::ready(8)
        ));
    }

    #[test]
    fn whole_cycle_forget_invalidates_prior_ack_without_touching_the_new_result() {
        let (store, wake, cap) = rig();
        let caller = std::ptr::from_ref(wake) as usize;
        let done = || Entry::Done {
            invocation: 301,
            stored: Stored::ready(1),
            shorts: 0,
            delivered: true,
        };
        issue(&store, wake, cap, 4, done());
        let old = Acknowledgement {
            capability: cap,
            handles: vec![Handle {
                domain: Domain::Host,
                seq: 4,
            }],
        };
        assert_eq!(store.forget(cap.ticket), 1);
        store.held.forget(cap.ticket);
        let next = store
            .retirement_input(caller, cap.owner, cap.ticket)
            .unwrap();
        assert_ne!(next.epoch, cap.epoch);
        issue(&store, wake, next, 4, done());
        assert_eq!(store.retire_results(wake, &old), Err(()));
        assert_eq!(store.held(), 1);
        store
            .retire_results(
                wake,
                &Acknowledgement {
                    capability: next,
                    handles: old.handles,
                },
            )
            .unwrap();
        assert_eq!(store.held(), 0);
    }
}
