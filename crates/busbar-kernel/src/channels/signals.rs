// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The in-process DETACH-key registry behind SIGNAL and DX_BROADCAST (IF §12.19 round 18, §8.6
//! SignalRec, §16.159). One per gateway process; never replicated through the store.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_plugin_abi::plane::MAX_FANOUT;
use tokio::sync::mpsc;

use super::authority::{AdmissionBucket, ChannelAuthority};
use super::SessionSignals;
use crate::plugin_records::RecordsDenied;

/// What a session's task receives: delivered by it as piece(FROM_CORE, 0, flags, bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signalled {
    pub flags: u32,
    pub bytes: Box<[u8]>,
}

struct Member {
    session: u64,
    subject: Option<[u8; 32]>,
    tx: mpsc::Sender<Signalled>,
}

/// One command-channel registration.
struct CommandMember {
    session: u64,
    tx: mpsc::Sender<Signalled>,
}

/// The sessions registered under one admission and one key. It holds the actual admission once:
/// a signal compares it once, then reaches every member.
struct CommandGroup {
    authority: ChannelAuthority,
    members: Vec<CommandMember>,
}

type LegacyKey = (u64, Box<[u8]>);
type CommandKey = (u64, AdmissionBucket, Box<[u8]>);

#[derive(Default)]
struct Table {
    legacy: HashMap<LegacyKey, Vec<Member>>,
    /// Almost always one group per key. Two admissions whose bucket values are equal get one each.
    command: HashMap<CommandKey, Vec<CommandGroup>>,
    next: u64,
}

/// Where a registration sits, so its guard can remove it.
enum Seat {
    Legacy(LegacyKey),
    Command(CommandKey),
}

/// The registry. Sessions register under the key their DETACH named; the guard unregisters on drop.
#[derive(Default)]
pub struct SignalRegistry {
    table: Mutex<Table>,
    dropped: AtomicU64,
}

/// Held by the session's task; dropping it removes the session from the registry.
pub struct Registered {
    registry: Arc<SignalRegistry>,
    seat: Seat,
    session: u64,
}

impl SignalRegistry {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a live session of plane instance `instance` under DETACH key `key`. `subject` = the
    /// session's subject hash (CH_PER_CALLER signals reach only its own sessions).
    pub fn register(
        self: &Arc<Self>,
        instance: u64,
        key: &[u8],
        subject: Option<[u8; 32]>,
        tx: mpsc::Sender<Signalled>,
    ) -> Registered {
        let key: LegacyKey = (instance, key.into());
        let mut table = self.lock();
        table.next += 1;
        let session = table.next;
        table.legacy.entry(key.clone()).or_default().push(Member {
            session,
            subject,
            tx,
        });
        drop(table);
        Registered {
            registry: Arc::clone(self),
            seat: Seat::Legacy(key),
            session,
        }
    }

    /// Register under the actual command admission. A repeated key in another unit/Open is unrelated.
    pub fn register_command(
        self: &Arc<Self>,
        instance: u64,
        authority: &ChannelAuthority,
        key: &[u8],
        tx: mpsc::Sender<Signalled>,
    ) -> Result<Registered, RecordsDenied> {
        if !authority.is_live() || key.is_empty() || key.len() > super::carrier::MAX_KEY {
            return Err(RecordsDenied::Invalid);
        }
        let key: CommandKey = (instance, authority.bucket(), key.into());
        let mut table = self.lock();
        if !authority.is_live() {
            return Err(RecordsDenied::Invalid);
        }
        table.next = table
            .next
            .checked_add(1)
            .ok_or(RecordsDenied::Unavailable)?;
        let session = table.next;
        let groups = table.command.entry(key.clone()).or_default();
        let at = match groups
            .iter()
            .position(|group| group.authority == *authority)
        {
            Some(at) => at,
            None => {
                groups.push(CommandGroup {
                    authority: authority.clone(),
                    members: Vec::new(),
                });
                groups.len() - 1
            }
        };
        groups[at].members.push(CommandMember { session, tx });
        Ok(Registered {
            registry: Arc::clone(self),
            seat: Seat::Command(key),
            session,
        })
    }

    /// `plane_signal_dropped_total`: deliveries a full session channel refused.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Live sessions under (instance, key).
    #[must_use]
    pub fn live(&self, instance: u64, key: &[u8]) -> usize {
        self.lock()
            .legacy
            .get(&(instance, Box::<[u8]>::from(key)))
            .map_or(0, Vec::len)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Take `session` out of `members`. `true`: the list is now empty.
fn leave<M>(members: &mut Vec<M>, session_of: impl Fn(&M) -> u64, session: u64) -> bool {
    members.retain(|m| session_of(m) != session);
    members.is_empty()
}

impl Drop for Registered {
    fn drop(&mut self) {
        let mut table = self.registry.lock();
        match &self.seat {
            Seat::Legacy(key) => {
                if table
                    .legacy
                    .get_mut(key)
                    .is_some_and(|members| leave(members, |m| m.session, self.session))
                {
                    table.legacy.remove(key);
                }
            }
            Seat::Command(key) => {
                if let Some(groups) = table.command.get_mut(key) {
                    for group in groups.iter_mut() {
                        leave(&mut group.members, |m| m.session, self.session);
                    }
                    groups.retain(|group| !group.members.is_empty());
                    if groups.is_empty() {
                        table.command.remove(key);
                    }
                }
            }
        }
    }
}

impl SessionSignals for SignalRegistry {
    fn signal(
        &self,
        instance: u64,
        key: &[u8],
        subject: Option<[u8; 32]>,
        flags: u32,
        bytes: &[u8],
    ) -> u32 {
        let table = self.lock();
        let Some(members) = table.legacy.get(&(instance, Box::<[u8]>::from(key))) else {
            return 0;
        };
        let mut accepted = 0;
        for member in members
            .iter()
            .filter(|m| subject.is_none() || m.subject == subject)
            .take(MAX_FANOUT as usize)
        {
            if self.send(&member.tx, flags, bytes) {
                accepted += 1;
            }
        }
        accepted
    }

    fn signal_command(
        &self,
        instance: u64,
        authority: &ChannelAuthority,
        key: &[u8],
        flags: u32,
        bytes: &[u8],
    ) -> u32 {
        if !authority.is_live() || key.is_empty() || key.len() > super::carrier::MAX_KEY {
            return 0;
        }
        let table = self.lock();
        let Some(group) = table
            .command
            .get(&(instance, authority.bucket(), Box::<[u8]>::from(key)))
            .and_then(|groups| groups.iter().find(|group| group.authority == *authority))
        else {
            return 0;
        };
        let mut accepted = 0;
        for member in group.members.iter().take(MAX_FANOUT as usize) {
            if !authority.is_live() {
                break;
            }
            if self.send(&member.tx, flags, bytes) {
                accepted += 1;
            }
        }
        accepted
    }
}

impl SignalRegistry {
    /// Hand one signal to one session's channel. `false`: the channel was full and the drop is counted.
    fn send(&self, tx: &mpsc::Sender<Signalled>, flags: u32, bytes: &[u8]) -> bool {
        let signalled = Signalled {
            flags,
            bytes: bytes.into(),
        };
        if tx.try_send(signalled).is_ok() {
            true
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}
