// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared channel account. Budget handles establish capacity, never invocation authority.
//! Root retains one process account and one instance account across serving/draining epochs.

use std::sync::{Arc, Mutex, PoisonError};

use super::frame::MAX_MESSAGE;

pub const UNIT_BYTES: usize = 16 << 20;
pub const REPLY_BYTES: usize = 2 * MAX_MESSAGE + 33;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Claim {
    pub bytes: usize,
    pub outbound_bytes: usize,
    pub leases: usize,
    pub keys: usize,
    pub completions: usize,
    pub asks: usize,
    pub messages: usize,
}

impl Claim {
    fn values(self) -> [usize; 7] {
        [
            self.bytes,
            self.outbound_bytes,
            self.leases,
            self.keys,
            self.completions,
            self.asks,
            self.messages,
        ]
    }

    fn from_values(
        [bytes, outbound_bytes, leases, keys, completions, asks, messages]: [usize; 7],
    ) -> Self {
        Self {
            bytes,
            outbound_bytes,
            leases,
            keys,
            completions,
            asks,
            messages,
        }
    }

    fn add(self, other: Self) -> Option<Self> {
        let a = self.values();
        let b = other.values();
        let mut next = [0; 7];
        for ((out, a), b) in next.iter_mut().zip(a).zip(b) {
            *out = a.checked_add(b)?;
        }
        Some(Self::from_values(next))
    }

    fn fits(self, limit: Self) -> bool {
        self.values()
            .into_iter()
            .zip(limit.values())
            .all(|(used, max)| used <= max)
    }

    fn subtract(self, other: Self) -> Self {
        let mut next = self.values();
        for (used, amount) in next.iter_mut().zip(other.values()) {
            // Only private move-only charges subtract their own previous reservation.
            *used -= amount;
        }
        Self::from_values(next)
    }

    fn reply_limit(self) -> Self {
        Self {
            bytes: self.bytes.min(REPLY_BYTES),
            outbound_bytes: self.outbound_bytes.min(MAX_MESSAGE + 1),
            completions: self.completions.min(1),
            messages: self.messages.min(1),
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityDenied;

#[derive(Clone, Copy)]
enum Class {
    General,
    Reply,
}

struct Counts {
    cap: Claim,
    general: Claim,
    reply: Claim,
}

impl Counts {
    fn addable(&self, amount: Claim, class: Class) -> bool {
        let (used, cap) = match class {
            Class::General => (self.general, self.cap.subtract(self.cap.reply_limit())),
            Class::Reply => (self.reply, self.cap.reply_limit()),
        };
        used.add(amount).is_some_and(|next| next.fits(cap))
    }

    fn used_mut(&mut self, class: Class) -> &mut Claim {
        match class {
            Class::General => &mut self.general,
            Class::Reply => &mut self.reply,
        }
    }
}

struct Account(Mutex<Counts>);

impl Account {
    fn new(cap: Claim) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Counts {
            cap,
            general: Claim::default(),
            reply: Claim::default(),
        })))
    }

    #[cfg(test)]
    fn used(&self) -> Claim {
        let counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        counts.general.add(counts.reply).unwrap()
    }
}

/// Construct once at process composition, then share through every instance and draining epoch.
pub struct ChannelBudget {
    account: Arc<Account>,
}

impl Default for ChannelBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelBudget {
    pub fn new() -> Self {
        Self {
            account: Account::new(Claim {
                bytes: 256 << 20,
                outbound_bytes: 256 << 20,
                leases: 1024,
                keys: 256,
                completions: 2048,
                asks: 2048,
                messages: 2048,
            }),
        }
    }

    /// One configured instance, retained across its runtime/config epochs.
    pub fn instance(&self) -> InstanceBudget {
        InstanceBudget {
            process: Arc::clone(&self.account),
            account: Account::new(Claim {
                bytes: 64 << 20,
                outbound_bytes: 64 << 20,
                leases: 256,
                keys: 64,
                completions: 512,
                asks: 512,
                messages: 512,
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn used(&self) -> Claim {
        self.account.used()
    }
}

#[derive(Clone)]
pub struct InstanceBudget {
    process: Arc<Account>,
    account: Arc<Account>,
}

impl InstanceBudget {
    /// One actual admitted unit. Clones retain this account; constructing another is not admission.
    pub fn unit(&self) -> UnitBudget {
        UnitBudget {
            scope: Scope {
                process: Arc::clone(&self.process),
                instance: Arc::clone(&self.account),
                unit: Some(Account::new(Claim {
                    bytes: UNIT_BYTES,
                    outbound_bytes: UNIT_BYTES,
                    leases: 8,
                    keys: usize::MAX,
                    completions: 16,
                    asks: 32,
                    messages: 64,
                })),
                channel: None,
            },
        }
    }

    /// Shared by every attachment to the same channel incarnation, not recreated for each unit.
    pub fn link(&self) -> LinkBudget {
        LinkBudget {
            instance: Arc::clone(&self.account),
            account: Account::new(Claim {
                outbound_bytes: 8 << 20,
                asks: 64,
                messages: 64,
                ..Claim::default()
            }),
        }
    }

    pub(super) fn accepts_unit(&self, unit: &UnitBudget) -> bool {
        Arc::ptr_eq(&self.account, &unit.scope.instance)
    }

    /// Only sessionless DEMUX control fallback may omit a unit. It never consumes protected reserve.
    pub(super) fn reserve_fallback(
        &self,
        link: &LinkBudget,
        bytes: usize,
        wire: usize,
    ) -> Result<(Charge, Charge), CapacityDenied> {
        if bytes > 4096 || !Arc::ptr_eq(&self.account, &link.instance) {
            return Err(CapacityDenied);
        }
        let scope = Scope {
            process: self.process.clone(),
            instance: self.account.clone(),
            unit: None,
            channel: None,
        };
        let payload = scope.reserve(
            Claim {
                bytes: bytes + 1,
                ..Claim::default()
            },
            Class::General,
        )?;
        let scope = Scope {
            process: self.process.clone(),
            instance: self.account.clone(),
            unit: None,
            channel: Some(link.account.clone()),
        };
        let outbound = scope.reserve(
            Claim {
                outbound_bytes: wire,
                messages: 1,
                ..Claim::default()
            },
            Class::General,
        )?;
        Ok((payload, outbound))
    }
}

#[derive(Clone)]
pub struct UnitBudget {
    scope: Scope,
}

#[derive(Clone)]
pub struct LinkBudget {
    instance: Arc<Account>,
    account: Arc<Account>,
}

impl LinkBudget {
    pub(crate) fn same_link(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.account, &other.account) && Arc::ptr_eq(&self.instance, &other.instance)
    }
}

impl UnitBudget {
    pub(super) fn accepts_link(&self, link: &LinkBudget) -> bool {
        Arc::ptr_eq(&self.scope.instance, &link.instance)
    }

    pub fn reserve(
        &self,
        claim: Claim,
        link: Option<&LinkBudget>,
    ) -> Result<Charge, CapacityDenied> {
        self.reserve_class(claim, link, Class::General)
    }

    pub(super) fn reserve_reply(
        &self,
        claim: Claim,
        link: Option<&LinkBudget>,
    ) -> Result<Charge, CapacityDenied> {
        self.reserve_class(claim, link, Class::Reply)
    }

    fn reserve_class(
        &self,
        claim: Claim,
        link: Option<&LinkBudget>,
        class: Class,
    ) -> Result<Charge, CapacityDenied> {
        let mut scope = self.scope.clone();
        if let Some(link) = link {
            if !Arc::ptr_eq(&scope.instance, &link.instance) {
                return Err(CapacityDenied);
            }
            scope.channel = Some(Arc::clone(&link.account));
        }
        scope.reserve(claim, class)
    }

    #[cfg(test)]
    pub(super) fn used(&self) -> Claim {
        self.scope.unit.as_ref().unwrap().used()
    }
}

#[derive(Clone)]
struct Scope {
    process: Arc<Account>,
    instance: Arc<Account>,
    unit: Option<Arc<Account>>,
    channel: Option<Arc<Account>>,
}

impl Scope {
    fn reserve(self, claim: Claim, class: Class) -> Result<Charge, CapacityDenied> {
        self.transaction(|accounts| {
            if !accounts.iter().all(|account| account.addable(claim, class)) {
                return Err(CapacityDenied);
            }
            for account in accounts {
                let used = account.used_mut(class);
                // Preflight above checks every dimension before any account is changed.
                if let Some(next) = used.add(claim) {
                    *used = next;
                }
            }
            Ok(())
        })?;
        Ok(Charge {
            scope: self,
            claim,
            class,
        })
    }

    fn transaction<R>(&self, f: impl FnOnce(&mut [&mut Counts]) -> R) -> R {
        // Every reservation, transfer and release uses this order. No callbacks, logging or
        // allocations run in the transaction; the process lock makes the multi-scope change atomic.
        let mut process = self
            .process
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut instance = self
            .instance
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut unit = self
            .unit
            .as_ref()
            .map(|account| account.0.lock().unwrap_or_else(PoisonError::into_inner));
        let mut channel = self
            .channel
            .as_ref()
            .map(|account| account.0.lock().unwrap_or_else(PoisonError::into_inner));
        match (unit.as_mut(), channel.as_mut()) {
            (Some(unit), Some(channel)) => f(&mut [&mut process, &mut instance, unit, channel]),
            (Some(unit), None) => f(&mut [&mut process, &mut instance, unit]),
            (None, Some(channel)) => f(&mut [&mut process, &mut instance, channel]),
            (None, None) => f(&mut [&mut process, &mut instance]),
        }
    }
}

/// Move-only reservation. A payload owner must destroy its backing before dropping this charge.
pub struct Charge {
    scope: Scope,
    claim: Claim,
    class: Class,
}

impl Charge {
    pub fn claim(&self) -> Claim {
        self.claim
    }

    pub fn split(&mut self, claim: Claim) -> Result<Self, CapacityDenied> {
        if !claim.fits(self.claim) {
            return Err(CapacityDenied);
        }
        self.claim = self.claim.subtract(claim);
        Ok(Self {
            scope: self.scope.clone(),
            claim,
            class: self.class,
        })
    }

    /// Reclassify the entire retained charge immediately, or leave every account unchanged.
    /// The caller must separately pre-admit all effects before publishing a general answer.
    pub fn reclassify_general(&mut self) -> Result<(), CapacityDenied> {
        if matches!(self.class, Class::General) {
            return Ok(());
        }
        self.scope.transaction(|accounts| {
            if !accounts
                .iter()
                .all(|account| account.addable(self.claim, Class::General))
            {
                return Err(CapacityDenied);
            }
            for account in accounts {
                if let Some(next) = account.general.add(self.claim) {
                    account.general = next;
                }
                account.reply = account.reply.subtract(self.claim);
            }
            Ok(())
        })?;
        self.class = Class::General;
        Ok(())
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.scope.transaction(|accounts| {
            for account in accounts {
                let used = account.used_mut(self.class);
                *used = used.subtract(self.claim);
            }
        });
    }
}
