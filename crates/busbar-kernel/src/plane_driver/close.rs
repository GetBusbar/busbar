// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::ticket::Ticket;

use super::cancel::{poll_cancel, CancelFuture};
use busbar_contract::caps::PrincipalId;

use super::{PlaneDriver, PlaneUnits};

/// Where a unit stands with its plane's closing call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Close {
    /// `arrive` has not crossed for it: the plane holds nothing of it.
    #[default]
    NotArrived,
    /// `arrive` crossed and no closing call has: the plane holds the unit.
    Open,
    /// Its closing call crossed, or is owed to the driver's sweep, which makes it.
    Closed,
}

impl Close {
    pub(crate) fn closed(&mut self) {
        if *self == Close::Open {
            *self = Close::Closed;
        }
    }
}

pub(crate) struct Owed {
    unit: u64,

    principal: Option<PrincipalId>,
    ticket: Option<Ticket>,
    cancel: Option<CancelFuture>,
}

impl PlaneDriver {
    pub(crate) fn close_owed(&self) {
        let count = self.lock_owed().len();
        for _ in 0..count {
            let Some(owed) = self.lock_owed().pop() else {
                return;
            };
            let mut paying = Paying {
                driver: self,
                owed: Some(owed),
            };
            let owed = paying.owed.as_mut().expect("owned debt");
            if owed.ticket.is_none() {
                let Some(ticket) = self.calls.mint() else {
                    return;
                };
                self.calls.bind_unit(ticket, owed.unit);
                owed.ticket = Some(ticket);
            }
            if owed.cancel.is_none() {
                owed.cancel = Some(self.cancel_unit(owed.ticket.expect("owned ticket"), owed.unit));
            }
            let cancelled = match poll_cancel(owed.cancel.as_mut().expect("queued cancel")) {
                std::task::Poll::Pending => {
                    let owed = paying.owed.take().expect("pending debt");
                    self.lock_owed().insert(0, owed);
                    continue;
                }
                std::task::Poll::Ready(cancelled) => cancelled,
            };
            let owed = paying.owed.take().expect("paid debt");
            if let Some(ticket) = owed.ticket {
                self.calls.recycle(ticket);
            }
            if let Some(cancelled) = cancelled {
                self.fold_writes(&cancelled.writes, owed.principal.as_ref());
            }
        }
    }

    pub fn owed_closes(&self) -> usize {
        self.lock_owed().len()
    }

    fn lock_owed(&self) -> std::sync::MutexGuard<'_, Vec<Owed>> {
        self.owed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct Paying<'d> {
    driver: &'d PlaneDriver,
    owed: Option<Owed>,
}

impl Drop for Paying<'_> {
    fn drop(&mut self) {
        if let Some(owed) = self.owed.take() {
            self.driver.lock_owed().push(owed);
        }
    }
}

impl<S, F, C> Drop for PlaneUnits<'_, S, F, C> {
    fn drop(&mut self) {
        let st = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.close != Close::Open {
            return;
        }
        st.close = Close::Closed;
        let owed = Owed {
            unit: st.unit,
            principal: st.principal.clone(),
            ticket: None,
            cancel: None,
        };
        self.driver.lock_owed().push(owed);
    }
}
