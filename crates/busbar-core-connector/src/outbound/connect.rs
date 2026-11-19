// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEVERAL ADDRESSES FOR ONE NAME: which is connected to, when.
//!
//! * Each address gets a share of the time left: (time left) / (addresses left). An attempt that
//!   has neither connected nor failed in its share is dropped and the next begins. One dead
//!   address no longer eats the whole open deadline.
//! * When the answer holds both address families, the first address of the other family is
//!   started [`FAMILY_DELAY`] after the first; the first to connect wins and the other socket is
//!   closed. At most two sockets are in flight.
//! * Every address is one the guard admitted; the order is the resolver's.
//!
//! This part owns no socket and reads no clock: the dial tells it what happened and when, and it
//! answers what to do. Times are the dial's one monotonic reading, in nanoseconds.

use std::net::SocketAddr;

/// The delay before the other address family is started: 250 ms, the "Connection Attempt Delay"
/// RFC 8305 section 5 recommends.
pub(crate) const FAMILY_DELAY_NS: u64 = 250_000_000;

/// One of the two sockets a race may have in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    /// The lane the first address started on.
    First,
    /// The lane of the other address family.
    Second,
}

/// What the dial does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Begin a connect to this address on this lane (closing the lane's socket if it has one).
    Connect(Lane, SocketAddr),
    /// Nothing to begin: wake at this time unless a socket becomes ready first.
    Wait(u64),
    /// No address is left and nothing is in flight: the dial failed at the connect.
    Failed,
}

#[derive(Clone, Copy, Debug)]
struct Flight {
    /// The attempt is dropped at this time.
    until: u64,
}

/// THE RACE over one name's admitted addresses.
#[derive(Debug)]
pub(crate) struct Race {
    /// The addresses not yet tried, in the resolver's order.
    left: Vec<SocketAddr>,
    /// The open deadline.
    deadline: u64,
    /// When the other family may start; `None` once it has, or when there is no other family.
    family_at: Option<u64>,
    /// The family of the first address tried.
    first_v4: bool,
    first: Option<Flight>,
    second: Option<Flight>,
    won: bool,
}

impl Race {
    /// A race over `addrs` (the judged address first, then the name's other admitted addresses,
    /// in the resolver's order), beginning at `now` and bounded by `deadline`.
    pub(crate) fn new(addrs: &[SocketAddr], now: u64, deadline: u64) -> Self {
        let first_v4 = addrs.first().is_some_and(SocketAddr::is_ipv4);
        let both = addrs.iter().any(|addr| addr.is_ipv4() != first_v4);
        Self {
            // Kept reversed: the next address is popped off the end.
            left: addrs.iter().rev().copied().collect(),
            deadline,
            family_at: both.then(|| now.saturating_add(FAMILY_DELAY_NS)),
            first_v4,
            first: None,
            second: None,
            won: false,
        }
    }

    /// When an attempt begun at `now` is dropped: (time left) / (addresses left, the one about to
    /// begin included). Asked before the address is taken off the list.
    fn share(&self, now: u64) -> u64 {
        let left = self.deadline.saturating_sub(now);
        let waiting = (self.left.len() as u64).max(1);
        now.saturating_add(left / waiting)
    }

    /// The next address for the first lane: the resolver's order.
    fn take_next(&mut self) -> Option<SocketAddr> {
        self.left.pop()
    }

    /// The first address of the other family, taken out of its place.
    fn take_other_family(&mut self) -> Option<SocketAddr> {
        let at = self
            .left
            .iter()
            .rposition(|addr| addr.is_ipv4() != self.first_v4)?;
        Some(self.left.remove(at))
    }

    fn lane(&mut self, lane: Lane) -> &mut Option<Flight> {
        match lane {
            Lane::First => &mut self.first,
            Lane::Second => &mut self.second,
        }
    }

    /// What to do at `now`. Called when the race begins, after every [`Self::failed`], and when a
    /// [`Step::Wait`] time passes. A `Connect` answer is acted on and `step` is asked again.
    pub(crate) fn step(&mut self, now: u64) -> Step {
        if self.won {
            return Step::Wait(self.deadline);
        }
        // An attempt past its share is dropped: its lane is free.
        for lane in [Lane::First, Lane::Second] {
            if self.lane(lane).is_some_and(|flight| now >= flight.until) {
                *self.lane(lane) = None;
            }
        }
        if now >= self.deadline {
            return Step::Failed;
        }
        if self.first.is_none() {
            // The second lane's address counts against the shares while it is in flight.
            let until = self.share(now);
            if let Some(addr) = self.take_next() {
                self.first = Some(Flight { until });
                return Step::Connect(Lane::First, addr);
            }
        }
        if self.second.is_none() && self.family_at.is_some_and(|at| now >= at) {
            self.family_at = None;
            let until = self.share(now);
            if let Some(addr) = self.take_other_family() {
                self.second = Some(Flight { until });
                return Step::Connect(Lane::Second, addr);
            }
        }
        let mut wake = self.deadline;
        for flight in [self.first, self.second].into_iter().flatten() {
            wake = wake.min(flight.until);
        }
        if let Some(at) = self.family_at.filter(|_| self.second.is_none()) {
            wake = wake.min(at);
        }
        if self.first.is_none() && self.second.is_none() && self.left.is_empty() {
            return Step::Failed;
        }
        Step::Wait(wake)
    }

    /// The connect on `lane` failed (refused, unreachable): its lane is free, and the other family
    /// need not wait any longer.
    pub(crate) fn failed(&mut self, lane: Lane, now: u64) {
        *self.lane(lane) = None;
        if self.family_at.is_some() {
            self.family_at = Some(now);
        }
    }

    /// The connect on `lane` succeeded: it wins. The dial closes the other lane's socket.
    pub(crate) fn connected(&mut self, lane: Lane) -> Option<Lane> {
        self.won = true;
        let other = match lane {
            Lane::First => Lane::Second,
            Lane::Second => Lane::First,
        };
        let loser = self.lane(other).take().map(|_| other);
        self.left.clear();
        loser
    }

    /// Sockets in flight.
    pub(crate) fn in_flight(&self) -> usize {
        usize::from(self.first.is_some()) + usize::from(self.second.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    fn v4(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 443))
    }

    fn v6(n: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, n], 443))
    }

    #[test]
    fn one_address_has_the_whole_deadline() {
        let mut race = Race::new(&[v4(1)], 0, 10 * SEC);
        assert_eq!(race.step(0), Step::Connect(Lane::First, v4(1)));
        assert_eq!(race.step(0), Step::Wait(10 * SEC));
        assert_eq!(race.step(10 * SEC), Step::Failed);
    }

    #[test]
    fn a_silent_first_address_is_dropped_at_its_share_and_the_second_begins() {
        let mut race = Race::new(&[v4(1), v4(2)], 0, 10 * SEC);
        assert_eq!(race.step(0), Step::Connect(Lane::First, v4(1)));
        assert_eq!(race.step(0), Step::Wait(5 * SEC), "half the time each");
        assert_eq!(race.step(5 * SEC), Step::Connect(Lane::First, v4(2)));
        assert_eq!(
            race.step(5 * SEC),
            Step::Wait(10 * SEC),
            "the last address has all that is left"
        );
        assert_eq!(race.connected(Lane::First), None);
    }

    #[test]
    fn a_refused_connect_moves_on_at_once() {
        let mut race = Race::new(&[v4(1), v4(2), v4(3)], 0, 9 * SEC);
        assert_eq!(race.step(0), Step::Connect(Lane::First, v4(1)));
        race.failed(Lane::First, SEC);
        assert_eq!(race.step(SEC), Step::Connect(Lane::First, v4(2)));
        assert_eq!(race.step(SEC), Step::Wait(5 * SEC), "half of the 8 s left");
        race.failed(Lane::First, 2 * SEC);
        assert_eq!(race.step(2 * SEC), Step::Connect(Lane::First, v4(3)));
        race.failed(Lane::First, 3 * SEC);
        assert_eq!(race.step(3 * SEC), Step::Failed);
    }

    #[test]
    fn the_other_family_starts_after_the_delay_and_the_first_to_connect_wins() {
        let mut race = Race::new(&[v6(1), v6(2), v4(1)], 0, 10 * SEC);
        assert_eq!(race.step(0), Step::Connect(Lane::First, v6(1)));
        assert_eq!(race.step(0), Step::Wait(FAMILY_DELAY_NS));
        assert_eq!(
            race.step(FAMILY_DELAY_NS),
            Step::Connect(Lane::Second, v4(1)),
            "the first address of the other family, out of its place in the order"
        );
        assert_eq!(race.in_flight(), 2);
        assert_eq!(
            race.connected(Lane::Second),
            Some(Lane::First),
            "the silent socket is closed"
        );
        assert_eq!(race.in_flight(), 1);
    }

    #[test]
    fn a_refused_first_family_starts_the_other_without_the_delay() {
        let mut race = Race::new(&[v6(1), v4(1)], 0, 10 * SEC);
        assert_eq!(race.step(0), Step::Connect(Lane::First, v6(1)));
        race.failed(Lane::First, 1_000);
        assert_eq!(race.step(1_000), Step::Connect(Lane::First, v4(1)));
    }

    #[test]
    fn one_family_never_has_two_sockets() {
        let mut race = Race::new(&[v4(1), v4(2), v4(3)], 0, 9 * SEC);
        assert_eq!(race.step(0), Step::Connect(Lane::First, v4(1)));
        assert_eq!(race.step(FAMILY_DELAY_NS), Step::Wait(3 * SEC));
        assert_eq!(race.in_flight(), 1);
    }

    #[test]
    fn at_most_two_sockets_are_in_flight() {
        let mut race = Race::new(&[v6(1), v4(1), v6(2), v4(2)], 0, 8 * SEC);
        let mut now = 0;
        let mut most = 0;
        loop {
            match race.step(now) {
                Step::Connect(..) => most = most.max(race.in_flight()),
                Step::Wait(at) => now = at,
                Step::Failed => break,
            }
        }
        assert_eq!(most, 2);
        assert!(now <= 8 * SEC);
    }

    #[test]
    fn no_address_fails_at_once() {
        assert_eq!(Race::new(&[], 0, SEC).step(0), Step::Failed);
    }
}
