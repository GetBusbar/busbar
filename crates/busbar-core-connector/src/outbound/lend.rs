// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LENDING: which connection an open rides.
//!
//! One core owns its connections; nothing here is shared between cores and nothing is a table
//! that grows: a key's entry lives while the key has a connection or a dial, and goes with the
//! last of them.
//!
//! An open to a key, in this order:
//!
//! 1. a connection in use to the same key whose session multiplexes, is live, is not draining and
//!    has room: open a stream on it;
//! 2. a kept idle connection (one look at the socket, as before);
//! 3. a dial. While nothing is known about a destination each open dials. Once a connection to the
//!    key has stated that it multiplexes, an open that finds a dial in flight waits for it and
//!    joins.
//!
//! The key already separates owner, need, trust, seal and reach, so a stream is never opened on a
//! connection another registration's trust made.
//!
//! Room and draining are what the transport states (`STREAM_BUSY`, `NO_NEW_STREAMS`, `CLOSE`),
//! never a count the engine guessed.

use super::records::Session;

/// What a connection in use has said about itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InUse {
    /// The session stated `S_MULTIPLEX`.
    multiplexes: bool,
    /// The last head offered was answered `STREAM_BUSY` and no stream has ended since.
    busy: bool,
    /// `NO_NEW_STREAMS` or `CLOSE`: open streams finish, none may open.
    draining: bool,
    /// The connection failed or closed.
    gone: bool,
    /// Streams open on it.
    streams: u32,
}

impl InUse {
    /// From the `SESSION` record `begin` answered.
    pub(crate) const fn begun(session: &Session) -> Self {
        Self {
            multiplexes: session.multiplexes(),
            busy: false,
            draining: false,
            gone: false,
            streams: 0,
        }
    }

    /// A stream opened on it (`STREAM_OPENED`).
    pub(crate) fn opened(&mut self) {
        self.streams += 1;
        self.busy = false;
    }

    /// A head was answered `STREAM_BUSY`: nothing opened; the open goes to another connection.
    pub(crate) fn busy(&mut self) {
        self.busy = true;
    }

    /// A stream ended, was reset or was forgotten: the far end's limit has room again.
    pub(crate) fn stream_over(&mut self) {
        self.streams = self.streams.saturating_sub(1);
        self.busy = false;
    }

    /// `NO_NEW_STREAMS` or `CLOSE`.
    pub(crate) fn draining(&mut self) {
        self.draining = true;
    }

    /// The connection failed or closed.
    pub(crate) fn gone(&mut self) {
        self.gone = true;
        self.streams = 0;
    }

    /// A new stream may open on it now.
    pub(crate) const fn takes_a_stream(&self) -> bool {
        !self.gone && !self.draining && !self.busy && (self.multiplexes || self.streams == 0)
    }

    /// Another exchange may share it while one is open.
    pub(crate) const fn shares(&self) -> bool {
        self.multiplexes && self.takes_a_stream()
    }

    /// No stream is left and it can carry another exchange: it becomes idle, and its idle time
    /// starts now.
    pub(crate) const fn idle(&self) -> bool {
        self.streams == 0 && !self.gone && !self.draining
    }

    /// No stream is left and it can carry nothing more: it is closed.
    pub(crate) const fn finished(&self) -> bool {
        self.streams == 0 && (self.gone || self.draining)
    }

    /// Streams open on it.
    pub(crate) const fn streams(&self) -> u32 {
        self.streams
    }
}

/// What one key's entry knows, on one core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyEntry {
    /// A connection to this key stated that it multiplexes. Goes with the entry.
    multiplexes: bool,
    /// Connections to the key (in use or idle).
    conns: u32,
    /// Dials in flight.
    dialling: u32,
}

impl KeyEntry {
    /// A dial to the key began.
    pub(crate) fn dial_began(&mut self) {
        self.dialling += 1;
    }

    /// A dial ended in a session; `session` is what its `begin` stated.
    pub(crate) fn dial_opened(&mut self, session: &Session) {
        self.dialling = self.dialling.saturating_sub(1);
        self.conns += 1;
        self.multiplexes |= session.multiplexes();
    }

    /// A dial failed.
    pub(crate) fn dial_failed(&mut self) {
        self.dialling = self.dialling.saturating_sub(1);
    }

    /// A connection to the key is gone (closed, failed, or dropped from the idle set).
    pub(crate) fn conn_gone(&mut self) {
        self.conns = self.conns.saturating_sub(1);
    }

    /// Nothing is left of the key: its entry is removed, and with it what was known.
    pub(crate) const fn empty(&self) -> bool {
        self.conns == 0 && self.dialling == 0
    }

    /// A dial is in flight.
    pub(crate) const fn dialling(&self) -> bool {
        self.dialling > 0
    }
}

/// What an open does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lend {
    /// Open a stream on the connection in use at this index.
    Stream(usize),
    /// Take a kept idle connection.
    Idle,
    /// Wait for the dial in flight and open a stream on its connection.
    Join,
    /// Dial.
    Dial,
}

/// Choose. `entry` = the key's entry on this core (`None` = nothing is known of the key).
/// `in_use` = the key's connections in use, by index. `idle` = the key has a kept idle connection
/// this open may be lent (the caller applies the plaintext rule to that answer). `pinned` = the
/// open pins the addresses it may reach (`within`): it is never lent a connection it did not dial.
pub(crate) fn choose(
    entry: Option<&KeyEntry>,
    in_use: impl IntoIterator<Item = InUse>,
    idle: bool,
    pinned: bool,
) -> Lend {
    if pinned {
        return Lend::Dial;
    }
    if let Some(at) = in_use.into_iter().position(|conn| conn.shares()) {
        return Lend::Stream(at);
    }
    if idle {
        return Lend::Idle;
    }
    match entry {
        Some(entry) if entry.multiplexes && entry.dialling() => Lend::Join,
        _ => Lend::Dial,
    }
}

/// The idle bound per key on one core: the stated figure divided across the cores, at least 1.
/// A stated figure of 0 keeps none. This is v1.5.5's rule: its per-thread clients shared the
/// operator's figure the same way.
pub(crate) const fn idle_bound(stated: usize, cores: usize) -> usize {
    if stated == 0 {
        return 0;
    }
    let cores = if cores == 0 { 1 } else { cores };
    let share = stated / cores;
    if share == 0 {
        1
    } else {
        share
    }
}

#[cfg(test)]
mod tests {
    use super::super::records::S_MULTIPLEX;
    use super::*;

    fn h2() -> Session {
        Session {
            flags: S_MULTIPLEX,
            stream_window: 1 << 20,
            conn_window: 4 << 20,
            _r: 0,
        }
    }

    fn h1() -> Session {
        Session::default()
    }

    #[test]
    fn n_opens_to_one_multiplexing_far_end_ride_one_connection() {
        let mut entry = KeyEntry::default();
        assert_eq!(choose(None, [], false, false), Lend::Dial);
        entry.dial_began();
        entry.dial_opened(&h2());
        let mut conn = InUse::begun(&h2());
        conn.opened();
        for _ in 0..100 {
            assert_eq!(choose(Some(&entry), [conn], false, false), Lend::Stream(0));
            conn.opened();
        }
        assert_eq!(conn.streams(), 101);
    }

    #[test]
    fn a_connection_that_does_not_multiplex_is_never_shared() {
        let mut entry = KeyEntry::default();
        entry.dial_began();
        entry.dial_opened(&h1());
        let mut conn = InUse::begun(&h1());
        conn.opened();
        assert_eq!(choose(Some(&entry), [conn], false, false), Lend::Dial);
        assert_eq!(choose(Some(&entry), [conn], true, false), Lend::Idle);
    }

    #[test]
    fn a_first_burst_dials_until_the_key_is_known_to_multiplex() {
        let mut entry = KeyEntry::default();
        entry.dial_began();
        assert_eq!(
            choose(Some(&entry), [], false, false),
            Lend::Dial,
            "nothing is known of the destination yet"
        );
        entry.dial_began();
        entry.dial_opened(&h2());
        assert_eq!(
            choose(Some(&entry), [], false, false),
            Lend::Join,
            "the key multiplexes and a dial is in flight"
        );
        entry.dial_opened(&h2());
        assert_eq!(choose(Some(&entry), [], false, false), Lend::Dial);
    }

    #[test]
    fn busy_sends_the_open_elsewhere_until_a_stream_ends() {
        let mut conn = InUse::begun(&h2());
        conn.opened();
        conn.busy();
        assert_eq!(choose(None, [conn], false, false), Lend::Dial);
        conn.stream_over();
        conn.opened();
        assert_eq!(choose(None, [conn], false, false), Lend::Stream(0));
    }

    #[test]
    fn no_new_streams_the_next_open_dials_and_the_open_ones_finish() {
        let mut conn = InUse::begun(&h2());
        conn.opened();
        conn.opened();
        conn.draining();
        assert_eq!(choose(None, [conn], false, false), Lend::Dial);
        assert!(!conn.finished());
        conn.stream_over();
        conn.stream_over();
        assert!(conn.finished() && !conn.idle());
    }

    #[test]
    fn the_second_connection_is_chosen_when_the_first_has_no_room() {
        let mut full = InUse::begun(&h2());
        full.opened();
        full.busy();
        let mut open = InUse::begun(&h2());
        open.opened();
        assert_eq!(choose(None, [full, open], true, false), Lend::Stream(1));
    }

    #[test]
    fn a_pinned_open_is_never_lent_a_connection() {
        let mut conn = InUse::begun(&h2());
        conn.opened();
        assert_eq!(choose(None, [conn], true, true), Lend::Dial);
    }

    #[test]
    fn a_connection_with_no_stream_left_goes_idle() {
        let mut conn = InUse::begun(&h2());
        conn.opened();
        assert!(!conn.idle());
        conn.stream_over();
        assert!(conn.idle() && !conn.finished());
        conn.gone();
        assert!(conn.finished() && !conn.takes_a_stream());
    }

    #[test]
    fn what_was_known_of_a_key_goes_with_its_last_connection() {
        let mut entry = KeyEntry::default();
        entry.dial_began();
        assert!(!entry.empty());
        entry.dial_opened(&h2());
        entry.conn_gone();
        assert!(entry.empty(), "the entry is removed: no table that grows");
        let mut failed = KeyEntry::default();
        failed.dial_began();
        failed.dial_failed();
        assert!(failed.empty());
    }

    #[test]
    fn the_idle_bound_is_the_stated_figure_divided_by_cores_at_least_one() {
        assert_eq!(idle_bound(16, 16), 1);
        assert_eq!(idle_bound(32, 16), 2);
        assert_eq!(idle_bound(4, 16), 1);
        assert_eq!(idle_bound(0, 16), 0);
        assert_eq!(idle_bound(8, 0), 8);
        assert_eq!(idle_bound(8, 1), 8);
    }
}
