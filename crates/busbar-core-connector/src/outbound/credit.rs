// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CREDIT: what a session may make the engine hold, and how a stream's window reopens.
//!
//! A session that stated `S_MULTIPLEX` reopens a stream's far-end window only by the credit the
//! engine gives it (`emit` piece `CONSUMED`: the stream, and the count of inbound body bytes its
//! reader has taken). It never reopens it on its own when it hands the engine a body piece. So
//! the bytes the engine can be made to hold for one stream are bounded by the stream window the
//! session stated, and for the connection by its connection window: figures the engine derives,
//! with no number of its own. A slow reader then stalls its own stream and nothing else; the
//! engine never stops reading a connection other requests share.
//!
//! A session that did not state `S_MULTIPLEX` gets no credit calls: the engine stops reading the
//! socket while its one reader is behind, which is exact for one stream.
//!
//! The same windows bound what the engine queues to write: per stream the stream window, per
//! connection the connection window, so one request with a full window cannot fill the socket
//! queue and starve its neighbours.
//!
//! Nothing here allocates. One [`Credit`] per connection, one [`StreamCredit`] in each stream's
//! own slot.

use super::records::Session;

/// The engine gives credit once this share of a window is owed: one half, the proportion HTTP/2
/// libraries use (a window update per piece would be one call per piece; one at the window's end
/// would stall the sender). It is the engine's choice, outside the contract: the bound on what
/// the engine holds is the window whatever this figure is.
const GRANT_SHARE: u64 = 2;

/// The transport handed the engine more than the windows it stated allow: it reopened a window on
/// its own. FAULT BadRecords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Overrun {
    /// One stream's window.
    Stream,
    /// The connection's window.
    Connection,
}

/// One stream's share of the windows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StreamCredit {
    /// Body bytes handed up and not yet taken by the stream's reader.
    held: u64,
    /// Bytes the reader took that the transport has not been told about.
    owed: u64,
}

impl StreamCredit {
    /// Bytes waiting for the reader.
    pub(crate) const fn held(&self) -> u64 {
        self.held
    }
}

/// The connection's windows.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Credit {
    session: Session,
    /// Held and owed bytes over every stream: what stands against the connection window.
    outstanding: u64,
    /// The owed part of `outstanding`.
    owed: u64,
}

impl Credit {
    /// From the `SESSION` record `begin` answered.
    pub(crate) const fn new(session: Session) -> Self {
        Self {
            session,
            outstanding: 0,
            owed: 0,
        }
    }

    /// The session carries several streams at once.
    pub(crate) const fn multiplexes(&self) -> bool {
        self.session.multiplexes()
    }

    /// The transport handed up `len` inbound body bytes of a stream.
    ///
    /// # Errors
    /// On a multiplexed session, the window the bytes overrun. Nothing is counted then.
    pub(crate) fn received(&mut self, stream: &mut StreamCredit, len: u32) -> Result<(), Overrun> {
        let len = u64::from(len);
        if self.multiplexes() {
            if stream.held + stream.owed + len > u64::from(self.session.stream_window) {
                return Err(Overrun::Stream);
            }
            if self.outstanding + len > u64::from(self.session.conn_window) {
                return Err(Overrun::Connection);
            }
        }
        stream.held += len;
        self.outstanding += len;
        Ok(())
    }

    /// The stream's reader took `len` of its held bytes. `Some(n)` = give the transport
    /// `CONSUMED(stream, n)` now.
    pub(crate) fn taken(&mut self, stream: &mut StreamCredit, len: u64) -> Option<u64> {
        let len = len.min(stream.held);
        stream.held -= len;
        if !self.multiplexes() {
            self.outstanding -= len;
            return None;
        }
        stream.owed += len;
        self.owed += len;
        let stream_due = stream.owed >= u64::from(self.session.stream_window) / GRANT_SHARE;
        // Many streams each owed a little can close the connection window with no stream due:
        // the connection's own share is checked too.
        let conn_due = self.owed >= u64::from(self.session.conn_window) / GRANT_SHARE;
        if stream.owed > 0 && (stream_due || conn_due) {
            Some(self.grant(stream))
        } else {
            None
        }
    }

    /// The stream is over (ended, reset, or its reader left): what it held is dropped, and what it
    /// owes is given at once so the connection window does not stay closed behind a stream that is
    /// gone. `Some(n)` = give the transport `CONSUMED(stream, n)` now.
    pub(crate) fn over(&mut self, stream: &mut StreamCredit) -> Option<u64> {
        let dropped = std::mem::take(&mut stream.held);
        if !self.multiplexes() {
            self.outstanding -= dropped;
            return None;
        }
        stream.owed += dropped;
        self.owed += dropped;
        (stream.owed > 0).then(|| self.grant(stream))
    }

    fn grant(&mut self, stream: &mut StreamCredit) -> u64 {
        let given = std::mem::take(&mut stream.owed);
        self.owed -= given;
        self.outstanding -= given;
        given
    }

    /// Whether the engine reads the socket now. A multiplexed session is always read: the windows
    /// it stated bound what can arrive. A session with one stream states no window: the engine
    /// reads the socket only when its one reader holds nothing, so what it holds is what one read
    /// of the socket became, and no figure of the engine's own is needed.
    pub(crate) fn reads_socket(&self) -> bool {
        self.multiplexes() || self.outstanding == 0
    }

    /// How many body bytes the engine may emit on a stream now. `stream_unsent` = the stream's
    /// bytes queued and not yet taken by the socket; `conn_unsent` = the same over the connection.
    /// A session with one stream states no window: its body goes while the socket queue is empty
    /// (`u64::MAX`: the caller's own piece size is the bound) and waits while it is not.
    pub(crate) fn write_room(&self, stream_unsent: u64, conn_unsent: u64) -> u64 {
        if !self.multiplexes() {
            return if conn_unsent == 0 { u64::MAX } else { 0 };
        }
        let by_stream = u64::from(self.session.stream_window).saturating_sub(stream_unsent);
        let by_conn = u64::from(self.session.conn_window).saturating_sub(conn_unsent);
        by_stream.min(by_conn)
    }

    /// The most bytes the session can make the engine hold for one stream.
    pub(crate) const fn stream_bound(&self) -> u32 {
        self.session.stream_window
    }

    /// The most bytes the session can make the engine hold over the connection.
    pub(crate) const fn connection_bound(&self) -> u32 {
        self.session.conn_window
    }

    /// Bytes standing against the connection window.
    pub(crate) const fn outstanding(&self) -> u64 {
        self.outstanding
    }
}

#[cfg(test)]
mod tests {
    use super::super::records::S_MULTIPLEX;
    use super::*;

    const MIB: u32 = 1024 * 1024;

    fn h2() -> Credit {
        Credit::new(Session {
            flags: S_MULTIPLEX,
            stream_window: MIB,
            conn_window: 4 * MIB,
            _r: 0,
        })
    }

    fn h1() -> Credit {
        Credit::new(Session {
            flags: 0,
            stream_window: 0,
            conn_window: 0,
            _r: 0,
        })
    }

    #[test]
    fn a_slow_reader_holds_at_most_its_stream_window() {
        let mut credit = h2();
        let mut slow = StreamCredit::default();
        credit.received(&mut slow, MIB).unwrap();
        assert_eq!(
            credit.received(&mut slow, 1),
            Err(Overrun::Stream),
            "the transport reopened the window on its own"
        );
        assert_eq!(slow.held(), u64::from(MIB));
    }

    #[test]
    fn a_slow_reader_does_not_stall_another_stream() {
        let mut credit = h2();
        let (mut slow, mut fast) = (StreamCredit::default(), StreamCredit::default());
        credit.received(&mut slow, MIB).unwrap();
        assert!(credit.reads_socket(), "a shared connection is always read");
        for _ in 0..16 {
            credit.received(&mut fast, MIB / 2).unwrap();
            assert_eq!(
                credit.taken(&mut fast, u64::from(MIB / 2)),
                Some(u64::from(MIB / 2))
            );
        }
        assert_eq!(credit.outstanding(), u64::from(MIB));
    }

    #[test]
    fn credit_is_given_at_half_the_window_not_per_piece() {
        let mut credit = h2();
        let mut stream = StreamCredit::default();
        credit.received(&mut stream, MIB).unwrap();
        let quarter = u64::from(MIB / 4);
        assert_eq!(credit.taken(&mut stream, quarter), None);
        assert_eq!(credit.taken(&mut stream, quarter), Some(2 * quarter));
        assert_eq!(credit.taken(&mut stream, quarter), None);
    }

    #[test]
    fn owed_bytes_still_stand_against_the_window() {
        let mut credit = h2();
        let mut stream = StreamCredit::default();
        credit.received(&mut stream, MIB).unwrap();
        assert_eq!(credit.taken(&mut stream, 1024), None);
        assert_eq!(
            credit.received(&mut stream, 1024),
            Err(Overrun::Stream),
            "no credit was given for those bytes yet"
        );
    }

    #[test]
    fn many_streams_owing_a_little_cannot_close_the_connection_window() {
        let mut credit = h2();
        let mut streams = [StreamCredit::default(); 8];
        let some = MIB / 2 - 1024;
        let mut grants = 0_u64;
        for stream in &mut streams {
            credit.received(stream, some).unwrap();
            if let Some(given) = credit.taken(stream, u64::from(some)) {
                grants += given;
            }
        }
        assert!(
            grants > 0,
            "no stream reached its own half, the connection's half was reached"
        );
        assert!(credit.outstanding() < u64::from(2 * MIB));
    }

    #[test]
    fn the_connection_window_is_a_bound_too() {
        let mut credit = h2();
        let mut streams = [StreamCredit::default(); 5];
        for stream in &mut streams[..4] {
            credit.received(stream, MIB).unwrap();
        }
        assert_eq!(
            credit.received(&mut streams[4], 1),
            Err(Overrun::Connection)
        );
    }

    #[test]
    fn a_stream_that_is_over_gives_back_everything_at_once() {
        let mut credit = h2();
        let mut stream = StreamCredit::default();
        credit.received(&mut stream, 4096).unwrap();
        assert_eq!(credit.taken(&mut stream, 96), None);
        assert_eq!(credit.over(&mut stream), Some(4096));
        assert_eq!(credit.outstanding(), 0);
        assert_eq!(credit.over(&mut stream), None);
    }

    #[test]
    fn a_session_with_one_stream_gets_no_credit_and_stops_the_socket() {
        let mut credit = h1();
        let mut stream = StreamCredit::default();
        credit.received(&mut stream, MIB).unwrap();
        assert!(!credit.reads_socket());
        assert_eq!(credit.taken(&mut stream, u64::from(MIB)), None);
        assert!(credit.reads_socket());
        credit.received(&mut stream, 2 * MIB).unwrap();
        assert_eq!(credit.over(&mut stream), None);
        assert_eq!(credit.outstanding(), 0);
    }

    #[test]
    fn one_request_cannot_fill_the_socket_queue() {
        let credit = h2();
        assert_eq!(credit.write_room(0, 0), u64::from(MIB));
        assert_eq!(credit.write_room(u64::from(MIB), u64::from(MIB)), 0);
        assert_eq!(
            credit.write_room(0, u64::from(MIB)),
            u64::from(MIB),
            "a neighbour's full window leaves this stream its own"
        );
        assert_eq!(credit.write_room(0, u64::from(4 * MIB) - 10), 10);
    }

    #[test]
    fn taking_more_than_is_held_takes_what_is_held() {
        let mut credit = h2();
        let mut stream = StreamCredit::default();
        credit.received(&mut stream, 10).unwrap();
        credit.taken(&mut stream, 1_000);
        assert_eq!(stream.held(), 0);
        assert_eq!(credit.over(&mut stream), Some(10));
    }

    #[test]
    fn a_session_with_one_stream_sends_its_body_while_the_socket_queue_is_empty() {
        let credit = h1();
        assert_eq!(credit.write_room(0, 0), u64::MAX);
        assert_eq!(credit.write_room(0, 1), 0);
        assert_eq!((credit.stream_bound(), credit.connection_bound()), (0, 0));
    }
}
