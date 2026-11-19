// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT WAS SENT DECIDES: whether a failed attempt is sent again, whether the provider is charged
//! (its breaker), and what is recorded.
//!
//! The evidence is the attempt's own delivery state ([`super::delivery::Ledger::state_of`]), per
//! request on its own stream, never a count for the whole connection: on a shared connection one
//! request may be sent again and its neighbour not.
//!
//! | What was sent | How the attempt ended | The engine | Provider charged | Recorded |
//! |---|---|---|---|---|
//! | `none` | a kept connection turned out closed or closing | sends once on a fresh dial; the walk is not told | no | a redial |
//! | `none` | a fresh dial failed (connect, security, deadline) | the walk moves on | yes | failed, nothing sent |
//! | `none` | the proxy failed | the walk moves on | no | failed at the proxy |
//! | `part`, `whole` | the far end states it did not act on the stream | sends once on a fresh dial, never silently | no | both attempts, each with its state |
//! | `part`, `whole` | anything else | never sent again to this provider; the walk decides | yes | the state |
//!
//! Bounds: one redial per exchange; a redial is always a fresh dial, never another kept
//! connection. After the one redial every failure is the walk's.
//!
//! Money: `none` is proof the provider received nothing, so nothing can be billed twice. The
//! fourth row rests on the far end's own statement. The fifth row is where a provider may have
//! spent tokens on a request the engine then failed over: the state in the record is what lets
//! the operator see it.

use super::delivery::State;

/// How an attempt ended, as the dial saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    /// The connection closed, was closing (`NO_NEW_STREAMS`, `CLOSE`), was reset or failed.
    Connection,
    /// The connect, the connection security or the open deadline failed: no session ever began.
    Dial,
    /// The operator's proxy failed or refused the tunnel.
    Proxy,
    /// The far end reset the stream stating it did not act on it (`RESET_NOT_PROCESSED`).
    NotProcessed,
    /// The request's own deadline or budget passed.
    Deadline,
    /// The engine's own head was refused by the transport: nobody's fault but the engine's.
    Local,
}

/// What is written about the attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recorded {
    /// The request was sent again on a fresh dial after a kept connection turned out closed.
    /// Nothing had left; a redial is counted.
    Redial,
    /// The attempt failed with nothing sent.
    NothingSent,
    /// The attempt failed at the operator's proxy.
    AtProxy,
    /// A request that had left was refused unprocessed by the far end and sent again: both
    /// attempts are recorded, this one with the state it reached.
    RefusedUnprocessed(State),
    /// The attempt failed having sent this much: the provider may have worked on it.
    Failed(State),
    /// The engine's own fault.
    Local,
}

/// What the engine does about a failed attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    /// Send the same request once more, on a fresh dial to the same provider.
    pub(crate) resend: bool,
    /// Charge the provider's breaker.
    pub(crate) charge: bool,
    /// Tell the walk the attempt failed (it may move to the next provider).
    pub(crate) walk: bool,
    /// What the attempt's record says.
    pub(crate) record: Recorded,
}

/// Decide. `sent` = the attempt's delivery state when it ended. `kept` = the connection was not
/// dialled for this attempt (a kept idle one, or one in use that the request joined). `redialled`
/// = this exchange has already been sent again once.
pub(crate) const fn decide(sent: State, ended: Ended, kept: bool, redialled: bool) -> Decision {
    let nothing = matches!(sent, State::None);
    match ended {
        Ended::Local => Decision {
            resend: false,
            charge: false,
            walk: true,
            record: Recorded::Local,
        },
        Ended::Proxy => Decision {
            resend: false,
            charge: false,
            walk: true,
            record: if nothing {
                Recorded::AtProxy
            } else {
                Recorded::Failed(sent)
            },
        },
        Ended::Connection | Ended::NotProcessed if nothing && kept && !redialled => Decision {
            resend: true,
            charge: false,
            walk: false,
            record: Recorded::Redial,
        },
        Ended::NotProcessed if !nothing && !redialled => Decision {
            resend: true,
            charge: false,
            walk: false,
            record: Recorded::RefusedUnprocessed(sent),
        },
        Ended::Connection | Ended::NotProcessed | Ended::Dial | Ended::Deadline => Decision {
            resend: false,
            charge: true,
            walk: true,
            record: if nothing {
                Recorded::NothingSent
            } else {
                Recorded::Failed(sent)
            },
        },
    }
}

/// Whether the engine must still hold the request's head (and its sealed values) to be able to
/// send it again. Until the attempt's state leaves `none` (rows one and three); on a multiplexed
/// session, until the answer's head arrives (row four: a refused stream can be reported after the
/// whole request left). Never after the one redial.
pub(crate) const fn keeps_head(
    sent: State,
    multiplexed: bool,
    answered: bool,
    redialled: bool,
) -> bool {
    if redialled || answered {
        return false;
    }
    matches!(sent, State::None) || multiplexed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_connection_closed_before_any_byte_is_redialled_and_nobody_is_charged() {
        let decision = decide(State::None, Ended::Connection, true, false);
        assert_eq!(
            decision,
            Decision {
                resend: true,
                charge: false,
                walk: false,
                record: Recorded::Redial
            }
        );
    }

    #[test]
    fn closed_after_the_head_was_accepted_is_never_sent_again() {
        for sent in [State::Part, State::Whole] {
            let decision = decide(sent, Ended::Connection, true, false);
            assert!(!decision.resend);
            assert!(decision.charge && decision.walk);
            assert_eq!(decision.record, Recorded::Failed(sent));
        }
    }

    #[test]
    fn a_fresh_dial_that_fails_is_the_walks_and_is_charged() {
        let decision = decide(State::None, Ended::Dial, false, false);
        assert_eq!(
            decision,
            Decision {
                resend: false,
                charge: true,
                walk: true,
                record: Recorded::NothingSent
            }
        );
        // A fresh connection that closes before any byte is not the keep-alive race.
        assert!(!decide(State::None, Ended::Connection, false, false).resend);
    }

    #[test]
    fn a_proxy_failure_charges_no_provider() {
        let decision = decide(State::None, Ended::Proxy, false, false);
        assert_eq!(
            decision,
            Decision {
                resend: false,
                charge: false,
                walk: true,
                record: Recorded::AtProxy
            }
        );
    }

    #[test]
    fn a_stream_the_far_end_refused_unprocessed_is_sent_again_and_recorded() {
        for sent in [State::Part, State::Whole] {
            let decision = decide(sent, Ended::NotProcessed, true, false);
            assert!(decision.resend && !decision.charge && !decision.walk);
            assert_eq!(decision.record, Recorded::RefusedUnprocessed(sent));
        }
        // Also on a connection dialled for it: the statement is the far end's, not a guess.
        assert!(decide(State::Whole, Ended::NotProcessed, false, false).resend);
    }

    #[test]
    fn two_requests_on_one_connection_differ() {
        let unsent = decide(State::None, Ended::Connection, true, false);
        let sent = decide(State::Part, Ended::Connection, true, false);
        assert!(unsent.resend && !unsent.charge);
        assert!(!sent.resend && sent.charge);
    }

    #[test]
    fn there_is_one_redial_per_exchange() {
        for ended in [Ended::Connection, Ended::NotProcessed, Ended::Dial] {
            for sent in [State::None, State::Part, State::Whole] {
                let decision = decide(sent, ended, true, true);
                assert!(!decision.resend, "{ended:?} {sent:?}");
                assert!(decision.walk && decision.charge);
            }
        }
    }

    #[test]
    fn a_deadline_is_never_a_redial() {
        let decision = decide(State::None, Ended::Deadline, true, false);
        assert!(!decision.resend && decision.charge && decision.walk);
    }

    #[test]
    fn the_engines_own_refused_head_charges_nobody() {
        let decision = decide(State::None, Ended::Local, true, false);
        assert_eq!(
            decision,
            Decision {
                resend: false,
                charge: false,
                walk: true,
                record: Recorded::Local
            }
        );
    }

    #[test]
    fn the_head_is_kept_only_while_a_redial_is_possible() {
        assert!(keeps_head(State::None, false, false, false));
        assert!(!keeps_head(State::Part, false, false, false));
        assert!(
            keeps_head(State::Whole, true, false, false),
            "a refused stream can be reported after the whole request left"
        );
        assert!(!keeps_head(State::Whole, true, true, false));
        assert!(!keeps_head(State::None, true, false, true));
    }
}
