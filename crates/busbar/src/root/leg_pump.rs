// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND HALF OF A RELAYED SESSION'S UPSTREAM LEG: what the provider says, on its way back to
//! the client.
//!
//! A relayed session has two pumps and it has to. The client's own
//! ([`busbar_transport_ws::mount::pump`], or any wire's) is a strict alternation — read one frame,
//! drive it, write the answers, read again — and that alternation is the backpressure posture the
//! whole mount is built on. A leg's replies do not arrive in that rhythm and must not be made to: a
//! provider that is speaking has nothing to do with whether the client has spoken, and a
//! composition that waited for the client's next frame before reading the provider's reply would
//! have built a half-duplex session out of two full-duplex sockets.
//!
//! So the leg gets a pump of its own, on its own task, and the two meet at exactly one place: the
//! driver's slot for the session. That is where the leg's codec state is, where the client's
//! offering end is, and where the session's ending is decided — and because both pumps reach it
//! through the driver's own lock, one session's two directions are serialised against each other
//! without either pump knowing the other exists.
//!
//! ## What this file does NOT do
//!
//! It does not read the bytes, it does not know what protocol they are, and it does not write them:
//! [`SessionLoopDriver::upstream`] hands them to the plane and the plane's answer goes out on the
//! client's lease. What is left here is the loop and the ending, which is exactly what the client
//! pump one layer down is.
//!
//! ## A PROVIDER THAT GOES ENDS THE SESSION, and ends it ONCE
//!
//! An upstream leg that closed is a relayed session with nothing left to relay, and carrying on
//! would leave a client talking to a node that is quietly answering nothing. So this pump closes
//! the session — through [`SessionDriver::close`], which is exactly-once by its own enforcement, so
//! the client's pump closing the same session afterwards releases nothing a second time.
//!
//! And the client is TOLD, without this file writing to its socket: closing the session drops the
//! slot, the slot holds the client's offering end, and a drain whose offering end has gone writes
//! this wire's orderly close. The courtesy frame therefore comes from the one writer that owns the
//! socket, rather than from a second task deciding to write to a client whose own pump is mid-read.

use busbar_contract::transport::driver::Outcome;
use busbar_contract::transport::session::{Cut, SessionDriver, SessionEnd, SessionHandle};
use busbar_contract::wire::CloseReason;
use busbar_transport_ws::mount::{reason_for, FrameSource};

use crate::root::session_driver::{SessionLoopDriver, SessionUnits};

/// RUN ONE DIALLED LEG'S INBOUND HALF to its end, and close the session it belongs to.
///
/// One frame at a time and in order, for the reason the client's pump is: what a reply MEANS
/// depends on the replies before it, and a leg read by two tasks at once is a leg neither of them
/// can reason about.
///
/// Every ending closes the session, including the ugly ones. The three are the provider's orderly
/// close, a carrier that failed under the read, and the driver's own decision that the session is
/// over — which is what a client that cannot be written to comes back as.
pub async fn pump_leg<Src, U>(
    driver: &SessionLoopDriver<'_, U>,
    session: SessionHandle,
    mut source: Src,
) -> SessionEnd
where
    Src: FrameSource,
    U: SessionUnits + ?Sized,
{
    let end = loop {
        match source.next_frame().await {
            // The provider went first, orderly. Nothing is wrong and nothing is anybody's fault:
            // the exchange this leg carried is finished, and so is the session over it.
            None => {
                break SessionEnd {
                    cut: Cut::Upstream,
                    reason: CloseReason::Normal,
                }
            }
            // The leg failed rather than ended. Still this node's own side that stopped serving —
            // the client did nothing — and the word is whatever the carrier's failure spells.
            Some(Err(error)) => {
                break SessionEnd {
                    cut: Cut::Upstream,
                    reason: reason_for(error),
                }
            }
            Some(Ok(payload)) => {
                let reply = driver.upstream(session, &payload);
                if let Some(reason) = reply.close {
                    break SessionEnd {
                        cut: Cut::Upstream,
                        reason,
                    };
                }
                debug_assert_eq!(
                    reply.outcome,
                    Outcome::Completed,
                    "a reply that did not end the session completed it"
                );
            }
        }
    };
    driver.close(session, end);
    end
}

// THE CELLS FOR THIS FILE LIVE BESIDE THE DRIVER'S, in `tests/session_driver.rs`, for the reason
// `leg_dial`'s do: what this pump does is only observable through a driver with a leg attached to
// it, and a second copy of that harness is a second thing to keep in step with the first.
