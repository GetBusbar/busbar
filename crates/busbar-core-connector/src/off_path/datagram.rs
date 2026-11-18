// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `datagram` (and its DTLS engine, `dtls`) off-path code (see `crate::off_path`): the clock tick's
//! sweeps. The tick visits the associations whose deadline passed and expires what aged out; no
//! datagram, emit or admission runs it.

use std::net::SocketAddr;
use std::time::Instant;

use busbar_contract::abi::transport::{
    FrameSpan, RendezvousTerms, FINGERPRINT_BYTES, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES,
};

use crate::datagram::{fault, Answered, Owed, PortAssociations, Terms};
use crate::dtls::{Association, IceCredentials, Role, CONSENT_TIMEOUT};
use crate::framer::Refused;

impl PortAssociations {
    /// The serving caller's incremental clock path. A busy producer retains its ordinary
    pub fn timeout_incremental(&self, now: Instant, send: &dyn Fn(SocketAddr, &[u8])) -> Answered {
        let due: Vec<_> = {
            let mut assocs = self.lock();
            for out in assocs.out.values_mut() {
                if out.deadline.is_some_and(|deadline| deadline <= now) {
                    out.deadline = None;
                    out.owed.push_back(Owed::Timer);
                }
            }
            assocs
                .framings
                .iter()
                .filter_map(|(id, f)| {
                    f.deadline()
                        .is_some_and(|deadline| deadline <= now)
                        .then_some(*id)
                })
                .collect()
        };
        due.into_iter()
            .flat_map(|id| self.incremental(id, Owed::Timer, now, send))
            .collect()
    }

    /// The clock, for every association whose deadline has passed (one out is owed it).
    pub fn timeout(&self, now: Instant, send: &dyn Fn(SocketAddr, &[u8])) -> Answered {
        let due: Vec<u64> = {
            let mut assocs = self.lock();
            for out in assocs.out.values_mut() {
                if out.deadline.is_some_and(|d| d <= now) {
                    out.deadline = None;
                    out.owed.push_back(Owed::Timer);
                }
            }
            assocs
                .framings
                .iter()
                .filter(|(_, f)| f.deadline().is_some_and(|d| d <= now))
                .map(|(id, _)| *id)
                .collect()
        };
        due.into_iter()
            .flat_map(|id| self.turn(id, Owed::Timer, now, send).1)
            .collect()
    }
}

impl Association {
    /// `dtls` timers: heard and proven paths and probes older than [`CONSENT_TIMEOUT`] age out (the
    /// bound and wanted paths are kept), the probe index with its probes.
    pub(crate) fn expire(&mut self, now: Instant) {
        let keep = [self.bound, self.wanted];
        let fresh = |t: &Instant| now.saturating_duration_since(*t) < CONSENT_TIMEOUT;
        self.heard
            .retain(|p, t| keep.contains(&Some(*p)) || fresh(t));
        self.proven
            .retain(|p, t| keep.contains(&Some(*p)) || fresh(t));
        self.probes.retain(|_, (_, sent)| fresh(sent));
        self.probed.retain(|_, sents| {
            sents.retain(|sent| fresh(&*sent));
            !sents.is_empty()
        });
    }
}

/// The rendezvous terms a framer answered, read out of its frame (already judged by the ABI's own
/// checks). A framing's terms settle once, when its rendezvous completes.
pub(crate) fn read_terms(t: &RendezvousTerms, frame: &[u8]) -> Result<Terms, Refused> {
    let span = |s: FrameSpan| -> Result<&[u8], Refused> {
        let at = usize::try_from(s.offset).map_err(|_| fault("terms span"))?;
        let len = usize::try_from(s.len).map_err(|_| fault("terms span"))?;
        frame
            .get(at..at.saturating_add(len))
            .ok_or_else(|| fault("the framer's terms are out of bounds"))
    };
    let utf8 = |s| -> Result<String, Refused> {
        let text = std::str::from_utf8(span(s)?)
            .map_err(|_| fault("the framer's check credentials are not text"))?;
        Ok(text.to_owned())
    };
    // A user name is made shared text here, once: the association is found by it afterwards.
    let user = |s| -> Result<busbar_contract::kept::Text, Refused> {
        let text = std::str::from_utf8(span(s)?)
            .map_err(|_| fault("the framer's check credentials are not text"))?;
        Ok(busbar_contract::kept::off_path::text(text))
    };
    let role = match t.role {
        HANDSHAKE_INITIATES => Role::Client,
        HANDSHAKE_ANSWERS => Role::Server,
        _ => return Err(fault("the framer's terms name no handshake role")),
    };
    let candidates = std::str::from_utf8(span(t.candidates)?)
        .map_err(|_| fault("the far end's candidates are not text"))?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    let mut fingerprint = [0_u8; FINGERPRINT_BYTES as usize];
    let stated = span(t.peer_fingerprint)?
        .get(..fingerprint.len())
        .ok_or_else(|| fault("the far end's fingerprint is short"))?;
    fingerprint.copy_from_slice(stated);
    Ok(Terms {
        role,
        local: IceCredentials {
            ufrag: user(t.local_user)?,
            pwd: utf8(t.local_secret)?,
        },
        remote: IceCredentials {
            ufrag: user(t.remote_user)?,
            pwd: utf8(t.remote_secret)?,
        },
        fingerprint,
        candidates,
    })
}

/// A stream head's named value, trimmed and kept: a stream's head arrives once, when the stream
/// opens.
pub(crate) fn head_value(value: &str) -> String {
    value.trim().to_owned()
}

/// The upstream dial's opening fields, built once when the session's upstream leg is dialled.
pub(crate) fn opening<S: AsRef<str>>(
    caller: &[(u64, String)],
    channels: &[S],
) -> Vec<(String, Vec<u8>)> {
    caller
        .iter()
        .map(|(_, kind)| ("media".to_owned(), kind.clone().into_bytes()))
        .chain(
            channels
                .iter()
                .map(|l| ("channel".to_owned(), l.as_ref().as_bytes().to_vec())),
        )
        .collect()
}
