// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `datagram` (and its DTLS engine, `dtls`) cold code (see `crate::cold`): refusal and failure
//! text, and the rare sweeps a flood forces at a cap.

use std::fmt::{Debug, Display};
use std::net::SocketAddr;

use busbar_contract::abi::mechanism::call::Outcome;

use crate::datagram::PathBook;
use crate::dtls::{Association, Failure};
use crate::framer::Refused;

/// `datagram`: a failed association's refusal, naming its failure.
#[cold]
pub(crate) fn secure_layer_failed(failure: &Failure) -> Refused {
    Refused {
        outcome: Outcome::Failed,
        error: format!("the secure layer failed the association: {failure:?}"),
    }
}

/// `datagram`: a certificate that would not mint faults with its reason.
#[cold]
pub(crate) fn minting_fault(failure: &Failure) -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: format!("{failure:?}"),
    }
}

/// `datagram`: the refusal naming the door that is no datagram framer.
#[cold]
pub(crate) fn no_datagram_framer(name: &str) -> Refused {
    Refused {
        outcome: Outcome::Refused,
        error: format!("`{name}` is no datagram framer: its calls carry no datagram lane"),
    }
}

/// `datagram`: a broken datagram answer's fault, naming the rule and field.
#[cold]
pub(crate) fn datagram_answer_broken(rule: &dyn Debug, field: &dyn Display) -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: format!("the framer's datagram answer breaks {rule:?} at {field}"),
    }
}

/// `datagram`: a broken FINISH answer's fault, naming the rule and field.
#[cold]
pub(crate) fn finish_answer_broken(rule: &dyn Debug, field: &dyn Display) -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: format!("the framer's FINISH datagram answer breaks {rule:?} at {field}"),
    }
}

/// `datagram`: the bridge's refusal when the legs carry different counts of lines.
#[cold]
pub(crate) fn lines_differ_in_count(upstream: usize, caller: usize) -> String {
    format!("the upstream leg carries {upstream} line(s), the caller's {caller}")
}

/// `datagram`: the bridge's refusal when line `i` is of a different kind on each leg.
#[cold]
pub(crate) fn line_kinds_differ(i: usize, caller: &str, upstream: &str) -> String {
    format!("line {i} is `{caller}` on the caller's leg and `{upstream}` upstream")
}

/// `dtls`: the certificate could not be minted; its text.
#[cold]
pub(crate) fn certificate_failed(e: &dyn Display) -> Failure {
    Failure::Certificate(format!("{e}"))
}

/// `dtls`: a refused SRTP profile fails the association, naming it.
#[cold]
pub(crate) fn profile_refused(profile: &dyn Display) -> Failure {
    Failure::Profile(format!("{profile}"))
}

/// `dtls`: an output the engine never owes fails the association, naming it.
#[cold]
pub(crate) fn output_unowed(output: &dyn Debug) -> Failure {
    Failure::Dtls(format!("{output:?}"))
}

/// `dtls`: a failure of the DTLS layer itself, with its text.
#[cold]
pub(crate) fn dtls_failed(e: &dyn Display) -> Failure {
    Failure::Dtls(format!("{e}"))
}

impl PathBook {
    /// `datagram`: at the path cap (a flood of far-end addresses) the paths no one keeps are let
    /// go.
    #[cold]
    pub(crate) fn let_go_unkept(&mut self, keep: impl Fn(SocketAddr) -> bool) {
        // Each unkept address goes, with its path number, as the book is walked: no list is made.
        let Self {
            by_addr,
            by_path,
            untold,
            ..
        } = self;
        by_addr.retain(|addr, path| {
            if keep(*addr) {
                return true;
            }
            by_path.remove(path);
            untold.retain(|told| told != path);
            false
        });
    }
}

impl Association {
    /// `dtls`: at the heard-path cap, the oldest heard path that is neither bound nor wanted is let
    /// go (its proof with it); `false` when every heard path is kept.
    #[cold]
    pub(crate) fn let_go_oldest_heard(&mut self) -> bool {
        let keep = [self.bound, self.wanted];
        let oldest = self
            .heard
            .iter()
            .filter(|(p, _)| !keep.contains(&Some(**p)))
            .min_by_key(|(_, t)| **t)
            .map(|(p, _)| *p);
        match oldest {
            Some(p) => {
                self.heard.remove(&p);
                self.proven.remove(&p);
                true
            }
            None => false,
        }
    }

    /// `dtls`: at the probe cap, the probe to let go: the oldest to a path neither bound nor
    /// wanted, else the oldest of all.
    #[cold]
    pub(crate) fn oldest_probe(&self) -> Option<[u8; 12]> {
        let keep = [self.bound, self.wanted];
        let oldest = |spare: bool| {
            self.probes
                .iter()
                .filter(|(_, (to, _))| !spare || !keep.contains(&Some(*to)))
                .min_by_key(|(_, (_, sent))| *sent)
                .map(|(id, _)| *id)
        };
        oldest(true).or_else(|| oldest(false))
    }
}
