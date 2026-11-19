// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE OPEN THROUGH THE OPERATOR'S PROXY: the two judgements and the tunnelled dial.
//!
//! This replaces the refusal in `open_native` ("the operator's egress proxy is honoured by the
//! framed dial only"). A destination the proxy choice selects is dialled through the proxy, by
//! the same rules a plugin's own connection already follows on the needs path:
//!
//! 1. The target is judged first, exactly as for a direct dial (`judge_into`): the name, and
//!    every address it resolves to. A target the guard refuses is never shown to the proxy.
//! 2. The proxy's own host is judged in the operator-infrastructure class. Its addresses are
//!    what the socket connects to.
//!
//! Both judgements are asked for when the open is made; the dial begins when both have answered.
//! The plaintext rule and an open's pinned addresses are applied to the target's judged address,
//! never the proxy's.
//!
//! NOT YET DECLARED: `native_conns.rs` gains `#[path = "native_conns/route.rs"] mod route;` in
//! the change that (a) gives `State::Judging` the field `via: Option<Via>`, (b) gives
//! `NativeDial` the field `tunnel: Option<Tunnel>` read by `NativeConnection::dial` to make its
//! `Dialling`, and (c) switches the three call sites named on the functions below.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::Context;

use busbar_contract::conn::codes::EGRESS_OPERATOR_INFRASTRUCTURE;
use busbar_contract::conn::{ConnError, NeedRefusal};
use busbar_contract::services::codes::{DEST_NO_ADDRESSES, DEST_UNRESOLVABLE};
use busbar_contract::storage::StorageSource;

use super::{error_of, PendingDial};
use crate::conns::native_dial::{NativeConnection, NativeDial};
use crate::conns::{Answer, Verdict};
use crate::outbound::tunnel::{hop_for, Resolution, Target, VERDICT_PROXY};
use crate::proxy_route::ProxyHop;

/// The refusal texts of a tunnelled open (constants: no address, no credential).
pub(crate) mod text {
    /// The proxy's own host was refused by the guard or did not resolve.
    pub(crate) const PROXY_UNREACHED: &str =
        "the operator's proxy could not be reached: its host was refused or did not resolve";
    /// The proxy is reached over TLS and no trust is set to verify it by.
    pub(crate) const PROXY_UNTRUSTED: &str =
        "the operator's proxy is reached over TLS and no trust is set to verify it by";
}

/// The proxy a pending dial goes through: the hop, its own judgement, and who resolves.
pub(crate) struct Via {
    /// The proxy.
    pub(crate) hop: Arc<ProxyHop>,
    /// The judgement of the proxy's own host (operator infrastructure).
    pub(crate) answer: Answer,
    /// Who resolves the target's name.
    pub(crate) resolution: Resolution,
    /// The client TLS settings for the proxy's own host, read when the hop is reached over TLS.
    pub(crate) trust: Option<Arc<rustls::ClientConfig>>,
}

/// What a tunnelled dial hands `NativeConnection::dial` (the new `NativeDial::tunnel`).
pub(crate) struct Tunnel {
    /// The proxy.
    pub(crate) hop: Arc<ProxyHop>,
    /// What the CONNECT names.
    pub(crate) target: Target,
    /// The client TLS settings for the proxy's own host.
    pub(crate) trust: Option<Arc<rustls::ClientConfig>>,
}

/// A judgement's answer, taken if it has come; else the waker is kept for when it does.
fn taken(
    answer: &Answer,
    cx: &mut Context<'_>,
) -> Option<(Result<SocketAddr, Verdict>, Vec<SocketAddr>)> {
    let mut a = answer.lock().expect("judgement");
    match a.0.take() {
        Some(verdict) => Some((verdict, std::mem::take(&mut a.2))),
        None => {
            let previous = a.1.replace(cx.waker().clone());
            drop(a);
            drop(previous);
            None
        }
    }
}

/// Put a verdict back for the next poll (the other judgement has not answered yet).
fn put_back(answer: &Answer, verdict: Result<SocketAddr, Verdict>, also: Vec<SocketAddr>) {
    let mut a = answer.lock().expect("judgement");
    a.0 = Some(verdict);
    a.2 = also;
}

impl crate::conns::Connector {
    /// CALLED in `open_native` where the refusal was (after the carrier is found, before the
    /// trust is read): the proxy this open goes through, with the judgement of the proxy's own
    /// host already asked for. `None` = a direct dial, exactly as before.
    ///
    /// A kept idle connection is taken before this is consulted: it was tunnelled when it was
    /// dialled, and nothing about the proxy is done again.
    pub(crate) fn via_for(&self, secure: bool, authority: &str) -> Result<Option<Via>, ConnError> {
        let Some(hop) = hop_for(self.proxy.as_deref(), secure, authority) else {
            return Ok(None);
        };
        let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));
        // The proxy's own host: operator infrastructure, no reach of the opener's.
        let judged = self.judge_into(
            hop.endpoint(),
            hop.secure(),
            EGRESS_OPERATOR_INFRASTRUCTURE,
            false,
            &answer,
        );
        if let Some(verdict) = judged {
            put_back(&answer, verdict, Vec::new());
        }
        let trust = if hop.secure() {
            self.tls_for(hop.endpoint())?
        } else {
            None
        };
        Ok(Some(Via {
            resolution: if self.proxy_delegated() {
                Resolution::Proxy
            } else {
                Resolution::Engine
            },
            hop,
            answer,
            trust,
        }))
    }
}

/// CALLED in `Exchange::connected` in place of the single `answer` read when `via` is set: both
/// judgements, once both have answered. `None` = pending (the waker is kept on whichever has not).
pub(crate) fn both_judged(
    target: &Answer,
    via: &Via,
    cx: &mut Context<'_>,
) -> Option<(
    (Result<SocketAddr, Verdict>, Vec<SocketAddr>),
    (Result<SocketAddr, Verdict>, Vec<SocketAddr>),
)> {
    let first = taken(target, cx)?;
    match taken(&via.answer, cx) {
        Some(second) => Some((first, second)),
        None => {
            put_back(target, first.0, first.1);
            None
        }
    }
}

/// CALLED in `Exchange::connected` and in `open_native` in place of `dial_at` when `via` is set:
/// the tunnelled dial.
///
/// * `target` = the target's judgement. A refusal is the target's and is audited as today; the
///   proxy is never contacted. A name that does not resolve here is refused under the engine's
///   own resolution, and handed to the proxy by name where the operator chose that.
/// * `proxy` = the judgement of the proxy's own host: the addresses the socket connects to.
///
/// # Errors
/// The refusal; `why` carries its words. A proxy that cannot be reached is audited with verdict
/// `proxy` and charges no provider.
pub(crate) fn dial_through(
    dial: PendingDial,
    via: Via,
    target: Result<SocketAddr, Verdict>,
    proxy: (Result<SocketAddr, Verdict>, Vec<SocketAddr>),
    storage: &StorageSource,
    why: &mut Option<NeedRefusal>,
) -> Result<NativeConnection, ConnError> {
    let judged = match target {
        Ok(addr) => Some(addr),
        Err(DEST_UNRESOLVABLE | DEST_NO_ADDRESSES) if via.resolution == Resolution::Proxy => None,
        Err(verdict) => {
            crate::conns::egress_audit::dial_refused(
                &dial.located.authority,
                Some(dial.egress_class),
                crate::conns::egress_audit::verdict_name(verdict),
                None,
                &mut None,
            );
            *why = Some(crate::cold::conns::verdict_reason(verdict, false));
            return Err(crate::conns::pended_verdict(verdict));
        }
    };
    let pinned = !dial.within.is_empty();
    let connect_target = Target::of(via.resolution, &dial.located.authority, judged, pinned)
        .map_err(|words| {
            *why = Some(NeedRefusal::Policy(words));
            ConnError::Refused
        })?;
    // The plaintext rule and the pinned set are the target's, by its judged address. By name
    // (the proxy resolves) there is no address: only a secured target or an admitted plaintext
    // one goes, and a pinned open was refused above.
    let admitted = match connect_target.judged() {
        Some(addr) => crate::conns::class_admits(
            dial.egress_class,
            dial.located.secure,
            dial.plain,
            &dial.within,
            addr,
        ),
        None => dial.located.secure || dial.plain,
    };
    if !admitted {
        crate::conns::egress_audit::dial_refused(
            &dial.located.authority,
            Some(dial.egress_class),
            "plaintext",
            None,
            &mut None,
        );
        *why = Some(NeedRefusal::Policy(crate::conns::refusal_text::PLAINTEXT));
        return Err(ConnError::Refused);
    }
    let (proxy_at, proxy_also) = match proxy {
        (Ok(addr), also) => (addr, also),
        (Err(_), _) => {
            crate::conns::egress_audit::dial_refused(
                &dial.located.authority,
                Some(dial.egress_class),
                VERDICT_PROXY,
                None,
                &mut None,
            );
            *why = Some(NeedRefusal::Policy(text::PROXY_UNREACHED));
            return Err(ConnError::Fault);
        }
    };
    if via.hop.secure() && via.trust.is_none() {
        *why = Some(NeedRefusal::Policy(text::PROXY_UNTRUSTED));
        return Err(ConnError::Refused);
    }
    let PendingDial {
        carrier,
        located,
        tls,
        anchors,
        open_timeout,
        ..
    } = dial;
    NativeConnection::dial(
        carrier,
        NativeDial {
            located,
            // The socket connects to the proxy; TLS to the target, inside the tunnel, still
            // names the target (`located.name`), never the proxy.
            addr: proxy_at,
            also: proxy_also,
            tls,
            anchors,
            open_timeout,
            storage: storage.clone(),
            tunnel: Some(Tunnel {
                hop: via.hop,
                target: connect_target,
                trust: via.trust,
            }),
        },
    )
    .map_err(|failure| {
        *why = Some(crate::cold::conns::native_unreached(&failure));
        error_of(&failure)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(verdict: Option<Result<SocketAddr, Verdict>>) -> Answer {
        Arc::new(Mutex::new((verdict, None, Vec::new())))
    }

    fn via(proxy: Option<Result<SocketAddr, Verdict>>) -> Via {
        Via {
            hop: Arc::new(ProxyHop::new("proxy.internal".to_owned(), 3128, None)),
            answer: answer(proxy),
            resolution: Resolution::Engine,
            trust: None,
        }
    }

    fn cx_run(run: impl FnOnce(&mut Context<'_>)) {
        let waker = futures::task::noop_waker();
        run(&mut Context::from_waker(&waker));
    }

    #[test]
    fn the_dial_waits_for_both_judgements_and_loses_neither() {
        let target_addr: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let proxy_addr: SocketAddr = "10.0.0.9:3128".parse().unwrap();
        cx_run(|cx| {
            let target = answer(Some(Ok(target_addr)));
            let pending = via(None);
            assert!(both_judged(&target, &pending, cx).is_none());
            assert!(
                target.lock().unwrap().0.is_some(),
                "the target's verdict is kept for the next poll"
            );
            pending.answer.lock().unwrap().0 = Some(Ok(proxy_addr));
            let ((first, _), (second, _)) = both_judged(&target, &pending, cx).unwrap();
            assert_eq!((first, second), (Ok(target_addr), Ok(proxy_addr)));
        });
    }

    #[test]
    fn nothing_is_judged_ready_while_the_target_is_pending() {
        cx_run(|cx| {
            let target = answer(None);
            let ready = via(Some(Ok("10.0.0.9:3128".parse().unwrap())));
            assert!(both_judged(&target, &ready, cx).is_none());
            assert!(ready.answer.lock().unwrap().0.is_some());
            assert!(target.lock().unwrap().1.is_some(), "the waker is kept");
        });
    }
}
