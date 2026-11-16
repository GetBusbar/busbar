// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEED JUDGE (IF 13, round 8): on a pool miss only, `judge_name_with`, then `Resolve`, then
//! `judge_answer_with`, then `Guard::not_the_node(class, addr, true)` on every admitted address
//! (the node's own ports are refused in every class), all before one byte is sent.
//!
//! A refusal is audited here with its full reason and reaches the plugin as `NeedErr::Denied` with
//! no text (I2); a failed resolution is `Unavailable`.

use std::net::{IpAddr, SocketAddr};

use busbar_plugin_abi::host_side::needs::NeedErr;
use futures::channel::oneshot;

use crate::guard::{Guard, Resolve};

/// The Need judge: the connector's own guard and its resolver (no judge type parameter, IF 13).
#[derive(Debug)]
pub struct Judge<R: Resolve> {
    guard: Guard,
    resolver: R,
}

/// `host` and `port` of a `host:port` dest (a bracketed IPv6 literal loses its brackets).
///
/// # Errors
/// `Invalid` for no port, a port that is not a u16, or an empty host.
pub fn split_dest(dest: &str) -> Result<(&str, u16), NeedErr> {
    let (host, port) = dest.rsplit_once(':').ok_or(NeedErr::Invalid)?;
    let port = port.parse::<u16>().map_err(|_| NeedErr::Invalid)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err(NeedErr::Invalid);
    }
    Ok((host, port))
}

/// `host` and `port` of a FETCH URL (the scheme's default port when it names none).
///
/// # Errors
/// `Invalid` for a URL that does not parse, names no host, or whose scheme is not http or https.
pub fn split_url(url: &str) -> Result<(String, u16), NeedErr> {
    let u = url::Url::parse(url).map_err(|_| NeedErr::Invalid)?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(NeedErr::Invalid);
    }
    let host = u.host_str().ok_or(NeedErr::Invalid)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = u.port_or_known_default().ok_or(NeedErr::Invalid)?;
    Ok((host.to_owned(), port))
}

impl<R: Resolve> Judge<R> {
    /// A judge over `guard` and `resolver`.
    #[must_use]
    pub fn new(guard: Guard, resolver: R) -> Self {
        Judge { guard, resolver }
    }

    /// The guard, for the boot metadata publish (`Guard::publish_own`, `Guard::publish`).
    #[must_use]
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let (tx, rx) = oneshot::channel();
        self.resolver.resolve(
            host,
            Box::new(move |answer| {
                // A dropped receiver is a cancelled chain: nobody is waiting for the answer.
                let _ = tx.send(answer);
            }),
        );
        rx.await
            .unwrap_or_else(|_| Err("the resolver dropped the lookup".to_owned()))
    }

    /// Judge a dial of `host:port` under the judged `class` and return the addresses to connect
    /// to, in answer order. Every address answered is judged; one refusal refuses the dial.
    ///
    /// # Errors
    /// `Denied` for any guard refusal (audited, with the reason, on the core side), `Unavailable`
    /// for a failed resolution.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        class: u32,
        owner: (u64, u32),
    ) -> Result<Vec<SocketAddr>, NeedErr> {
        let refused = |why: crate::guard::Refusal| {
            crate::egress_audit::dial_refused(
                host,
                Some(class),
                crate::egress_audit::verdict_name(why.verdict),
                Some(owner),
            );
            NeedErr::Denied
        };
        let ips = match self
            .guard
            .judge_name_with(host, class, false, false)
            .map_err(refused)?
        {
            Some(literal) => vec![literal],
            None => {
                let answer = self.resolve(host).await.map_err(|_| NeedErr::Unavailable)?;
                self.guard
                    .judge_answer_with(host, &answer, class, false, false)
                    .map_err(refused)?;
                answer
            }
        };
        ips.into_iter()
            .map(|ip| {
                let at = SocketAddr::new(ip, port);
                self.guard
                    .not_the_node(class, at, true)
                    .map(|()| at)
                    .map_err(refused)
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../tests/need_judge_tests.rs"]
mod tests;
