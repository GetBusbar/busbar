// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE GUARD IN FRONT OF AN EGRESS DIAL, and why there is exactly one of it.
//!
//! A relayed session's upstream leg is a socket this node opens to an address a deployment
//! configured. Two things have to be true before that socket exists, and neither is the transport's
//! to decide:
//!
//! * **the address must be one this node may reach at all.** A name an operator wrote resolves to
//!   whatever DNS says today, and what DNS says today may be `169.254.169.254`, a link-local
//!   address, or a host inside the deployment's own network. The transport cannot judge that: its
//!   own dial comment says so in as many words — *"no name is resolved here, which is what puts the
//!   network guard in front of the dial instead of inside it"*. This is that guard, and the judge it
//!   runs is [`busbar_unit_trust::net`]'s — the unit's, not a second copy of it;
//! * **the endpoint must not already be known to be down.** A provider that is refusing every
//!   connection should be refused in microseconds, on the cell's own reading, rather than by waiting
//!   out a dial timeout per session. That is [`busbar_unit_breaker`]'s answer, and it is a CORE
//!   capability on a unit: every plane's egress dial is guarded by the same one, keyed by the lane
//!   the sealed destination already names.
//!
//! ## Why it lives HERE, in the composition root, and names no plane
//!
//! This module is generic over nothing and specific to nobody: it takes a sealed
//! [`busbar_contract::dest::VerifiedDestination`] and answers whether a socket may be opened to it.
//! Every duplex plane's leg is dialled through [`crate::root::registry::WsLegEgress`], which holds
//! one of these and runs it before any byte leaves, so the guard is on the path EVERY plane's egress
//! dial takes and there is nothing plane-shaped anywhere on it.
//!
//! The alternative, measured rather than imagined, was the shape that stood here until this commit:
//! a plane crate's own `dial_provider` — a net-guarded, breaker-admitted dial, complete and correct
//! — reached from a SYNCHRONOUS probe seam on the unit loop. It guarded a socket the unit loop does
//! not open. The socket that is actually opened is the composition's, between frames, and it went
//! through no guard at all. One guard, on the path that dials, is the whole of the correction.
//!
//! ## What this guard does NOT do, stated so nobody looks for it
//!
//! **It does not fold the dial's outcome back into the breaker's state machine.**
//! [`busbar_unit_breaker::Breaker::observe`] — the trip/cooldown/recovery fold — takes a
//! `&UnitToken<Route>`, and a step token exists only inside the synchronous unit loop. The dial
//! happens outside it, between two frames, where no token does or may exist: minting one here would
//! be the composition sealing a step decision, which is the one thing a composition must never do.
//! So what this guard drives is the pair of token-free verbs the unit publishes for exactly this
//! position — [`busbar_unit_breaker::BreakerUnit::try_admit`] and
//! [`busbar_unit_breaker::BreakerUnit::release_probe`] — which give the two observable properties a
//! guard is wanted for: **a tripped cell refuses the dial before a socket**, and **a recovery probe
//! admits exactly one dial**. What they do not give is the trip itself; a cell is tripped by the
//! Route step's own observation, and the seam that would let this position report into it is a
//! token-free peek on the unit, not a token this module invents.
//!
//! **It does not pin.** [`busbar_unit_trust::net`]'s judge answers about a host and about every
//! address that host currently answers with, and this runs all of it; what it cannot do is force the
//! socket onto the address it judged, because the address the socket goes to is the one the SEALED
//! destination carries and only a step token may re-seal one. Narrowing beneath is the transport's
//! own step (`dial_with` re-addresses through `VerifiedDestination::beneath`), and it cannot widen
//! where the unit may go. The residue is a resolver that could answer differently between this
//! judgement and that dial, which is the TOCTOU every resolve-then-pin outside a single connect
//! call has; it is named here rather than papered over.

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::TransportError;
use busbar_unit_breaker::{BreakerUnit, DestinationId};
use busbar_unit_trust::net::{judge_host_name, pin_answer, GuardPolicy};

/// THE DEGENERATE CELL a duplex leg is keyed under.
///
/// A configured `upstreams:` row is ONE endpoint, not a pool with members to fail over between: the
/// grammar's own answer to "this row is down" is that the session ends, because a live session
/// cannot be moved to a second provider mid-sentence. So the member index is zero, exactly as the
/// leg the legacy path dialled keyed itself, and the cell is the lane's.
const DEGENERATE_MEMBER: DestinationId = DestinationId::new(0);

/// THE GUARD ONE COMPOSITION HOLDS: the breaker cells it has learned, and the outbound trust
/// posture it judges against.
///
/// One per composition and never one per dial. The cells ARE the state — what this node has learned
/// about which endpoints are down — and a guard built per session would be a node that learned
/// nothing, refused nobody and re-opened a dead provider on every single upgrade.
pub struct EgressGuard {
    /// The breaker unit's cells. The root's own, with the root's diagnostics sink beneath it, so an
    /// unrecognized `error_map` class is warned through the node's logging exactly as it is on every
    /// other plane's egress.
    breaker: crate::root::adapters::RootBreakerUnit,
    /// The outbound trust posture every dial through this guard is judged against.
    ///
    /// The FAIL-CLOSED default, unconditionally, and it is a field rather than a constant so a cell
    /// can drive the judge from both ends. A public provider endpoint is exactly the shape the
    /// default exists for, and a composition that widened it per dial would be the root deciding a
    /// security question the trust unit owns.
    policy: GuardPolicy,
}

impl std::fmt::Debug for EgressGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressGuard")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl Default for EgressGuard {
    fn default() -> Self {
        EgressGuard::new(GuardPolicy::default())
    }
}

impl EgressGuard {
    /// Compose the guard.
    #[must_use]
    pub fn new(policy: GuardPolicy) -> Self {
        EgressGuard {
            breaker: BreakerUnit::with_diagnostics(crate::root::adapters::root_diagnostics()),
            policy,
        }
    }

    /// The breaker unit beneath, so a composition can pre-state a cell and a cell can read one.
    #[must_use]
    pub fn breaker(&self) -> &crate::root::adapters::RootBreakerUnit {
        &self.breaker
    }

    /// MAY A SOCKET BE OPENED TO THIS SEALED DESTINATION?
    ///
    /// The order is the design, and it is the order [`busbar_unit_trust::net::resolve_and_pin`]
    /// states: the structural refusals FIRST, so a hostile name never reaches a resolver; then
    /// exactly one resolution; then every address it answered with; and only then the endpoint's own
    /// cell, so a target this node would not reach at all is refused without touching a breaker.
    ///
    /// On `Ok`, the caller holds an [`Admitted`] for the length of the dial. Dropping it releases a
    /// recovery probe this admission won — which is what makes "one probe admits exactly one dial"
    /// true on the failure path as well as the success one.
    ///
    /// # Errors
    ///
    /// [`TransportError::AddressRefused`] when the destination is not an upstream socket, its
    /// address will not split, or the network judge refuses the host or an address it resolves to.
    /// [`TransportError::Refused`] when the endpoint's breaker cell is not admitting — this node
    /// declining to try, which is its own fact and not a network failure.
    pub async fn admit<'g>(
        &'g self,
        dest: &VerifiedDestination,
    ) -> Result<Admitted<'g>, TransportError> {
        let DestinationFacts::Upstream { address, lane, .. } = dest.facts() else {
            return Err(TransportError::AddressRefused);
        };
        let url = address.authority().ok_or(TransportError::AddressRefused)?;
        let (secure, host, port) = split_authority(url)?;

        // STRUCTURAL FIRST. A literal internal address, a cloud-metadata name, an alternate IPv4
        // encoding: all refused on the string, before anything is asked to resolve it.
        judge_host_name(&host, self.policy).map_err(|_| TransportError::AddressRefused)?;
        // EXACTLY ONE RESOLUTION, and none at all for a literal — a stub that echoed literals back
        // would be one more thing that could disagree with the judgement above.
        let addrs = match host.parse::<std::net::IpAddr>() {
            Ok(literal) => vec![literal],
            Err(_) => tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| TransportError::AddressRefused)?
                .map(|socket| socket.ip())
                .collect(),
        };
        // EVERY ADDRESS, not the one that will be used: a name that answers with one public address
        // and one link-local one is a name that can be made to answer with the link-local one.
        pin_answer(&host, port, secure, &addrs, self.policy)
            .map_err(|_| TransportError::AddressRefused)?;

        // AND ONLY THEN THE CELL. Fast-fail in microseconds against an endpoint already known to be
        // down, rather than a dial timeout per session.
        let pool = lane.as_str();
        match self.breaker.try_admit(pool, DEGENERATE_MEMBER, now_secs()) {
            Ok(admit) => Ok(Admitted {
                guard: self,
                pool: pool.to_string(),
                epoch: admit.probe_epoch,
            }),
            Err(state) => {
                // The line names the endpoint and the cell's reading and nothing about the leg: a
                // duplex upstream's dial URL may carry this deployment's credential in its query
                // string by its dialect's own declaration, so no URL-shaped value is written here.
                tracing::warn!(
                    lane = pool,
                    state = ?state,
                    "egress dial refused before any socket: this endpoint's breaker cell is not \
                     admitting"
                );
                Err(TransportError::Refused)
            }
        }
    }
}

/// ONE ADMISSION, held for the length of one dial.
///
/// What it owns is a RECOVERY PROBE, when this admission won one. A won probe is a single-flight
/// permission — one caller, one dial — and it stays in flight until somebody says the dial is over.
/// Dropping this says so, on every path out: the socket opened, the socket did not open, the future
/// was cancelled because the client went away. A probe left in flight would refuse every later dial
/// to that endpoint for as long as the process lived, which is a node that silently stopped relaying
/// after one cancelled upgrade.
pub struct Admitted<'g> {
    guard: &'g EgressGuard,
    pool: String,
    epoch: Option<u64>,
}

impl std::fmt::Debug for Admitted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("pool", &self.pool)
            .field("probe", &self.epoch)
            .finish()
    }
}

impl Admitted<'_> {
    /// Whether this admission won the endpoint's single-flight recovery probe.
    #[must_use]
    pub fn won_probe(&self) -> bool {
        self.epoch.is_some()
    }
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        if let Some(epoch) = self.epoch {
            // OWNER-CHECKED by the unit itself: a stale release cannot revert a newer probe some
            // other caller has since won, so a late drop is inert rather than harmful.
            self.guard
                .breaker
                .release_probe(&self.pool, DEGENERATE_MEMBER, epoch, now_secs());
        }
    }
}

/// Split a duplex upstream's dial address into `(secure, host, port)`.
///
/// THE SAME RECOGNISER THE WIRE USES, deliberately strict and deliberately small: a permissive
/// parser's job is to find a reading that works, and "find a reading that works" is the opposite of
/// what a security check wants from a string an operator's configuration reached. The host comes back
/// UNBRACKETED so an IPv6 literal reads the same here as it does to
/// [`busbar_unit_trust::net::judge_host_name`] and to `IpAddr::from_str`.
fn split_authority(url: &str) -> Result<(bool, String, u16), TransportError> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err(TransportError::AddressRefused);
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() || authority.contains('@') {
        return Err(TransportError::AddressRefused);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| TransportError::AddressRefused)?,
        ),
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map_or(host.clone(), str::to_string);
    Ok((secure, host, port))
}

/// The breaker's clock: whole seconds since the epoch, which is the unit the cells' cooldowns are in.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
#[path = "tests/egress_guard.rs"]
mod tests;
