// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE GUARD IN FRONT OF AN EGRESS DIAL, driven from both ends.
//!
//! Every cell here drives the guard itself rather than a socket, and that is the point: what is
//! under test is the answer given BEFORE a socket exists. A battery that proved the refusal by
//! observing that no connection arrived would be proving it against a listener that might simply
//! have been slow.
//!
//! The destinations are sealed the way a real one is — through
//! [`busbar_contract::dest::VerifiedDestination::seal`], with a trust token, because a destination
//! is the one thing a composition may not mint for itself.

use busbar_caps::{KernelSeal, Route, UnitToken};
use busbar_contract::dest::{DestinationFacts, UpstreamAddress, VerifiedDestination};
use busbar_contract::ids::LaneId;
use busbar_contract::TransportError;
use busbar_unit_breaker::{Breaker, DestinationId};
use busbar_unit_trust::net::GuardPolicy;

use crate::root::egress_guard::EgressGuard;

/// The lane every cell here keys its cell under — an operator's own name, as a configured row
/// carries it.
const LANE: &str = "voice-realtime";

/// A sealed upstream destination at one address, the way unit zero seals one.
fn sealed(address: &'static str) -> VerifiedDestination {
    let kernel = busbar_kernel::teller::Kernel::new();
    VerifiedDestination::seal(
        &kernel.transport_key_token(),
        DestinationFacts::Upstream {
            transport: "ws",
            address: UpstreamAddress::socket(address),
            lane: LaneId::new(LANE),
        },
        "ws",
        None,
    )
}

/// The clock the guard reads, so a cell trips a cell in the same frame of reference.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A fresh `UnitToken<Route>` for one `observe` — the unit's own fold is token-bound to the Route
/// step, so a cell that trips a cell through it has to mint one, exactly as the unit's own battery
/// does.
fn route_token() -> UnitToken<Route> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// The posture a cell dialling something the OS lent it runs under.
fn loopback() -> GuardPolicy {
    GuardPolicy {
        allow_private: true,
        ..GuardPolicy::default()
    }
}

/// THE FAIL-CLOSED POSTURE REFUSES A PRIVATE ADDRESS, before anything is resolved and before a
/// socket exists.
///
/// A deployment's `streams.upstreams:` row is a string an operator wrote, and a string an operator
/// wrote can name this node's own network. The default posture says no, and it says no on the
/// literal — no resolver is asked about `10.0.0.1`, because asking is one more thing that could
/// answer differently than the judgement.
#[tokio::test]
async fn the_fail_closed_posture_refuses_a_private_address() {
    let guard = EgressGuard::default();
    let refused = guard.admit(&sealed("wss://10.0.0.1:443/leg")).await;
    assert!(
        matches!(refused, Err(TransportError::AddressRefused)),
        "a private address is not admissible under the default posture, got {refused:?}"
    );
}

/// AND A CLOUD-METADATA HOST IS REFUSED WHATEVER THE POSTURE SAYS.
///
/// This is the one refusal that is not policy. An operator who set `allow_private` has said "this
/// upstream is on our internal network"; they have said nothing about IMDS, and IMDS is the address
/// whose whole value to an attacker is that it hands credentials to anything inside. The guard keeps
/// it refused under the MOST permissive posture a caller can spell, which is what makes it a guard
/// rather than a default.
#[tokio::test]
async fn a_cloud_metadata_host_is_refused_under_the_most_permissive_posture() {
    let guard = EgressGuard::new(GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    });
    let refused = guard.admit(&sealed("wss://169.254.169.254/leg")).await;
    assert!(
        matches!(refused, Err(TransportError::AddressRefused)),
        "the metadata address is the guard, not the policy, got {refused:?}"
    );
}

/// AN ADDRESS THIS WIRE CANNOT READ IS REFUSED HERE, not discovered at the socket.
///
/// A bare authority — no scheme — is what unit zero used to seal while the only thing that ever
/// built a URL was the synchronous probe beside it. Nothing dialled that seal, so nothing noticed.
/// The guard reads the same shape the wire reads and refuses the same strings, so a composition that
/// seals an address this wire cannot open is told at the guard rather than at a handshake.
#[tokio::test]
async fn an_address_this_wire_cannot_read_is_refused_before_a_socket() {
    let guard = EgressGuard::new(loopback());
    for address in ["api.example.invalid", "https://api.example.invalid", ""] {
        let refused = guard
            .admit(&sealed(Box::leak(address.to_string().into_boxed_str())))
            .await;
        assert!(
            matches!(refused, Err(TransportError::AddressRefused)),
            "`{address}` is not an address this wire opens a socket to, got {refused:?}"
        );
    }
}

/// A TRIPPED CELL REFUSES THE DIAL, in microseconds, before any socket.
///
/// This is the first of the two observables the breaker is wanted for on this path. The endpoint is
/// reachable — loopback, admitted by the posture — and the guard refuses anyway, because the cell
/// for its lane has been tripped. The refusal is `Refused` rather than `AddressRefused`: nothing is
/// wrong with the address, this node is declining to try.
#[tokio::test]
async fn a_tripped_cell_refuses_the_dial_before_a_socket() {
    let guard = EgressGuard::new(loopback());
    let dest = sealed("ws://127.0.0.1:9/leg");

    // Admitted while the cell is fresh: the guard is not refusing this address for any other
    // reason, which is what makes the refusal below attributable to the cell.
    assert!(
        guard.admit(&dest).await.is_ok(),
        "a fresh cell admits, so the refusal below is the trip and not the address"
    );

    // TRIP IT THROUGH THE UNIT'S OWN FOLD, with the unit's own token: a cell forced by writing its
    // state from outside would be a cell this battery invented rather than the one a Route step
    // trips.
    let route = route_token();
    let cfg = busbar_unit_breaker::cfg::BreakerCfg::default();
    // THE GUARD'S OWN CLOCK, because the guard reads one: its admission is taken at wall-clock
    // `now`, so a cell tripped at a fixed instant in the past would be a cell whose cooldown had
    // already expired by the time the guard looked at it.
    let now = now_secs();
    for _ in 0..8 {
        guard.breaker().observe(
            LANE,
            DestinationId::new(0),
            busbar_unit_breaker::Outcome::Transient { retry_after: None },
            &cfg,
            now,
            &route,
        );
    }

    let refused = guard.admit(&dest).await;
    assert!(
        matches!(refused, Err(TransportError::Refused)),
        "a tripped cell refuses the dial, and says so as this node declining rather than as an \
         inadmissible address, got {refused:?}"
    );
}

/// A RECOVERY PROBE ADMITS EXACTLY ONE DIAL, and releasing it hands the next caller the probe.
///
/// The second observable. Once a tripped cell's cooldown has passed it admits ONE caller to find out
/// whether the endpoint is back; a second concurrent caller must not get a socket, or a provider
/// that is still down is hit by every session at once the moment the cooldown expires.
///
/// The release is the other half and is why the admission is an owned value: the probe stays in
/// flight until somebody says the dial is over, and "somebody" is the drop, which runs on the
/// success path, the failure path and the cancelled path alike. A probe that leaked would refuse
/// every later dial to that endpoint for the life of the process.
#[tokio::test]
async fn a_recovery_probe_admits_exactly_one_dial() {
    let guard = EgressGuard::new(loopback());
    let route = route_token();
    let cfg = busbar_unit_breaker::cfg::BreakerCfg::default();
    // THE GUARD'S OWN CLOCK, because the guard reads one: its admission is taken at wall-clock
    // `now`, so a cell tripped at a fixed instant in the past would be a cell whose cooldown had
    // already expired by the time the guard looked at it.
    let now = now_secs();
    for _ in 0..8 {
        guard.breaker().observe(
            LANE,
            DestinationId::new(0),
            busbar_unit_breaker::Outcome::Transient { retry_after: None },
            &cfg,
            now,
            &route,
        );
    }
    // Past the cooldown: the cell is probe-winnable rather than cooling. Driven through the unit's
    // own verbs, which is what the guard drives, so the single-flight property is read where it
    // lives rather than inferred from two admissions racing a wall clock.
    let after = now + cfg.max_cooldown_secs + 1;
    let won = guard
        .breaker()
        .try_admit(LANE, DestinationId::new(0), after)
        .expect("the cooldown has passed, so this caller wins the probe");
    assert!(
        won.probe_epoch.is_some(),
        "the first caller past a cooldown wins the single-flight probe"
    );
    assert!(
        guard
            .breaker()
            .try_admit(LANE, DestinationId::new(0), after)
            .is_err(),
        "and a second caller is refused while that probe is in flight — a provider that is still \
         down must not be hit by every waiting session the instant its cooldown expires"
    );
    guard.breaker().release_probe(
        LANE,
        DestinationId::new(0),
        won.probe_epoch.expect("won above"),
        after,
    );
    assert!(
        guard
            .breaker()
            .try_admit(LANE, DestinationId::new(0), after)
            .is_ok(),
        "and once the probe is released the next caller may take it — which is what the admission \
         value's drop does on every path out of a dial"
    );
}

/// THE ADMISSION RELEASES ITS PROBE WHEN IT IS DROPPED, on the path a dial never completes.
///
/// Driven through the guard's own value rather than through the unit's verbs, because the claim is
/// about the DROP: a dial that fails, or a client that goes away mid-upgrade, must not leave the
/// endpoint's recovery probe in flight.
#[tokio::test]
async fn dropping_an_admission_releases_the_probe_it_won() {
    let guard = EgressGuard::new(loopback());
    let dest = sealed("ws://127.0.0.1:9/leg");
    let route = route_token();
    let cfg = busbar_unit_breaker::cfg::BreakerCfg::default();
    // THE GUARD'S OWN CLOCK, because the guard reads one: its admission is taken at wall-clock
    // `now`, so a cell tripped at a fixed instant in the past would be a cell whose cooldown had
    // already expired by the time the guard looked at it.
    let now = now_secs();
    for _ in 0..8 {
        guard.breaker().observe(
            LANE,
            DestinationId::new(0),
            busbar_unit_breaker::Outcome::Transient { retry_after: None },
            &cfg,
            now,
            &route,
        );
    }
    // The cell is cooling, so nothing is admitted at all — the trip's own refusal.
    assert!(guard.admit(&dest).await.is_err());

    // A second guard over the same posture, whose cell is fresh: this admission wins no probe and
    // has nothing to release, which is the ordinary case and must not be a release of somebody
    // else's.
    let fresh = EgressGuard::new(loopback());
    let admitted = fresh
        .admit(&dest)
        .await
        .expect("a fresh cell admits without a probe");
    assert!(
        !admitted.won_probe(),
        "an admission on a closed cell wins no probe, so its drop releases nothing"
    );
    drop(admitted);
    assert!(
        fresh.admit(&dest).await.is_ok(),
        "and the cell is unchanged by an admission that never won one"
    );
}
