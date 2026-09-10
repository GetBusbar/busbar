// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The egress unit's remaining seams, bound to the objects this node already has.
//!
//! ## What a binding is here, and what it is not
//!
//! The egress unit names no other unit and no runtime object. It reaches the concurrency permits,
//! the write-ahead journal, the clock, the counters and the credential that decorates an outbound
//! request through five small traits, and the composition root binds them. The breaker — the sixth
//! — is bound in [`super::adapters`], because it is a mapping between two units' widths rather than
//! a mapping onto a runtime object, and the two kinds of seam read differently.
//!
//! Every binding below is COMPOSITION. Each one forwards to something that already exists and
//! already runs: the permits are the ones the shipping admission peeks, the journal is the one
//! chain this node keeps, the clock is the root's own reading, the counters are the host's own
//! emits, and the credential is the scheme the DIALECT declared, resolved by the substrate's own
//! resolver. Not one of them decides anything. If a binding here started deciding — choosing a
//! credential, classifying an answer, sizing a wait — it would be a second engine wearing an
//! adapter's name, and the design refuses that in the same words it refuses a dual-write window.
//!
//! ## Asked by declaration, never by name
//!
//! The credential binding is the one where that rule is easiest to break and worst to break. There
//! is no arm here for any provider. A destination's scheme is resolved ONCE, at boot, from the
//! dialect's own declaration through the substrate's resolver, and the decoration asks the resolved
//! scheme for its headers. A signer and a static header are the same call at this seam, which is
//! what makes a new dialect cost this file nothing.
//!
//! ## Dark
//!
//! Nothing served reaches any of these. They are composed, and the cells drive them through the
//! unit's own surface; the route step dials, records and decorates the way it always has.

use std::sync::{Arc, Mutex};

use busbar_api::UpstreamCreds;
use busbar_caps::{DurabilityToken, StepName};
use busbar_contract::VerifiedDestination;
use busbar_substrate::config::ProviderAuth;
use busbar_substrate::egress_auth::{resolve as resolve_scheme, CredentialProvider};
use busbar_substrate::plane_host::{AuthStyleInput, LaneInput, PlaneBuildInput, TelemetryHost};
use busbar_substrate::proto::SigningContext;
use busbar_substrate::store::LaneRuntime;
use busbar_substrate::store::Permit as LaneSlotPermit;
use busbar_unit_egress::ports::{
    BoxFut, Capacity, Clock, DecorationRefused, DestinationId, Dispatched, DurabilityUnavailable,
    EgressAuth, Journal, OutboundRequest, Permit, PermitHandle, Telemetry,
};
use busbar_unit_wal::{BodyWriter, Entry, RecordClass};

use super::durability::Durability;
use super::pool_hydration::{destination_of_lane, lane_of_destination};

// ── the pool's own concurrency ──────────────────────────────────────────────────────────────────

/// One slot on one member, held for the life of an attempt.
///
/// The slot itself is the store's, and it is never read here — it exists to be HELD, and dropping
/// this handle drops it, which is what frees the member. The `Debug` says which member and nothing
/// else: a permit prints as a position, because there is nothing else in it a reader wants and the
/// store's own handle is not printable.
struct LaneSlot {
    destination: DestinationId,
    _held: LaneSlotPermit,
}

impl std::fmt::Debug for LaneSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneSlot")
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl PermitHandle for LaneSlot {
    fn destination(&self) -> DestinationId {
        self.destination
    }
}

/// The pool's permit store, bound to the node's own.
///
/// The permits the unit takes are the permits the shipping admission peeks — the same semaphores,
/// on the same members, counted once. That is the whole reason this is a forward and not a store of
/// its own: two permit books over one upstream would enforce neither cap, and the one this replaces
/// is the one the previous release's `max_concurrent` means.
pub struct LaneCapacity {
    store: Arc<dyn LaneRuntime>,
}

impl std::fmt::Debug for LaneCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneCapacity").finish_non_exhaustive()
    }
}

impl LaneCapacity {
    /// Bind the unit's permit seam to the node's lane store.
    #[must_use]
    pub fn new(store: Arc<dyn LaneRuntime>) -> Self {
        LaneCapacity { store }
    }
}

impl Capacity for LaneCapacity {
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit> {
        self.store
            .try_acquire(lane_of_destination(destination))
            .map(|held| {
                Permit::new(Box::new(LaneSlot {
                    destination,
                    _held: held,
                }))
            })
    }

    fn acquire_any<'a>(
        &'a self,
        destinations: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(async move {
            // A member with no semaphore is UNBOUNDED: nothing counts it, so it is never at
            // capacity and never something a waiter is waiting on. Skipped rather than treated as
            // a closed queue, which is what the store's own `None` means here.
            let waits: Vec<_> = destinations
                .iter()
                .filter_map(|&d| {
                    self.store
                        .lane_semaphore(lane_of_destination(d))
                        .map(|sem| (d, sem))
                })
                .map(|(d, sem)| Box::pin(async move { (d, sem.acquire_owned().await) }))
                .collect();
            if waits.is_empty() {
                return None;
            }
            // The store hands ONE freed slot to ONE waiter, in arrival order, and stores a slot
            // freed between a waiter's re-poll and its next await. That is the property this seam
            // is documented to require, and it is the store's, not this binding's: nothing here
            // polls, retries or re-checks. The first resolved wait is the answer.
            let (won, _index, _rest) = futures::future::select_all(waits).await;
            let (destination, acquired) = won;
            // A closed queue is a member shutting down, not a slot. `None` for the member; the
            // terminal that called this re-asks or sheds, which is its decision and not this one's.
            let held = acquired.ok()?;
            Some((
                destination,
                Permit::new(Box::new(LaneSlot {
                    destination,
                    _held: LaneSlotPermit::Bounded(held),
                })),
            ))
        })
    }
}

// ── the clock ───────────────────────────────────────────────────────────────────────────────────

/// The node's clock and its one sleep.
///
/// Two readings and a wait, and each is the reading the shipping walk already takes: whole seconds
/// since the epoch for every deadline the previous release states in seconds, milliseconds for the
/// one wait too short to state in them, and the runtime's own timer for the wait itself. Time is an
/// input to the unit and this is where it comes in; a unit that read the clock for itself would
/// stop being replayable from what it was handed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeClock;

impl Clock for NodeClock {
    fn now_secs(&self) -> u64 {
        // The root's own reading, in the root's own words: a clock that reads before the epoch
        // gives zero rather than panicking, exactly as every other reading on this path spells it.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn now_millis(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis())
    }

    fn sleep(&self, ms: u64) -> BoxFut<'_, ()> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
    }
}

// ── the counters ────────────────────────────────────────────────────────────────────────────────

/// The live depth of requests parked in a bounded wait, per pool.
///
/// The gauge the previous release published reads a depth at scrape time rather than accumulating a
/// delta, so the unit's balanced enter/leave pair has to land somewhere that can be read as a
/// number. This is that somewhere. It is node-local runtime state that outlives a request, which is
/// why it is held rather than derived, and the balance is the caller's: the unit's own terminal
/// pairs its two calls on every exit including a dropped future.
#[derive(Debug, Default)]
pub struct PoolQueueDepth {
    counts: Mutex<std::collections::HashMap<String, i64>>,
}

impl PoolQueueDepth {
    /// A depth with nothing parked.
    #[must_use]
    pub fn new() -> Self {
        PoolQueueDepth::default()
    }

    /// Move one pool's depth. Never below zero: a depth that went negative would be an unbalanced
    /// pair somewhere, and reporting it as a negative gauge would put the defect on a dashboard
    /// instead of leaving the number readable.
    pub fn shift(&self, pool: &str, delta: i64) {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let slot = counts.entry(pool.to_string()).or_insert(0);
        *slot = slot.saturating_add(delta).max(0);
    }

    /// One pool's live parked depth.
    #[must_use]
    pub fn depth(&self, pool: &str) -> i64 {
        self.counts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(pool)
            .copied()
            .unwrap_or(0)
    }
}

/// The walk's counters, bound to the host's own emits.
///
/// Every method forwards and none of them decides. The member reaches the host as the lane index it
/// has always been — the same number the `lane` label is resolved from — because a metric that
/// changed its label space at a re-pointing would break every dashboard reading it, and this
/// re-points the emitter, not the series.
pub struct HostTelemetry {
    host: Arc<dyn TelemetryHost>,
    queued: Arc<PoolQueueDepth>,
}

impl std::fmt::Debug for HostTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostTelemetry").finish_non_exhaustive()
    }
}

impl HostTelemetry {
    /// Bind the unit's counters to the host's, over the depth this node publishes the wait gauge
    /// from.
    #[must_use]
    pub fn new(host: Arc<dyn TelemetryHost>, queued: Arc<PoolQueueDepth>) -> Self {
        HostTelemetry { host, queued }
    }

    /// The depth the wait gauge is published from.
    #[must_use]
    pub fn queue_depth(&self) -> &Arc<PoolQueueDepth> {
        &self.queued
    }
}

impl Telemetry for HostTelemetry {
    fn upstream_attempt(&self, pool: &str, destination: DestinationId) {
        self.host
            .telemetry_upstream_attempt(pool, lane_of_destination(destination));
    }

    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str) {
        self.host
            .telemetry_upstream_failure(pool, lane_of_destination(destination), disposition);
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        self.host.telemetry_failover(pool, reason);
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        self.host
            .telemetry_breaker_trip(pool, lane_of_destination(destination));
    }

    fn queued(&self, pool: &str, delta: i64) {
        self.queued.shift(pool, delta);
    }
}

// ── the write-ahead journal ─────────────────────────────────────────────────────────────────────

/// The dispatch record's journal body.
///
/// A position in the plan, an attempt number, the cell it is recorded against, the member being
/// dialled and the lane it was sealed on — which is everything a reader needs to say WHICH dispatch
/// this was, and nothing about what was in it. Content is not here for the same reason it is not in
/// a sealed audit record: the journal is a financial record exempt from erasure, so anything put in
/// it can never be taken out.
///
/// The trailing marker is what separates a dispatch that was recorded and then happened from one
/// that was recorded and then abandoned. The design requires an abandoned attempt to be EXPLICIT
/// rather than inferred from a missing settle, and a reader that had to infer it would have to know
/// what a settle looks like.
#[must_use]
pub fn dispatch_body(record: &Dispatched, marker: &str) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.num(u64::from(record.leg));
    body.num(u64::from(record.attempt));
    body.text(&record.pool);
    body.num(record.destination.get());
    body.text(record.lane.as_ref().map_or("", |lane| lane.as_str()));
    body.text(marker);
    body.finish()
}

/// The marker a dispatch that is about to happen carries.
const DISPATCHED: &str = "dispatched";

/// The marker a journaled dispatch that never produced an answer carries.
const ABANDONED: &str = "abandoned";

/// The write-ahead journal, bound to this node's one chain.
///
/// Borrowed rather than held, and for one reason: the durability credential is minted for the
/// length of one call and lent down, so a binding that owned one would be a binding that could
/// write a record outside the step that authorised it. This one carries the borrow it was lent and
/// nothing else, which is why it has a lifetime and the other four do not.
///
/// The record is DURABLE BEFORE THE DIAL. That is not a property this binding adds — it is the
/// journal's own append, which does not return until the record is durable — but it is the reason
/// this seam is fallible at all, and a failure here ends the attempt before any byte leaves.
pub struct ChainJournal<'a> {
    durability: &'a Mutex<Durability>,
    token: &'a DurabilityToken,
}

impl std::fmt::Debug for ChainJournal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainJournal").finish_non_exhaustive()
    }
}

impl<'a> ChainJournal<'a> {
    /// Bind the unit's journal seam to this node's chain, under the credential the step was lent.
    #[must_use]
    pub fn new(durability: &'a Mutex<Durability>, token: &'a DurabilityToken) -> Self {
        ChainJournal { durability, token }
    }

    /// Put one dispatch record on the chain.
    ///
    /// `Transaction`, because that is the class the chain already declares a dispatch under — a
    /// hold, a dispatch, a settlement or an adjustment — so the record a dispatch makes and the
    /// record its settlement makes are on the same chain in the right order, which is the whole
    /// thing one journal buys.
    fn append(&self, record: &Dispatched, marker: &str) -> Result<(), DurabilityUnavailable> {
        let entry = Entry::new(RecordClass::Transaction, dispatch_body(record, marker));
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability
            .journal
            .append(self.token, StepName::Route, &[entry])
            .map(|_ack| ())
            .map_err(|_lost| DurabilityUnavailable)
    }
}

impl Journal for ChainJournal<'_> {
    fn dispatched(&self, record: &Dispatched) -> Result<(), DurabilityUnavailable> {
        self.append(record, DISPATCHED)
    }

    fn abandoned(&self, record: &Dispatched) {
        // An abandonment cannot refuse the thing it is recording — the dispatch has already not
        // happened. A chain that will not take the record is a durability problem the journal
        // reports through its own path; there is nothing for this seam to do about it and nothing
        // for a caller to decide, which is why the port's own signature does not offer one.
        let _ = self.append(record, ABANDONED);
    }
}

// ── the credential that decorates an outbound request ───────────────────────────────────────────

/// One destination's declared egress credential, resolved once.
///
/// The scheme comes from the DIALECT's own declaration, resolved through the substrate's resolver
/// at boot; the secret is the lane's. Held together because that is what a decoration needs and
/// neither half names the other: several dialects decorate under one scheme, and which secret is
/// substituted is a fact of the lane, not of the scheme.
struct LaneCredential {
    provider: Arc<dyn CredentialProvider>,
    key: busbar_api::Redacted<String>,
    mode: UpstreamCreds,
}

impl std::fmt::Debug for LaneCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written, and it prints no credential. The wrapper around the key redacts already;
        // this is the second of the two, so neither the wrapper nor a derive is the single thing
        // standing between the secret and a log line.
        f.debug_struct("LaneCredential").finish_non_exhaustive()
    }
}

/// The auth-style override a lane declared, as the substrate's resolver takes it.
///
/// A total map between two neutral vocabularies and nothing else. `Default` is the absence of an
/// override — the resolver then answers with the dialect's own declared scheme, which is the arm
/// every lane this build serves takes.
fn declared_auth(style: AuthStyleInput) -> Option<ProviderAuth> {
    match style {
        AuthStyleInput::Default => None,
        AuthStyleInput::Bearer => Some(ProviderAuth::Bearer),
        AuthStyleInput::ApiKey => Some(ProviderAuth::ApiKey),
        AuthStyleInput::JwtBearer => Some(ProviderAuth::JwtBearer),
        AuthStyleInput::OAuthClientCredentials => Some(ProviderAuth::OAuthClientCredentials),
    }
}

/// The egress-auth seam, bound to the schemes the dialects declared.
///
/// Keyed by the lane the trust unit sealed, because that is the only thing a verified destination
/// carries that names WHICH credential: the scheme alone does not, and a decoration that guessed
/// one from the scheme is precisely what this seam exists to make impossible.
///
/// **There is no arm for any provider in this file, and there must never be one.** A destination's
/// scheme was resolved from the dialect's own declaration before this node served anything; asking
/// it for headers is one call whether it writes a static header or signs the body. That is what
/// makes a new dialect cost this binding nothing, and it is the same property the dialect
/// declaration was introduced to buy.
pub struct DeclaredEgressAuth {
    by_lane: std::collections::HashMap<&'static str, LaneCredential>,
}

impl std::fmt::Debug for DeclaredEgressAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclaredEgressAuth")
            .field("lanes", &self.by_lane.len())
            .finish_non_exhaustive()
    }
}

impl DeclaredEgressAuth {
    /// Resolve every configured lane's declared scheme, once, at boot.
    ///
    /// `seat` is the root's interner: a lane is keyed here by the same static name the pool's
    /// members carry, so the two tables agree by construction rather than by a string compare that
    /// could disagree about a trailing space.
    ///
    /// The all-pools credential mode is the deployment's; a pool that overrides it overrides it for
    /// the pools it names, and the walk resolves WHOSE credential decorates a request once per walk
    /// — so what is held per lane is the deployment default, and the override reaches the
    /// decoration through the walk, not through this table.
    #[must_use]
    pub fn resolve(input: &PlaneBuildInput, seat: &mut dyn FnMut(&str) -> &'static str) -> Self {
        let mut by_lane = std::collections::HashMap::with_capacity(input.lanes.len());
        for lane in &input.lanes {
            by_lane.insert(seat(&lane.model), Self::credential_for(lane, input));
        }
        DeclaredEgressAuth { by_lane }
    }

    /// One lane's credential, asked of the substrate's resolver by the lane's own protocol name and
    /// declared override.
    fn credential_for(lane: &LaneInput, input: &PlaneBuildInput) -> LaneCredential {
        LaneCredential {
            provider: resolve_scheme(&lane.protocol, declared_auth(lane.auth_style)),
            key: lane.api_key.clone(),
            mode: input.upstream_credentials,
        }
    }

    /// The credential for one verified destination, by the lane it was sealed on.
    ///
    /// Read off the sealed destination's own lane accessor, which reads it off the sealed facts —
    /// so this binding holds no second reading of which lane a destination is on, and a
    /// destination that is not an upstream has no lane to be keyed by and no credential here.
    fn credential(&self, dest: &VerifiedDestination) -> Option<&LaneCredential> {
        self.by_lane.get(dest.lane()?.as_str())
    }
}

impl EgressAuth for DeclaredEgressAuth {
    fn decorate(
        &self,
        dest: &VerifiedDestination,
        request: &mut OutboundRequest<'_>,
    ) -> Result<(), DecorationRefused> {
        // A destination this node holds no credential for is refused, not decorated with nothing:
        // an undecorated request to an upstream that requires a credential is a guaranteed refusal
        // wearing the shape of a transient one, and it would reach the breaker as the
        // destination's fault.
        let credential = self.credential(dest).ok_or(DecorationRefused)?;
        // ASKED OF THE DECLARATION, never of the name. A scheme states whether its headers are a
        // pure function of the resolved credential and the mode — reading nothing else about the
        // request it decorates. One that says yes is decorated here and the two request-shaped
        // slots below are provably unread. One that says no signs over the request itself, and the
        // request it would have to sign does not exist yet at this seam: the transport renders the
        // envelope AFTER the decoration returns, so the path a signature covers is not knowable
        // here. Such a scheme is REFUSED rather than signed over the wrong bytes — a signature that
        // does not verify is a guaranteed upstream refusal wearing the shape of a transient one,
        // and it would reach the breaker as the destination's fault. What that seam needs is named
        // in the hand-back; it is not something this binding may decide.
        if !credential.provider.is_lane_constant() {
            return Err(DecorationRefused);
        }
        let ctx = SigningContext {
            host: "",
            canonical_uri: "",
            body: request.body,
            timestamp_epoch: NodeClock.now_secs(),
            upstream_creds: credential.mode,
        };
        for (name, value) in credential
            .provider
            .headers_for(credential.key.expose_secret(), &ctx)
        {
            request
                .fields
                .push((name.as_str().to_string(), value.as_bytes().to_vec()));
        }
        Ok(())
    }
}

/// The destination one lane index names, re-exported at this module's own path so a caller binding
/// the five seams above does not have to reach into the pool's file for the one correspondence they
/// all key on.
#[must_use]
pub fn destination_for(lane_idx: usize) -> DestinationId {
    destination_of_lane(lane_idx)
}

#[cfg(test)]
#[path = "tests/egress_bindings.rs"]
mod tests;
