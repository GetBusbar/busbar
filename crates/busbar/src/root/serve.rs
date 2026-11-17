// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane::{declares_record_kind, PlaneDeclaration};
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
};
use busbar_kernel::host_records::QUEUE_CAP;
use busbar_kernel::host_services::{BlockingPool, DestJudge, KernelServices, SignKey};
use busbar_kernel::limits::process_admission::RequestLease;
use busbar_kernel::plane_driver::serve::ServeTables;
use busbar_kernel::plane_driver::{
    refusal_status, CallerEnd, Egress, HeadFields, PlaneDriver, PlaneMoney, Rendered, SessionCaller,
};
use busbar_kernel::store::plane_view::KIND_DEMOTION;
use tokio::sync::{mpsc, oneshot};

use crate::root::boot::DoorPlane;
use crate::root::door_steps::{DoorFacts, DoorPools};
use crate::root::loader::dispatch::kinds::plane::OwnedSnapshot;
use crate::root::loader::dispatch::services::ServicesSlot;

use crate::root::door_steps::{egress_pool, DoorCaller, DoorSteps};
use crate::root::loader::dispatch::Dispatcher;
use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
use busbar_contract::abi::mechanism::route::RouteMethod;
use busbar_contract::abi::plane::{CLAIM_ENTRY, CLAIM_OPEN, CLAIM_RAW_AFFIX};
use busbar_contract::auth::AuthPrincipal;
use busbar_contract::caps::{Pass, PrincipalId, Route};
use busbar_kernel::observability::arrival::EntrySpans;
use busbar_kernel::plane_driver::{
    Arrival, EgressFarEnd, FarEnd, FarPiece, OutboundRequest, Pick, RoutedScope, UnitRoute,
};
use busbar_kernel::plane_routes::PlaneReqCtx;

// The test modules below name these through `use super::*`.
#[cfg(test)]
use crate::root::door_steps::door_facts;
#[cfg(test)]
use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_PATTERN};
#[cfg(test)]
use busbar_contract::yaml::ValueExt;

// The composition this module's request path serves: built off the request path.
pub(crate) use crate::root::off_path::serve::*;

#[cfg(test)]
pub(crate) const DEFAULT_EGRESS_CLASS: u32 = 0;

#[path = "serve_neutral.rs"]
pub(crate) mod neutral;

#[path = "serve_observations.rs"]
mod observations;

#[path = "native_nests.rs"]
mod native_nests;

#[cfg(test)]
#[must_use]
pub(crate) fn kernel_services(dest: Arc<dyn DestJudge>) -> KernelServices {
    KernelServices::new()
        .with_mono_clock(Arc::new(crate::root::loader::dispatch::now_ns))
        .with_dest_judge(dest)
        .with_disk_lane(crate::root::linked::disk_lane())
}

pub(crate) fn compose(
    dest: Arc<dyn DestJudge>,
    app: &busbar_kernel::state::App,
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    planes: &[&PlaneDeclaration],
) -> Arc<Services> {
    let signer = app.governance.clone().map(|gov| gov as Arc<dyn SignKey>);
    let tickets = app.governance.as_ref().map(|governance| {
        Arc::new(GenerationTickets {
            governance: Arc::clone(governance),
            block_max_ttl_secs: app.mint_policy.block_max_ttl_secs,
        }) as Arc<dyn busbar_kernel::host_services::TicketPress>
    });
    let kernel = KernelServices::from_inputs(busbar_kernel::host_services::CoreServicesInputs {
        persistence: core,
        pool: Arc::new(BlockingPool::new(
            tokio::runtime::Handle::current(),
            QUEUE_CAP,
        )),
        signer,
        demotions: Arc::clone(&app.demotion_record),
        demotion_owner: demotion_owner(planes).map(Arc::from),
        tickets,
        standing: busbar_kernel::plane_driver::policy_standing(
            app.governance.clone(),
            app.role_bindings.clone(),
        ),
        judge: dest,
        credentials: Arc::new(crate::root::credentials::AppCredentials::new(
            app.governance.clone(),
        )),
        disk: crate::root::linked::disk_lane(),
    })
    .with_mono_clock(Arc::new(crate::root::loader::dispatch::now_ns));
    Services::serving(Arc::new(kernel))
}

/// The most unredeemed tickets one node holds in custody, across every key.
const TICKET_CUSTODY_CAP: usize = 4_096;
/// The tickets one sweep observes.
pub(crate) const TICKET_SWEEP_BATCH: usize = 256;
/// The most unredeemed tickets one key holds on one node. At these defaults, 16 saturated keys are
/// needed to fill a node.
pub(crate) const TICKET_CUSTODY_PER_KEY: usize = 256;
/// One full sweep cycle, in seconds: the sweep visits every held ticket in this many passes.
const TICKET_SWEEP_CYCLE_SECS: u64 = (TICKET_CUSTODY_CAP / TICKET_SWEEP_BATCH) as u64;

/// Every node's ticket custody, by the node's registration order. A custody leaves the list when it
/// drops, so the list holds no dead entries to prune.
static TICKET_NODES: Mutex<BTreeMap<u64, std::sync::Weak<TicketCustody>>> =
    Mutex::new(BTreeMap::new());
/// The next [`TICKET_NODES`] key.
static TICKET_NODE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) struct TicketCustody {
    pub(crate) nonce: Arc<()>,
    /// This custody's key in [`TICKET_NODES`].
    pub(crate) node: u64,
    pub(crate) closed: std::sync::atomic::AtomicBool,
    pub(crate) sources: Mutex<foldhash::HashMap<busbar_contract::UnitKey, Arc<TicketSource>>>,
    pub(crate) entries: Mutex<TicketEntries>,
    /// Store reads the custody sweep issued.
    #[cfg(test)]
    pub(crate) sweep_reads: std::sync::atomic::AtomicU64,
}

impl Drop for TicketCustody {
    fn drop(&mut self) {
        let gone = TICKET_NODES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.node);
        drop(gone);
    }
}

/// A ticket source's key, indexed by its id: the source's key is shared, its id never copied.
pub(crate) struct KeyId(Arc<busbar_contract::records::VirtualKey>);

impl PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for KeyId {}

impl std::hash::Hash for KeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(self.0.id.as_str(), state);
    }
}

impl std::borrow::Borrow<str> for KeyId {
    fn borrow(&self) -> &str {
        &self.0.id
    }
}

/// The node's ticket custody. `tickets` is the map; `by_key` partitions it per key id as
/// `(expires_at, ticket id)`, `pending` names each unit's one ticket not yet ready, and `due`
/// orders every held ticket by expiry for the sweep. Every index shares the map's one copy of a
/// ticket id. Only [`TicketEntries::insert`], [`TicketEntries::remove_entry`],
/// [`TicketEntries::take_pending`] and [`TicketEntries::take_all`] change them, and each keeps the
/// four in step.
#[derive(Default)]
pub(crate) struct TicketEntries {
    pub(crate) tickets: BTreeMap<Arc<str>, TicketEntry>,
    pub(crate) by_key: foldhash::HashMap<KeyId, std::collections::BTreeSet<(u64, Arc<str>)>>,
    pub(crate) pending: foldhash::HashMap<busbar_contract::UnitKey, Arc<str>>,
    /// Every held ticket by its expiry (unix seconds), so the sweep reads only the due ones.
    pub(crate) due: std::collections::BTreeSet<(u64, Arc<str>)>,
    pub(crate) cursor: Option<Arc<str>>,
    /// When the round-robin backstop last ran.
    pub(crate) backstop_at: Option<std::time::Instant>,
    pub(crate) version: u64,
}

impl TicketEntries {
    /// Hold `entry` under `id`, indexed by its key, its expiry and, when not ready, by its unit.
    /// A ticket the map already held under `id` is answered, unindexed, for the caller to drop
    /// outside the lock.
    pub(crate) fn insert(&mut self, id: Arc<str>, entry: TicketEntry) -> Option<TicketEntry> {
        let replaced = self.remove(&id);
        self.by_key
            .entry(KeyId(Arc::clone(&entry.source.key)))
            .or_default()
            .insert((entry.expires_at, Arc::clone(&id)));
        if !entry.ready {
            self.pending.insert(entry.source.unit, Arc::clone(&id));
        }
        self.due.insert((entry.expires_at, Arc::clone(&id)));
        self.tickets.insert(id, entry);
        replaced
    }

    /// Release the ticket `id`, out of every index.
    pub(crate) fn remove(&mut self, id: &str) -> Option<TicketEntry> {
        self.remove_entry(id).map(|(_, entry)| entry)
    }

    /// Release the ticket `id`, out of every index, with the map's copy of its id.
    fn remove_entry(&mut self, id: &str) -> Option<(Arc<str>, TicketEntry)> {
        let (id, entry) = self.tickets.remove_entry(id)?;
        let key = entry.source.key.id.as_str();
        if let Some(held) = self.by_key.get_mut(key) {
            held.remove(&(entry.expires_at, Arc::clone(&id)));
            if held.is_empty() {
                self.by_key.remove(key);
            }
        }
        if self
            .pending
            .get(&entry.source.unit)
            .is_some_and(|pending| *pending == id)
        {
            self.pending.remove(&entry.source.unit);
        }
        self.due.remove(&(entry.expires_at, Arc::clone(&id)));
        Some((id, entry))
    }

    /// Release `unit`'s one ticket not yet ready, if it holds one, with its id.
    fn take_pending(&mut self, unit: busbar_contract::UnitKey) -> Option<(Arc<str>, TicketEntry)> {
        let id = Arc::clone(self.pending.get(&unit)?);
        self.remove_entry(&id)
    }

    /// Release every ticket.
    fn take_all(&mut self) -> BTreeMap<Arc<str>, TicketEntry> {
        self.by_key.clear();
        self.pending.clear();
        self.due.clear();
        std::mem::take(&mut self.tickets)
    }

    /// Whether one more ticket for `key_id` may be held at `now` (Unix seconds): refused when the
    /// key already holds `per_key` (retry when its own earliest ticket has expired and one sweep
    /// cycle has passed), or when the node holds [`TICKET_CUSTODY_CAP`] (retry after one cycle).
    fn admits(
        &self,
        key_id: &str,
        per_key: usize,
        now: u64,
    ) -> Result<(), busbar_kernel::governance::TicketRefusal> {
        use busbar_kernel::governance::TicketRefusal;
        let held = self.by_key.get(key_id);
        if held.map_or(0, std::collections::BTreeSet::len) >= per_key {
            let earliest = held
                .and_then(std::collections::BTreeSet::first)
                .map_or(now, |(expires_at, _)| *expires_at);
            let retry = earliest
                .saturating_sub(now)
                .saturating_add(TICKET_SWEEP_CYCLE_SECS);
            return Err(TicketRefusal::KeySaturated {
                retry_after_secs: u32::try_from(retry).unwrap_or(u32::MAX).max(1),
            });
        }
        if self.tickets.len() >= TICKET_CUSTODY_CAP {
            return Err(TicketRefusal::NodeSaturated {
                retry_after_secs: TICKET_SWEEP_CYCLE_SECS as u32,
            });
        }
        Ok(())
    }
}

pub(crate) const TICKET_SKEW_SECS: u64 = busbar_kernel::config::limits::DEFAULT_TICKET_SKEW_SECS;
pub(crate) const TICKET_BACKSTOP: std::time::Duration =
    std::time::Duration::from_secs(busbar_kernel::config::limits::DEFAULT_TICKET_BACKSTOP_SECS);
const _: () = assert!(TICKET_SKEW_SECS <= 60, "ticket skew stays within [0, 60] s");

pub(crate) struct TicketEntry {
    pub(crate) reservation: busbar_kernel::plane_driver::TicketReservation,
    pub(crate) source: Arc<TicketSource>,
    pub(crate) ready: bool,
    pub(crate) version: u64,
    pub(crate) store: Arc<busbar_kernel::persistence::facade::CoreStore>,
    pub(crate) expires_at: u64,
}

pub(crate) struct TicketSource {
    pub(crate) store: Arc<busbar_kernel::persistence::facade::CoreStore>,
    pub(crate) key: Arc<busbar_contract::records::VirtualKey>,
    pub(crate) money: std::sync::Weak<PlaneMoney>,
    pub(crate) instance: Arc<str>,
    pub(crate) instance_nonce: Arc<()>,
    pub(crate) live: std::sync::Weak<DoorApply>,
    pub(crate) unit: busbar_contract::UnitKey,
    /// The most unredeemed tickets this source's key may hold on its node.
    pub(crate) per_key: usize,
    pub(crate) actual: Mutex<
        Option<(
            busbar_contract::caps::CallId,
            std::sync::Weak<busbar_kernel::inflight::UnitSlot>,
        )>,
    >,
    pub(crate) reserved: std::sync::atomic::AtomicBool,
    pub(crate) active: std::sync::atomic::AtomicBool,
}

pub(crate) struct TicketSourceOwner {
    pub(crate) custody: Arc<TicketCustody>,
    pub(crate) source: Arc<TicketSource>,
}

impl Drop for TicketSourceOwner {
    fn drop(&mut self) {
        self.source
            .active
            .store(false, std::sync::atomic::Ordering::Release);

        let removed = self
            .custody
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.source.unit);
        drop(removed);
        let pending = {
            let mut entries = self
                .custody
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let owned = entries
                .pending
                .get(&self.source.unit)
                .and_then(|id| entries.tickets.get(&**id))
                .is_some_and(|e| Arc::ptr_eq(&e.source, &self.source));
            if owned {
                entries.take_pending(self.source.unit)
            } else {
                None
            }
        };
        drop(pending);
    }
}

impl TicketCustody {
    pub(crate) fn new() -> Arc<Self> {
        let node = TICKET_NODE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let custody = Arc::new(Self {
            nonce: Arc::new(()),
            node,
            closed: std::sync::atomic::AtomicBool::new(false),
            sources: Mutex::new(foldhash::HashMap::default()),
            entries: Mutex::new(TicketEntries::default()),
            #[cfg(test)]
            sweep_reads: std::sync::atomic::AtomicU64::new(0),
        });
        TICKET_NODES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(node, Arc::downgrade(&custody));
        custody
    }

    fn register(
        self: &Arc<Self>,
        unit: busbar_contract::UnitKey,
        key: Option<&Arc<busbar_contract::records::VirtualKey>>,
        served: &ServedPlane,
        live: &DoorLive,
        app: &busbar_kernel::state::App,
    ) -> Option<TicketSourceOwner> {
        let source = Arc::new(TicketSource {
            store: app.governance.as_ref()?.core_store_handle().ok()?,
            key: Arc::clone(key?),
            money: Arc::downgrade(&served.money),
            instance: Arc::clone(&served.live.instance),
            instance_nonce: Arc::clone(&live.ticket_nonce),
            live: Arc::downgrade(&served.live),
            unit,
            per_key: TICKET_CUSTODY_PER_KEY,
            actual: Mutex::new(None),
            reserved: std::sync::atomic::AtomicBool::new(false),
            active: std::sync::atomic::AtomicBool::new(true),
        });
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sources.contains_key(&unit) {
            return None;
        }
        sources.insert(unit, Arc::clone(&source));
        Some(TicketSourceOwner {
            custody: Arc::clone(self),
            source,
        })
    }

    pub(crate) fn bind_source(
        &self,
        ctx: &busbar_kernel::teller::UnitCtx,
        slot: &Arc<busbar_kernel::inflight::UnitSlot>,
    ) {
        let source = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ctx.key)
            .cloned();
        if let Some(source) = source {
            *source
                .actual
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((ctx.call, Arc::downgrade(slot)));
        }
    }

    fn bind(
        &self,
        source: &Arc<TicketSource>,
        identity: &busbar_kernel::host_services::VerifiedTicketIdentity,
    ) -> Result<(), busbar_kernel::governance::TicketRefusal> {
        use busbar_kernel::governance::TicketRefusal;
        if !Arc::ptr_eq(&source.store, identity.store()) {
            return Err(TicketRefusal::NotKept);
        }
        let (call, slot) = source
            .actual
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(TicketRefusal::NotKept)?;
        let slot = slot.upgrade().ok_or(TicketRefusal::NotKept)?;
        let principal = PrincipalId::new(source.key.id.as_str());
        let money = source.money.upgrade().ok_or(TicketRefusal::NotKept)?;
        let reservation = slot
            .cell()
            .with_admitted_call(call, &principal, || {
                source
                    .reserved
                    .compare_exchange(
                        false,
                        true,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .map_err(|_| ReasonCode::Replayed)?;
                money.reserve_ticket_admission(
                    source.unit,
                    call,
                    &source.key,
                    identity,
                    Arc::clone(&self.nonce),
                    Arc::clone(&source.instance_nonce),
                )
            })
            .map_err(|_| TicketRefusal::NotKept)?;
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !source.active.load(std::sync::atomic::Ordering::Acquire)
            || self.closed.load(std::sync::atomic::Ordering::Acquire)
            || entries.tickets.contains_key(identity.id())
            || entries.pending.contains_key(&source.unit)
        {
            drop(entries);
            drop(reservation);
            return Err(TicketRefusal::NotKept);
        }
        if let Err(refusal) = entries.admits(
            source.key.id.as_str(),
            source.per_key,
            busbar_kernel::store::now(),
        ) {
            drop(entries);
            drop(reservation);
            return Err(refusal);
        }
        let Some(version) = entries.version.checked_add(1) else {
            drop(entries);
            drop(reservation);
            return Err(TicketRefusal::NotKept);
        };
        entries.version = version;
        let replaced = entries.insert(
            Arc::from(identity.id()),
            TicketEntry {
                reservation,
                source: Arc::clone(source),
                ready: false,
                version,
                store: Arc::clone(identity.store()),
                expires_at: identity.expires_at(),
            },
        );
        drop(entries);
        drop(replaced);
        Ok(())
    }

    pub(crate) fn terminal(&self, key: busbar_contract::UnitKey, acknowledged_completed: bool) {
        let removed = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match entries.take_pending(key) {
                Some((id, mut entry)) if acknowledged_completed => {
                    entry.ready = true;
                    entries.insert(id, entry)
                }
                Some((_, entry)) => Some(entry),
                None => None,
            }
        };
        drop(removed);
    }

    fn claim(
        &self,
        identity: &busbar_kernel::host_services::VerifiedTicketIdentity,
    ) -> Option<busbar_kernel::plane_driver::TicketReservation> {
        let (source, version) = {
            let entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = entries.tickets.get(identity.id())?;
            if !entry.ready || !entry.reservation.matches(identity) {
                return None;
            }
            (Arc::clone(&entry.source), entry.version)
        };

        let live = source.live.upgrade()?.current();
        if !Arc::ptr_eq(&live.ticket_nonce, &source.instance_nonce) {
            return None;
        }
        let removed = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = entries.tickets.get(identity.id())?;
            if !entry.ready || entry.version != version || !entry.reservation.matches(identity) {
                return None;
            }
            entries.remove(identity.id())
        };
        removed.map(|entry| entry.reservation)
    }

    pub(crate) fn shutdown(&self) {
        let entries = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
            entries.take_all()
        };
        drop(entries);
    }
}

/// The first registered custody after `after` (registration order), and whether it is still live.
/// One entry per call: the list's lock is never held while a custody runs, or drops (its drop takes
/// the lock again).
fn next_ticket_node(after: Option<u64>) -> Option<(u64, Option<Arc<TicketCustody>>)> {
    use std::ops::Bound::{Excluded, Unbounded};
    let nodes = TICKET_NODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let lower = after.map_or(Unbounded, Excluded);
    let (key, node) = nodes.range((lower, Unbounded)).next()?;
    Some((*key, node.upgrade()))
}

pub(crate) fn claim_ticket_custody(
    identity: &busbar_kernel::host_services::VerifiedTicketIdentity,
) -> busbar_kernel::host_services::TicketClaimDisposition {
    use busbar_kernel::host_services::TicketClaimDisposition;

    let mut after = None;
    while let Some((key, node)) = next_ticket_node(after) {
        after = Some(key);
        let Some(node) = node else { continue };
        if let Some(reservation) = node.claim(identity) {
            return TicketClaimDisposition::Reserved(reservation);
        }
    }
    TicketClaimDisposition::Refused
}

/// Mint authority retained by the serving generation that admitted the unit.
pub(crate) struct GenerationTickets {
    pub(crate) governance: Arc<busbar_kernel::governance::GovState>,
    pub(crate) block_max_ttl_secs: Option<u64>,
}

#[async_trait::async_trait]
impl busbar_kernel::host_services::TicketPress for GenerationTickets {
    async fn mint_for_unit(
        &self,
        unit: u64,
        caller: &Caller,
        principal: &Arc<busbar_contract::records::VirtualKey>,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), busbar_kernel::governance::TicketRefusal> {
        use busbar_kernel::governance::TicketRefusal;
        if ttl_secs == 0 || now.checked_add(ttl_secs).is_none() {
            return Err(TicketRefusal::NoLifetime);
        }
        let gov = &self.governance;
        let unit_key = busbar_contract::UnitKey::new(unit);
        let mut found = None;
        let mut after = None;
        while let Some((key, node)) = next_ticket_node(after) {
            after = Some(key);
            let Some(node) = node else { continue };
            let source = node
                .sources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&unit_key)
                .filter(|s| {
                    *s.instance == *caller.namespace().as_ref()
                        && s.key.as_ref() == principal.as_ref()
                })
                .cloned();
            if let Some(source) = source {
                if found.is_some() {
                    return Err(TicketRefusal::NotKept);
                }
                found = Some((node, source));
            }
        }
        let (node, source) = found.ok_or(TicketRefusal::NotKept)?;
        // A saturated key or node writes nothing: `bind` stays the authoritative gate, and the
        // mint's compensating delete covers only a race between the two checks.
        node.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admits(principal.id.as_str(), source.per_key, now)?;
        gov.mint_ticket_bound(
            &principal.id,
            prefix,
            ttl_secs,
            self.block_max_ttl_secs,
            record,
            now,
            |identity| node.bind(&source, identity),
        )
        .await
    }

    async fn mint(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), busbar_kernel::governance::TicketRefusal> {
        let gov = &self.governance;
        gov.mint_ticket(
            key_id,
            prefix,
            ttl_secs,
            self.block_max_ttl_secs,
            record,
            now,
        )
        .await
    }
}

pub(crate) const RECORD_DRAIN: std::time::Duration =
    std::time::Duration::from_secs(5 * busbar_kernel::host_records::FLUSH_INTERVAL.as_secs());

pub(crate) async fn drain_records(late: &Services, deadline: std::time::Duration) -> bool {
    let Some(kernel) = late.kernel() else {
        return true;
    };
    tokio::task::spawn_blocking(move || kernel.drain(deadline))
        .await
        .unwrap_or(false)
}

#[must_use]
pub(crate) fn demotion_owner(planes: &[&PlaneDeclaration]) -> Option<&'static str> {
    let mut owners = planes
        .iter()
        .filter(|d| declares_record_kind(d, KIND_DEMOTION));
    match (owners.next(), owners.next()) {
        (Some(d), None) => Some(d.config_section),
        _ => None,
    }
}

/// Complete services for a phase. Bootstrap owns a permanently restricted provider;
/// a serving generation owns its fully constructed kernel.
pub(crate) struct Services {
    pub(crate) slot: Arc<ServicesSlot>,
    kernel: Option<Arc<KernelServices>>,
}

pub(crate) const NOT_INSTALLED: &str = "bootstrap services do not have serving authority";

impl Services {
    pub(crate) fn bootstrap() -> Arc<Self> {
        Arc::new(Self {
            slot: ServicesSlot::of(Arc::new(BootstrapServices)),
            kernel: None,
        })
    }

    pub(crate) fn serving(kernel: Arc<KernelServices>) -> Arc<Self> {
        Arc::new(Self {
            slot: ServicesSlot::of(kernel.clone()),
            kernel: Some(kernel),
        })
    }

    pub(crate) fn slot(&self) -> Arc<ServicesSlot> {
        Arc::clone(&self.slot)
    }
    pub(crate) fn kernel(&self) -> Option<Arc<KernelServices>> {
        self.kernel.clone()
    }

    /// Prepare the flush loop under the same lifecycle owner as the generation's other workers.
    pub(crate) fn prepare_workers(&self, workers: &mut super::boot::workers::PreparedWorkers) {
        if let Some(kernel) = self.kernel() {
            workers.push(async move { kernel.flushes().await });
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(provider: Arc<dyn HostServices>) -> Arc<Self> {
        Arc::new(Self {
            slot: ServicesSlot::of(provider),
            kernel: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn served(&self) -> Arc<dyn HostServices> {
        Arc::clone(self.slot.get())
    }
}

/// THE ONE TRUST BINDING (TRUST-ADMIN-PRODUCER-DESIGN r3 §2.2): the serving kernel twice, as the
/// admin governance's decide-capable handle and as the read-only handle the `AppHandle` carries.
/// Bootstrap services have neither.
pub(crate) fn admin_trust(
    services: &Services,
) -> (
    Option<Arc<KernelServices>>,
    Option<busbar_kernel::trust::TrustReadout>,
) {
    let kernel = services.kernel();
    let readout = kernel.clone().map(busbar_kernel::trust::TrustReadout::over);
    (kernel, readout)
}

pub(crate) struct BootstrapServices;

fn not_installed() -> Stored {
    Stored::refused(NOT_INSTALLED)
}

impl HostServices for BootstrapServices {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: busbar_kernel::store::now_ns(),
            mono_ns: crate::root::loader::dispatch::now_ns(),
        }
    }

    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        Ran::Now(not_installed())
    }

    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        not_installed()
    }

    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn trust_unreached(&self, _: &Caller, _: &str) -> Stored {
        not_installed()
    }

    fn trust_decide(
        &self,
        _: &Caller,
        _ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        _: busbar_contract::services::TrustKeyRef<'_>,
        _: Option<&str>,
        _: bool,
        _: Later,
    ) -> Ran {
        Ran::Now(not_installed())
    }

    fn trust_state(&self, _: &Caller, _: &str) -> Stored {
        not_installed()
    }

    fn trust_sight_item(&self, _: &Caller, _: &str, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn trust_serves(&self, _: &Caller, _: &str, _: Option<&str>, _: Option<&str>) -> Stored {
        not_installed()
    }

    fn trust_due(&self, _: &Caller) -> Stored {
        not_installed()
    }

    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        not_installed()
    }

    fn random_fill(&self, _: u64) -> Stored {
        not_installed()
    }

    fn session_emit(&self, _: &Caller, _: u64, _: &[u8]) -> Stored {
        not_installed()
    }

    fn ticket_mint(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn ticket_take(&self, _: &Caller, _: Option<u64>) -> Stored {
        not_installed()
    }

    fn records_secret(&self, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        not_installed()
    }

    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn hook_call(&self, _: &Caller, _: Option<u64>, _: HookAsk, _: Later) -> Ran {
        Ran::Now(not_installed())
    }

    fn snapshot_read(&self, _: &Caller, _: u32, _: Later) -> Ran {
        Ran::Now(not_installed())
    }
}

/// ONE DOOR PLANE, COMPOSED: its instance, the driver the
/// kernel serves it through, the snapshot its `open` published (its claims and admin routes), and
/// what its units are served by: its tail's facts, the pools its section states, its money steps
/// and its egress.
#[derive(Clone)]
pub(crate) struct ServedPlane {
    /// The instance's label.
    pub(crate) instance: String,
    /// The plane's driver: admitted to the kernel's services, its driver ticket minted.
    pub(crate) driver: Arc<PlaneDriver>,
    /// The first generation's snapshot, as the host copied it.
    pub(crate) snapshot: OwnedSnapshot,
    /// The `audit_kind` its tail states: what its units are audited under.
    #[cfg(test)]
    pub(crate) audit_kind: &'static str,
    /// Its key, scope kind, billable classes and fee units, read off its tail.
    pub(crate) facts: DoorFacts,
    /// Its money steps: the same seam its driver reports units, cancel bills and abandoned ends to.
    pub(crate) money: Arc<PlaneMoney>,
    /// What its units are served over for the current refresh generation (its pools and its
    /// egress), replaced whole by a config apply ([`DoorApply`]).
    pub(crate) live: Arc<DoorApply>,
    /// The kernel's host services it was admitted to: its units' records are written there.
    pub(crate) kernel: Arc<KernelServices>,
    /// Its tail's dialects, in order: what a unit's dialect index names.
    pub(crate) dialects: Vec<&'static str>,
}

pub(crate) struct BoundConns {
    pub(crate) inner: Arc<dyn busbar_contract::conn::PollConns>,
    pub(crate) _binding: crate::root::loader::dispatch::plugin::ConnectionBinding,
}

impl busbar_contract::conn::Conns for BoundConns {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.inner.open(caller, need, desc)
    }
    fn open_with_security(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        secure: bool,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.inner.open_with_security(caller, need, desc, secure)
    }
    fn open_located(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        secure: bool,
        located: Option<&busbar_contract::conn::LocatedTarget>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.inner.open_located(caller, need, desc, secure, located)
    }
    fn open_owned(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        head: busbar_contract::conn::OwnedHead,
        secure: bool,
        located: Option<&busbar_contract::conn::LocatedTarget>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        self.inner
            .open_owned(caller, need, desc, head, secure, located)
    }
    fn write(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.inner.write(caller, conn, bytes, end, text)
    }
    fn read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        ticket: busbar_contract::conn::Ticket,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.inner.read(caller, conn, ticket, buf)
    }
    fn wait(
        &self,
        caller: busbar_contract::conn::InstanceId,
        set: &[busbar_contract::conn::ConnId],
        ticket: busbar_contract::conn::Ticket,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.inner.wait(caller, set, ticket)
    }
    fn facts(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        self.inner.facts(caller, conn)
    }
    fn close(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.close(caller, conn)
    }
}
impl busbar_contract::conn::PollConns for BoundConns {
    fn failure_cause(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Option<busbar_contract::conn::ConnCause> {
        self.inner.failure_cause(caller, conn)
    }
    fn poll_read(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        self.inner.poll_read(caller, conn, cx, buf)
    }
    fn anchor(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        anchors: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.anchor(owner, need, member, target, anchors)
    }
    fn head_defaults(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<busbar_contract::conn::HeadDefaults, busbar_contract::conn::ConnError> {
        self.inner.head_defaults(owner, need, target, timeout_ms)
    }
    fn locate_head(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<
        (
            busbar_contract::conn::HeadDefaults,
            Option<Arc<busbar_contract::conn::LocatedTarget>>,
        ),
        busbar_contract::conn::ConnError,
    > {
        self.inner.locate_head(owner, need, target, timeout_ms)
    }
    fn seal_reach(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.inner.seal_reach(owner, need, member, target, reach)
    }
}

pub(crate) fn bound_conns(
    binding: crate::root::loader::dispatch::plugin::ConnectionBinding,
    inner: Arc<dyn busbar_contract::conn::PollConns>,
) -> Arc<dyn busbar_contract::conn::PollConns> {
    Arc::new(BoundConns {
        inner,
        _binding: binding,
    })
}

pub(crate) struct DoorLive {
    pub(crate) observations: BTreeMap<String, busbar_kernel::plane_driver::ObservationPolicy>,
    pub(crate) ticket_nonce: Arc<()>,
    pub(crate) section: busbar_contract::yaml::Value,

    pub(crate) generation: u64,

    pub(crate) pools: DoorPools,

    pub(crate) egress: Option<Arc<Egress>>,

    pub(crate) facts: DoorFacts,

    pub(crate) probes: Option<Arc<busbar_kernel::plane_driver::PlaneProbes>>,

    pub(crate) shown: Option<crate::root::model_egress::ModelShown>,
}

pub(crate) struct DoorApply {
    /// The instance's label, shared with every ticket source its units register.
    pub(crate) instance: Arc<str>,
    pub(crate) observations_supported: bool,
    /// The target naming each carrier's listener setting, keyed when the plane composed
    /// ([`crate::root::off_path::serve::listen_targets`]).
    pub(crate) listen_targets: foldhash::HashMap<&'static str, &'static str>,
    pub(crate) plugin: DoorPlane,
    pub(crate) dispatcher: Arc<Dispatcher>,
    pub(crate) served_facts: crate::root::loader::dispatch::kinds::plane::ServedFacts,
    pub(crate) facts: DoorFacts,
    pub(crate) reach: Option<ApplyReach>,
    pub(crate) live: std::sync::RwLock<Arc<DoorLive>>,

    pub(crate) driver: Arc<PlaneDriver>,

    pub(crate) probe_schedule: Arc<busbar_kernel::probe::ProbeSchedule>,

    pub(crate) scope_kinds: Vec<&'static str>,

    pub(crate) clock: Arc<dyn busbar_kernel_egress::ports::Clock>,

    pub(crate) units: Arc<busbar_kernel::host_units::UnitRecords>,
}

/// Keep admission identity until the observation is recorded; never classify display text.
#[derive(Debug)]
pub(crate) enum DoorRefreshError {
    Preparation(String),
    Admission(busbar_kernel::host_services::AdmitRefused),
}

impl From<String> for DoorRefreshError {
    fn from(error: String) -> Self {
        Self::Preparation(error)
    }
}

impl std::fmt::Display for DoorRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparation(error) => f.write_str(error),
            Self::Admission(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl DoorRefreshError {
    pub(crate) fn classification(&self) -> busbar_kernel::state::activation::RefreshFailure {
        use busbar_kernel::state::activation::RefreshFailure;
        match self {
            Self::Admission(busbar_kernel::host_services::AdmitRefused::BootstrapHeld {
                ..
            }) => RefreshFailure::BootstrapHeld,
            _ => RefreshFailure::RefreshFailed,
        }
    }
}

impl DoorApply {
    /// The target naming `carrier`'s listener setting, if an inbound need names the carrier.
    #[must_use]
    pub(crate) fn listen_target(&self, carrier: &str) -> Option<&'static str> {
        self.listen_targets.get(carrier).copied()
    }

    #[must_use]
    pub(crate) fn current(&self) -> Arc<DoorLive> {
        Arc::clone(
            &self
                .live
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl std::fmt::Debug for DoorLive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorLive")
            .field("generation", &self.generation)
            .field("pools", &self.pools)
            .field("egress", &self.egress.is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DoorApply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorApply")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ServedPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServedPlane")
            .field("instance", &self.instance)
            .field("snapshot", &self.snapshot)
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// EVERY DOOR PLANE THIS PROCESS SERVES, composed once after the first app is built.
#[derive(Debug, Default, Clone)]
pub(crate) struct Served {
    /// The process's shared nested-unit registry, also lent to the line carrier at boot.
    pub(crate) nests: Option<NestRoutes>,
    /// In the order the planes were bound.
    pub(crate) planes: Vec<ServedPlane>,
    /// The MIN-3 plane instances served through their ports (`PortDriver`), in the order they were opened.
    pub(crate) ports: Vec<busbar_kernel::plane_driver::port::PortSeat>,
    /// Complete native instance ownership of this serving generation.
    pub(crate) native: Option<Arc<crate::root::min3_boot::Booted>>,
    /// Retain the actual opened fixture and its invocation admission for the serving lifetime.
    #[cfg(test)]
    pub(crate) native_fixture: Option<Arc<crate::root::min3_boot::fixture::PlaneFixture>>,
    /// What bills the requests those ports serve (their unit admission and settlement); `None` = no governance
    /// book, so a port request is not a billed unit (audit rows only).
    pub(crate) billing: Option<busbar_kernel::plane_driver::port_billing::PortBilling>,
    /// The posting site the planes' money steps post an abandoned end to, and the units' facts are
    /// opened on while they run: the process's one node's.
    pub(crate) post: Option<Arc<crate::root::plane_node::NodeEndPost>>,
    /// The framer that answers a claim, by its name: what frames a stream that arrived on a claim
    /// another framer than the data listener's own answers. `None` = the process's
    /// one connector's.
    pub(crate) framers: Option<StreamFramers>,
    /// THE CLAIM DOORS, by the claim their datagram framer answers: the datagram port each one's
    /// inbound need binds ([`serve_datagram::ClaimDoor`]). Empty = no datagram claim is served.
    pub(crate) claim_doors: serve_datagram::ClaimDoors,
    /// THE PUBLISHED INSTANCES' ADMIN TABLE these planes were published into: the generation's
    /// (`App::serve_tables`) the composition was lent, held here for the data listener's public
    /// mount ([`public_routes`]).
    pub(crate) tables: ServeTables,
}

/// The framer that answers a claim, by its name (`Connector::framer_for`).
#[derive(Clone)]
pub(crate) struct StreamFramers(pub Arc<FramerFor>);

pub(crate) type FramerFor =
    dyn Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> + Send + Sync;

impl std::fmt::Debug for StreamFramers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamFramers")
    }
}

pub(crate) struct HookStage {
    pub(crate) host: busbar_kernel::plane_driver::GenerationHost,

    pub(crate) gov: Arc<busbar_kernel::governance::GovState>,

    pub(crate) journal: Option<Arc<dyn busbar_kernel::plane_driver::HookJournal>>,
}

pub(crate) struct GovCaller {
    pub(crate) host: Arc<dyn busbar_kernel::plane_driver::EngineHost>,
    pub(crate) gov: Arc<busbar_kernel::governance::GovState>,
}

impl GovCaller {
    pub(crate) fn key(&self, principal: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        self.gov.lookup_by_sub(principal)
    }
}

impl busbar_kernel::plane_driver::CallerFacts for GovCaller {
    fn key(&self, principal: &str) -> Option<busbar_kernel::plane_driver::CallerKey> {
        self.key(principal)
            .map(|k| busbar_kernel::plane_driver::CallerKey {
                id: k.id.clone(),
                name: k.name.clone(),
            })
    }

    fn in_groups(&self, principal: Option<&str>, groups: &[String]) -> bool {
        let group = principal
            .and_then(|p| self.key(p))
            .and_then(|k| k.group.clone());
        self.host.caller_in_hook_groups(group.as_deref(), groups)
    }

    fn rate_headroom(&self, principal: &str, pool: &str) -> Option<f64> {
        let key = self.key(principal)?;
        let pin = self.host.meter_pin()?;
        self.host
            .rate_headroom(&pin, &key, Some(pool), busbar_kernel::store::now())
    }

    fn budget(&self, principal: &str) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        match (self.key(principal), self.host.meter_pin()) {
            (Some(key), Some(pin)) => {
                self.host
                    .budget_state(&pin, &key, busbar_kernel::store::now())
            }
            _ => Vec::new(),
        }
    }

    fn hook_read<'a>(
        &'a self,
        hook: &'a str,
        principal: Option<&'a str>,
        dialect: &'a str,
        identity: bool,
    ) -> busbar_kernel::audit::amend::ReadConfirmation<'a> {
        self.host.hook_read(hook, principal, dialect, identity)
    }

    fn hook_reads<'a>(
        &'a self,
        hooks: &'a [&'a str],
        principal: Option<&'a str>,
        dialect: &'a str,
        identity: bool,
    ) -> busbar_kernel::audit::amend::ReadConfirmation<'a> {
        self.host.hook_reads(hooks, principal, dialect, identity)
    }
}

pub(crate) struct LiveHooks {
    pub(crate) host: busbar_kernel::plane_driver::GenerationHost,
    pub(crate) gov: Arc<busbar_kernel::governance::GovState>,
    pub(crate) dialects: Vec<String>,

    pub(crate) plane_key: String,
}

impl LiveHooks {
    pub(crate) fn current(&self) -> busbar_kernel::plane_driver::HostHooks {
        let host = (self.host)();
        busbar_kernel::plane_driver::HostHooks {
            host: Arc::clone(&host),
            caller: Arc::new(GovCaller {
                host,
                gov: Arc::clone(&self.gov),
            }),
            dialects: self.dialects.clone(),
            plane_key: self.plane_key.clone(),
        }
    }
}

impl busbar_kernel::plane_driver::HookBinder for LiveHooks {
    fn bind(
        &self,
        bind: &busbar_kernel::plane_driver::Bind<'_>,
    ) -> Option<busbar_kernel::plane_driver::UnitHooks> {
        self.current().bind(bind)
    }

    fn denied(&self, dialect: u32, status: u16) {
        self.current().denied(dialect, status);
    }

    fn dialect(&self, dialect: u32) -> String {
        busbar_kernel::plane_driver::dialect_at(&self.dialects, dialect)
    }
}

/// Reserved credential and hop fields never enter a plane request, regardless of carrier.
fn keep_arrival_field(name: &[u8]) -> bool {
    !name.eq_ignore_ascii_case(b"x-busbar-recovery-work")
        && !name.eq_ignore_ascii_case(
            busbar_contract::abi::host::service::CARRIER_SESSION_FIELD.as_bytes(),
        )
        && !NEVER_KEPT
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved.as_bytes()))
}

pub(crate) struct DataRoutes {
    pub(crate) snapshot: Arc<DispatchSnapshot>,
    pub(crate) generation: Option<Arc<busbar_kernel::host_services::ServingGeneration>>,
}

impl std::ops::Deref for DataRoutes {
    type Target = DispatchSnapshot;
    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

impl DataRoutes {
    pub(crate) fn new(snapshot: DispatchSnapshot) -> Result<Arc<Self>, String> {
        let snapshot = Arc::new(snapshot);
        let native = Arc::new(native_nests::NativeNests::new(&snapshot)?);
        let kernel = snapshot
            .served
            .planes
            .first()
            .map(|plane| Arc::clone(&plane.kernel))
            .or_else(|| {
                snapshot
                    .served
                    .ports
                    .first()
                    .map(|seat| Arc::clone(seat.driver.core()))
            });
        let generation = match kernel {
            Some(kernel) => {
                if snapshot
                    .served
                    .planes
                    .iter()
                    .any(|other| !Arc::ptr_eq(&kernel, &other.kernel))
                    || snapshot
                        .served
                        .ports
                        .iter()
                        .any(|seat| !Arc::ptr_eq(&kernel, seat.driver.core()))
                {
                    return Err("listener planes do not share the same core services".into());
                }
                if snapshot
                    .served
                    .planes
                    .iter()
                    .any(|plane| plane.driver.invocation_caller().is_none())
                {
                    return Err("listener plane has no admitted invocation owner".into());
                }
                let runtime =
                    tokio::runtime::Handle::try_current().map_err(|error| error.to_string())?;
                Some(Arc::new(
                    busbar_kernel::host_services::ServingGeneration::try_new(
                        kernel,
                        Arc::new(DoorNests {
                            routes: Arc::clone(&snapshot),
                            native,
                            runtime,
                            detached: busbar_kernel::detached::worker_detached(),
                        }),
                    )
                    .map_err(|_| "native routing generation counter exhausted".to_owned())?,
                ))
            }
            None => None,
        };
        Ok(Arc::new(Self {
            snapshot,
            generation,
        }))
    }

    /// Register the allocated native unit against this selected immutable dispatch snapshot.
    /// Monetary/effect authority remains pending until the retained task resolves its actual pool.
    pub(crate) fn native_unit(
        self: &Arc<Self>,
        seat: &busbar_kernel::plane_driver::port::PortSeat,
        unit: &mut busbar_kernel::plane_driver::port::Unit,
        ctx: &PlaneReqCtx,
    ) -> Result<NativeUnit, &'static str> {
        let generation = self
            .generation
            .as_ref()
            .ok_or("native route has no complete generation")?;
        unit.ctx.generation = generation
            .routing_generation()
            .ok_or("native route has no allocated routing generation")?;
        let app = Arc::clone(&ctx.engine)
            .downcast::<busbar_kernel::state::App>()
            .map_err(|_| "native invocation needs its selected App snapshot")?;
        let key = ctx
            .gov
            .as_ref()
            .and_then(|gov| gov.key.clone())
            .ok_or("native billed invocation has no verified key")?;
        if !Arc::ptr_eq(generation.core(), seat.driver.core()) {
            return Err("native invocation belongs to another core services owner");
        }
        let id = unit.ctx.key.get();
        if self.frames_lock().contains_key(&id) || generation.core().units().get(id).is_some() {
            return Err("native unit is already registered");
        }
        let registered = match &ctx.signed_authority {
            Some(authority) => {
                if !Arc::ptr_eq(&key, authority.original_key()) {
                    return Err("native signed allocation has a different original key");
                }
                generation.core().units().pre_admitted_signed_for(
                    id,
                    seat.driver.caller(),
                    authority.clone(),
                    0,
                )
            }
            None => generation.core().units().pre_admitted_for(
                id,
                seat.driver.caller(),
                busbar_kernel::host_units::UnitRecord {
                    principal: Some(key),
                    depth: 0,
                },
            ),
        };
        if !registered {
            return Err("native allocation could not be registered");
        }
        let context = match seat.driver.invocation(Arc::clone(generation), id) {
            Ok(context) => context,
            Err(why) => {
                generation.core().units().ended(id);
                return Err(why);
            }
        };
        if let Some(credential) = &ctx.caller_credential {
            generation.core().units().lend(id, credential.clone());
        }
        generation.core().units().ticketed(id, ctx.ticket.clone());
        self.frames_lock().insert(
            id,
            DispatchFrame {
                app,
                request: ctx.request.clone(),
            },
        );
        Ok(NativeUnit {
            context,
            routes: Arc::clone(self),
        })
    }

    fn invocation_owner(
        &self,
        plane: usize,
    ) -> Option<(Arc<busbar_kernel::host_services::ServingGeneration>, Caller)> {
        Some((
            Arc::clone(self.generation.as_ref()?),
            self.served
                .planes
                .get(plane)?
                .driver
                .invocation_caller()?
                .clone(),
        ))
    }
}

pub(crate) struct DispatchSnapshot {
    /// The plane configuration sealed with this listener dispatcher.
    pub(crate) live: Vec<Arc<DoorLive>>,
    pub(crate) entries: Vec<Arc<EntrySpans>>,
    pub(crate) served: Served,

    pub(crate) claim_doors: Option<Arc<serve_datagram::ClaimDoors>>,
    pub(crate) post: Arc<crate::root::plane_node::NodeEndPost>,

    pub(crate) pin: fn() -> Option<crate::root::kernel::PinnedHistory>,

    pub(crate) guests: busbar_kernel::guest::GuestList,
    pub(crate) of_line: foldhash::HashMap<(String, u32), DoorClaim>,

    pub(crate) frames: Mutex<foldhash::HashMap<u64, DispatchFrame>>,
}

/// A nested operation inherits its parent's exact application and logical request admission.
/// Cloning the frame shares that admission; no child acquires another request-count permit.
#[derive(Clone)]
pub(crate) struct DispatchFrame {
    pub(crate) app: Arc<busbar_kernel::state::App>,
    pub(crate) request: RequestLease,
}

pub(crate) struct UnitFrame<'r> {
    pub(crate) routes: &'r DataRoutes,
    pub(crate) unit: u64,
}

pub(crate) struct NativeUnit {
    pub(crate) context: busbar_kernel::host_services::InvocationContext,
    routes: Arc<DataRoutes>,
}

impl Drop for NativeUnit {
    fn drop(&mut self) {
        let id = self.context.unit();
        self.context.retire();
        self.routes.frames_lock().remove(&id);
    }
}

impl Drop for UnitFrame<'_> {
    fn drop(&mut self) {
        self.routes.frames_lock().remove(&self.unit);
    }
}

pub(crate) const NEST_REPLY_MAX: usize = 16 << 20;

pub(crate) const NEST_UNSERVED: &str = "no plane serves the nested unit's claim";

pub(crate) const NEST_PARENT_GONE: &str = "the nested unit's parent is not in flight";

pub(crate) const NEST_UNREAD: &str = "the nested unit's reply could not be read";

pub(crate) const NEST_INPUT_FULL: &str = "the nested unit's input budget is exhausted";

pub(crate) struct DoorNests {
    pub(crate) routes: Arc<DispatchSnapshot>,
    native: Arc<native_nests::NativeNests>,
    pub(crate) runtime: tokio::runtime::Handle,
    pub(crate) detached: Option<Arc<busbar_kernel::detached::DetachedTasks>>,
}

pub(crate) type NestRoutes = Arc<Mutex<Vec<std::sync::Weak<DataRoutes>>>>;

impl busbar_kernel::host_services::NestRoute for DoorNests {
    fn nest(
        &self,
        context: busbar_kernel::host_services::InvocationContext,
        nest: busbar_kernel::host_services::Nest,
        done: busbar_kernel::host_services::NestDone,
    ) {
        let routes = Arc::new(DataRoutes {
            snapshot: Arc::clone(&self.routes),
            generation: Some(Arc::clone(context.generation())),
        });
        let native = Arc::clone(&self.native);
        let child = async move {
            if let Some(answer) = native
                .dispatch(Arc::clone(&routes.snapshot), &context, &nest)
                .await
            {
                done(answer);
                return;
            }
            let Some(bound) = routes.parent_of(&nest) else {
                done(busbar_kernel::host_services::NestReply::Unserved(
                    NEST_PARENT_GONE,
                ));
                return;
            };
            let _parent_context = context;
            let limits = nest.constraints.clone();
            let run = routes.nested(nest, bound);
            let answer = if let Some(limits) = limits {
                tokio::select! {
                    biased;
                    _ = limits.cancellation.cancelled() => busbar_kernel::host_services::NestReply::Failed("hook child cancelled"),
                    _ = tokio::time::sleep_until(limits.deadline.into()) => busbar_kernel::host_services::NestReply::Failed("hook child deadline exceeded"),
                    answer = run => answer,
                }
            } else {
                run.await
            };
            done(answer);
        };
        drop(match &self.detached {
            Some(detached) => detached.spawn_on(&self.runtime, child),
            None => self.runtime.spawn(child),
        });
    }
}

impl std::fmt::Debug for DataRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataRoutes")
            .field("served", &self.served)
            .finish_non_exhaustive()
    }
}

pub(crate) struct DoorRequest {
    pub(crate) request: busbar_kernel::limits::process_admission::RequestLease,
    pub(crate) method: axum::http::Method,

    pub(crate) uri: axum::http::Uri,

    pub(crate) headers: axum::http::HeaderMap,

    pub(crate) body: Bytes,

    pub(crate) gov: busbar_contract::records::PlaneRequestCtx,

    pub(crate) credential: Option<busbar_kernel::auth::CallerCredential>,

    pub(crate) ticket: Option<Vec<u8>>,

    pub(crate) host_ticket_admission: Option<busbar_kernel::host_services::HostTicketAdmission>,

    pub(crate) app: Arc<busbar_kernel::state::App>,

    pub(crate) scheme: u8,

    pub(crate) consumed_fields: Vec<(String, String)>,
}

pub(crate) fn line_auth(flags: u32, data_chain: &[ChainAuth]) -> busbar_kernel::guest::LineAuth {
    if flags & CLAIM_OPEN != 0 {
        busbar_kernel::guest::LineAuth::None
    } else {
        chain_auth(data_chain)
    }
}

pub(crate) type ChainAuth = (String, busbar_contract::abi::auth::AuthPoints);

pub(crate) fn listener_method_bits(method: RouteMethod) -> u32 {
    busbar_contract::abi::transport::route::method_bit(method.as_str())
        | if method == RouteMethod::Get {
            busbar_contract::abi::transport::route::METHOD_HEAD
        } else {
            0
        }
}

const SESSION_QUEUE: usize = 64;

pub(crate) fn routed(claim: &crate::root::loader::dispatch::kinds::plane::OwnedClaim) -> bool {
    claim.flags & (CLAIM_RAW_AFFIX | CLAIM_ENTRY) == 0
}

pub(crate) type DoorClaim = (usize, u32);

impl DoorRequest {
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        match self.headers.get(name) {
            Some(value) => value.to_str().ok(),
            None => self
                .consumed_fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, scheme)| scheme.as_str()),
        }
    }

    pub(crate) fn of(ctx: PlaneReqCtx) -> Option<Self> {
        let app = match ctx.engine.downcast::<busbar_kernel::state::App>() {
            Ok(app) => app,
            Err(engine) => engine
                .downcast::<busbar_kernel::state::AppHandle>()
                .ok()?
                .load(),
        };

        let mut headers = ctx.headers;
        headers.remove(busbar_contract::abi::host::service::CARRIER_SESSION_FIELD);
        Some(DoorRequest {
            request: ctx.request,
            method: axum::http::Method::from_bytes(ctx.method.as_str().as_bytes()).ok()?,
            uri: ctx.uri,
            headers,
            body: ctx.body,
            gov: ctx.gov.unwrap_or_default(),
            credential: ctx.caller_credential,
            ticket: ctx.ticket,
            host_ticket_admission: ctx.host_ticket_admission,
            app,
            scheme: ctx.scheme,
            consumed_fields: ctx.consumed_fields,
        })
    }
}

pub(crate) type BoundParent = (DispatchFrame, crate::root::plane_node::Parent);

impl DataRoutes {
    pub(crate) fn catalog(&self, plane: usize, req: &DoorRequest) -> Response {
        let names = busbar_kernel::endpoints::catalog_names(
            &req.app,
            &req.gov,
            &self.served.planes[plane].facts.plane,
        );
        let target = req
            .uri
            .path_and_query()
            .map_or_else(|| req.uri.path(), |t| t.as_str());
        let head: Vec<(Vec<u8>, Vec<u8>)> = req
            .headers
            .iter()
            .filter(|(n, _)| keep_arrival_field(n.as_str().as_bytes()))
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let rendered = self.served.planes[plane].driver.catalog_unitless(
            req.method.as_str().as_bytes(),
            target.as_bytes(),
            &head,
            &names,
        );
        match rendered {
            Some(r) => stated((r.status, r.fields), Body::from(r.body)),
            None => stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            ),
        }
    }

    pub(crate) async fn open_session(
        self: Arc<Self>,
        plane: usize,
        claim: u32,
        req: DoorRequest,
    ) -> busbar_kernel::plane_routes::SessionAnswer {
        use busbar_kernel::plane_routes::{SessionAnswer, SessionPipe};
        let (door, arrival, _) = self.arrived(plane, claim, req);
        let (from_caller, from_rx) = mpsc::channel(SESSION_QUEUE);
        let (to_tx, to_caller) = mpsc::channel(SESSION_QUEUE);
        let caller = PipeCaller {
            from: tokio::sync::Mutex::new(from_rx),
            to: to_tx,
        };
        let (verdict, said) = oneshot::channel();
        busbar_kernel::detached::spawn_detached(self.session(
            door,
            ClosingCaller::new(caller),
            arrival,
            verdict,
            Attach::switched(),
        ));
        match said.await {
            Ok(Ok(())) => SessionAnswer::Accepted(SessionPipe {
                from_caller,
                to_caller,
            }),
            Ok(Err(Some(rendered))) => SessionAnswer::Refused(stated(
                (rendered.status, rendered.fields),
                Body::from(rendered.body),
            )),
            Ok(Err(None)) | Err(_) => SessionAnswer::Refused(stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            )),
        }
    }

    async fn session<C: SessionCaller + Send + Sync + 'static>(
        self: Arc<Self>,
        door: SessionDoor,
        caller: C,
        arrival: Arrival,
        verdict: oneshot::Sender<Result<(), Option<Rendered>>>,
        mut attach: Attach,
    ) {
        use busbar_kernel::teller::SessionOpen;
        let served = &self.served.planes[door.plane];
        if let Some(refused) = journal_refused(served, &self.post, &arrival) {
            if let Some(admission) = &door.admission {
                admission.refuse(
                    busbar_contract::caps::StepName::Arrival,
                    ReasonCode::DurabilityUnavailable,
                );
            }
            let _ = verdict.send(Err(Some(refused)));
            return;
        }
        let live = if door.admission.is_some() {
            Arc::clone(&self.live[door.plane])
        } else {
            served.live.current()
        };
        let Some(node) = self.post.node() else {
            let _ = verdict.send(Err(None));
            return;
        };
        let unit = door
            .admission
            .as_ref()
            .map_or_else(|| node.mint(), |admission| admission.unit_key());
        let arrived = node.arrived();
        let scope = match super::measurements::RequestScope::new(
            &served.money,
            unit,
            &door.principal,
            door.key.as_deref(),
            arrived,
        ) {
            Ok(scope) => scope,
            Err(error) => {
                tracing::error!(?error, "request measurement attribution unavailable");
                let _ = verdict.send(Err(None));
                return;
            }
        };
        super::measurements::request(scope, async {
        let carrier_end = CarrierEnd {
            unit: unit.get(),
            ended: attach.ended.take(),
        };
        self.frames_lock().insert(unit.get(), DispatchFrame {
            app: Arc::clone(&door.app),
            request: door.request.clone(),
        });
        let _frame = UnitFrame {
            routes: &self,
            unit: unit.get(),
        };
        let _ticket_source =
            node.ticket_custody
                .register(unit, door.key.as_ref(), served, &live, &door.app);
        let steps = DoorSteps::new(
            &live.facts,
            &live.pools,
            node.resolver(),
            door.app,
            Some(&*served.money),
            DoorCaller {
                principal: door.principal.clone(),
                key: door.key,
                open: door.open,
                arrived: arrived.secs(),
                records: Some(Arc::clone(served.kernel.units())),
                depth: 0,
                credential: door.credential.clone(),
                ticket: door.ticket,
            },
        )
        .with_invocation_owner(self.invocation_owner(door.plane))
        .with_ticket_admission(
            door.host_ticket_admission,
            Arc::clone(&node.ticket_custody.nonce),
            Arc::clone(&live.ticket_nonce),
        );
        let far = DoorFar {
            observations: Some(observations::UnitBinding {
                served,
                live: &live,
                unit,
                selected_member: OnceLock::new(),
            }),
            authorization: Arc::clone(served.kernel.units()),
            egress: live.egress.as_deref(),
            shown: live.shown.as_ref(),
            steps: &steps,
            unit,
            credential: door.credential,
            far: OnceLock::new(),
        };
        let units = served.driver.unit(&steps, &far, &caller, arrival, 0);
        let Some((opened, ctx, slot)) = node
            .open_borrowed(
                unit,
                arrived,
                &door.principal,
                &self.post,
                &units,
                (self.pin)(),
                live.facts.audit_kind,
                door.admission.as_ref(),
                &door.request,
            )
            .await
        else {
            let _ = verdict.send(Err(None));
            return;
        };
        let slot = slot.with_money(&served.money, &live.facts);
        let admitted = match opened {
            SessionOpen::Admitted {
                route,
                destinations,
                ..
            } => match units.open_hooks(&route, &ctx).await {
                Err(reason) => {
                    self.post.stopped(unit, reason);
                    None
                }
                Ok(()) => match attach.admitted.take().map(|admitted| admitted(unit.get())) {
                    Some(Err(reason)) => {
                        tracing::warn!(plane = %served.instance, unit = unit.get(), error = ?reason,
                            "session carrier could not attach to its admitted unit");
                        self.post.stopped(unit, ReasonCode::HandoffMismatch);
                        None
                    }
                    None | Some(Ok(())) => Some((route, destinations)),
                },
            },
            SessionOpen::Refused | SessionOpen::Settled(_) => None,
        };
        let status = match admitted {
            Some((route, destinations)) => {
                let _ = verdict.send(Ok(()));
                match units
                    .session_priced(&route, &ctx, &destinations, steps.charged())
                    .await
                {
                    Ok(()) => self.post.completed(unit),
                    Err(reason) => self.post.stopped(unit, reason),
                }
                attach.answered
            }
            None => {
                let rendered = units.take_rendered();
                let status = rendered
                    .as_ref()
                    .map_or_else(|| refusal_status(ReasonCode::PlanePanic), |r| r.status);
                let _ = verdict.send(Err(rendered));
                status
            }
        };

        self.post
            .reported(unit, report_of(&served.money, unit, &live.facts));
        if let Err(error) = slot.finish_with(&self.post, &units).await {
            // Persistence uncertainty cannot rewrite the observed client/plane
            // outcome or invent a different fee/refund verdict. The original
            // audit and checkpoint custody remain pending; no ticket becomes
            // ready until the native audit confirmation succeeds.
            tracing::error!(?error, "session audit was not durably confirmed");
        }
        served.money.settle_end(unit, status);
        // This callback only unpairs the physical carrier. Keep it alive across
        // terminal confirmation, then release it on failure as well: a real
        // disconnect is resource cleanup, never a durable-success assertion.
        drop(carrier_end);
        }).await;
    }

    /// The datagram opening as the owner tests drive it: a named carrier.
    #[cfg(test)]
    async fn open_datagram(
        self: Arc<Self>,
        (framer, carrier): (Arc<dyn busbar_core_connector::framer::FramerDoor>, String),
        door: SessionDoor,
        arrival: Arrival,
    ) -> Response {
        let whole = self.open_datagram_on(framer, &carrier, door, arrival).await;
        stated((whole.status, whole.fields), Body::from(whole.body))
    }

    async fn open_datagram_framed(
        self: Arc<Self>,
        framer: Arc<dyn busbar_core_connector::framer::FramerDoor>,
        door: SessionDoor,
        arrival: Arrival,
    ) -> Response {
        // The carrier is borrowed from the claim it was framed on, through a second handle.
        let routes = Arc::clone(&self);
        let carrier = routes.served.planes[door.plane]
            .snapshot
            .claims
            .get(arrival.claim as usize)
            .map_or("", |c| c.carrier.as_str());
        let whole = self.open_datagram_on(framer, carrier, door, arrival).await;
        stated((whole.status, whole.fields), Body::from(whole.body))
    }

    async fn open_datagram_on(
        self: Arc<Self>,
        framer: Arc<dyn busbar_core_connector::framer::FramerDoor>,
        carrier: &str,
        door: SessionDoor,
        arrival: Arrival,
    ) -> neutral::Whole {
        let doors = self
            .claim_doors
            .as_ref()
            .map(Arc::as_ref)
            .unwrap_or(&self.served.claim_doors);
        let Some(claim_door) = doors.get(carrier) else {
            let live = &self.served.planes[door.plane].live;
            let text = crate::root::cold::media_unlistened(
                live.served_facts.section,
                live.listen_target(carrier),
                carrier,
            );
            return self.refused_open(&door, &arrival, carrier, ReasonCode::NoDestination, &text);
        };
        let opened = match serve_datagram::Opened::open(
            &claim_door,
            framer,
            &arrival.body,
            door.request.clone(),
        ) {
            Ok(o) => o,
            Err(why) => {
                let text = crate::root::cold::media_unopened(&why);
                return self.refused_open(
                    &door,
                    &arrival,
                    carrier,
                    ReasonCode::DecodeFailed,
                    &text,
                );
            }
        };
        let serve_datagram::Opened {
            description,
            caller,
            head,
            joining,
        } = opened;

        let mut opening = DatagramOpening::new(joining);
        let admitted = opening.admission();
        let ended = Box::new(|unit: u64| crate::root::connector::the().unpair(unit))
            as Box<dyn FnOnce(u64) + Send>;
        let (verdict, said) = oneshot::channel();
        let attach = Attach {
            answered: CREATED,
            admitted: Some(admitted),
            ended: Some(ended),
        };
        busbar_kernel::detached::spawn_detached(self.session(
            door,
            ClosingCaller::new(caller),
            arrival,
            verdict,
            attach,
        ));
        match said.await {
            Ok(Ok(())) => match serve_datagram::plane_head(head, OPEN_HEAD_WAIT).await {
                Some((status, fields)) => {
                    let response = neutral::Whole {
                        status,
                        fields,
                        body: description.into_bytes(),
                    };
                    opening.transfer();
                    response
                }
                None => neutral::Whole::failed(),
            },
            Ok(Err(Some(rendered))) => neutral::Whole::from(rendered),
            Ok(Err(None)) | Err(_) => neutral::Whole::failed(),
        }
    }

    fn refused_open(
        &self,
        door: &SessionDoor,
        arrival: &Arrival,
        carrier: &str,
        reason: ReasonCode,
        text: &str,
    ) -> neutral::Whole {
        neutral::Whole::from(crate::root::cold::refused_open(
            &self.served.planes[door.plane],
            door.principal.as_str(),
            arrival,
            carrier,
            reason,
            text,
        ))
    }

    fn arrived(&self, plane: usize, claim: u32, req: DoorRequest) -> (SessionDoor, Arrival, Bytes) {
        let DoorRequest {
            request,
            method,
            uri,
            headers,
            body,
            gov,
            credential,
            ticket,
            host_ticket_admission,
            app,
            scheme: _,
            consumed_fields: _,
        } = req;
        let fields: HeadFields = headers
            .iter()
            .filter(|(n, _)| keep_arrival_field(n.as_str().as_bytes()))
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let target = uri
            .path_and_query()
            .map_or_else(|| uri.path(), |t| t.as_str());
        let arrival = Arrival {
            claim,
            method: method.as_str().as_bytes().to_vec(),
            target: target.as_bytes().to_vec(),
            fields,
            body: body.clone(),
            carrier: 0,
        };
        let principal = match gov.key() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };

        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let key = gov.key;
        let door = SessionDoor {
            request,
            admission: None,
            plane,
            app,
            principal,
            key,
            open,
            credential,
            ticket,
            host_ticket_admission,
        };
        (door, arrival, body)
    }

    // Only the host line carrier can supply this typed session identity. Client fields
    // still pass through arrived() and its reserved-field filter before this is added.
    fn arrived_on_line(
        &self,
        plane: usize,
        claim: u32,
        req: DoorRequest,
        session: std::num::NonZeroU64,
    ) -> (SessionDoor, Arrival, Bytes) {
        let (door, mut arrival, body) = self.arrived(plane, claim, req);
        arrival.carrier = session.get();
        arrival.fields.push((
            busbar_contract::abi::host::service::CARRIER_SESSION_FIELD
                .as_bytes()
                .to_vec(),
            session.get().to_string().into_bytes(),
        ));
        (door, arrival, body)
    }

    pub(crate) async fn answer(
        self: Arc<Self>,
        plane: usize,
        claim: u32,
        req: DoorRequest,
    ) -> Response {
        self.answer_with_session(plane, claim, req, None).await
    }

    async fn answer_with_session(
        self: Arc<Self>,
        plane: usize,
        claim: u32,
        req: DoorRequest,
        session: Option<std::num::NonZeroU64>,
    ) -> Response {
        let scheme = req.scheme;
        let (door, arrival, body) = match session {
            Some(session) => self.arrived_on_line(plane, claim, req, session),
            None => self.arrived(plane, claim, req),
        };

        let framed = self.served.planes[plane]
            .snapshot
            .claims
            .get(claim as usize)
            .and_then(|c| self.framer_for(&c.carrier).map(|d| (d, c.carrier.as_str())));

        let datagram_framer = framed
            .as_ref()
            .filter(|(d, _)| d.facts().datagram)
            .map(|(d, _)| Arc::clone(d));
        if let Some(framer) = datagram_framer {
            return self.open_datagram_framed(framer, door, arrival).await;
        }
        let SessionDoor {
            request,
            app,
            principal,
            key,
            open,
            credential,
            ticket,
            host_ticket_admission,
            ..
        } = door;

        if let Some((door, carrier)) =
            framed.and_then(|(d, c)| framed_by(c, |_| Some(Arc::clone(&d))).map(|door| (door, c)))
        {
            let head: Vec<(String, Vec<u8>)> = arrival
                .fields
                .iter()
                .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone()))
                .collect();
            let target = String::from_utf8_lossy(&arrival.target);
            let Ok(mut stream) = busbar_core_connector::framed_stream::FramedStream::open(
                door, carrier, &target, &head, scheme,
            ) else {
                return stated(
                    (refusal_status(ReasonCode::DecodeFailed), Vec::new()),
                    Body::empty(),
                );
            };
            let messages = match stream.ingest(&body, true) {
                Ok(messages) => messages,
                Err(why) => {
                    let status = refusal_status(ReasonCode::DecodeFailed);
                    return match stream.refuse_response(why.error.as_bytes(), status, false) {
                        Ok(closing) => {
                            serve_framed::whole(closing.status.unwrap_or(status), &closing.fields)
                        }
                        Err(_) => stated((status, Vec::new()), Body::empty()),
                    };
                }
            };
            let Ok((arrival, inner, reply)) = deframed_arrival(arrival, messages, &request) else {
                return stated(
                    (refusal_status(ReasonCode::InFlightCap), Vec::new()),
                    Body::empty(),
                );
            };
            let stream = serve_framed::shared(stream);
            let (trailers, trailed) = oneshot::channel();
            let caller = serve_framed::FramedCaller::new(inner, Arc::clone(&stream), trailers);
            let unit = async move {
                let caller = caller;
                self.drive(
                    plane,
                    app,
                    (principal, key, credential, ticket, host_ticket_admission),
                    open,
                    &caller,
                    arrival,
                    None,
                    None,
                    &request,
                )
                .await
            };
            return reply
                .with_trailers(trailed)
                .answer_with(Box::pin(unit), move |rendered| {
                    serve_framed::refused(&stream, rendered)
                })
                .await;
        }
        let (caller, reply) = IngressCaller::arriving(body);
        let unit = async move {
            let caller = caller;
            self.drive(
                plane,
                app,
                (principal, key, credential, ticket, host_ticket_admission),
                open,
                &caller,
                arrival,
                None,
                None,
                &request,
            )
            .await
        };
        reply.answer(Box::pin(unit)).await
    }

    pub(crate) fn framer_for(
        &self,
        scheme: &str,
    ) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
        match &self.served.framers {
            Some(f) => (f.0)(scheme),
            None => crate::root::connector::the().framer_for(scheme),
        }
    }

    fn frames_lock(&self) -> std::sync::MutexGuard<'_, foldhash::HashMap<u64, DispatchFrame>> {
        self.frames
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn parent_of(&self, nest: &busbar_kernel::host_services::Nest) -> Option<BoundParent> {
        let frame = self.frames_lock().get(&nest.parent).cloned()?;
        let parent = self
            .post
            .node()?
            .parent(busbar_contract::UnitKey::new(nest.parent))?;
        Some((frame, parent))
    }

    async fn nested(
        self: Arc<Self>,
        nest: busbar_kernel::host_services::Nest,
        (frame, parent): BoundParent,
    ) -> busbar_kernel::host_services::NestReply {
        use busbar_kernel::guest::{Claimant, Matched};
        use busbar_kernel::host_services::NestReply;
        let DispatchFrame { app, request } = frame;
        let path = nest.ask.target.split('?').next().unwrap_or_default();
        let door = match self.guests.matched(&nest.ask.verb, path, &[]) {
            Matched::Line(line) => match &line.claimant {
                Claimant::Plane(instance) => self
                    .of_line
                    .get(&(instance.clone(), line.route.rung))
                    .copied(),
                _ => None,
            },
            _ => None,
        };
        let Some((plane, claim)) = door else {
            return NestReply::Unserved(NEST_UNSERVED);
        };
        if let Some(limits) = &nest.constraints {
            if limits.grant.plane != self.served.planes[plane].instance
                || limits.grant.operation != nest.ask.verb
                || limits.grant.target != nest.ask.target
                || limits.grant.validate().is_err()
            {
                return NestReply::Unserved("hook child target is outside its grant");
            }
        }
        let reply_bound = nest
            .constraints
            .as_ref()
            .map_or(NEST_REPLY_MAX, |c| c.grant.max_output_bytes);
        let principal = match nest.principal.as_deref() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };
        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|c| c.flags & CLAIM_OPEN != 0);
        let body = match request.adopt_input(nest.ask.body) {
            Ok(body) => body.into_bytes(),
            Err(_) => return NestReply::Unserved(NEST_INPUT_FULL),
        };
        let arrival = Arrival {
            claim,
            method: nest.ask.verb.into_bytes(),
            target: nest.ask.target.into_bytes(),
            fields: Vec::new(),
            body,
            carrier: 0,
        };
        let nesting = Nesting {
            parent,
            depth: nest.depth,
            ancestry: nest.ancestry,
            constraints: nest.constraints,
        };
        let key = nest.principal;
        let (caller, reply) = IngressCaller::new();
        let routes = Arc::clone(&self);
        let unit = async move {
            let caller = caller;
            routes
                .drive(
                    plane,
                    app,
                    (principal, key, None, None, None),
                    open,
                    &caller,
                    arrival,
                    Some(nesting),
                    None,
                    &request,
                )
                .await
        };
        reply.answer_nested_bound(Box::pin(unit), reply_bound).await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one unit's parts, moved into the drive that owns it"
    )]
    pub(crate) async fn drive<C: SessionCaller + Stated + Send + Sync>(
        &self,
        plane: usize,
        app: Arc<busbar_kernel::state::App>,
        (principal, key, credential, ticket, host_ticket_admission): UnitCaller,
        open: bool,
        caller: &C,
        arrival: Arrival,
        mut nesting: Option<Nesting>,
        admission: Option<&busbar_kernel::inbound::RequestAdmission>,
        request: &RequestLease,
    ) -> Option<Rendered> {
        let served = &self.served.planes[plane];
        if let Some(refused) = journal_refused(served, &self.post, &arrival) {
            if let Some(admission) = admission {
                admission.refuse(
                    busbar_contract::caps::StepName::Arrival,
                    ReasonCode::DurabilityUnavailable,
                );
            }
            return Some(refused);
        }

        let live = if admission.is_some() {
            Arc::clone(&self.live[plane])
        } else {
            served.live.current()
        };
        let started = busbar_core_connector::framer::now();
        caller.began(started);
        let claim = arrival.claim;
        let app_for_metrics = Arc::clone(&app);
        let node = self.post.node()?;
        let unit = admission.map_or_else(|| node.mint(), |admission| admission.unit_key());
        let unit_id = node.unit_id(unit);
        if let Some(id) = unit_id {
            caller.minted(id);
        }
        let arrived = node.arrived();
        let measurement_scope = match super::measurements::RequestScope::new(
            &served.money,
            unit,
            &principal,
            key.as_deref(),
            arrived,
        ) {
            Ok(scope) => scope,
            Err(error) => {
                tracing::error!(?error, "request measurement attribution unavailable");
                return None;
            }
        };

        self.frames_lock().insert(
            unit.get(),
            DispatchFrame {
                app: Arc::clone(&app),
                request: request.clone(),
            },
        );
        let _frame = UnitFrame {
            routes: self,
            unit: unit.get(),
        };
        let _ticket_source = node
            .ticket_custody
            .register(unit, key.as_ref(), served, &live, &app);
        let mut steps = DoorSteps::new(
            &live.facts,
            &live.pools,
            node.resolver(),
            app,
            Some(&*served.money),
            DoorCaller {
                principal: principal.clone(),
                key,
                open,
                arrived: arrived.secs(),
                records: Some(Arc::clone(served.kernel.units())),
                depth: nesting.as_ref().map_or(0, |n| n.depth),
                credential: credential.clone(),
                ticket,
            },
        )
        .with_invocation_owner(self.invocation_owner(plane))
        .with_ticket_admission(
            host_ticket_admission,
            Arc::clone(&node.ticket_custody.nonce),
            Arc::clone(&live.ticket_nonce),
        );
        if let Some(n) = nesting.as_mut() {
            // The ancestry is read nowhere after this: it moves into the unit records.
            served
                .kernel
                .units()
                .set_child_ancestry(unit.get(), std::mem::take(&mut n.ancestry));
        }
        if let Some(n) = &nesting {
            steps = steps
                .under(n.parent.cell())
                .with_child_constraints(n.constraints.clone());
        }
        let far = DoorFar {
            observations: Some(observations::UnitBinding {
                served,
                live: &live,
                unit,
                selected_member: OnceLock::new(),
            }),
            authorization: Arc::clone(served.kernel.units()),
            egress: live.egress.as_deref(),
            shown: live.shown.as_ref(),
            steps: &steps,
            unit,
            credential,
            far: OnceLock::new(),
        };
        let units = served.driver.unit(&steps, &far, caller, arrival, 0);
        let money = Arc::clone(&served.money);
        let held = Arc::clone(&live);
        let late: crate::root::linked::node::Late =
            Box::new(move || report_of(&money, unit, &held.facts));

        let ended = super::measurements::request(
            measurement_scope,
            node.drive_borrowed(
                unit,
                arrived,
                &principal,
                &self.post,
                &units,
                late,
                (self.pin)(),
                nesting.as_ref().map(|n| &n.parent),
                live.facts.audit_kind,
                admission,
                Some(super::plane_node::Timing { started, caller }),
                request,
            ),
        )
        .await;

        let downgraded = steps.downgraded();

        caller.ended(ended);
        let rendered = units.take_rendered();
        let status = rendered
            .as_ref()
            .map(|r| r.status)
            .or_else(|| caller.stated())
            .unwrap_or_else(|| refusal_status(ReasonCode::PlanePanic));

        served.money.settle_end_as(
            unit,
            busbar_kernel::plane_driver::UnitEnd {
                caller_status: status,
                cut: steps.stream_cut(),
                refused_unspent: units.refused_unspent(),
            },
        );

        if live.facts.plane.lane_prefix().is_empty() {
            let decoded = units.decoded();
            let counted = decoded.is_some()
                || units.declined_unsupported_action()
                || units
                    .declined_status()
                    .is_some_and(|s| s != 404 && s != 405);
            if counted {
                let dialect = decoded.as_ref().map_or_else(
                    || {
                        served
                            .snapshot
                            .claims
                            .get(claim as usize)
                            .map_or(0, |c| u32::from(c.refusal_dialect))
                    },
                    |d| d.dialect,
                );
                let pool = downgraded
                    .or_else(|| decoded.and_then(|d| d.pool).map(decoded_name))
                    .filter(|name| {
                        live.pools.pools().contains_key(name)
                            || live.pools.entries().iter().any(|e| e == name)
                    });
                let pool = pool.as_deref().unwrap_or("unresolved");
                busbar_kernel::telemetry::model_request_finished(
                    &app_for_metrics,
                    served.dialects.get(dialect as usize).copied().unwrap_or(""),
                    pool,
                    u16::try_from(status).unwrap_or(u16::MAX),
                    busbar_core_connector::framer::now()
                        .saturating_duration_since(started)
                        .as_secs_f64(),
                    unit_id.as_ref().map(|id| id as &dyn std::fmt::Display),
                );
            }
        }
        rendered
    }
}

/// A pool name a plane decoded, as text: its own bytes when they are UTF-8 (no copy).
fn decoded_name(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(name) => name,
        Err(invalid) => crate::root::cold::lossy_name(invalid.as_bytes()),
    }
}

fn journal_refused(
    served: &ServedPlane,
    post: &crate::root::plane_node::NodeEndPost,
    arrival: &Arrival,
) -> Option<Rendered> {
    let why = match post.node() {
        Some(node) => node.journal_refusal()?,
        None => "original node unavailable".to_owned(),
    };
    let status = refusal_status(ReasonCode::DurabilityUnavailable);
    let dialect = served
        .snapshot
        .claims
        .get(arrival.claim as usize)
        .map_or(0, |c| u32::from(c.refusal_dialect));
    Some(
        served
            .driver
            .refuse_kernel(
                ReasonCode::DurabilityUnavailable,
                status,
                &why,
                dialect,
                &arrival.target,
            )
            .unwrap_or_else(|| Rendered {
                status,
                fields: Vec::new(),
                body: why.into_bytes(),
            }),
    )
}

pub(crate) struct Nesting {
    pub(crate) parent: crate::root::plane_node::Parent,
    pub(crate) depth: u32,
    pub(crate) ancestry: Vec<Arc<str>>,
    pub(crate) constraints: Option<busbar_kernel::hook_child::Constraints>,
}

pub(crate) fn report_of(
    money: &PlaneMoney,
    unit: busbar_contract::UnitKey,
    facts: &DoorFacts,
) -> Option<crate::root::linked::node::Reported> {
    // The meter gate's fold, carried (SP-M1): re-folded only when the counts moved since.
    let view = money.usage_view(unit)?;
    let (lane, attribution, fold) = match view.as_ref() {
        busbar_kernel::plane_driver::UsageView::Legacy {
            lane,
            attribution,
            usage,
        } => (lane.clone(), attribution.clone(), usage.clone()),
        busbar_kernel::plane_driver::UsageView::Partitioned(_) => {
            return Some(crate::root::linked::node::Reported::Partitioned)
        }
    };
    let mut usage_units: BTreeMap<String, busbar_contract::Count> = BTreeMap::new();
    let mut fee = 0u32;
    for (class, sum) in fold.by_class() {
        if facts.fee_units.contains(&class) {
            // Counts are never negative: a class summed above zero (or past a `Count`) was
            // incurred.
            fee = fee.max(u32::from(!matches!(sum, Some(n) if n.is_zero())));
            continue;
        }
        if let Some(name) = facts.classes.get(class as usize) {
            let count = sum?;
            // Counts are nonnegative, so a class totals zero only when every count is zero: a zero
            // count never opens an entry (no zero row to sweep out afterwards).
            if count.is_zero() {
                continue;
            }
            let n = usage_units
                .entry(name.clone())
                .or_insert(busbar_contract::Count::ZERO);
            *n = n.checked_add(count).ok()?;
        }
    }
    Some(crate::root::linked::node::Reported::Legacy((
        busbar_contract::billing::ExactUsage { usage_units },
        fee,
        lane,
        attribution,
    )))
}

pub(crate) struct DoorFar<'d, 's> {
    pub(crate) observations: Option<observations::UnitBinding<'d>>,
    pub(crate) egress: Option<&'d Egress>,

    pub(crate) shown: Option<&'d crate::root::model_egress::ModelShown>,
    pub(crate) steps: &'d DoorSteps<'s>,
    pub(crate) unit: busbar_contract::UnitKey,

    pub(crate) credential: Option<busbar_kernel::auth::CallerCredential>,
    pub(crate) authorization: Arc<busbar_kernel::host_units::UnitRecords>,
    pub(crate) far: OnceLock<Option<EgressFarEnd<'d>>>,
}

impl<'d> DoorFar<'d, '_> {
    fn far(&self) -> Option<&EgressFarEnd<'d>> {
        self.far
            .get_or_init(|| {
                let egress = self.egress?;
                let pool = self
                    .steps
                    .with_routed(|routed| egress_pool(self.steps.lane_prefix(), routed))?;
                let described = self.shown.and_then(|s| s.described.get(&pool).cloned());
                let mut far = egress.unit(UnitRoute {
                    member_grants: self.steps.member_grants(),
                    allowed_member: self.steps.child_member(),
                    unit: self.unit,
                    pool,
                    connection_required: self.steps.connection_required(),
                    authorization: Some(Arc::clone(&self.authorization)),
                    caller_credential: self.credential.clone(),
                    once: self.steps.once(),

                    wants_stream: self.steps.streamed(),
                    affinity: self.steps.affinity(),
                    ..UnitRoute::default()
                });
                if let Some(described) = described {
                    far = far.described(described);
                }
                if let Some(shown) = self.shown {
                    far = far.signals(Arc::clone(&shown.signals));
                }
                Some(far)
            })
            .as_ref()
    }
}

fn spent() -> Pick {
    Pick::Exhausted {
        status: refusal_status(ReasonCode::BreakerOpen),
        retry_after: None,
        detail: busbar_kernel_egress::wire::DETAIL_OVERLOADED,
    }
}

impl FarEnd for DoorFar<'_, '_> {
    fn deadline_ns(&self, now_ns: u64) -> u64 {
        self.far().map_or(0, |far| far.deadline_ns(now_ns))
    }

    fn scope(&self, _token: &Pass<Route>) -> Option<RoutedScope> {
        self.steps.with_routed(|routed| RoutedScope {
            pool: egress_pool(self.steps.lane_prefix(), routed),
            container: match routed {
                (label, _) if !label.is_empty() => label.clone(),
                (_, members) => members.first().cloned().unwrap_or_default(),
            },
        })
    }

    async fn member(&self, token: &Pass<Route>, attempt_no: u32) -> Pick {
        match self.far() {
            Some(far) => {
                let picked = far.member(token, attempt_no).await;
                if let Pick::Member { name, .. } = &picked {
                    if self
                        .observations
                        .as_ref()
                        .is_some_and(|binding| !binding.selected(name))
                    {
                        return spent();
                    }
                }
                picked
            }
            None => spent(),
        }
    }

    async fn send(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        match self.far() {
            Some(far) => {
                if crate::root::connector::the()
                    .wait_session_opening(self.unit.get())
                    .await
                    .is_err()
                {
                    return false;
                }
                far.send(token, request).await
            }
            None => false,
        }
    }

    async fn next(&self, token: &Pass<Route>) -> Option<FarPiece> {
        match self.far() {
            Some(far) => far.next(token).await,
            None => None,
        }
    }

    async fn followup(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        match self.far() {
            Some(far) => far.followup(token, request).await,
            None => false,
        }
    }

    fn judged(&self, token: &Pass<Route>, fault: u8) {
        if let Some(far) = self.far() {
            far.judged(token, fault);
        }
    }

    fn judged_stating(&self, token: &Pass<Route>, fault: u8, reason: Option<&str>) {
        if let Some(far) = self.far() {
            far.judged_stating(token, fault, reason);
        }
    }

    fn taken(&self, token: &Pass<Route>) {
        if let Some(far) = self.far() {
            far.taken(token);
        }
    }

    async fn write(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        match self.far() {
            Some(far) => far.write(token, request).await,
            None => false,
        }
    }

    fn stated(&self, token: &Pass<Route>, labels: busbar_kernel_egress::ports::StatedLabels) {
        if let Some(far) = self.far() {
            far.stated(token, labels);
        }
    }

    fn member_wait(&self, token: &Pass<Route>, member: &str) -> Option<u32> {
        self.far().and_then(|far| far.member_wait(token, member))
    }

    fn remaining(&self, token: &Pass<Route>) -> Option<usize> {
        self.far().and_then(|far| far.remaining(token))
    }

    fn failure(&self, token: &Pass<Route>) -> Option<&'static str> {
        self.far().and_then(|far| far.failure(token))
    }

    fn attempt_span(&self, token: &Pass<Route>) -> tracing::Span {
        self.far()
            .map_or_else(tracing::Span::none, |far| far.attempt_span(token))
    }

    fn unsent(&self, token: &Pass<Route>) -> Option<busbar_contract::abi::plane::RefusalCode> {
        self.far().and_then(|far| far.unsent(token))
    }

    fn candidates(&self, token: &Pass<Route>) -> Option<busbar_kernel::plane_driver::Candidates> {
        let mut candidates = self.far()?.candidates(token)?;
        for candidate in &mut candidates.members {
            candidate.route_cost = self.steps.route_cost(&candidate.model);
        }
        Some(candidates)
    }

    fn constrain(&self, token: &Pass<Route>, constraint: busbar_kernel::plane_driver::Constraint) {
        if let Some(far) = self.far() {
            far.constrain(token, constraint);
        }
    }
}

const SWITCHED: u32 = 101;

const CREATED: u32 = 201;

const OPEN_HEAD_WAIT: std::time::Duration = busbar_core_connector::compose::DEFAULT_OPEN_TIMEOUT;

pub(crate) struct Attach {
    pub(crate) answered: u32,
    pub(crate) admitted: Option<OnAdmitted>,
    pub(crate) ended: Option<Box<dyn FnOnce(u64) + Send>>,
}

pub(crate) type OnAdmitted = Box<dyn FnOnce(u64) -> Result<(), String> + Send>;

pub(crate) struct DatagramOpening {
    pub(crate) state: Arc<Mutex<DatagramOpeningState>>,
    pub(crate) transferred: bool,
}

pub(crate) struct DatagramOpeningState {
    pub(crate) joining: Option<serve_datagram::Joining>,
    pub(crate) unit: Option<u64>,
    pub(crate) abandoned: bool,
}

const DATAGRAM_OPEN_ABANDONED: &str = "the datagram opening was abandoned";
const DATAGRAM_ALREADY_ADMITTED: &str = "the datagram opening was admitted twice";

impl DatagramOpening {
    fn new(joining: serve_datagram::Joining) -> Self {
        Self {
            state: Arc::new(Mutex::new(DatagramOpeningState {
                joining: Some(joining),
                unit: None,
                abandoned: false,
            })),
            transferred: false,
        }
    }

    fn admission(&self) -> OnAdmitted {
        let state = Arc::clone(&self.state);
        Box::new(move |unit| Self::admit_with(&state, unit, |joining| joining.admit(unit)))
    }

    fn admit_with(
        state: &Mutex<DatagramOpeningState>,
        unit: u64,
        join: impl FnOnce(serve_datagram::Joining) -> Result<(), String>,
    ) -> Result<(), String> {
        let joining = {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.abandoned {
                return Err(crate::root::cold::admission_refused(
                    DATAGRAM_OPEN_ABANDONED,
                ));
            }
            state
                .joining
                .take()
                .ok_or_else(|| crate::root::cold::admission_refused(DATAGRAM_ALREADY_ADMITTED))?
        };

        join(joining)?;
        let abandoned = {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.abandoned {
                true
            } else {
                state.unit = Some(unit);
                false
            }
        };
        if abandoned {
            crate::root::connector::the().unpair(unit);
            Err(crate::root::cold::admission_refused(
                DATAGRAM_OPEN_ABANDONED,
            ))
        } else {
            Ok(())
        }
    }

    fn transfer(&mut self) {
        self.transferred = true;
    }
}

impl Drop for DatagramOpening {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        let (joining, unit) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.abandoned = true;
            (state.joining.take(), state.unit.take())
        };
        drop(joining);
        if let Some(unit) = unit {
            crate::root::connector::the().unpair(unit);
        }
    }
}

pub(crate) struct CarrierEnd {
    pub(crate) unit: u64,
    pub(crate) ended: Option<Box<dyn FnOnce(u64) + Send>>,
}

impl Drop for CarrierEnd {
    fn drop(&mut self) {
        if let Some(ended) = self.ended.take() {
            ended(self.unit);
        }
    }
}

impl Attach {
    fn switched() -> Self {
        Attach {
            answered: SWITCHED,
            admitted: None,
            ended: None,
        }
    }
}

pub(crate) struct SessionDoor {
    pub(crate) request: busbar_kernel::limits::process_admission::RequestLease,
    pub(crate) admission: Option<busbar_kernel::inbound::RequestAdmission>,
    pub(crate) plane: usize,
    pub(crate) app: Arc<busbar_kernel::state::App>,
    pub(crate) principal: PrincipalId,
    pub(crate) key: Option<Arc<busbar_contract::records::VirtualKey>>,
    pub(crate) open: bool,

    pub(crate) credential: Option<busbar_kernel::auth::CallerCredential>,

    pub(crate) ticket: Option<Vec<u8>>,
    pub(crate) host_ticket_admission: Option<busbar_kernel::host_services::HostTicketAdmission>,
}

pub(crate) struct ClosingCaller<C> {
    pub(crate) inner: C,
    pub(crate) shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

impl<C> ClosingCaller<C> {
    fn new(inner: C) -> Self {
        Self {
            inner,
            shutdown: busbar_kernel::detached::worker_shutdown(),
        }
    }
}

impl<C: SessionCaller> CallerEnd for ClosingCaller<C> {
    fn head(&self, status: u32, fields: HeadFields) {
        self.inner.head(status, fields);
    }

    fn head_whole(&self, status: u32, fields: HeadFields, len: usize) {
        self.inner.head_whole(status, fields, len);
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => false,
            written = self.inner.write(bytes) => written,
        }
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => false,
            written = self.inner.write_text(bytes) => written,
        }
    }

    async fn write_piece(&self, bytes: &[u8], text: bool, message_end: bool) -> bool {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => false,
            written = self.inner.write_piece(bytes, text, message_end) => written,
        }
    }
}

impl<C: SessionCaller> SessionCaller for ClosingCaller<C> {
    async fn read_owned(&self) -> Option<busbar_kernel::plane_driver::SessionInput> {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => None,
            piece = self.inner.read_owned() => piece,
        }
    }

    async fn read(&self) -> Option<Vec<u8>> {
        tokio::select! {
            biased;
            () = busbar_kernel::detached::shutdown_fired(self.shutdown.clone()) => None,
            piece = self.inner.read() => piece,
        }
    }
}

pub(crate) struct PipeCaller {
    pub(crate) from: tokio::sync::Mutex<mpsc::Receiver<busbar_kernel::plane_driver::SessionInput>>,
    pub(crate) to: mpsc::Sender<busbar_kernel::plane_routes::SessionOut>,
}

impl CallerEnd for PipeCaller {
    fn head(&self, _status: u32, _fields: HeadFields) {}

    async fn write(&self, bytes: &[u8]) -> bool {
        let out = busbar_kernel::plane_routes::SessionOut {
            bytes: bytes.to_vec(),
            text: false,
        };
        self.to.send(out).await.is_ok()
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        let out = busbar_kernel::plane_routes::SessionOut {
            bytes: bytes.to_vec(),
            text: true,
        };
        self.to.send(out).await.is_ok()
    }
}

impl busbar_kernel::plane_driver::SessionCaller for PipeCaller {
    /// Budgeted callers require owned reads; bare reads must not dequeue or strip custody.
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }

    async fn read_owned(&self) -> Option<busbar_kernel::plane_driver::SessionInput> {
        self.from.lock().await.recv().await
    }
}

/// The deframed messages, as the unit's body: one message is handed over as is (no copy); only
/// several are joined.
fn deframed_arrival(
    arrival: Arrival,
    messages: Vec<Vec<u8>>,
    request: &busbar_kernel::limits::process_admission::RequestLease,
) -> Result<
    (Arrival, IngressCaller, IngressReply),
    busbar_kernel::limits::process_admission::CapacityDenied,
> {
    let deframed = gathered_input(messages, request)?;
    let arrival = Arrival {
        body: deframed.clone(),
        ..arrival
    };
    let (caller, reply) = IngressCaller::arriving(deframed);
    Ok((arrival, caller, reply))
}

fn gathered_input(
    messages: Vec<Vec<u8>>,
    request: &busbar_kernel::limits::process_admission::RequestLease,
) -> Result<Bytes, busbar_kernel::limits::process_admission::CapacityDenied> {
    let mut messages = messages.into_iter();
    let mut joined = request.adopt_input(messages.next().unwrap_or_default())?;
    for message in messages {
        let input = request.adopt_input(message)?;
        joined
            .try_append(input)
            .map_err(|_| busbar_kernel::limits::process_admission::CapacityDenied)?;
    }
    Ok(joined.into_bytes())
}

/// THE CALLER'S SIDE OF A DRIVEN UNIT over today's hyper ingress.
///
/// The head goes to the handler once; the bytes go into the response body through a channel of one
/// piece, so a `write` resolves only once the body has taken the piece before it (the caller's side
/// was writable). A body the server dropped (the caller went away) answers `false`.
///
/// A unit served as a duplex session (`ROUTE_SESSION`) uses this caller
/// side as its session's caller leg: its read yields the
/// arrival's body once, then nothing until the response is dropped, and the long-lived response is
/// what the session writes.
#[derive(Debug)]
pub(crate) struct IngressCaller {
    pub(crate) head: Mutex<Option<oneshot::Sender<Head>>>,
    pub(crate) body: mpsc::Sender<Bytes>,
    /// The status the unit stated its head with; `0` before it did.
    pub(crate) stated: std::sync::atomic::AtomicU32,
    /// The arrival's body, until a session's caller leg has read it.
    pub(crate) arrived: Mutex<Option<Bytes>>,
    /// The unit's node-qualified id, once the drive minted the unit: the reply's `X-Request-Id`.
    pub(crate) unit_id: Arc<Mutex<Option<HeaderValue>>>,
    /// When the drive began the unit, once it has.
    pub(crate) began: std::sync::OnceLock<std::time::Instant>,
    /// Nanoseconds from `began` to the first successful body write; `0` until one.
    pub(crate) first_write_ns: std::sync::atomic::AtomicU64,
}

pub(crate) type Head = (u32, HeadFields);

/// The data plane's response header naming the unit (ADMIN-API-1.6 §3.4).
pub(crate) const X_REQUEST_ID: &str = "x-request-id";

/// Room for a unit id: `node_` + 16 hex, `.`, 32 hex, `.`, at most 20 decimal digits.
const UNIT_ID_LEN: usize = 5 + 16 + 1 + 32 + 1 + 20;

/// The handler's end of an [`IngressCaller`]: the reply, once the unit states its head.
#[derive(Debug)]
pub(crate) struct IngressReply {
    pub(crate) head: oneshot::Receiver<Head>,
    pub(crate) body: mpsc::Receiver<Bytes>,
    /// The answer's trailers, where a framer renders a close after its body.
    pub(crate) trailers: Option<oneshot::Receiver<axum::http::HeaderMap>>,
    /// Shared with the caller: the unit id the reply is stamped with.
    pub(crate) unit_id: Arc<Mutex<Option<HeaderValue>>>,
}

/// Stamp `response` with the unit's id, replacing any `x-request-id` a plane forwarded from
/// upstream: core's id is the one a client joins records and content by.
fn stamp_unit_id(mut response: Response, unit_id: &Mutex<Option<HeaderValue>>) -> Response {
    let minted = unit_id
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(id) = minted {
        response
            .headers_mut()
            .insert(HeaderName::from_static(X_REQUEST_ID), id);
    }
    response
}

impl IngressCaller {
    #[must_use]
    pub(crate) fn new() -> (Self, IngressReply) {
        Self::arriving(Bytes::new())
    }

    #[must_use]
    pub(crate) fn arriving(body: Bytes) -> (Self, IngressReply) {
        let (head_tx, head) = oneshot::channel();
        let (body_tx, reply_body) = mpsc::channel(1);
        let unit_id = Arc::new(Mutex::new(None));
        let caller = IngressCaller {
            head: Mutex::new(Some(head_tx)),
            body: body_tx,
            stated: std::sync::atomic::AtomicU32::new(0),
            arrived: Mutex::new(Some(body)),
            unit_id: Arc::clone(&unit_id),
            began: std::sync::OnceLock::new(),
            first_write_ns: std::sync::atomic::AtomicU64::new(0),
        };
        (
            caller,
            IngressReply {
                head,
                body: reply_body,
                trailers: None,
                unit_id,
            },
        )
    }

    #[must_use]
    pub(crate) fn stated(&self) -> Option<u32> {
        Some(self.stated.load(std::sync::atomic::Ordering::Acquire)).filter(|s| *s != 0)
    }
}

pub(crate) trait Stated {
    fn stated(&self) -> Option<u32>;

    fn ended(&self, _outcome: Option<busbar_contract::caps::Outcome>) {}

    /// The drive minted the unit this caller is answered for: `id` is its node-qualified id.
    fn minted(&self, _id: busbar_kernel_audit::UnitId) {}

    /// The drive began the unit at `at`: the clock its first write is read against.
    fn began(&self, _at: std::time::Instant) {}

    /// Nanoseconds from the unit's start to its first successful body write, `0` before one (or
    /// for a caller that does not measure it).
    fn first_write_ns(&self) -> u64 {
        0
    }
}

impl Stated for IngressCaller {
    fn stated(&self) -> Option<u32> {
        IngressCaller::stated(self)
    }

    fn began(&self, at: std::time::Instant) {
        let _first = self.began.set(at);
    }

    fn first_write_ns(&self) -> u64 {
        self.first_write_ns
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn minted(&self, id: busbar_kernel_audit::UnitId) {
        // One allocation: the id is formatted once and the header takes the string's bytes.
        let mut text = String::with_capacity(UNIT_ID_LEN);
        if std::fmt::Write::write_fmt(&mut text, format_args!("{id}")).is_ok() {
            if let Ok(value) = HeaderValue::try_from(text) {
                *self
                    .unit_id
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value);
            }
        }
    }
}

impl CallerEnd for IngressCaller {
    fn head(&self, status: u32, fields: HeadFields) {
        self.stated
            .store(status, std::sync::atomic::Ordering::Release);
        let sender = self
            .head
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(sender) = sender {
            let _gone = sender.send((status, fields));
        }
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        let sent = self.body.send(Bytes::copy_from_slice(bytes)).await.is_ok();
        // The first successful write is the unit's time to first byte (§9): one monotonic read,
        // then a relaxed load per later write.
        if sent
            && self
                .first_write_ns
                .load(std::sync::atomic::Ordering::Relaxed)
                == 0
        {
            if let Some(began) = self.began.get() {
                let ns = u64::try_from(
                    busbar_core_connector::framer::now()
                        .saturating_duration_since(*began)
                        .as_nanos(),
                )
                .unwrap_or(u64::MAX);
                self.first_write_ns
                    .store(ns.max(1), std::sync::atomic::Ordering::Relaxed);
            }
        }
        sent
    }
}

impl SessionCaller for IngressCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        let first = self
            .arrived
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(body) = first {
            // A uniquely held body hands over its allocation; a shared one is copied once.
            return Some(Vec::from(body));
        }
        self.body.closed().await;
        None
    }
}

impl IngressReply {
    #[cfg(test)]
    pub(crate) async fn response(self) -> Option<Response> {
        let head = self.head.await.ok()?;
        Some(stated(
            head,
            Body::new(ReplyBody(self.body, None, self.trailers)),
        ))
    }

    #[must_use]
    pub(crate) fn with_trailers(
        mut self,
        trailers: oneshot::Receiver<axum::http::HeaderMap>,
    ) -> Self {
        self.trailers = Some(trailers);
        self
    }

    pub(crate) async fn answer(self, unit: DrivenUnit) -> Response {
        self.answer_collecting(unit).await
    }

    #[cfg(test)]
    async fn answer_nested(self, unit: DrivenUnit) -> busbar_kernel::host_services::NestReply {
        self.answer_nested_bound(unit, NEST_REPLY_MAX).await
    }

    pub(crate) async fn answer_nested_bound(
        self,
        mut unit: DrivenUnit,
        bound: usize,
    ) -> busbar_kernel::host_services::NestReply {
        use busbar_kernel::host_services::NestReply;
        let IngressReply {
            mut head, mut body, ..
        } = self;
        let first = tokio::select! {
            biased;
            head = &mut head => Ok(head.ok()),
            rendered = &mut unit => Err(rendered),
        };
        let rendered = match first {
            Ok(Some((status, fields))) => {
                return match collect_nested_bound(body, unit, bound).await {
                    Some(body) => NestReply::Answered {
                        status,
                        fields,
                        body,
                    },
                    None => NestReply::Failed(NEST_UNREAD),
                };
            }
            Ok(None) => unit.await,
            Err(rendered) => match head.try_recv() {
                Ok((status, fields)) => {
                    let mut whole = NestedBody::bounded(bound);
                    while let Ok(piece) = body.try_recv() {
                        if !whole.push(piece) {
                            return NestReply::Failed(NEST_UNREAD);
                        }
                    }
                    return NestReply::Answered {
                        status,
                        fields,
                        body: whole.into_bytes(),
                    };
                }
                Err(_) => rendered,
            },
        };
        match rendered {
            Some(Rendered {
                status,
                fields,
                body,
            }) if body.len() <= bound => NestReply::Answered {
                status,
                fields,
                body,
            },
            Some(_) => NestReply::Failed(NEST_UNREAD),
            None => NestReply::Answered {
                status: refusal_status(ReasonCode::PlanePanic),
                fields: Vec::new(),
                body: Vec::new(),
            },
        }
    }

    async fn answer_collecting(self, unit: DrivenUnit) -> Response {
        self.answer_with_collection(unit, |rendered| match rendered {
            Some(r) => stated((r.status, r.fields), Body::from(r.body)),
            None => stated(
                (refusal_status(ReasonCode::PlanePanic), Vec::new()),
                Body::empty(),
            ),
        })
        .await
    }

    pub(crate) async fn answer_with(
        self,
        unit: DrivenUnit,
        unrendered: impl FnOnce(Option<Rendered>) -> Response,
    ) -> Response {
        self.answer_with_collection(unit, unrendered).await
    }

    /// Every answer, whole, streamed or refused, leaves stamped with the unit's id.
    async fn answer_with_collection(
        self,
        unit: DrivenUnit,
        unrendered: impl FnOnce(Option<Rendered>) -> Response,
    ) -> Response {
        let unit_id = Arc::clone(&self.unit_id);
        let response = self.answer_unstamped(unit, unrendered).await;
        stamp_unit_id(response, &unit_id)
    }

    async fn answer_unstamped(
        self,
        mut unit: DrivenUnit,
        unrendered: impl FnOnce(Option<Rendered>) -> Response,
    ) -> Response {
        let IngressReply {
            mut head,
            body,
            mut trailers,
            ..
        } = self;
        let first = tokio::select! {
            biased;
            h = &mut head => Ok(h.ok()),
            rendered = &mut unit => Err(rendered),
        };
        let rendered = match first {
            Ok(Some(h)) if whole_answer(&h.1) => {
                let whole = collect(body, unit).await;
                return unlengthed(stated(h, Body::from(whole)));
            }

            Ok(Some(h)) => {
                if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                    let _ = unit.await;
                    return closed_whole(h, block);
                }
                let running = Running(busbar_kernel::detached::spawn_detached(unit));
                return stated(h, Body::new(ReplyBody(body, Some(running), trailers)));
            }
            Ok(None) => unit.await,
            Err(rendered) => match head.try_recv() {
                Ok(h) if whole_answer(&h.1) => {
                    let mut body = body;
                    let mut whole = Whole::default();
                    while let Ok(bytes) = body.try_recv() {
                        whole.push(bytes);
                    }
                    return unlengthed(stated(h, Body::from(whole.into_bytes())));
                }
                Ok(h) => {
                    if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                        return closed_whole(h, block);
                    }
                    return stated(h, Body::new(ReplyBody(body, None, trailers)));
                }
                Err(_) => rendered,
            },
        };
        unrendered(rendered)
    }
}

pub(crate) type UnitCaller = (
    PrincipalId,
    Option<Arc<busbar_contract::records::VirtualKey>>,
    Option<busbar_kernel::auth::CallerCredential>,
    Option<Vec<u8>>,
    Option<busbar_kernel::host_services::HostTicketAdmission>,
);

fn closed_before_body(
    body: &mpsc::Receiver<Bytes>,
    trailers: Option<&mut oneshot::Receiver<HeaderMap>>,
) -> Option<HeaderMap> {
    if !body.is_empty() {
        return None;
    }
    trailers?.try_recv().ok()
}

fn closed_whole(h: Head, block: HeaderMap) -> Response {
    let mut response = stated(h, Body::empty());
    response.headers_mut().remove(axum::http::header::TRAILER);
    response.headers_mut().extend(block);
    response
}

fn whole_answer(fields: &HeadFields) -> bool {
    let named = |field: &[u8]| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(field))
            .map(|(_, value)| String::from_utf8_lossy(value))
    };
    named(b"content-length").is_some()
        && !named(b"content-type").is_some_and(|v| streamed_media(&v))
}

fn declared_stream_media() -> impl Iterator<Item = &'static str> {
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .flat_map(|decl| {
            busbar_kernel::plane_driver::door::streaming_content_types(decl)
                .iter()
                .copied()
        })
}

fn streamed_media(content_type: &str) -> bool {
    std::iter::once(busbar_contract::protocol::TEXT_EVENT_STREAM)
        .chain(declared_stream_media())
        .any(|media| {
            content_type
                .get(..media.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(media))
        })
}

/// A whole answer's response without the unit's stated length: its body is measured instead.
fn unlengthed(mut response: Response) -> Response {
    response
        .headers_mut()
        .remove(axum::http::header::CONTENT_LENGTH);
    response
}

async fn collect(mut body: mpsc::Receiver<Bytes>, mut unit: DrivenUnit) -> Bytes {
    let mut whole = Whole::default();
    loop {
        tokio::select! {
            biased;
            piece = body.recv() => match piece {
                Some(bytes) => whole.push(bytes),
                None => {
                    let _ = unit.await;
                    break;
                }
            },
            _ = &mut unit => {
                while let Ok(bytes) = body.try_recv() {
                    whole.push(bytes);
                }
                break;
            }
        }
    }
    whole.into_bytes()
}

async fn collect_nested_bound(
    mut body: mpsc::Receiver<Bytes>,
    mut unit: DrivenUnit,
    bound: usize,
) -> Option<Vec<u8>> {
    let mut whole = NestedBody::bounded(bound);
    loop {
        tokio::select! {
            biased;
            piece = body.recv() => match piece {
                Some(piece) => {
                    if !whole.push(piece) { return None; }
                }
                None => {
                    let _ = unit.await;
                    break;
                }
            },
            _ = &mut unit => {
                while let Ok(piece) = body.try_recv() {
                    if !whole.push(piece) { return None; }
                }
                break;
            }
        }
    }
    Some(whole.into_bytes())
}

#[derive(Default)]
pub(crate) struct NestedBody {
    pub(crate) bound: Option<usize>,
    pub(crate) length: usize,
    pub(crate) whole: Whole,
}

impl NestedBody {
    fn bounded(bound: usize) -> Self {
        Self {
            bound: Some(bound),
            ..Self::default()
        }
    }
    pub(crate) fn push(&mut self, piece: Bytes) -> bool {
        let Some(length) = self
            .length
            .checked_add(piece.len())
            .filter(|n| *n <= self.bound.unwrap_or(NEST_REPLY_MAX))
        else {
            return false;
        };
        self.length = length;
        self.whole.push(piece);
        true
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        // The joined pieces, or a lone uniquely held piece, hand over their allocation (no copy).
        Vec::from(self.whole.into_bytes())
    }
}

/// A whole answer's pieces, joined: a lone piece is kept as written, never copied.
#[derive(Default)]
pub(crate) struct Whole {
    pub(crate) one: Option<Bytes>,
    pub(crate) many: Vec<u8>,
}

impl Whole {
    pub(crate) fn push(&mut self, piece: Bytes) {
        match self.one.take() {
            None if self.many.is_empty() => self.one = Some(piece),
            first => {
                if let Some(first) = first {
                    self.many.extend_from_slice(&first);
                }
                self.many.extend_from_slice(&piece);
            }
        }
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        self.one.unwrap_or_else(|| Bytes::from(self.many))
    }
}

pub(crate) type DrivenUnit =
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<Rendered>> + Send>>;

pub(crate) fn stated((status, fields): Head, body: Body) -> Response {
    let status = [status, refusal_status(ReasonCode::PlanePanic)]
        .into_iter()
        .find_map(|s| StatusCode::from_u16(u16::try_from(s).ok()?).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&name),
            HeaderValue::from_bytes(&value),
        ) {
            headers.append(name, value);
        }
    }
    response
}

pub(crate) struct Running(tokio::task::JoinHandle<Option<Rendered>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct ReplyBody(
    mpsc::Receiver<Bytes>,
    Option<Running>,
    Option<oneshot::Receiver<axum::http::HeaderMap>>,
);

impl http_body::Body for ReplyBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.0.poll_recv(cx) {
            std::task::Poll::Ready(Some(bytes)) => {
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => {
                if let Some(running) = &mut this.1 {
                    match std::future::Future::poll(std::pin::Pin::new(&mut running.0), cx) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) if e.is_panic() => {
                            std::panic::resume_unwind(e.into_panic())
                        }
                        std::task::Poll::Ready(_) => this.1 = None,
                    }
                }
                let Some(trailers) = &mut this.2 else {
                    return std::task::Poll::Ready(None);
                };
                match std::future::Future::poll(std::pin::Pin::new(trailers), cx) {
                    std::task::Poll::Pending => std::task::Poll::Pending,
                    std::task::Poll::Ready(sent) => {
                        this.2 = None;
                        std::task::Poll::Ready(
                            sent.ok().map(|map| Ok(http_body::Frame::trailers(map))),
                        )
                    }
                }
            }
        }
    }
}

fn framed_by(
    carrier: &str,
    framer_for: impl Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>>,
) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    if lines::carrier() == Some(carrier) {
        return None;
    }
    serve_framed::stream_framer(carrier, framer_for)
}

#[path = "serve_lines.rs"]
pub(crate) mod lines;

#[path = "serve_framed.rs"]
mod serve_framed;

#[path = "serve_datagram.rs"]
pub(crate) mod serve_datagram;

#[cfg(test)]
#[path = "tests/claim_line.rs"]
mod claim_line_tests;

#[cfg(test)]
#[path = "tests/serve.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/serve_planes.rs"]
pub(crate) mod planes_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/serve_tests.rs"]
mod door_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/door_rig.rs"]
pub(crate) mod door_rig;

#[cfg(test)]
include!(concat!(env!("OUT_DIR"), "/root_test_sources.rs"));

#[cfg(all(test, linked_section_pools))]
include!(concat!(env!("OUT_DIR"), "/door_cells.rs"));

#[cfg(test)]
#[path = "tests/serve_money.rs"]
mod money_tests;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/serve_door_far.rs"]
mod door_far_tests;

#[cfg(all(test, linked_section_pools, linked_driver_proofs))]
#[path = "tests/node_door_rig.rs"]
mod node_rig;

#[cfg(all(test, linked_section_pools, linked_driver_proofs))]
#[path = "tests/work_budget.rs"]
mod work_budget;

#[cfg(all(test, linked_section_pools, linked_driver_proofs))]
#[path = "tests/node_arrival.rs"]
mod node_arrival;

#[cfg(all(test, linked_section_pools, linked_driver_proofs))]
#[path = "tests/node_door_cells.rs"]
mod node_door_cells;

#[cfg(all(test, linked_section_pools))]
#[path = "tests/serve_framed.rs"]
mod framed_tests;

#[cfg(all(test, linked_section_pools, linked_axis_plane_door))]
#[path = "tests/secret_source.rs"]
mod secret_source_tests;

#[cfg(test)]
#[path = "tests/journal_live_retry.rs"]
mod journal_live_retry_tests;

#[cfg(test)]
#[path = "tests/catalog_scope_provenance.rs"]
mod catalog_scope_provenance_tests;
