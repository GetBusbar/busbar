// SPDX-License-Identifier: Apache-2.0
//! Host-owned price publication and recovery. Native persistence plans remain
//! inside their original owner across cancellation; configuration commit is the
//! separate, synchronous publication boundary after Applied activation.
use super::{
    Activation, EntryAuthor, Outcome, Phase, PricePlan, Snapshot, StoredEntry, StoredIntent,
    VoidRecord,
};
use crate::{config::card::CardFields, persistence::facade::CoreStore};
use busbar_kernel_ledger::cost::{EntryKey, History, RateCard};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};

pub const RESCAN_INTERVAL: Duration = Duration::from_secs(5);
pub const CARD_ALARMS_TOTAL: &str = "busbar_card_history_alarms_total";
const SKEW_MS: u64 = 5 * 60 * 1000;
fn now_ms() -> u64 {
    crate::store::now_ms()
}
fn error(error: super::Error) -> String {
    format!("price persistence: {error:?}")
}
fn opening(entry: &StoredEntry) -> bool {
    matches!(
        entry.author,
        EntryAuthor::Opening {} | EntryAuthor::Migrated { opening: true, .. }
    )
}

#[derive(Default)]
struct State {
    snapshot: Snapshot,
    pending: BTreeMap<EntryKey, Arc<Pending>>,
    voiding: BTreeMap<EntryKey, Arc<PendingVoid>>,
    own: Option<EntryKey>,
    preparing: bool,
    alarms: BTreeSet<String>,
}
struct Pending {
    entry: StoredEntry,
    own: bool,
    flow: tokio::sync::Mutex<Flow>,
}
struct Flow {
    phase: Option<Phase>,
    activation: Option<Activation>,
    plan: Option<PricePlan>,
    operation: Option<Operation>,
    boot_progress: BootNativeProgress,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum BootNativeProgress {
    NoPending,
    PendingOriginal,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Prepare,
    AuthorizeActivation,
    Activate,
    AuthorizeRetirement,
    Retire,
}
struct PendingVoid {
    record: VoidRecord,
    plan: tokio::sync::Mutex<Option<PricePlan>>,
}

pub struct CardStore {
    store: Arc<CoreStore>,
    node: u64,
    incarnation: [u8; 8],
    counter: AtomicU32,
    state: Mutex<State>,
    rates: fn(&CardFields) -> RateCard,
    published: arc_swap::ArcSwapOption<History>,
    node_published: arc_swap::ArcSwapOption<History>,
    loaded: AtomicBool,
    background: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl std::fmt::Debug for CardStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardStore")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}
impl Drop for CardStore {
    fn drop(&mut self) {
        if let Some(task) = self.background.get_mut().take() {
            task.abort();
        }
    }
}
impl Pending {
    fn new(entry: StoredEntry, own: bool) -> Self {
        Self {
            entry,
            own,
            flow: tokio::sync::Mutex::new(Flow {
                phase: None,
                activation: None,
                plan: None,
                operation: None,
                boot_progress: BootNativeProgress::NoPending,
            }),
        }
    }
    fn recovered(intent: StoredIntent) -> Self {
        Self {
            entry: intent.entry,
            own: intent.own,
            flow: tokio::sync::Mutex::new(Flow {
                phase: Some(intent.phase),
                activation: intent.activation,
                plan: None,
                operation: None,
                boot_progress: BootNativeProgress::NoPending,
            }),
        }
    }
}

pub struct PreparedCard {
    book: Arc<CardStore>,
    key: Option<EntryKey>,
    owns_lease: bool,
}
impl Drop for PreparedCard {
    fn drop(&mut self) {
        if self.owns_lease {
            self.book.lock().preparing = false;
        }
    }
}
pub struct ConfirmedCard {
    prepared: PreparedCard,
}
impl PreparedCard {
    pub async fn confirm_activation(self) -> Result<ConfirmedCard, String> {
        let key = self.key.ok_or("prepared price entry has no identity")?;
        let pending = self.book.lock().pending.get(&key).cloned();
        if let Some(pending) = pending {
            let mut flow = pending.flow.lock().await;
            self.book.resolve_current(&pending, &mut flow).await?;
            if matches!(flow.phase, Some(Phase::Retiring | Phase::Retired)) {
                return Err(format!(
                    "retirement of rate-card entry {key} requires explicit recovery"
                ));
            }
            if pending.own && flow.phase != Some(Phase::Active) {
                self.book
                    .drive(&pending, &mut flow, Operation::Prepare)
                    .await?;
                if flow.activation.is_none() {
                    flow.activation = Some(Activation {
                        effective_from: if opening(&pending.entry) { 0 } else { now_ms() },
                    });
                }
                if flow.phase == Some(Phase::Prepared) {
                    self.book
                        .drive(&pending, &mut flow, Operation::AuthorizeActivation)
                        .await?;
                }
                self.book
                    .drive(&pending, &mut flow, Operation::Activate)
                    .await?;
            }
        }
        Ok(ConfirmedCard { prepared: self })
    }
}
impl ConfirmedCard {
    pub fn commit(mut self) -> EntryKey {
        let key = self.prepared.key.take().expect("confirmed price identity");
        let mut state = self.prepared.book.lock();
        let confirmed: Vec<_> = state
            .pending
            .iter()
            .filter_map(|(held, pending)| {
                (*held <= key && pending.own && pending.entry.writer == self.prepared.book.node)
                    .then(|| {
                        pending
                            .flow
                            .try_lock()
                            .ok()
                            .filter(|flow| flow.phase == Some(Phase::Active))
                            .map(|flow| (*held, pending.entry.clone(), flow.activation))
                    })
                    .flatten()
            })
            .collect();
        for (held, entry, activation) in confirmed {
            if let Some(activation) = activation {
                state.snapshot.activations.insert(held, activation);
            }
            state.snapshot.entries.insert(held, entry);
            state.pending.remove(&held);
        }
        assert!(
            state.snapshot.entries.contains_key(&key),
            "Applied price activation precedes publication"
        );
        state.own = Some(key);
        self.prepared.book.publish(&state);
        key
    }
}
impl CardStore {
    pub fn new(
        store: Arc<CoreStore>,
        node: u64,
        rates: fn(&CardFields) -> RateCard,
    ) -> Result<Arc<Self>, String> {
        let authority = store
            .authority()
            .map_err(|error| format!("price writer authority: {error:?}"))?;
        let mut identity = authority.writer.to_vec();
        identity.extend_from_slice(&authority.execution_epoch.to_be_bytes());
        identity.extend_from_slice(&node.to_be_bytes());
        let digest = crate::config::card::sha256(&identity);
        Ok(Arc::new(Self {
            store,
            node,
            incarnation: digest[..8].try_into().expect("digest width"),
            counter: AtomicU32::new(0),
            state: Mutex::default(),
            rates,
            published: arc_swap::ArcSwapOption::empty(),
            node_published: arc_swap::ArcSwapOption::empty(),
            loaded: AtomicBool::new(false),
            background: tokio::sync::Mutex::default(),
        }))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }
    pub fn node(&self) -> u64 {
        self.node
    }
    pub fn is_bound_to(&self, store: &Arc<CoreStore>) -> bool {
        Arc::ptr_eq(&self.store, store)
    }
    /// Native transitions must settle before readiness. A confirmed generation
    /// may still await its caller's synchronous configuration publication.
    pub fn has_unconfirmed_operations(&self) -> bool {
        let state = self.lock();
        !state.voiding.is_empty()
            || state.pending.values().any(|pending| {
                let Ok(flow) = pending.flow.try_lock() else {
                    return true;
                };
                flow.plan.is_some()
                    || flow.operation.is_some()
                    || !matches!(flow.phase, Some(Phase::Active | Phase::Retired))
            })
    }
    pub fn history(&self) -> Option<Arc<History>> {
        self.published.load_full()
    }
    pub fn node_history(&self) -> Option<Arc<History>> {
        self.node_published.load_full()
    }
    pub fn entries(&self) -> Vec<StoredEntry> {
        self.lock().snapshot.entries.values().cloned().collect()
    }
    pub fn entry(&self, key: &EntryKey) -> Option<StoredEntry> {
        self.lock().snapshot.entries.get(key).cloned()
    }
    pub fn alarms(&self) -> Vec<String> {
        self.lock().alarms.iter().cloned().collect()
    }
    pub fn pending(&self) -> Option<EntryKey> {
        let state = self.lock();
        state
            .pending
            .iter()
            .find(|(_, p)| p.entry.writer == self.node)
            .map(|(key, _)| *key)
            .or_else(|| state.voiding.keys().next().copied())
    }
    pub fn pending_refusal(&self) -> Option<String> {
        self.pending().map(|key|format!("rate-card entry {key} is pending native Store confirmation or generation commit; previous confirmed prices remain active"))
    }
    pub fn own(&self) -> Option<(EntryKey, CardFields)> {
        let state = self.lock();
        let key = state.own?;
        state
            .snapshot
            .entries
            .get(&key)
            .map(|entry| (key, entry.card.clone()))
    }
    pub fn card_at(&self, at: u64) -> Option<(EntryKey, CardFields)> {
        let state = self.lock();
        let history = state.snapshot.history(self.rates);
        let key = history.current().entry_at(at)?.key();
        state
            .snapshot
            .entries
            .get(&key)
            .map(|entry| (key, entry.card.clone()))
    }
    pub fn in_force(&self) -> Option<CardFields> {
        self.is_loaded()
            .then(|| self.card_at(now_ms()).map(|(_, card)| card))
            .flatten()
    }
    fn publish(&self, state: &State) {
        self.published
            .store(Some(Arc::new(state.snapshot.history(self.rates))));
        self.node_published.store(Some(Arc::new(
            state
                .snapshot
                .node_history(self.node, state.own, self.rates),
        )));
    }
    fn next_key(&self, state: &State) -> EntryKey {
        let head = state
            .snapshot
            .intents
            .keys()
            .chain(state.snapshot.entries.keys())
            .chain(state.pending.keys())
            .map(EntryKey::t_ms)
            .max();
        let at = head.map_or(now_ms(), |at| now_ms().max(at.saturating_add(1)));
        EntryKey::new(
            at,
            self.incarnation,
            self.counter.fetch_add(1, Ordering::Relaxed),
        )
    }
    fn alarm(&self, state: &mut State, message: String) {
        if state.alarms.insert(message.clone()) {
            tracing::error!(alarm = "card_history", "{message}");
            metrics::counter!(CARD_ALARMS_TOTAL).increment(1);
        }
    }
    fn check_alarms(&self, state: &mut State) {
        let now = now_ms();
        let voided: BTreeSet<_> = state
            .snapshot
            .voids
            .iter()
            .map(|v| v.voided.clone())
            .collect();
        let mut messages = Vec::new();
        for entry in state.snapshot.entries.values() {
            let from = state
                .snapshot
                .activations
                .get(&entry.key)
                .map_or(entry.effective_from, |activation| activation.effective_from);
            if from > now.saturating_add(SKEW_MS) && !voided.contains(&entry.key.hex()) {
                messages.push(format!(
                    "rate-card entry {} from node {} starts {} ms ahead of this node's clock",
                    entry.key,
                    entry.writer,
                    from - now
                ));
            }
            if entry.base.is_some_and(|base| voided.contains(&base.hex())) {
                messages.push(format!("rate-card entry {} extends a voided entry; correct the configuration and reload",entry.key));
            }
        }
        if let Some(own) = state.own.and_then(|key| state.snapshot.entries.get(&key)) {
            let history = state.snapshot.history(self.rates);
            if let Some(fleet) = history
                .current()
                .entry_at(now)
                .and_then(|entry| state.snapshot.entries.get(&entry.key()))
            {
                if own.key != fleet.key && own.card != fleet.card {
                    messages.push(format!(
                        "node {} prices with rate-card entry {}; fleet entry {} differs in [{}]",
                        self.node,
                        own.key,
                        fleet.key,
                        own.card.differing_fields(&fleet.card).join(", ")
                    ));
                }
            }
        }
        let changes: Vec<_> = state
            .snapshot
            .entries
            .values()
            .filter(|entry| {
                matches!(entry.author, EntryAuthor::Change) && !voided.contains(&entry.key.hex())
            })
            .collect();
        for (index, lower) in changes.iter().enumerate() {
            for higher in &changes[index + 1..] {
                if lower.base.is_some() && lower.base == higher.base {
                    messages.push(format!("nodes run different rate cards: entries {} (node {}, {}) and {} (node {}, {}) both extend {}; each node prices its own counts with its own card, and a time-based read takes the later ({}), whose card differs in [{}]. Make the nodes' configuration agree", lower.key, lower.writer, lower.actor, higher.key, higher.writer, higher.actor, lower.base.map(|base| base.hex()).unwrap_or_default(), higher.key, lower.card.differing_fields(&higher.card).join(", ")));
                }
            }
        }
        for message in messages {
            self.alarm(state, message);
        }
    }

    /// Complete at most one retained native operation. Never replace an unknown
    /// plan, consult a read as a substitute for its receipt, or hold a host mutex
    /// while awaiting backend work.
    async fn drive(
        &self,
        pending: &Pending,
        flow: &mut Flow,
        operation: Operation,
    ) -> Result<(), String> {
        flow.boot_progress = BootNativeProgress::NoPending;
        let complete = match operation {
            Operation::Prepare => flow.phase.is_some(),
            Operation::AuthorizeActivation => {
                matches!(flow.phase, Some(Phase::Activating | Phase::Active))
            }
            Operation::Activate => flow.phase == Some(Phase::Active),
            Operation::AuthorizeRetirement => {
                matches!(flow.phase, Some(Phase::Retiring | Phase::Retired))
            }
            Operation::Retire => flow.phase == Some(Phase::Retired),
        };
        if complete {
            return Ok(());
        }
        if flow.operation.is_some_and(|held| held != operation) {
            return Err(
                "the original price transition must resolve before another transition".into(),
            );
        }
        if flow.plan.is_none() {
            let prices = self.store.prices();
            let plan = match operation {
                Operation::Prepare => prices.prepare(pending.entry.clone(), pending.own).await,
                Operation::AuthorizeActivation => {
                    prices
                        .authorize_activation(
                            pending.entry.key,
                            flow.activation.ok_or("missing retained activation")?,
                        )
                        .await
                }
                Operation::Activate => prices.activate(pending.entry.key).await,
                Operation::AuthorizeRetirement => {
                    prices.authorize_retirement(pending.entry.key).await
                }
                Operation::Retire => prices.retire(pending.entry.key).await,
            }
            .map_err(error)?;
            flow.plan = Some(plan);
            flow.operation = Some(operation);
        }
        let outcome = match self
            .store
            .prices()
            .submit(flow.plan.as_mut().expect("retained price plan"))
            .await
        {
            Ok(outcome) => outcome,
            Err(cause) => {
                use crate::persistence::facade::AccessError;
                use busbar_contract::persistence::Failure;
                if matches!(
                    cause,
                    super::Error::Backend(Failure::Unavailable | Failure::Overloaded)
                        | super::Error::Access(AccessError::Overloaded)
                        | super::Error::Access(AccessError::Backend(
                            Failure::Unavailable | Failure::Overloaded
                        ))
                ) {
                    flow.boot_progress = BootNativeProgress::PendingOriginal;
                }
                return Err(error(cause));
            }
        };
        if matches!(
            outcome,
            Outcome::Pending(_)
                | Outcome::Busy(_)
                | Outcome::NoEffect(
                    busbar_contract::persistence::Failure::Overloaded
                        | busbar_contract::persistence::Failure::Unavailable
                )
        ) {
            flow.boot_progress = BootNativeProgress::PendingOriginal;
        }
        match outcome {
            Outcome::Applied => {
                let phase = match operation {
                    Operation::Prepare if !pending.own => Phase::Active,
                    Operation::Prepare => Phase::Prepared,
                    Operation::AuthorizeActivation => Phase::Activating,
                    Operation::Activate => Phase::Active,
                    Operation::AuthorizeRetirement => Phase::Retiring,
                    Operation::Retire => Phase::Retired,
                };
                flow.phase = Some(phase);
                flow.plan = None;
                flow.operation = None;
                Ok(())
            }
            Outcome::Conflict => {
                flow.plan = None;
                flow.operation = None;
                Err(format!(
                    "price guard conflict for {}; immutable entry retained for another guarded attempt",
                    pending.entry.key
                ))
            }
            outcome => Err(format!(
                "price transition for {} remains unresolved or refused: {outcome:?}; original native plan retained",
                pending.entry.key
            )),
        }
    }

    async fn resolve_current(&self, pending: &Pending, flow: &mut Flow) -> Result<(), String> {
        if let Some(operation) = flow.operation {
            self.drive(pending, flow, operation).await?;
        }
        Ok(())
    }
    pub async fn rescan(&self, _deadline: Option<Instant>) -> Result<bool, String> {
        let mut snapshot = self.store.prices().snapshot().await.map_err(error)?;
        let mut state = self.lock();
        for (key, intent) in &snapshot.intents {
            if state
                .snapshot
                .intents
                .get(key)
                .is_some_and(|held| held.entry != intent.entry)
                || state
                    .pending
                    .get(key)
                    .is_some_and(|held| held.entry != intent.entry)
            {
                return Err(format!("conflicting immutable rate-card entry {key}"));
            }
        }
        for (key, activation) in &snapshot.activations {
            if state
                .snapshot
                .activations
                .get(key)
                .is_some_and(|held| held != activation)
            {
                return Err(format!("conflicting immutable price activation {key}"));
            }
        }
        // A canonical read cannot confirm a local pending operation or publish a
        // generation whose configuration has not crossed ConfirmedCard::commit.
        for key in state.pending.keys() {
            snapshot.entries.remove(key);
            snapshot.activations.remove(key);
        }
        snapshot.voids.retain(|record| {
            EntryKey::parse_hex(&record.voided).is_some_and(|key| !state.voiding.contains_key(&key))
        });
        let changed = state.snapshot.entries != snapshot.entries
            || state.snapshot.voids != snapshot.voids
            || state.snapshot.activations != snapshot.activations;
        state.snapshot = snapshot;
        if changed {
            self.publish(&state);
        }
        self.check_alarms(&mut state);
        Ok(changed)
    }
    pub async fn boot(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
        migrated: Vec<StoredEntry>,
    ) -> Result<(), String> {
        if !migrated.is_empty() {
            return Err("historical price import requires an explicit offline migration".into());
        }
        let mut snapshot = self.store.prices().snapshot().await.map_err(error)?;
        {
            let mut state = self.lock();
            for key in state.pending.keys() {
                snapshot.entries.remove(key);
                snapshot.activations.remove(key);
            }
            snapshot.voids.retain(|record| {
                EntryKey::parse_hex(&record.voided)
                    .is_some_and(|key| !state.voiding.contains_key(&key))
            });
            for (key, intent) in &snapshot.intents {
                if intent.own
                    && intent.entry.writer == self.node
                    && !matches!(intent.phase, Phase::Active | Phase::Retired)
                {
                    state
                        .pending
                        .entry(*key)
                        .or_insert_with(|| Arc::new(Pending::recovered(intent.clone())));
                }
            }
            state.own = snapshot
                .intents
                .iter()
                .rev()
                .find(|(_, intent)| {
                    intent.own && intent.entry.writer == self.node && intent.phase == Phase::Active
                })
                .map(|(key, _)| *key);
            state.snapshot = snapshot;
            self.publish(&state);
        }
        self.loaded.store(true, Ordering::Release);
        loop {
            let confirmed = match self.prepare_recovery(card, origin).await {
                Ok(prepared) => prepared.confirm_activation().await,
                Err(error) => Err(error),
            };
            match confirmed {
                Ok(confirmed) => {
                    confirmed.commit();
                    break;
                }
                Err(error) => {
                    let pending: Vec<_> = self
                        .lock()
                        .pending
                        .values()
                        .filter(|pending| pending.own && pending.entry.writer == self.node)
                        .cloned()
                        .collect();
                    let mut retry_original = false;
                    for held in pending {
                        let flow = held.flow.lock().await;
                        retry_original |= flow.plan.is_some()
                            && flow.boot_progress == BootNativeProgress::PendingOriginal;
                    }
                    if !retry_original {
                        self.loaded.store(false, Ordering::Release);
                        return Err(error);
                    }
                    // Continue this boot's actual owner; configuration and operation
                    // identities remain fixed, and no global owner is rebound.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        self.start_background()?;
        Ok(())
    }
    pub async fn apply(self: &Arc<Self>, card: &CardFields, origin: &str) -> Option<EntryKey> {
        Some(
            self.prepare(card, origin)
                .await
                .ok()?
                .confirm_activation()
                .await
                .ok()?
                .commit(),
        )
    }
    pub async fn prepare(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
    ) -> Result<PreparedCard, String> {
        self.prepare_with(card, origin, false).await
    }
    pub async fn prepare_recovery(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
    ) -> Result<PreparedCard, String> {
        self.prepare_with(card, origin, true).await
    }
    async fn prepare_with(
        self: &Arc<Self>,
        card: &CardFields,
        origin: &str,
        recovery: bool,
    ) -> Result<PreparedCard, String> {
        if !self.is_loaded() {
            return Err("the rate-card history is not loaded".into());
        }
        {
            let mut state = self.lock();
            if state.preparing {
                return Err("a rate-card preparation is already in progress".into());
            }
            state.preparing = true;
        }
        let mut prepared = PreparedCard {
            book: self.clone(),
            key: None,
            owns_lease: true,
        };
        loop {
            let pending = self
                .lock()
                .pending
                .values()
                .rev()
                .find(|pending| pending.own && pending.entry.writer == self.node)
                .cloned();
            let Some(pending) = pending else {
                break;
            };
            if pending.entry.card == *card {
                let mut flow = pending.flow.lock().await;
                self.resolve_current(&pending, &mut flow).await?;
                if !matches!(flow.phase, Some(Phase::Retiring | Phase::Retired)) {
                    self.drive(&pending, &mut flow, Operation::Prepare).await?;
                    prepared.key = Some(pending.entry.key);
                    return Ok(prepared);
                }
            }
            if !recovery {
                return Err(format!(
                    "rate-card entry {} remains pending; retry its exact configuration or explicitly reload for recovery",
                    pending.entry.key
                ));
            }
            let mut flow = pending.flow.lock().await;
            self.resolve_current(&pending, &mut flow).await?;
            self.drive(&pending, &mut flow, Operation::Prepare).await?;
            if flow.activation.is_some()
                && !matches!(flow.phase, Some(Phase::Retiring | Phase::Retired))
            {
                if flow.phase == Some(Phase::Prepared) {
                    self.drive(&pending, &mut flow, Operation::AuthorizeActivation)
                        .await?;
                }
                self.drive(&pending, &mut flow, Operation::Activate).await?;
                // Keep the older confirmed activation unpublished until the
                // superseding generation commits, preserving the old barrier.
                break;
            }
            self.drive(&pending, &mut flow, Operation::AuthorizeRetirement)
                .await?;
            self.drive(&pending, &mut flow, Operation::Retire).await?;
            self.lock().pending.remove(&pending.entry.key);
        }
        let pending = {
            let mut state = self.lock();
            let previous = state
                .pending
                .values()
                .rev()
                .find(|pending| pending.own && pending.entry.writer == self.node)
                .map(|pending| pending.entry.clone())
                .or_else(|| {
                    state
                        .own
                        .and_then(|key| state.snapshot.entries.get(&key).cloned())
                })
                .or_else(|| {
                    let history = state.snapshot.history(self.rates);
                    history
                        .current()
                        .entry_at(now_ms())
                        .and_then(|entry| state.snapshot.entries.get(&entry.key()).cloned())
                });
            if let Some(previous) = previous
                .as_ref()
                .filter(|entry| entry.card == *card && !state.pending.contains_key(&entry.key))
            {
                prepared.key = Some(previous.key);
                return Ok(prepared);
            }
            let opening = state.snapshot.entries.is_empty() && previous.is_none();
            let now = now_ms();
            let entry = StoredEntry {
                key: self.next_key(&state),
                effective_from: if opening { 0 } else { now },
                effective_until: None,
                appended_at: now,
                author: if opening {
                    EntryAuthor::Opening {}
                } else {
                    EntryAuthor::Change
                },
                actor: origin.into(),
                base: previous.as_ref().map(|entry| entry.key),
                writer: self.node,
                set_fields: previous
                    .as_ref()
                    .map(|entry| entry.card.differing_fields(card))
                    .unwrap_or_default(),
                card: card.clone(),
                correction: None,
            };
            let pending = Arc::new(Pending::new(entry, true));
            state.pending.insert(pending.entry.key, pending.clone());
            pending
        };
        {
            let mut flow = pending.flow.lock().await;
            self.drive(&pending, &mut flow, Operation::Prepare).await?;
        }
        prepared.key = Some(pending.entry.key);
        Ok(prepared)
    }
    pub async fn amend(
        self: &Arc<Self>,
        from: u64,
        until: u64,
        card: CardFields,
        reason_hash: [u8; 32],
        actor: &str,
    ) -> Result<EntryKey, String> {
        let base = self.card_at(from).map(|(key, _)| key);
        self.amend_from((from, until), base, card, reason_hash, actor)
            .await
    }
    pub async fn amend_from(
        self: &Arc<Self>,
        window: (u64, u64),
        base: Option<EntryKey>,
        card: CardFields,
        reason_hash: [u8; 32],
        actor: &str,
    ) -> Result<EntryKey, String> {
        if !self.is_loaded() {
            return Err("the rate-card history is not loaded".into());
        }
        let (from, until) = window;
        let author = EntryAuthor::Amend {
            reason: hex::encode(reason_hash),
        };
        let pending = {
            let mut state = self.lock();
            let matches = |entry: &StoredEntry| {
                entry.writer == self.node
                    && entry.effective_from == from
                    && entry.effective_until == Some(until)
                    && entry.base == base
                    && entry.card == card
                    && entry.actor == actor
                    && entry.author == author
            };
            if let Some(entry) = state.snapshot.entries.values().rev().find(|entry| {
                matches(entry)
                    && !state
                        .snapshot
                        .voids
                        .iter()
                        .any(|record| record.voided == entry.key.hex())
            }) {
                return Ok(entry.key);
            }
            if let Some(pending) = state
                .pending
                .values()
                .find(|pending| !pending.own && matches(&pending.entry))
            {
                pending.clone()
            } else {
                let entry = StoredEntry {
                    key: self.next_key(&state),
                    effective_from: from,
                    effective_until: Some(until),
                    appended_at: now_ms(),
                    author,
                    actor: actor.into(),
                    base,
                    writer: self.node,
                    set_fields: Vec::new(),
                    card,
                    correction: None,
                };
                let pending = Arc::new(Pending::new(entry, false));
                state.pending.insert(pending.entry.key, pending.clone());
                pending
            }
        };
        {
            let mut flow = pending.flow.lock().await;
            self.drive(&pending, &mut flow, Operation::Prepare).await?;
        }
        let mut state = self.lock();
        state
            .snapshot
            .entries
            .insert(pending.entry.key, pending.entry.clone());
        state.pending.remove(&pending.entry.key);
        self.publish(&state);
        self.check_alarms(&mut state);
        Ok(pending.entry.key)
    }
    pub async fn void(&self, key: EntryKey, actor: &str) -> Result<(), String> {
        let pending = {
            let mut state = self.lock();
            if state
                .snapshot
                .voids
                .iter()
                .any(|record| record.voided == key.hex())
            {
                return Ok(());
            }
            state
                .voiding
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(PendingVoid {
                        record: VoidRecord {
                            voided: key.hex(),
                            voider: self.node,
                            at_ms: now_ms(),
                            actor: actor.into(),
                            why: "void".into(),
                        },
                        plan: tokio::sync::Mutex::new(None),
                    })
                })
                .clone()
        };
        let mut held = pending.plan.lock().await;
        if held.is_none() {
            *held = Some(
                self.store
                    .prices()
                    .void(pending.record.clone(), now_ms())
                    .await
                    .map_err(error)?,
            );
        }
        match self
            .store
            .prices()
            .submit(held.as_mut().expect("retained void plan"))
            .await
            .map_err(error)?
        {
            Outcome::Applied => {}
            outcome => {
                return Err(format!(
                    "VOID for {key} remains pending or refused: {outcome:?}"
                ));
            }
        }
        let mut state = self.lock();
        state.snapshot.voids.push(pending.record.clone());
        state.voiding.remove(&key);
        self.publish(&state);
        Ok(())
    }
    pub async fn retry_pending(&self) -> Result<(), String> {
        let pending: Vec<_> = self.lock().pending.values().cloned().collect();
        for pending in pending {
            let mut flow = pending.flow.lock().await;
            self.resolve_current(&pending, &mut flow).await?;
            self.drive(&pending, &mut flow, Operation::Prepare).await?;
            if !pending.own && flow.phase == Some(Phase::Active) {
                let mut state = self.lock();
                state
                    .snapshot
                    .entries
                    .insert(pending.entry.key, pending.entry.clone());
                state.pending.remove(&pending.entry.key);
                self.publish(&state);
            }
        }
        let voids: Vec<_> = self
            .lock()
            .voiding
            .iter()
            .map(|(key, pending)| (*key, pending.record.actor.clone()))
            .collect();
        for (key, actor) in voids {
            self.void(key, &actor).await?;
        }
        Ok(())
    }
    /// Stop maintenance without discarding any semantic candidate or recovered intent.
    /// The retained handle survives cancellation of this waiter.
    pub async fn stop_background(&self) -> Result<(), String> {
        let mut task = self.background.lock().await;
        if let Some(handle) = task.as_mut() {
            handle.abort();
            let result = match handle.await {
                Ok(()) => Ok(()),
                Err(error) if error.is_cancelled() => Ok(()),
                Err(_) => Err("price maintenance task failed".into()),
            };
            *task = None;
            return result;
        }
        Ok(())
    }

    fn start_background(self: &Arc<Self>) -> Result<(), String> {
        let mut task = self
            .background
            .try_lock()
            .map_err(|_| "price maintenance is stopping".to_string())?;
        if task.is_some() {
            return Ok(());
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "price history requires its async runtime")?;
        let weak: Weak<Self> = Arc::downgrade(self);
        let handle = runtime.spawn(async move {
            loop {
                tokio::time::sleep(RESCAN_INTERVAL).await;
                let Some(book) = weak.upgrade() else {
                    return;
                };
                match tokio::time::timeout(RESCAN_INTERVAL, book.retry_pending()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::warn!("{error}"),
                    Err(_) => {
                        tracing::warn!("price retry timed out; original native plans retained")
                    }
                }
                match tokio::time::timeout(RESCAN_INTERVAL, book.rescan(None)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => tracing::warn!("{error}"),
                    Err(_) => tracing::warn!("price history rescan timed out"),
                }
            }
        });
        *task = Some(handle);
        Ok(())
    }
}

impl crate::rate_apply::PreparedRates for PreparedCard {
    fn confirm_activation(
        self: Box<Self>,
    ) -> crate::rate_apply::RateFuture<
        'static,
        Result<Box<dyn crate::rate_apply::RateCommit>, String>,
    > {
        Box::pin(async move {
            (*self)
                .confirm_activation()
                .await
                .map(|confirmed| Box::new(confirmed) as Box<dyn crate::rate_apply::RateCommit>)
        })
    }
}
impl crate::rate_apply::RateCommit for ConfirmedCard {
    fn commit(self: Box<Self>) {
        ConfirmedCard::commit(*self);
    }
}
