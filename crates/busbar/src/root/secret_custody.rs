// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret kind on the MIN-3 path (HOST M3a; IF §11.3, §12.2): immutable prefixes of opened instances,
//! by configured name, and custody bound to each prefix. A secret reference `{module, settings}` names a
//! configured secret instance; custody reaches it through its `SecretPort` and hands the plugin the
//! reference's `settings` only, never its `module` (I2).

use std::sync::Arc;
use std::time::Instant;

use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::{
    Custody, CustodyDenied, CustodyEvent, CustodyHost, CustodyKey, HeldView, Leased, RoundValues,
    SecretCustody, SecretSource,
};
use busbar_kernel::plugin_config::{ConfigBinder, RefSource};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::scrub::Scrub;
#[cfg(test)]
use busbar_ports::secret::SecretPort;
use busbar_ports::CallCx;
use foldhash::HashMap;

/// An immutable prefix of successfully opened secret instances. Cloning retains exactly these ports;
/// a later prefix never changes what an earlier per-open Needs can resolve.
#[derive(Clone, Default)]
struct SecretView {
    open: Arc<HashMap<Box<str>, SecretSource>>,
}

impl SecretView {
    fn appended(&self, name: &str, source: SecretSource) -> Result<Self, CustodyDenied> {
        if name.is_empty()
            || source.instance == 0
            || self.open.contains_key(name)
            || self
                .open
                .values()
                .any(|existing| existing.instance == source.instance)
        {
            return Err(CustodyDenied::Denied);
        }
        let mut open = (*self.open).clone();
        open.insert(Box::from(name), source);
        Ok(Self {
            open: Arc::new(open),
        })
    }

    #[cfg(test)]
    fn without(&self, name: &str) -> Self {
        let mut open = (*self.open).clone();
        open.remove(name);
        Self {
            open: Arc::new(open),
        }
    }

    fn get(&self, name: &str) -> Option<SecretSource> {
        self.open.get(name).cloned()
    }
}

/// What custody reads from the process: the open secret instances, plugin-facing bindings (`ConfigBinder::secret`,
/// §12.7) and instance scrub sets (§10.6).
pub(crate) struct Host {
    view: SecretView,
    binder: Arc<dyn ConfigBinder>,
    slots: Arc<busbar_plugin_loader::instance::SlotTable>,
    rotations: Arc<Rotations>,
}

impl CustodyHost for Host {
    fn binding(&self, key: CustodyKey) -> Option<SecretRef> {
        self.binder.secret(key.instance, key.handle)
    }

    fn scrub(&self, who: &busbar_plugin_abi::host_side::caller::Caller<'_>) -> Option<Arc<Scrub>> {
        self.slots.scrub_of(who.slot)
    }

    fn source(&self, module: &str) -> Option<SecretSource> {
        self.view.get(module)
    }

    fn audit(
        &self,
        who: &busbar_plugin_abi::host_side::caller::Caller<'_>,
        handle: u32,
        event: CustodyEvent,
    ) {
        let row = match event {
            CustodyEvent::HandleForeign => "secret_handle_foreign",
            CustodyEvent::TooShortToScrub => "secret_too_short_to_scrub",
            CustodyEvent::Resolved => "secret_resolve",
        };
        tracing::info!(
            target: "busbar::audit",
            event = row,
            kind = ?who.kind,
            instance = who.name,
            handle,
        );
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    /// DES-454 §2.1: an unleased handle is a rotation subscriber; a leased one rotates through the lease path.
    fn published(
        &self,
        who: &Caller<'_>,
        handle: u32,
        binding: &SecretRef,
        until: Option<Instant>,
    ) {
        if until.is_some() {
            return;
        }
        let Some((_, _, alive)) = self.slots.owner(who.slot) else {
            return;
        };
        self.rotations.subscribe(
            who.kind,
            who.name,
            who.instance,
            At::Handle(handle),
            binding,
            alive,
            until,
        );
    }
}

/// One immutable secret prefix and its custody. Owned by the per-open Needs that captures it.
pub(crate) struct BootSecrets {
    view: SecretView,
    binder: Arc<dyn ConfigBinder>,
    slots: Arc<busbar_plugin_loader::instance::SlotTable>,
    custody: Custody<Host>,
    rotations: Arc<Rotations>,
}

impl BootSecrets {
    /// Synchronous configuration readers dispatch resolution onto the owned I/O executor,
    /// which keeps progressing even when the reader runs on a current-thread runtime.
    pub(crate) fn resolver(
        self: &Arc<Self>,
        runtime: tokio::runtime::Handle,
        sugars: busbar_contract::secret_ref::Sugars,
    ) -> Arc<busbar_kernel::config::secret::SecretResolver> {
        // The kernel's secret axis resolves through the same prefix (WP3 step 2): the latest resolver's.
        super::native_secrets::NATIVE.publish_opened(self, runtime.clone());
        let prefix = Arc::clone(self);
        let resolver = busbar_kernel::config::secret::SecretResolver::with_scoped_plugin(Box::new(
            move |module, settings, _scope| {
                let reference = SecretRef::Source(busbar_contract::secret_ref::SourceReference {
                    module: module.to_owned(),
                    settings: settings.clone(),
                });
                prefix.resolve_blocking(&runtime, reference)
            },
        ));
        Arc::new(resolver.with_sources(sugars))
    }

    /// One reference, resolved for a synchronous reader: dispatched onto `runtime` (the owned I/O executor, which
    /// progresses even when the reader runs on a current-thread runtime) and awaited up to the core secret
    /// deadline. A refusal names no source and carries no value.
    pub(crate) fn resolve_blocking(
        self: &Arc<Self>,
        runtime: &tokio::runtime::Handle,
        reference: SecretRef,
    ) -> Result<
        busbar_contract::redacted::Secret<Vec<u8>>,
        busbar_kernel::config::secret::SecretRefused,
    > {
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let deadline = Instant::now() + super::min3_boot::CORE_SECRET_DEADLINE;
        let prefix = Arc::clone(self);
        let task = runtime.spawn(async move {
            let result = prefix.resolve_ref(deadline, &reference).await;
            let _ = send.send(result);
        });
        let result = receive.recv_timeout(super::min3_boot::CORE_SECRET_DEADLINE);
        task.abort();
        match result {
            Ok(Ok(value)) => Ok(busbar_contract::redacted::Secret::new(value.into_vec())),
            _ => Err(busbar_kernel::config::secret::SecretRefused {
                error_kind: busbar_contract::abi::secret::ERROR_KIND_INTERNAL,
                text: "the configured secret source did not resolve".to_owned(),
            }),
        }
    }

    /// The complete empty prefix exists before the first secret open; it refuses forward references.
    pub(crate) fn empty(
        binder: Arc<dyn ConfigBinder>,
        slots: Arc<busbar_plugin_loader::instance::SlotTable>,
    ) -> Arc<Self> {
        Self::from_view(binder, slots, SecretView::default())
    }

    fn from_view(
        binder: Arc<dyn ConfigBinder>,
        slots: Arc<busbar_plugin_loader::instance::SlotTable>,
        view: SecretView,
    ) -> Arc<Self> {
        let rotations = Arc::new(Rotations::default());
        let custody = Custody::new(Host {
            view: view.clone(),
            binder: Arc::clone(&binder),
            slots: Arc::clone(&slots),
            rotations: Arc::clone(&rotations),
        });
        let secrets = Arc::new(Self {
            view,
            binder,
            slots,
            custody,
            rotations,
        });
        let _ = secrets.rotations.prefix.set(Arc::downgrade(&secrets));
        secrets
    }

    /// Extend after a successful reserved open. Existing Needs keep their old prefix and cache;
    /// the successor has fresh custody and cannot inherit a cached answer for a changed source.
    pub(crate) fn with_opened(
        self: &Arc<Self>,
        name: &str,
        source: SecretSource,
    ) -> Result<Arc<Self>, CustodyDenied> {
        Ok(Self::from_view(
            Arc::clone(&self.binder),
            Arc::clone(&self.slots),
            self.view.appended(name, source)?,
        ))
    }

    /// Construct effective-generation custody over the same immutable source leases and process slots.
    /// Existing bootstrap instances keep their original binder, prefix and cached handle answers.
    pub(crate) fn with_binder(self: &Arc<Self>, binder: Arc<dyn ConfigBinder>) -> Arc<Self> {
        Self::from_view(binder, Arc::clone(&self.slots), self.view.clone())
    }

    /// A candidate retirement removes a source only from the returned view; an already captured prefix
    /// remains valid until its owning instance is retired and drops it.
    #[cfg(test)]
    pub(crate) fn without(self: &Arc<Self>, name: &str) -> Arc<Self> {
        Self::from_view(
            Arc::clone(&self.binder),
            Arc::clone(&self.slots),
            self.view.without(name),
        )
    }

    #[cfg(test)]
    pub(crate) fn port(&self, name: &str) -> Option<Arc<dyn SecretPort>> {
        self.view.get(name).map(|source| source.port)
    }

    /// A kernel-internal secret (admin token, signing key, mTLS material): by reference, with an
    /// empty call stack. Errors carry no source name and no text (§12.2 step 4).
    pub(crate) async fn resolve_ref(
        &self,
        deadline: Instant,
        reference: &SecretRef,
    ) -> Result<SecureVec, CustodyDenied> {
        let cx = CallCx {
            deadline,
            request_id: 0,
            stack: Default::default(),
        };
        self.custody
            .resolve_ref(cx, reference)
            .await
            .map(|leased| leased.value)
    }
}

/// The custody the Need handlers own: the immutable prefix captured for that specific open.
#[derive(Clone)]
pub(crate) struct BootCustody(pub(crate) Arc<BootSecrets>);

impl SecretCustody for BootCustody {
    fn resolve(
        &self,
        who: &Caller<'_>,
        handle: u32,
    ) -> impl core::future::Future<Output = Result<Arc<SecureVec>, CustodyDenied>> + Send {
        self.0.custody.resolve(who, handle)
    }

    fn generation(&self, who: &Caller<'_>, handle: u32) -> u64 {
        self.0.custody.generation(who, handle)
    }

    fn resolve_ref<'a>(
        &'a self,
        cx: CallCx,
        r: &'a SecretRef,
    ) -> BoxFut<'a, Result<Leased, CustodyDenied>> {
        self.0.custody.resolve_ref(cx, r)
    }

    fn seed(&self, instance: u64, values: RoundValues) {
        self.0.custody.seed(instance, values);
    }

    fn unseed(&self, instance: u64) {
        self.0.custody.unseed(instance);
    }

    fn held(&self, instance: u64, handle: u32) -> Option<HeldView> {
        self.0.custody.held(instance, handle)
    }
}

/// Complete reference authority for one open: the immutable secret prefix and process slot table.
pub(crate) struct BootRefs(pub(crate) Arc<BootSecrets>);

impl BootSecrets {
    pub(crate) fn refs(self: &Arc<Self>) -> Arc<dyn RefSource> {
        Arc::new(BootRefs(Arc::clone(self)))
    }
}

impl RefSource for BootRefs {
    fn resolve<'a>(
        &'a self,
        instance: u64,
        slot: u32,
        binding: u32,
        reference: &'a SecretRef,
    ) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async move {
            if instance == 0 {
                return None;
            }
            let scrub_handle = binding.checked_add(0x8000_0000)?;
            let scrub = self.0.slots.scrub_of(slot)?;
            let leased = self
                .0
                .custody
                .resolve_ref(
                    CallCx {
                        deadline: Instant::now() + super::min3_boot::CORE_SECRET_DEADLINE,
                        request_id: 0,
                        stack: Default::default(),
                    },
                    reference,
                )
                .await
                .ok()?;
            // Reference bindings cannot overwrite the ordinary SECRET handles or each other.
            scrub.register(scrub_handle, &[leased.value.as_slice()]);
            // DES-454 §2.1: every D_REF_PATH binding is a rotation subscriber of each source it reads.
            if let Some((kind, name, alive)) = self.0.slots.owner(slot) {
                self.0.rotations.subscribe(
                    kind,
                    &name,
                    instance,
                    At::Ref(binding),
                    reference,
                    alive,
                    leased.until,
                );
            }
            Some(leased.value)
        })
    }
}

#[cfg(test)]
#[path = "tests/secret_switch_over.rs"]
mod tests;

/// Where a subscriber holds its source's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// A D_REF_PATH binding, by ordinal: compared with the binder's committed digest.
    Ref(u32),
    /// An unleased D_SECRET_PATH handle: compared with custody's published digest.
    Handle(u32),
}

/// DES-454 §2.1: one custody's rotation items, by source id, and the per-instance latches (§2.4).
#[derive(Default)]
pub(crate) struct Rotations {
    prefix: std::sync::OnceLock<std::sync::Weak<BootSecrets>>,
    items: std::sync::Mutex<HashMap<[u8; 32], Arc<busbar_kernel::rotation::Item>>>,
    latches: std::sync::Mutex<HashMap<u64, Arc<std::sync::Mutex<()>>>>,
}

impl Rotations {
    /// Subscribe `instance`'s binding of `reference` to the item of each source it reads. A new instance under
    /// a label clears that label's rotation report (the reload or restart that took the value).
    #[allow(clippy::too_many_arguments)]
    fn subscribe(
        &self,
        kind: busbar_plugin_abi::types::KindCode,
        name: &str,
        instance: u64,
        at: At,
        reference: &SecretRef,
        alive: std::sync::Weak<Scrub>,
        until: Option<Instant>,
    ) {
        let Some(prefix) = self.prefix.get().cloned() else {
            return;
        };
        let label = format!("{}.{name}", kind.word());
        let latch = {
            let mut latches = lock(&self.latches);
            latches.retain(|_, latch| Arc::strong_count(latch) > 1);
            if !latches.contains_key(&instance) {
                busbar_kernel::rotation::opened(&label);
            }
            Arc::clone(latches.entry(instance).or_default())
        };
        let subscriber: Arc<dyn busbar_kernel::rotation::Subscriber> = Arc::new(Bound {
            label,
            kind,
            instance,
            at,
            reference: reference.clone(),
            alive,
            prefix: prefix.clone(),
            latch,
        });
        let now = Instant::now();
        let mut items = lock(&self.items);
        items.retain(|_, item| item.live());
        for source in sources_of(reference) {
            let Some(id) = busbar_kernel::custody::source_id(&source) else {
                continue;
            };
            if let Some(item) = items.get(&id) {
                item.subscribe(Arc::clone(&subscriber));
                continue;
            }
            let Some(item) = busbar_kernel::rotation::Item::new(
                source,
                Arc::new(CustodyReader(prefix.clone())),
                busbar_kernel::rotation::process_pool(),
                &busbar_kernel::refresh::HOST_REPORT,
            ) else {
                continue;
            };
            item.subscribe(Arc::clone(&subscriber));
            let weak = Arc::downgrade(&item);
            busbar_kernel::refresh::keep(
                weak,
                busbar_kernel::rotation::due(now, until, busbar_kernel::retry::unit()),
            );
            items.insert(id, item);
        }
    }

    /// A config apply: every item of this custody polls now (I4).
    pub(crate) fn due_now(&self) {
        let items: Vec<_> = lock(&self.items).values().cloned().collect();
        for item in &items {
            item.due_now();
        }
        busbar_kernel::refresh::process().due_now(&|kept| {
            items
                .iter()
                .any(|item| std::ptr::addr_eq(Arc::as_ptr(kept), Arc::as_ptr(item)))
        });
    }
}

impl BootSecrets {
    /// A config apply re-reads every source a running instance holds (DES-454 §2.2 step 1, I4).
    pub(crate) fn rotate_now(&self) {
        self.rotations.due_now();
    }
}

/// The source references `reference` reads: itself, or each fill of a template.
fn sources_of(reference: &SecretRef) -> Vec<busbar_contract::secret_ref::SourceReference> {
    if let Some(source) = reference.source() {
        return vec![source.clone()];
    }
    let wanted = std::cell::RefCell::new(Vec::new());
    let asked = |fill: &SecretRef| -> Result<busbar_contract::Secret<String>, CustodyDenied> {
        if let Some(source) = fill.source() {
            wanted.borrow_mut().push(source.clone());
        }
        Ok(busbar_contract::Secret::new(String::new()))
    };
    let _ = reference.resolve_template_typed(&asked);
    wanted.into_inner()
}

/// Run `work` on the owned I/O executor and wait for it until `deadline` (the rotation pool's blocking call).
fn run_until<T: Send + 'static>(
    deadline: Instant,
    work: impl core::future::Future<Output = T> + Send + 'static,
) -> Option<T> {
    let runtime = super::native_secrets::NATIVE.runtime()?;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let task = runtime.spawn(async move {
        let _ = send.send(work.await);
    });
    let result = receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok();
    task.abort();
    result
}

fn kernel_cx(deadline: Instant) -> CallCx {
    CallCx {
        deadline,
        request_id: 0,
        stack: Default::default(),
    }
}

/// An item's reads: through the subscriber custody's own `resolve_ref`, so its leased source cache is shared.
struct CustodyReader(std::sync::Weak<BootSecrets>);

impl busbar_kernel::rotation::Reader for CustodyReader {
    fn read(
        &self,
        source: &busbar_contract::secret_ref::SourceReference,
        deadline: Instant,
    ) -> Result<Leased, CustodyDenied> {
        let prefix = self.0.upgrade().ok_or(CustodyDenied::Unavailable)?;
        let reference = SecretRef::Source(source.clone());
        run_until(deadline, async move {
            prefix
                .custody
                .resolve_ref(kernel_cx(deadline), &reference)
                .await
        })
        .unwrap_or(Err(CustodyDenied::Unavailable))
    }
}

/// One instance binding subscribed to rotation.
struct Bound {
    label: String,
    kind: busbar_plugin_abi::types::KindCode,
    instance: u64,
    at: At,
    reference: SecretRef,
    alive: std::sync::Weak<Scrub>,
    prefix: std::sync::Weak<BootSecrets>,
    latch: Arc<std::sync::Mutex<()>>,
}

impl busbar_kernel::rotation::Subscriber for Bound {
    fn label(&self) -> &str {
        &self.label
    }

    fn alive(&self) -> bool {
        self.alive.strong_count() > 0 && self.prefix.strong_count() > 0
    }

    /// PM D1: no non-export kind is refreshed in place in 1.6.0. Every plugin store reopen needs a restart
    /// (`Registry::reopen`), so a store says `restart-required`.
    fn action(&self) -> busbar_kernel::rotation::Action {
        use busbar_kernel::rotation::Action;
        match self.kind {
            busbar_plugin_abi::types::KindCode::Store => Action::Restart,
            _ => Action::Reload,
        }
    }

    fn differs(&self, round: &RoundValues) -> Result<bool, busbar_contract::secret::RelendCause> {
        use busbar_contract::secret::RelendCause;
        let prefix = self.prefix.upgrade().ok_or(RelendCause::Unresolvable)?;
        let deadline = Instant::now() + super::min3_boot::CORE_SECRET_DEADLINE;
        let (reference, round_owned) = (self.reference.clone(), round.clone());
        let resolver = Arc::clone(&prefix);
        let value = run_until(deadline, async move {
            resolver
                .custody
                .resolve_with(kernel_cx(deadline), &reference, &round_owned)
                .await
        })
        .ok_or(RelendCause::Unresolvable)?
        .map_err(|_| RelendCause::Unresolvable)?
        .value;
        match self.at {
            At::Ref(binding) => {
                let text = core::str::from_utf8(value.as_slice())
                    .map_err(|_| RelendCause::Unresolvable)?;
                let committed = prefix
                    .binder
                    .committed(self.instance)
                    .and_then(|digests| digests.get(usize::try_from(binding).ok()?).copied());
                Ok(committed.is_some_and(|committed| {
                    committed != busbar_contract::crypto::sha256(text.as_bytes())
                }))
            }
            At::Handle(handle) => {
                Ok(prefix
                    .custody
                    .held(self.instance, handle)
                    .is_some_and(|held| {
                        held.digest != busbar_contract::crypto::sha256_parts(&[value.as_slice()])
                    }))
            }
        }
    }

    fn swap(&self, _round: &RoundValues) -> Result<(), busbar_contract::secret::RelendCause> {
        // `action` never answers Swap for this binding.
        Err(busbar_contract::secret::RelendCause::ReopenFailed)
    }

    fn latch(&self) -> &std::sync::Mutex<()> {
        &self.latch
    }
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
