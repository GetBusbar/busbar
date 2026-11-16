// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only durable ownership. A signing key change does not rename an existing caller's
//! protected records. This mapping is never writable through a plugin record namespace.

use super::*;
use crate::persistence::scoped::{Outcome, Request, ScopedStore};
use busbar_contract::Secret;

pub(super) const CALLERS: &str = "kernel-caller-bindings";

/// Recovered work items handed back per poll.
const RECOVERY_BATCH: usize = 8;

type ActiveWork = Arc<Mutex<foldhash::HashSet<(Arc<str>, crate::host_work::Reference)>>>;

#[derive(Default)]
pub(super) struct RecoveryRuntime {
    ready: std::sync::atomic::AtomicBool,
    scan: tokio::sync::Mutex<foldhash::HashMap<Arc<str>, ScanState>>,
    active: ActiveWork,
    /// One caller-binding store handle per opened instance, bound on its first use.
    callers: Mutex<foldhash::HashMap<Arc<str>, Arc<ScopedStore>>>,
}

#[derive(Default)]
struct ScanState {
    cursor: Option<crate::persistence::scoped::Cursor>,
    pending: std::collections::VecDeque<(Vec<u8>, Secret<Vec<u8>>)>,
}

/// A host-restored live work item. Only a confirmed private work row can construct this.
pub struct RecoveryWork {
    instance: Arc<str>,
    reference: crate::host_work::Reference,
    binding: crate::host_work::RecoveryBinding,
    target: String,
    active: ActiveWork,
}

impl Drop for RecoveryWork {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(self.instance.clone(), self.reference));
    }
}

impl RecoveryWork {
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn reference(&self) -> String {
        reference_text(&self.reference)
    }
    /// Re-resolve standing from the current authoritative identity book. Rotation of a signing
    /// key preserves this binding; deletion, disablement, expiry, or identity reissue does not.
    pub fn restore(
        &self,
        gov: &crate::governance::GovState,
        now: u64,
    ) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        if self.binding.expires_at.is_some_and(|at| at <= now) {
            return None;
        }
        if gov.is_revoked_at(&self.binding.principal, now) {
            return None;
        }
        let key = gov.lookup_by_sub(&self.binding.principal)?;
        (key.enabled
            && key.deleted_at.is_none()
            && key.created_at == self.binding.created_at
            && key.generation_hash == self.binding.generation
            && !key.expires_at.is_some_and(|at| at <= now))
        .then_some(key)
    }

    pub fn restore_for_app(
        &self,
        app: &crate::state::App,
        now: u64,
    ) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        let gov = app.governance.as_deref()?;
        if self
            .binding
            .generation
            .starts_with(crate::governance::PRINCIPAL_MARKER_PREFIX)
        {
            if gov.is_revoked_at(&self.binding.principal, now) {
                return None;
            }
            return self.restore_bound(&app.role_bindings, now);
        }
        self.restore(gov, now)
    }

    fn restore_bound(
        &self,
        bindings: &crate::config::RoleBindings,
        now: u64,
    ) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        let expires_at = self.binding.expires_at.filter(|at| *at > now)?;
        let captured = busbar_contract::records::VirtualKey {
            id: self.binding.principal.clone(),
            generation_hash: self.binding.generation.clone(),
            ..Default::default()
        };
        let (module, principal) = crate::governance::bound_admission(&captured)?;
        let mut key = crate::governance::synthesize_bound_key(&module, &principal, bindings)?;
        Arc::make_mut(&mut key).expires_at = Some(expires_at);
        Some(key)
    }
}

/// The process-local set of work rows a recovery session holds, for a work custody outside the admitted
/// instances (the MIN-3 plane instances' `plane_driver::port_work::StoreWork`): an entry leaves the set when its
/// [`RecoveryWork`] drops, so one row is polled by at most one session per process (IF §12.24 step 3).
#[derive(Clone, Default)]
pub struct ActiveSet(ActiveWork);

impl ActiveSet {
    /// Takes `reference` of `instance` for one recovery session; false when one already holds it.
    pub(crate) fn claim(
        &self,
        instance: &Arc<str>,
        reference: crate::host_work::Reference,
    ) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((Arc::clone(instance), reference))
    }

    /// The recovery item of a claimed row: it releases the claim when it drops.
    pub(crate) fn item(
        &self,
        instance: Arc<str>,
        reference: crate::host_work::Reference,
        binding: crate::host_work::RecoveryBinding,
        target: String,
    ) -> RecoveryWork {
        RecoveryWork {
            instance,
            reference,
            binding,
            target,
            active: Arc::clone(&self.0),
        }
    }
}

impl KernelServices {
    /// Composition-root scheduler lifetime, never a plugin callable service.
    pub fn set_recovery_scheduler_ready(&self, ready: bool) {
        self.recovery
            .ready
            .store(ready, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn supports_work_recovery(&self) -> bool {
        self.persistence.get().is_some()
            && self
                .recovery
                .ready
                .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn supports_unit_recovery(&self, caller: &Caller, unit: u64) -> bool {
        self.supports_work_recovery()
            && self.facts(caller).is_some()
            && self.recovery_binding(Some(unit)).is_ok()
    }
    pub(super) fn capture_recovery(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        record: &[u8],
    ) -> Result<Option<crate::host_work::RecoveryBinding>, &'static str> {
        if busbar_contract::abi::sdk::recovery::poll_target(record)?.is_none() {
            return Ok(None);
        }
        if !self.supports_work_recovery() || self.facts(caller).is_none() {
            return Err("recovery requires admitted durable custody");
        }
        self.recovery_binding(unit).map(Some)
    }

    fn recovery_binding(
        &self,
        unit: Option<u64>,
    ) -> Result<crate::host_work::RecoveryBinding, &'static str> {
        let key = unit
            .and_then(|unit| self.units.get(unit))
            .and_then(|unit| unit.principal.clone())
            .ok_or("recovery requires an authenticated principal")?;
        recovery_binding_of(&key, (self.wall_ms)() / 1000, self.standing.get())
    }

    /// Scan one native Store page, retaining pagination across ticks. Only the opened instance
    /// can be selected, and each item has one process-local owner until its future is retired.
    pub(crate) async fn recovery_work(
        &self,
        caller: &Caller,
    ) -> Result<Vec<RecoveryWork>, &'static str> {
        if self.facts(caller).is_none() {
            return Err("recovery instance is not admitted");
        }
        let Some(store) = self.persistence.get() else {
            return Ok(Vec::new());
        };
        let rows = ScopedStore::host_private(
            store.clone(),
            caller.namespace(),
            [WORK_SCHEMA.as_str().into()],
        )
        .map_err(|_| "recovery namespace unavailable")?;
        let mut scans = self.recovery.scan.lock().await;
        let scan = scans.entry(caller.namespace().clone()).or_default();
        if scan.pending.is_empty() {
            let page = match rows
                .page(WORK_SCHEMA.as_str(), &[], scan.cursor.as_ref())
                .await
            {
                Ok(page) => page,
                Err(_) => {
                    scan.cursor = None;
                    return Err("recovery scan failed");
                }
            };
            scan.cursor = page.next;
            scan.pending.extend(page.rows);
        }
        // A bounded batch retains the unconsumed part of this page, so slow polls cannot
        // starve the later records by repeatedly restarting from the first work item.
        let instance = caller.namespace();
        let active = &self.recovery.active;
        Ok(crate::off_path::host_services::recovery_batch(
            instance,
            &mut scan.pending,
            RECOVERY_BATCH,
            |reference| {
                active
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert((Arc::clone(instance), reference))
            },
            |reference, binding, target| RecoveryWork {
                instance: Arc::clone(instance),
                reference,
                binding,
                target,
                active: Arc::clone(active),
            },
        ))
    }

    /// The opened instance's caller-binding store handle, bound once per instance.
    fn caller_rows(
        &self,
        store: &Arc<crate::persistence::facade::CoreStore>,
        caller: &Caller,
    ) -> Result<Arc<ScopedStore>, &'static str> {
        let mut callers = self
            .recovery
            .callers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(rows) = callers.get(caller.namespace()) {
            return Ok(Arc::clone(rows));
        }
        let rows =
            crate::cold::host::services_caller_rows(Arc::clone(store), caller.namespace(), CALLERS)
                .map_err(|_| "caller binding unavailable")?;
        let rows = Arc::new(rows);
        callers.insert(caller.namespace().clone(), Arc::clone(&rows));
        Ok(rows)
    }

    /// The durable caller reference for `principal`: the bound one when a row exists, else
    /// `proposed`, bound now. The answer reuses `proposed`'s buffer either way.
    pub(crate) async fn resolve_caller_reference(
        &self,
        caller: &Caller,
        principal: &str,
        mut proposed: String,
    ) -> Result<String, &'static str> {
        if principal.is_empty() || !valid_reference(&proposed) || self.facts(caller).is_none() {
            return Err("invalid caller binding");
        }
        let Some(store) = self.persistence.get() else {
            return Ok(proposed);
        };
        let rows = self.caller_rows(store, caller)?;
        let mut binding: Option<Request> = None;
        for _ in 0..3 {
            if let Some(saved) = rows
                .get(CALLERS, principal.as_bytes())
                .await
                .map_err(|_| "caller binding read failed")?
            {
                let seal = crate::seal::lend();
                let bound = read_reference(saved.expose(&seal)).ok_or("corrupt caller binding")?;
                if bound != proposed {
                    proposed.clear();
                    proposed.push_str(bound);
                }
                return Ok(proposed);
            }
            let op_id = store
                .next_id()
                .map_err(|_| "caller binding id unavailable")?
                .operation;
            let request = match &mut binding {
                Some(request) => {
                    request.op_id = op_id;
                    request
                }
                None => {
                    let first = crate::cold::host::services_caller_binding(
                        op_id, CALLERS, principal, &proposed,
                    );
                    binding.insert(first)
                }
            };
            match rows
                .conditional_native(request)
                .await
                .map_err(|_| "caller binding write failed")?
            {
                Outcome::Applied => return Ok(proposed),
                Outcome::ConditionConflict => continue,
                // Unconfirmed custody cannot authorize the plugin to create an index.
                _ => return Err("caller binding not durably confirmed"),
            }
        }
        Err("caller binding contention")
    }
}

/// The recovery binding governance captures for `key` at `now` (seconds): the id, generation and expiry the
/// recovery scheduler re-resolves standing from. Shared by the unit-bound `work_open` and the plane port's
/// store-backed WORK (`plane_driver::port_work`).
///
/// # Errors
/// Why the key has no recoverable standing: not a live principal, an external role with no original expiry, or no
/// current standing (none attached, or governance no longer permits it).
pub(crate) fn recovery_binding_of(
    key: &Arc<busbar_contract::records::VirtualKey>,
    now: u64,
    standing: Option<&Standing>,
) -> Result<crate::host_work::RecoveryBinding, &'static str> {
    if key.id.is_empty()
        || key.generation_hash.is_empty()
        || !key.enabled
        || key.deleted_at.is_some()
        || key.expires_at.is_some_and(|at| at <= now)
    {
        return Err("recovery requires a live principal binding");
    }
    // Suggested authentication cache TTL is not a verified credential expiration. Never
    // invent indefinite recovery authority from an external role assertion lacking it.
    if crate::governance::bound_admission(key).is_some() && key.expires_at.is_none() {
        return Err("external recovery requires the original authentication expiry");
    }
    if standing.is_none_or(|standing| standing(key, now).is_none()) {
        return Err("recovery principal has no current standing");
    }
    Ok(crate::host_work::RecoveryBinding {
        principal: key.id.clone(),
        generation: key.generation_hash.clone(),
        created_at: key.created_at,
        expires_at: key.expires_at,
    })
}

/// Decodes a stored caller binding row: exactly one valid caller reference, the same pseudonymous
/// value lent to plugins as `caller_ref`. Anything else is a corrupt row and yields nothing.
fn read_reference(row: &[u8]) -> Option<&str> {
    let reference = std::str::from_utf8(row).ok()?;
    valid_reference(reference).then_some(reference)
}

fn valid_reference(reference: &str) -> bool {
    reference.len() == 64
        && reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
#[path = "tests/host_recovery_tests.rs"]
mod tests;
