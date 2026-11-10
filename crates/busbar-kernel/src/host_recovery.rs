// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only durable ownership. A signing key change does not rename an existing caller's
//! protected records. This mapping is never writable through a plugin record namespace.

use super::*;
use crate::persistence::scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore};
use busbar_contract::Secret;

pub(super) const CALLERS: &str = "kernel-caller-bindings";

type ActiveWork = Arc<Mutex<std::collections::HashSet<(Arc<str>, crate::host_work::Reference)>>>;

#[derive(Default)]
pub(super) struct RecoveryRuntime {
    ready: std::sync::atomic::AtomicBool,
    scan: tokio::sync::Mutex<HashMap<Arc<str>, ScanState>>,
    active: ActiveWork,
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

impl KernelServices {
    /// Composition-root scheduler lifetime, never a plugin callable service.
    pub fn set_recovery_scheduler_ready(&self, ready: bool) {
        self.recovery
            .ready
            .store(ready, std::sync::atomic::Ordering::Release);
    }

    pub fn supports_work_recovery(&self) -> bool {
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
        let now = (self.wall_ms)() / 1000;
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
        if crate::governance::bound_admission(&key).is_some() && key.expires_at.is_none() {
            return Err("external recovery requires the original authentication expiry");
        }
        if self
            .standing
            .get()
            .is_none_or(|standing| standing(&key, now).is_none())
        {
            return Err("recovery principal has no current standing");
        }
        Ok(crate::host_work::RecoveryBinding {
            principal: key.id.clone(),
            generation: key.generation_hash.clone(),
            created_at: key.created_at,
            expires_at: key.expires_at,
        })
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
        let mut ready = Vec::new();
        // A bounded batch retains the unconsumed part of this page, so slow polls cannot
        // starve the later records by repeatedly restarting from the first work item.
        while ready.len() < 8 {
            let Some((reference, bytes)) = scan.pending.pop_front() else {
                break;
            };
            let Ok(reference) = crate::host_work::Reference::try_from(reference.as_slice()) else {
                continue;
            };
            let Some(work) = Work::read(
                caller.namespace(),
                reference,
                bytes.expose(&crate::seal::lend()),
            ) else {
                continue;
            };
            if !work.live {
                continue;
            }
            let Some(binding) = work.recovery else {
                continue;
            };
            let Some(target) = busbar_contract::abi::sdk::recovery::poll_target(&work.record)
                .ok()
                .flatten()
            else {
                continue;
            };
            let mut active = self
                .recovery
                .active
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if active.insert((caller.namespace().clone(), reference)) {
                ready.push(RecoveryWork {
                    instance: caller.namespace().clone(),
                    reference,
                    binding,
                    target: target.into(),
                    active: self.recovery.active.clone(),
                });
            }
        }
        Ok(ready)
    }

    pub(crate) async fn resolve_caller_reference(
        &self,
        caller: &Caller,
        principal: &str,
        proposed: &str,
    ) -> Result<String, &'static str> {
        if principal.is_empty() || !valid_reference(proposed) || self.facts(caller).is_none() {
            return Err("invalid caller binding");
        }
        let Some(store) = self.persistence.get() else {
            return Ok(proposed.to_owned());
        };
        let rows =
            ScopedStore::host_private(store.clone(), caller.namespace(), [CALLERS.to_string()])
                .map_err(|_| "caller binding unavailable")?;
        for _ in 0..3 {
            if let Some(saved) = rows
                .get(CALLERS, principal.as_bytes())
                .await
                .map_err(|_| "caller binding read failed")?
            {
                let seal = crate::seal::lend();
                let reference = std::str::from_utf8(saved.expose(&seal))
                    .map_err(|_| "corrupt caller binding")?;
                return valid_reference(reference)
                    .then(|| reference.to_owned())
                    .ok_or("corrupt caller binding");
            }
            let request = Request {
                op_id: store
                    .next_id()
                    .map_err(|_| "caller binding id unavailable")?
                    .operation,
                predicates: vec![Predicate {
                    schema: CALLERS.into(),
                    key: principal.as_bytes().to_vec(),
                    expected: Expected::Absent,
                }],
                mutations: vec![Mutation::Put {
                    schema: CALLERS.into(),
                    key: principal.as_bytes().to_vec(),
                    value: Secret::new(proposed.as_bytes().to_vec()),
                }],
            };
            match rows
                .conditional_native(&request)
                .await
                .map_err(|_| "caller binding write failed")?
            {
                Outcome::Applied => return Ok(proposed.to_owned()),
                Outcome::ConditionConflict => continue,
                // Unconfirmed custody cannot authorize the plugin to create an index.
                _ => return Err("caller binding not durably confirmed"),
            }
        }
        Err("caller binding contention")
    }
}

fn valid_reference(reference: &str) -> bool {
    reference.len() == 64
        && reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_external_binding_preserves_expiry_and_rechecks_current_roles() {
        let mut bindings = crate::config::RoleBindings::new();
        bindings.insert(
            "idp".into(),
            [("reader".into(), crate::config::RoleBindingCfg::default())].into(),
        );
        let principal = crate::auth::Principal {
            id: "alice".into(),
            name: None,
            roles: vec!["reader".into()],
            ttl_secs: Some(9999),
        };
        let key = crate::governance::synthesize_bound_key("idp", &principal, &bindings).unwrap();
        let mut work = RecoveryWork {
            instance: "plane".into(),
            reference: [1; 16],
            target: "/jobs/1".into(),
            active: Arc::default(),
            binding: crate::host_work::RecoveryBinding {
                principal: key.id.clone(),
                generation: key.generation_hash.clone(),
                created_at: 0,
                expires_at: Some(100),
            },
        };
        assert_eq!(
            work.restore_bound(&bindings, 99).unwrap().expires_at,
            Some(100)
        );
        assert!(work.restore_bound(&bindings, 100).is_none());
        bindings.get_mut("idp").unwrap().clear();
        assert!(work.restore_bound(&bindings, 99).is_none());
        bindings.get_mut("idp").unwrap().insert(
            "different-role".into(),
            crate::config::RoleBindingCfg::default(),
        );
        assert!(work.restore_bound(&bindings, 99).is_none());
        bindings
            .get_mut("idp")
            .unwrap()
            .insert("reader".into(), crate::config::RoleBindingCfg::default());
        work.binding.expires_at = None;
        assert!(
            work.restore_bound(&bindings, 99).is_none(),
            "cache TTL grants no recovery lifetime"
        );
    }
}
