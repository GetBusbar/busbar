// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver`'s off-path code: a plane instance's host admission, lowered once per generation
//! (and its refusal in words for the refresh), the plane's timer task, started once at boot, and
//! the caller-reference migration that runs once before listener publication.

use std::sync::Arc;

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::plane_calls::InstanceDecl;

use crate::host_services::{InstanceFacts, KernelServices, Signing};
use crate::plane_driver::{PlaneDriver, PreparedSection};
use crate::trust::section::parse_section;

impl PreparedSection<'_> {
    /// Commit after every other fallible step of a generation refresh has succeeded.
    pub async fn commit(self) -> Result<(), String> {
        self.commit_typed().await.map_err(|e| e.to_string())
    }
}

pub(crate) fn prepare_admission<'a>(
    d: &InstanceDecl,
    services: &'a KernelServices,
    section: (&str, &busbar_contract::yaml::Value),
) -> Result<PreparedSection<'a>, String> {
    if d.conditional_records_optional && !d.conditional_records {
        return Err("optional record transactions require declared protocol support".into());
    }
    if d.conditional_records
        && !d.conditional_records_optional
        && !services.supports_record_transactions()
    {
        return Err("the configured store does not support conditional record transactions".into());
    }
    let trust = parse_section(section.0, section.1, &d.trust_keys)?;
    let facts = InstanceFacts {
        conditional_record_kinds: d.conditional_record_kinds.clone(),
        record_collections: d.record_collections.clone(),
        record_kinds: d
            .record_kinds
            .iter()
            .copied()
            .map(RecordSchemaId::new)
            .collect(),
        signing: d.signing.map(|(domain, kid_prefix)| Signing {
            domain: domain.into(),
            kid_prefix: kid_prefix.into(),
        }),
        trust: trust.into_iter().collect(),
        scope_kinds: d.scope_kinds.iter().map(|k| (*k).to_string()).collect(),
        record_chains: d.record_chains.clone(),
        record_retentions: d.record_retentions.clone(),
        ticket_prefix: d.ticket_prefix.map(str::to_string),
    };

    let work = crate::host_work::WorkBounds::of_section(
        section.0,
        section.1,
        services.default_work_bounds(),
    )?;
    Ok(PreparedSection {
        services,
        label: Arc::clone(&d.label),
        facts,
        work,
    })
}

enum Cause {
    Timer,

    Woke,
}

const fn earlier(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, b) => b,
        (a, 0) => a,
        (a, b) => {
            if a < b {
                a
            } else {
                b
            }
        }
    }
}

impl PlaneDriver {
    pub async fn ticks(&self) {
        let Some(driver) = self.driver else {
            return;
        };
        let mut at = 0;
        let mut cause = Cause::Timer;
        loop {
            let Some(next) = self.calls.tick(driver, self.calls.now_ns()).await else {
                return;
            };
            at = match cause {
                Cause::Timer => next,
                Cause::Woke => earlier(at, next),
            };
            let Some(woken) = self.await_tick(at).await else {
                return;
            };
            cause = woken;
        }
    }

    async fn await_tick(&self, at: u64) -> Option<Cause> {
        let timer = async {
            if at == 0 {
                std::future::pending::<()>().await;
            }
            let now = self.calls.now_ns();
            if at > now {
                tokio::time::sleep(std::time::Duration::from_nanos(at - now)).await;
            }
        };
        let woke = self.calls.woke();
        tokio::pin!(timer, woke);
        let mut channel = true;
        loop {
            tokio::select! {
                () = &mut timer => return Some(Cause::Timer),
                alive = &mut woke, if channel => {
                    if alive {
                        return Some(Cause::Woke);
                    }
                    channel = false;
                    if at == 0 {
                        return None;
                    }
                }
            }
        }
    }

    /// Adopt the current signer's references for identities that predate durable bindings.
    /// Run before listener publication, while the deployment still possesses that signer.
    /// Existing bindings win; a newly configured signer never overwrites their references.
    pub async fn migrate_caller_references(
        &self,
        gov: &crate::governance::GovState,
    ) -> Result<(), String> {
        let Some((services, caller)) = &self.records else {
            return Ok(());
        };
        let Some(slot) = &self.config.caller_refs else {
            return Ok(());
        };
        let key = slot
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| "caller reference key unavailable during migration".to_string())?;
        for principal in gov.all_keys_async().await.map_err(|e| e.to_string())? {
            services
                .resolve_caller_reference(caller, &principal.id, key.caller_ref(&principal.id))
                .await
                .map_err(str::to_owned)?;
        }
        Ok(())
    }
}

/// Make the credential-warning seats for a generation's providers: one for each name given, and
/// the table's spare seats for any other. Called when a generation's egress is built; the far end
/// only reads the table it finds here (`far_end::warn_credential_refused`).
pub fn declare_providers<'p>(providers: impl IntoIterator<Item = &'p str>) {
    let table = crate::plane_driver::CREDENTIAL_WARNED.get_or_init(std::sync::Mutex::default);
    let mut table = table
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for provider in providers {
        table.plan(provider, None);
    }
}
