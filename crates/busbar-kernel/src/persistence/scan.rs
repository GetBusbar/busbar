// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One guarded pagination loop for core owners. Page limits bound each native
//! crossing; collections can span any number of pages without silent truncation.

use super::facade::CoreStore;
use busbar_contract::persistence::{
    Address, ExpectedValue, Failure, NamespaceId, Predicate, Read, ReadResult, Scan,
};
use busbar_contract::Secret;
use std::sync::Arc;

pub(crate) struct Collection {
    pub generation: u64,
    pub rows: Vec<(Address, Secret<Vec<u8>>)>,
}

impl CoreStore {
    /// Linearize a read-only decision over previously collected point/scan
    /// observations. No fake mutation or transport receipt is needed for a no-op.
    pub(crate) async fn guards_hold(&self, guards: &[Predicate]) -> Result<bool, Failure> {
        if guards.is_empty() {
            return Ok(true);
        }
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(guards.len())
            .map_err(|_| Failure::Overloaded)?;
        addresses.extend(guards.iter().map(|guard| guard.address.clone()));
        let result = self
            .backend()
            .read(Arc::new(Read {
                dataset: self.info().dataset,
                addresses,
                time: None,
            }))
            .await?;
        let ReadResult::Values {
            observed_at,
            values,
        } = result
        else {
            return Err(Failure::Corrupt);
        };
        if observed_at.authority != self.info().clock_authority || values.len() != guards.len() {
            return Err(Failure::Corrupt);
        }
        Ok(guards
            .iter()
            .zip(values)
            .all(|(guard, value)| match &guard.expected {
                ExpectedValue::Absent => value.is_none(),
                ExpectedValue::Exact(expected) => value.as_ref() == Some(expected),
            }))
    }

    pub(crate) async fn scan(
        &self,
        namespace: NamespaceId,
        prefix: Vec<u8>,
        mut after: Option<Vec<u8>>,
    ) -> Result<Collection, Failure> {
        let limits = self.limits();
        let mut rows = Vec::new();
        let mut generation = None;
        loop {
            let page = self
                .backend()
                .scan(Arc::new(Scan {
                    dataset: self.info().dataset,
                    namespace,
                    prefix: prefix.clone(),
                    after: after.clone(),
                    generation,
                    // An initial seek is a lower bound, not a continuation from
                    // an observed generation. Admit that first page explicitly;
                    // every later page pins the generation it returns.
                    allow_change: generation.is_none() && after.is_some(),
                    max_items: limits.scan_items,
                    max_bytes: limits.scan_bytes,
                }))
                .await?;
            if generation.is_some_and(|expected| expected != page.generation) {
                return Err(Failure::StaleScan);
            }
            generation = Some(page.generation);
            if page.rows.len() > limits.scan_items {
                return Err(Failure::Corrupt);
            }
            let seal = crate::seal::lend();
            let mut bytes = 0usize;
            let mut previous = after.as_ref();
            for (address, value) in &page.rows {
                if address.namespace != namespace.0
                    || !address.key.starts_with(&prefix)
                    || previous.is_some_and(|key| key >= &address.key)
                {
                    return Err(Failure::Corrupt);
                }
                previous = Some(&address.key);
                bytes = bytes
                    .checked_add(address.key.len())
                    .and_then(|bytes| bytes.checked_add(value.expose(&seal).len()))
                    .ok_or(Failure::Corrupt)?;
            }
            if bytes > limits.scan_bytes
                || page.next.as_ref().is_some_and(|next| {
                    page.rows.last().map(|(address, _)| &address.key) != Some(next)
                })
            {
                return Err(Failure::Corrupt);
            }
            rows.try_reserve(page.rows.len())
                .map_err(|_| Failure::Overloaded)?;
            rows.extend(page.rows);
            after = page.next;
            if after.is_none() {
                return Ok(Collection {
                    generation: page.generation,
                    rows,
                });
            }
        }
    }
}
