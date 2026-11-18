// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::serve`'s off-path code: a composition's serve tables checked for collisions and
//! published (once per composition), an instance's table withdrawn (once per withdraw), and the
//! published snapshot's route index built with it. A request resolves through the index.

use std::sync::{Arc, PoisonError};

use busbar_contract::abi::plane::ROUTE_PUBLIC;

use crate::plane_driver::serve::{
    param, Collision, RouteIndex, ServeRoute, ServeTable, ServeTables, Snapshot,
};

impl ServeTables {
    /// Every published instance's routes, in publication order: what an admin read reports as an
    /// instance's `runtime.plane.routes` (ADMIN-API-1.6 §5.3). Reads the snapshot without a lock;
    /// an admin read, never a request.
    #[must_use]
    pub fn published(&self) -> Vec<(String, Vec<ServeRoute>)> {
        self.0
            .now
            .load()
            .tables
            .iter()
            .map(|table| (table.instance.clone(), table.routes.clone()))
            .collect()
    }

    pub fn publish(&self, table: ServeTable, reserved: &[(&str, &str)]) -> Result<(), Collision> {
        self.publish_batch(vec![table], reserved)
    }

    /// Check the whole staged composition before committing its native publication
    /// marker. Publishing repeats this check under the writer lock.
    pub fn validate_batch(
        &self,
        batch: &[ServeTable],
        reserved: &[(&str, &str)],
    ) -> Result<(), Collision> {
        validate_tables(&self.0.now.load().tables, batch, reserved)
    }

    /// Publish one fully confirmed composition in a single visible snapshot. Until
    /// this succeeds, readers retain the entire previous generation's route table.
    pub fn publish_batch(
        &self,
        batch: Vec<ServeTable>,
        reserved: &[(&str, &str)],
    ) -> Result<(), Collision> {
        let _turn = self
            .0
            .writing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self.0.now.load();
        validate_tables(&current.tables, &batch, reserved)?;
        let mut next: Vec<Arc<ServeTable>> = current
            .tables
            .iter()
            .filter(|t| !batch.iter().any(|new| new.instance == t.instance))
            .cloned()
            .collect();
        next.extend(batch.into_iter().map(Arc::new));
        self.0.now.store(Arc::new(snapshot(next)));
        Ok(())
    }

    pub fn withdraw(&self, instance: &str) {
        let _turn = self
            .0
            .writing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self.0.now.load();
        let next: Vec<Arc<ServeTable>> = current
            .tables
            .iter()
            .filter(|t| t.instance != instance)
            .cloned()
            .collect();
        self.0.now.store(Arc::new(snapshot(next)));
    }
}

/// The snapshot readers resolve `tables` through: the tables and their admin and public route
/// indexes.
pub(crate) fn snapshot(tables: Vec<Arc<ServeTable>>) -> Snapshot {
    let admin = route_index(&tables, false);
    let public = route_index(&tables, true);
    Snapshot {
        tables,
        admin,
        public,
    }
}

/// The routes of one class (`public` or admin), `(table, route)` in snapshot order, indexed by
/// their target's second `/`-separated element: a literal element keys its bucket; a `{param}`
/// element joins every bucket and `any`, in order; a target with no second element is `short`.
fn route_index(tables: &[Arc<ServeTable>], public: bool) -> RouteIndex {
    let mut index = RouteIndex::default();
    let of_class = |r: &ServeRoute| (r.flags & ROUTE_PUBLIC != 0) == public;
    for table in tables {
        for route in table.routes.iter().filter(|r| of_class(r)) {
            if let Some(segment) = route.target.split('/').nth(1).filter(|s| !param(s)) {
                index.by_segment.entry(segment.to_owned()).or_default();
            }
        }
    }
    for (t, table) in tables.iter().enumerate() {
        for (i, route) in table.routes.iter().enumerate() {
            if !of_class(route) {
                continue;
            }
            match route.target.split('/').nth(1) {
                None => index.short.push((t, i)),
                Some(segment) if param(segment) => {
                    for bucket in index.by_segment.values_mut() {
                        bucket.push((t, i));
                    }
                    index.any.push((t, i));
                }
                Some(segment) => {
                    if let Some(bucket) = index.by_segment.get_mut(segment) {
                        bucket.push((t, i));
                    }
                }
            }
        }
    }
    index
}

fn overlap(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.split('/'), b.split('/'));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if x == y || param(x) || param(y) => {}
            _ => return false,
        }
    }
}

pub(crate) fn validate_tables(
    tables: &[Arc<ServeTable>],
    batch: &[ServeTable],
    reserved: &[(&str, &str)],
) -> Result<(), Collision> {
    let mut seen: Vec<(&str, &str, &str)> =
        reserved.iter().map(|(v, t)| (*v, *t, "kernel")).collect();
    for table in tables
        .iter()
        .filter(|table| !batch.iter().any(|new| new.instance == table.instance))
    {
        seen.extend(
            admin(&table.routes).map(|route| (&*route.verb, &*route.target, &*table.instance)),
        );
    }
    for table in batch {
        for route in admin(&table.routes) {
            if let Some((_, _, with)) = seen.iter().find(|(verb, target, _)| {
                verb.eq_ignore_ascii_case(&route.verb) && overlap(target, &route.target)
            }) {
                return Err(Collision {
                    route: (route.verb.clone(), route.target.clone()),
                    with: (*with).to_string(),
                });
            }
            seen.push((&route.verb, &route.target, &table.instance));
        }
    }
    Ok(())
}

fn admin(routes: &[ServeRoute]) -> impl Iterator<Item = &ServeRoute> {
    routes.iter().filter(|r| r.flags & ROUTE_PUBLIC == 0)
}
