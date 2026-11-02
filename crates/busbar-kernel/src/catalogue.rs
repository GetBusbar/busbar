// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(unused_imports)]
#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

use busbar_contract::records::VirtualKey;

use crate::trust::validate::{Generations, Grant};

/// WHO IS ASKING, AND WHEN — the inputs the ordered gate's identity, expiry and generation steps
/// need, carried together.
///
/// One value rather than three arguments so a call site cannot pair this caller's key with another
/// request's clock or another apply's generation. Moved here from `a2a/catalogue.rs`, which had
/// written it for its own plane and stated exactly that reason; it is not a per-plane idea.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    /// `None` ONLY where governance is disabled and there is therefore no principal to carry a
    /// grant. It is not a way past the gate — [`crate::trust::validate`] states that posture once,
    /// for the whole tree, and this carries it rather than restating it.
    pub key: Option<&'a VirtualKey>,
    /// Seconds, for the key-expiry comparison. The caller's clock, so a test can move it.
    pub now: u64,
    /// The registry generation this ask is being judged under.
    pub generation: Generations,
}

pub trait CatalogueItem {
    type Excluded;

    type Query;

    type Fit;

    type Wire<'a>
    where
        Self: 'a;

    fn required_grants<'g>(&'g self, query: &'g Self::Query, out: &mut Vec<Grant<'g>>);

    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), Self::Excluded>;

    fn fit(&self, query: &Self::Query) -> Result<Self::Fit, Self::Excluded>;

    fn ungranted(&self) -> Self::Excluded;

    fn render(&self) -> Self::Wire<'_>;
}

pub struct Entitled<'i, I: CatalogueItem> {
    pub item: &'i I,
    pub fit: I::Fit,
}

impl<I: CatalogueItem> Clone for Entitled<'_, I>
where
    I::Fit: Clone,
{
    fn clone(&self) -> Self {
        Entitled {
            item: self.item,
            fit: self.fit.clone(),
        }
    }
}

impl<I: CatalogueItem + std::fmt::Debug> std::fmt::Debug for Entitled<'_, I>
where
    I::Fit: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entitled")
            .field("item", &self.item)
            .field("fit", &self.fit)
            .finish()
    }
}

impl<I: CatalogueItem + PartialEq> PartialEq for Entitled<'_, I>
where
    I::Fit: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.item == other.item && self.fit == other.fit
    }
}

pub fn judge<'i, I: CatalogueItem>(
    item: &'i I,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Result<Entitled<'i, I>, I::Excluded> {
    let mut grants: Vec<Grant<'_>> = Vec::new();
    item.required_grants(query, &mut grants);

    if grants.is_empty() {
        return Err(item.ungranted());
    }
    item.admit(caller, &grants)?;
    let fit = item.fit(query)?;
    Ok(Entitled { item, fit })
}

pub fn entitled<'i, I: CatalogueItem + 'i>(
    items: impl IntoIterator<Item = &'i I>,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Vec<Entitled<'i, I>> {
    items
        .into_iter()
        .filter_map(|i| judge(i, caller, query).ok())
        .collect()
}

pub fn visible<'i, I: CatalogueItem + 'i>(
    items: impl IntoIterator<Item = &'i I>,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Vec<&'i I> {
    entitled(items, caller, query)
        .into_iter()
        .map(|e| e.item)
        .collect()
}

pub fn rendered<'i, I: CatalogueItem + 'i>(
    items: impl IntoIterator<Item = &'i I>,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Vec<I::Wire<'i>> {
    entitled(items, caller, query)
        .into_iter()
        .map(|e| e.item.render())
        .collect()
}
