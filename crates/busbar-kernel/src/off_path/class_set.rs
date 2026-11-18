// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A set of class names made once: sorted and without repeats, shared by `Arc`. Made when an
//! instance's declaration is made (or a stored checkpoint is read back), never per request; a
//! request only clones the `Arc` and asks `contains`. Serialises as a `BTreeSet<String>` does.

use busbar_contract::kept::Text;
use std::sync::Arc;

/// Class names, sorted and without repeats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassSet(Arc<[Text]>);

impl ClassSet {
    /// The set of `names`: sorted, repeats dropped.
    #[must_use]
    pub fn new(names: impl IntoIterator<Item = Text>) -> Self {
        let mut all: Vec<Text> = names.into_iter().collect();
        all.sort();
        all.dedup();
        ClassSet(all.into())
    }

    /// Whether `class` is in the set.
    #[must_use]
    pub fn contains(&self, class: &str) -> bool {
        self.0.binary_search_by(|t| t.as_str().cmp(class)).is_ok()
    }

    /// The names, in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &str> + Clone {
        self.0.iter().map(Text::as_str)
    }

    /// How many names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for ClassSet {
    fn default() -> Self {
        ClassSet::new(std::iter::empty())
    }
}

impl serde::Serialize for ClassSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de> serde::Deserialize<'de> for ClassSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let names = <Vec<Text> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(ClassSet::new(names))
    }
}

impl ClassSet {
    /// Whether every name here is also in `other`.
    #[must_use]
    pub fn is_subset(&self, other: &ClassSet) -> bool {
        self.iter().all(|name| other.contains(name))
    }

    /// The names here that are not in `other`, in order.
    pub fn difference<'a>(&'a self, other: &'a ClassSet) -> impl Iterator<Item = &'a Text> {
        self.0.iter().filter(|name| !other.contains(name.as_str()))
    }

    /// This set without `class` (made when a selected activation drops its fee classes).
    #[must_use]
    pub fn without(&self, class: &str) -> ClassSet {
        ClassSet(
            self.0
                .iter()
                .filter(|name| name.as_str() != class)
                .cloned()
                .collect(),
        )
    }

    /// The names as shared text, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Text] {
        &self.0
    }
}

impl<'a> IntoIterator for &'a ClassSet {
    type Item = &'a Text;
    type IntoIter = std::slice::Iter<'a, Text>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<const N: usize> From<[&str; N]> for ClassSet {
    fn from(names: [&str; N]) -> Self {
        ClassSet::new(names.into_iter().map(|name| Text::Shared(Arc::from(name))))
    }
}

impl From<std::collections::BTreeSet<String>> for ClassSet {
    fn from(names: std::collections::BTreeSet<String>) -> Self {
        ClassSet::new(
            names
                .iter()
                .map(|name| Text::Shared(Arc::from(name.as_str()))),
        )
    }
}

impl<const N: usize> From<[String; N]> for ClassSet {
    fn from(names: [String; N]) -> Self {
        ClassSet::new(
            names
                .iter()
                .map(|name| Text::Shared(Arc::from(name.as_str()))),
        )
    }
}
