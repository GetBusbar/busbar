// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A trivial read-only config view for the stdio row's linked registration.
//!
//! The stdio row's live connection state (the reader, the single write lock, the owned child) lives
//! in the carrier ([`crate::carrier`]) and the door ([`crate::door`]), each keyed by its own handle.
//! All this module carries is the empty config view a linked registration hands in.

use busbar_contract::unit::ConfigView;
use busbar_contract::TransportConfigView;

/// A trivial read-only config view, for callers (and tests) that have nothing to declare. stdio
/// binds no address, so [`TransportConfigView::bind`] always answers `None`.
#[derive(Debug, Default, Clone)]
pub struct StaticConfig;

impl ConfigView for StaticConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for StaticConfig {
    fn bind(&self) -> Option<&str> {
        None
    }
}
