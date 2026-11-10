// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral metric recordings shared by core and exporter conformance witnesses.
//! These inputs contain raw names and text. Each exporter owns its wire-format oracle.

/// A deterministic sequence of descriptions, counters, gauges, and histogram observations.
/// Label order is explicit; text includes quotes, backslashes, newlines and an unsanitized name.
pub const RECORDING: &str = include_str!("metric-recording.json");

/// Raw recorder facts for [`RECORDING`], before any export wire encoding.
/// The original recording was independently compared with the historical recorder before
/// ownership transfer; core and each owner's external oracle both check this shared vector.
pub const SNAPSHOT: &str = include_str!("metric-snapshot.json");
