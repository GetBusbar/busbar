// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening battery for `stdio`: closes gaps a mutation run found where a battery happened
//! to pass regardless of what a mutated body returned. Every cell here pins one fact nothing else
//! reads directly: `StaticConfig` answering `None` for every declared key rather than some, the
//! carrier's real `Plugin::key`, and the single-shot listener's address.
//!
//! MIGRATION (door-only crate). The removed in-process `StdioTransport` is gone, so the cells that
//! drove it moved to the LIVE carrier/door paths, and the ones that pinned in-process-only mechanics
//! of a side table that no longer exists were folded. The full old-cell -> new-home mapping lives at
//! the top of `carrier_battery.rs`. What migrated here are the pure, synchronous unit facts:
//!
//! * `static_config_declares_nothing` — unchanged; `StaticConfig` is still the linked row's config.
//! * `plugin_key_is_stdio` — was `Plugin::key(&StdioTransport)`; now the live `StdioCarrier`.
//! * `the_listener_names_itself` — was `StdioTransport::listen(..).local_addr()`; now the carrier's
//!   `Carrier::listen`, which names the process's own standard input and output.

use busbar_contract::transport::Carrier;
use busbar_contract::unit::ConfigView;
use busbar_contract::{Plugin, TransportConfigView, TransportMeta};

use crate::{StaticConfig, StdioCarrier};

/// `StaticConfig` declares nothing: every accessor must answer `None`. A mutant that replaces any
/// of them with `Some(_)` survives everywhere a caller only ever reads `bind()` (which stays
/// `None` in every existing test's fixture, but never through `StaticConfig` itself).
#[test]
fn static_config_declares_nothing() {
    let cfg = StaticConfig;
    assert_eq!(ConfigView::get_str(&cfg, "anything"), None);
    assert_eq!(ConfigView::get_int(&cfg, "anything"), None);
    assert_eq!(ConfigView::get_bool(&cfg, "anything"), None);
    assert_eq!(TransportConfigView::bind(&cfg), None);
}

/// `Plugin::key` must report this transport's real key. A mutant that replaces it with `""` or
/// `"xyzzy"` survives everywhere the value is only ever compared to itself. (Was driven on the
/// removed `StdioTransport`; the live carrier carries the same key.)
#[test]
fn plugin_key_is_stdio() {
    let c = StdioCarrier::new();
    assert_eq!(Plugin::key(&c), "stdio");
    assert_eq!(Plugin::key(&c), <StdioCarrier as TransportMeta>::KEY);
}

/// The single-shot listener's address names what it is: the process's own standard input and
/// output. A mutant that replaces it with `String::new()` or `"xyzzy".into()` survives everywhere
/// the parent battery compares it only to the `OWN_PROCESS` constant rather than the literal. (Was
/// `StdioTransport::listen(..).local_addr()`; now `Carrier::listen`, which binds nothing.)
#[test]
fn the_listener_names_itself() {
    let c = StdioCarrier::new();
    let (_listener, addr) = c.listen("ignored").unwrap();
    assert_eq!(addr, "stdio:own-process");
}
