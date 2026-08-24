// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar NEUTRAL SUBSTRATE — the transport-agnostic value families and helpers a plane crate
//! (`busbar-mcp`, `busbar-a2a`) names without reaching into `busbar-core`.
//!
//! The Phase-B plane extraction inverts the old dependency direction: instead of the planes living
//! inside core and reaching for core-private types, the neutral pieces they share — trust value
//! families, egress-authorisation decisions, failover walk types, and the transport-neutral ingress
//! helpers — move DOWN into this crate. It depends only on the plugin contracts (`busbar-api`) and
//! the plugin ABI (`busbar-plugin`), both leaves, so a plane crate can depend on it with no path
//! back to core and no dependency cycle.
//!
//! This is the B0-a skeleton: the crate exists, is a workspace member, and compiles. The subsequent
//! Phase-B steps (B0-b relocates the Tier-0 leaves, B1 the trust/egress/failover families) fill it
//! in; core re-exports each relocated item during the transition so the in-core call sites do not
//! change in the same commit.
