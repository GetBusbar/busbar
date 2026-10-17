// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's IR-side config: a lane's declared request-shape capabilities.
//!
//! The neutral IR itself — the `IrFacts` projection the shared pipeline reads, the sealed
//! `IrHandle`, the egress parameter bag and the cross-plane `invoke`/`subscribe` leaves — is the
//! contract's (`busbar_contract::ir`), and the kernel names it there. The concrete chat IR and the
//! leaf-op IR are the llm plane's.

/// A lane's declared request-shape capabilities, resolved from its provider entry and model rules
/// (`resolve_lane_caps`) into the `LaneCaps` that `busbar_contract::ir::egress_prep` carries, named
/// at `busbar_kernel::ir::lane_caps`, beside the parameter bag it fills.
pub mod lane_caps;
