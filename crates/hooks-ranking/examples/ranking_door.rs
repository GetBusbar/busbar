// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ranking hook's door, dropped in: the one exported symbol, forwarding to the same door a
//! compiled-in row holds (`busbar_hooks_ranking::linked::door`). `tests/conformance.rs` loads it
//! beside the linked door and drives both the same way.

busbar_contract::export_door!(busbar_hooks_ranking::linked::door);
