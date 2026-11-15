// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin metrics: D_METRIC declarations and METRIC observations recorded under `kind` and `instance` (IF §12.17). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K8D fills it.

// W0-ABI: IF §12.17 freezes no Rust item for this module (its decoder, `decode_metrics`, is busbar-plugin-abi's
// `host_side::answer`, §10.2); the recorder's types are W1-K8D's own.
