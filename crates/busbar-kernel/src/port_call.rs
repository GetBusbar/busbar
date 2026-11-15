// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-instance port wrapper: `limits.timeout_ms` deadlines and the `limits.max_inflight` semaphore at every port call site (IF §12.22). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K8D fills it.

// W0-ABI: IF §12.22 freezes no Rust item for the port wrapper (its rules are the `timeout_ms` and `max_inflight`
// rows of the limits table); its types are W1-K8D's own.
