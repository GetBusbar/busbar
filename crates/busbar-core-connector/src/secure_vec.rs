// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`SecureVec`], the wiping buffer. It lives in `busbar_contract::secure` (one home for the wiping
//! logic, reachable by plugins); this module re-exports it under the connector's path.

#[cfg(any(test, feature = "test-support"))]
pub use busbar_contract::secure::refuse_growth;
pub use busbar_contract::secure::{Overflow, SecureVec, Tail};
