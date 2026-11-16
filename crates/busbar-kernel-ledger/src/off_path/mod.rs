// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LEDGER REQUEST-PATH MODULES' OFF-PATH CODE: what they need built once per configuration or
//! reload (the rate card), or read back for an operator usage view, a correction or recovery (a
//! cell's fee eras, its counts folded per lane), never per request. It sits outside the
//! request-path marker because it does not run per request; the request path only reads what it
//! built.

pub(crate) mod history;
pub(crate) mod rate;
pub(crate) mod usage;
