// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claims this transport declares, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2):
//! the schemes it answers for and, for each, the facts the root reads per scheme. A declaration and
//! nothing else, read once at registration.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::transport::{Claim, UNIT0_FIRST_LINE};

/// The schemes `stdio` claims, by name: the Statement's `claims`, the one place they are stated.
pub(crate) const CLAIM_NAMES: &[AbiStr] = &[abi_str(crate::meta::KEY)];

/// The claim's row: no selector forms (a stdio channel has no surface to select on), a session
/// whose first unit opens on its first line.
pub(crate) const CLAIMS: &[Claim] = &[Claim {
    selector_forms: abi_str(""),
    egress_selector_forms: abi_str(""),
    facts: std::ptr::null(),
    facts_len: 0,
    status_namespace: crate::meta::NONE,
    session: 1,
    session_bound: 1,
    unit0_trigger: UNIT0_FIRST_LINE,
    status_at: 0,
    _reserved: 0,
}];
