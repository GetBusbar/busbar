// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Connection and egress numbers and field predicates.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::host::conn::connector;
pub use crate::abi::host::conn::connector::{
    is_within_field, keeps_response_field_of, within_of, CAUSE_CONNECT, CAUSE_DEADLINE,
    CAUSE_EXCHANGE, CAUSE_FRAMER, CAUSE_PROXY, CAUSE_SECURITY, DIRECTION_INBOUND,
    DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB,
    EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER, KEEP_ALL_EXCEPT_DENIED, KEEP_NAMED,
    NEVER_KEPT,
};
