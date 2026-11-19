// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-service numbers and inspection shapes core's seams speak.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::host::service;
pub use crate::abi::host::service::{
    CARRIER_SESSION_FIELD, DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST,
    DEST_OBFUSCATED, DEST_PLAINTEXT, DEST_SCHEME, DEST_UNRESOLVABLE, DISK_APPEND_FAILED,
    DISK_OPEN_FAILED, DISK_RENAME_FAILED, DISK_RETENTION_FAILED, DISK_SHIFT_FAILED, FLOW_CONTINUE,
    FLOW_STOP, MAX_SPANS, MAX_WORK_RECORD, OUTBOUND_BIND, OUTBOUND_PUBLISH, OUTBOUND_PUBLISH_BODY,
    OUTBOUND_REVOKE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE, REFUSE_OVER_GATE,
    REFUSE_STOPPED, SCHEME_PLAIN, SCHEME_SECURE, SCHEME_UNDECLARED, SNAPSHOT_SCOPE_HOOKS,
    SNAPSHOT_SCOPE_WHOLE, VERIFY_FOLLOW, VERIFY_HIT, VERIFY_LEAD, WORK_LIVE, WORK_SETTLED,
    WORK_STATUS_ABSENT, WORK_STATUS_LIVE, WORK_STATUS_SETTLED, WORK_STATUS_SETTLING,
};
pub use crate::abi::mechanism::inspection::{
    InspectionError, InspectionObservation, InspectionQuery, InspectionResult, SessionObservation,
    WorkObservation,
};
