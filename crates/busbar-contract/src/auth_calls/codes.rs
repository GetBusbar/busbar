// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth vocabulary core keeps: styles, facts, scope fields.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::auth::{
    is_no_member_auth_field, is_scope_field, reject_hint_of, retry_after_of, scope_extensions,
    slot, BEGIN_AUTHORIZE, BEGIN_FORM, CAP_INBOUND, CAP_LOGIN, DECISION_CONTINUE, EXT_CARRIERS,
    FACT_DEFAULT_INBOUND_STYLE, FACT_INBOUND_ALL_HEADERS, FACT_OPERATOR, FACT_READS_CREDENTIALS,
    FIELDS_BUF_BYTES, FIELDS_HARD_MAX, FIELDS_MAX, FIELD_QUERY, FIELD_SENSITIVE, FORM_PASSWORD,
    IDENTITY_BUF_BYTES, IDENTITY_GROUPS, IDENTITY_GROUPS_HARD_MAX, IDENTITY_HAS_TTL,
    LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY, LOGIN_KIND_CREDENTIAL, LOGIN_KIND_REDIRECT, LOGIN_OUTAGE,
    LOGIN_SECURITY_CHECK_FAILED, MODE_OWN, MODE_PASSTHROUGH, STRIP_QUERY,
    STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL, STYLE_NEEDS_HEADERS,
    VERDICT_IDENTITY, VERDICT_REJECT,
};
