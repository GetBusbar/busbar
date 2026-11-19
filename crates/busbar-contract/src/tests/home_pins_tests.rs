// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The values core's own vocabulary has at its home paths. They gate auth, routing and money, so they are pinned
//! here before any definition moves out of `abi/`: the move must leave every line of this file passing unchanged.

use crate::conn::codes::{CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_FRAMER, CAUSE_SECURITY};
use crate::kinds::codes::KindCode;
use crate::measurement::{units_bill, UNITS_ESTIMATED, UNITS_FLOOR, UNITS_REPORTED};
use crate::plane::codes::{CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL};
use crate::route::{
    AuthPoint, AuthPoints, FIELD_VALUE_PREFIX, METHOD_ANY, METHOD_DELETE, METHOD_GET, METHOD_HEAD,
    METHOD_PATCH, METHOD_POST, METHOD_PUT, PATH_CONTAINS, PATH_EXACT, PATH_PATTERN, PATH_PREFIX,
    PATH_SUFFIX, POINT_HEAD, POINT_HEAD_BODY,
};
use crate::secret::codes::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
};
use crate::transport::codes::{
    FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT, STATUS_CALLER_FAULT,
    STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};

#[test]
fn method_bits_are_the_route_table_bits() {
    assert_eq!(
        [
            METHOD_GET,
            METHOD_HEAD,
            METHOD_POST,
            METHOD_PUT,
            METHOD_PATCH,
            METHOD_DELETE
        ],
        [1, 2, 4, 8, 16, 32]
    );
    assert_eq!(METHOD_ANY, 511);
}

#[test]
fn path_forms_and_field_predicates_keep_their_numbers() {
    assert_eq!(
        [
            PATH_EXACT,
            PATH_PATTERN,
            PATH_PREFIX,
            PATH_SUFFIX,
            PATH_CONTAINS
        ],
        [1, 2, 3, 4, 5]
    );
    assert_eq!(FIELD_VALUE_PREFIX, 2);
}

#[test]
fn auth_points_keep_their_bits() {
    assert_eq!([POINT_HEAD, POINT_HEAD_BODY], [2, 4]);
    assert_eq!(AuthPoints::EMPTY.bits(), 0);
    assert_eq!(AuthPoints::HEAD.bits(), POINT_HEAD);
    assert_eq!(AuthPoints::HEAD_BODY.bits(), POINT_HEAD_BODY);
    assert_eq!(AuthPoint::Head as u32, POINT_HEAD);
    assert_eq!(AuthPoint::HeadBody as u32, POINT_HEAD_BODY);
}

#[test]
fn connection_cause_stages_keep_their_numbers() {
    assert_eq!(
        [CAUSE_CONNECT, CAUSE_SECURITY, CAUSE_DEADLINE, CAUSE_FRAMER],
        [1, 2, 4, 5]
    );
}

#[test]
fn kind_codes_are_one_to_seven() {
    assert_eq!(
        [
            KindCode::Store as u32,
            KindCode::Secret as u32,
            KindCode::Auth as u32,
            KindCode::Hook as u32,
            KindCode::Export as u32,
            KindCode::Plane as u32,
            KindCode::Transport as u32,
        ],
        [1, 2, 3, 4, 5, 6, 7]
    );
}

#[test]
fn unit_sources_and_which_of_them_bill() {
    assert_eq!([UNITS_ESTIMATED, UNITS_REPORTED, UNITS_FLOOR], [0, 1, 2]);
    assert!(!units_bill(UNITS_ESTIMATED));
    assert!(units_bill(UNITS_REPORTED));
    assert!(units_bill(UNITS_FLOOR));
}

#[test]
fn cancel_fault_status_and_secret_error_numbers() {
    assert_eq!(
        [CANCEL_OK_PARTIAL, CANCEL_FAILED, CANCEL_ABORTED],
        [1, 2, 3]
    );
    assert_eq!(
        [FAULT_NONE, FAULT_TRANSIENT, FAULT_HARD, FAULT_RATE_LIMIT],
        [0, 2, 3, 5]
    );
    assert_eq!(
        [
            STATUS_SUCCESS,
            STATUS_CALLER_FAULT,
            STATUS_FAR_END_FAULT,
            STATUS_OTHER
        ],
        [1, 2, 3, 4]
    );
    assert_eq!(
        [
            ERROR_KIND_NOT_FOUND,
            ERROR_KIND_DENIED,
            ERROR_KIND_INVALID,
            ERROR_KIND_INTERNAL
        ],
        [1, 3, 4, 5]
    );
}
