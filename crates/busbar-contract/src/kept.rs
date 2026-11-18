// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KEPT RECORDS (GROUP-records, step K0): the building blocks for records that have a home made
//! once and are filled in place on a request. [`Text`] is a name made once and shared;
//! [`TextList`], [`Slots`], [`Window`] and [`Book`] hold records without allocating after warm-up.
//!
//! The blocks live in the request-path marked module `blocks` (nothing in it allocates per use).
//! The constructors, which allocate and run at boot, at generation build or at restore, are in
//! [`off_path`], outside the marker: a marked module's children inherit its marker, so the two are
//! siblings here, and the paths read `busbar_contract::kept::Text` and
//! `busbar_contract::kept::off_path::text`.

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
mod blocks;
/// Constructors that allocate: boot, generation build and restore only, never per request.
pub mod off_path;

pub use blocks::{set_bytes, set_text, Book, Kept, Slots, Text, TextList, TextListIter, Window};

#[cfg(test)]
#[path = "kept/tests.rs"]
mod tests;
