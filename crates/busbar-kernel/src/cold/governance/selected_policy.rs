// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::selected_policy` and `governance::unit_checkpoint` cold code (see `crate::cold::governance`):
//! the refusal text of a selected-rate definition the compiler refuses, and of a checkpoint whose custody stays
//! unresolved. Spelled only when the definition or the checkpoint is refused.

/// `selected_policy`: a group whose selected policy does not match the current group model.
#[cold]
pub(crate) fn selected_policy_group_mismatch(name: &str) -> String {
    format!("groups.{name}: selected policy does not match current group model")
}

/// `selected_policy`: a group with more applicable selected-resource rules than one request may carry.
#[cold]
pub(crate) fn selected_policy_too_many_rules(name: &str) -> String {
    format!("groups.{name}: more than 32 applicable selected-resource rules")
}

/// `selected_policy`: a group whose provisioned child would carry too many applicable rules.
#[cold]
pub(crate) fn selected_policy_child_too_many_rules(name: &str) -> String {
    format!("groups.{name}.child_default: child would exceed 32 applicable selected-resource rules")
}

/// `selected_policy`: a selected-resource rule of an invalid shape.
#[cold]
pub(crate) fn selected_policy_invalid_rule(group: &str) -> String {
    format!("groups.{group}: invalid selected-resource rule")
}

/// `selected_policy`: a selected rule naming an instance/resource no actual target has.
#[cold]
pub(crate) fn selected_policy_unavailable_target(group: &str, id: &str) -> String {
    format!("groups.{group}: selected rule `{id}` names an unavailable instance/resource")
}

/// `selected_policy`: a selected token rule over a target without attempt accounting.
#[cold]
pub(crate) fn selected_policy_token_accounting(group: &str, id: &str) -> String {
    format!(
        "groups.{group}: selected token rule `{id}` requires attempt accounting on every matching target"
    )
}

/// `unit_checkpoint`: selected RAM custody a drain could not resolve.
#[cold]
pub(crate) fn unit_checkpoint_selected_unresolved(failed: &dyn std::fmt::Display) -> String {
    format!("selected RAM custody remains unresolved: {failed}")
}
