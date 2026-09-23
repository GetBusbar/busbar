// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`PLUGIN-TREE.md` §3).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
///
/// `http` carries a request line and headers, so a claim on this wire can be about either, in each
/// of the path shapes the grammar spells.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::HeaderExact,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
];

/// The forms an EGRESS claim over this wire may take: none.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
