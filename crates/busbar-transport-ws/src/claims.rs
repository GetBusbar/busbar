// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`PLUGIN-TREE.md` §3).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::grammar::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
///
/// ws IS the top transport of its stack (composed over `http`), and the architecture states the
/// TOP transport owns claims — including the ones that, before the upgrade, are read off the
/// HTTP request carrying it. So this declares the request-shaped forms rather than none; a
/// genuine open question (flagged in the crate's report) is whether that reading is what the
/// design intends, since `http`'s own row would otherwise carry the identical set unused.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
    SelectorForm::HeaderExact,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::Sni,
    SelectorForm::Alpn,
    SelectorForm::Port,
];

/// The forms an EGRESS claim over this wire may take: none.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
