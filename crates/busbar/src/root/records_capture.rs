// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `records.user` AND `records.labels` (ADMIN-API-1.6 §3.5): what a unit's sealed record keeps of
//! the end user its plane projected and of the allow-listed request headers.
//!
//! Configured once at boot ([`configure`]) and keyed once when the deployment keyset is bound
//! ([`bind_user_key`]). A running process does not change either: a changed `records:` block
//! applies at the next boot. Off (the default) costs a unit one load and nothing else: no
//! allocation, no copy, no HMAC.
//!
//! `K_user` is HKDF-SHA256 over the keyset seed with the deployment id as salt and
//! [`USER_KEY_INFO`] as info. It is held as a [`Secret`] of this module's own seal, which no
//! serializer can reach (ADMIN-API-1.6 §14.2), and it never leaves this module.

use std::sync::{Arc, OnceLock};

use busbar_contract::redacted::Secret;
use busbar_kernel::config::{RecordsCfg, RecordsUser};

busbar_contract::own_seal!(Own);

/// The HKDF `info` `K_user` is derived under.
pub(crate) const USER_KEY_INFO: &[u8] = b"busbar.records.user.v1";

/// The most bytes a kept user or label value holds.
pub(crate) const VALUE_MAX: usize = 128;

/// The pseudonym's prefix.
const PSEUDONYM_PREFIX: &str = "u_";

/// How many MAC bytes a pseudonym carries.
const PSEUDONYM_BYTES: usize = 16;

/// What the process keeps, as configured at boot.
static CONFIGURED: OnceLock<Capture> = OnceLock::new();

/// `K_user`, once the deployment keyset is bound.
static USER_KEY: OnceLock<Secret<[u8; 32], Own>> = OnceLock::new();

/// One `records:` block, ready for the request path: the user mode and the allow-listed header
/// names in lower case, in the operator's order.
#[derive(Debug)]
pub(crate) struct Capture {
    user: RecordsUser,
    labels: Vec<Arc<str>>,
}

impl Capture {
    /// The capture a `records:` block configures. Runs once per boot.
    pub(crate) fn of(cfg: &RecordsCfg) -> Self {
        let mut labels = Vec::with_capacity(cfg.labels.len());
        for name in &cfg.labels {
            let mut lower = String::with_capacity(name.len());
            lower.push_str(name);
            lower.make_ascii_lowercase();
            labels.push(Arc::<str>::from(lower));
        }
        Capture {
            user: cfg.user,
            labels,
        }
    }

    /// Whether the record keeps the end user.
    pub(crate) fn keeps_user(&self) -> bool {
        self.user != RecordsUser::Off
    }

    /// Whether the record keeps any header.
    pub(crate) fn keeps_labels(&self) -> bool {
        !self.labels.is_empty()
    }

    /// The end user as the record keeps it: `None` when off, and when pseudonymous with no key,
    /// so the raw value is never kept in a pseudonym's place.
    pub(crate) fn user_of(&self, key: Option<&[u8; 32]>, value: &str) -> Option<String> {
        match self.user {
            RecordsUser::Off => None,
            RecordsUser::Plain => Some(owned(cut(value))),
            RecordsUser::Pseudonymous => pseudonym(key?, value),
        }
    }

    /// The allow-listed headers among `fields`, `(name, value)` in the allow-list's order: each
    /// the first field of that name (case aside), its value verbatim and cut to [`VALUE_MAX`]
    /// bytes; a value that is not UTF-8 is not kept. Empty, with no allocation, when none is
    /// configured or none arrived.
    pub(crate) fn labels_of(&self, fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Arc<str>, String)> {
        let mut kept = Vec::new();
        for name in &self.labels {
            let found = fields
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(name.as_bytes()));
            let Some(value) = found.and_then(|(_, value)| std::str::from_utf8(value).ok()) else {
                continue;
            };
            if kept.is_empty() {
                kept.reserve_exact(self.labels.len());
            }
            kept.push((Arc::clone(name), owned(cut(value))));
        }
        kept
    }
}

/// `"u_" + hex(HMAC-SHA256(key, utf8(value))[..16])`: 34 characters, one allocation.
fn pseudonym(key: &[u8; 32], value: &str) -> Option<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mac = busbar_contract::crypto::hmac_sha256(key, value.as_bytes()).ok()?;
    let mut out = String::with_capacity(PSEUDONYM_PREFIX.len() + 2 * PSEUDONYM_BYTES);
    out.push_str(PSEUDONYM_PREFIX);
    for &byte in &mac[..PSEUDONYM_BYTES] {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Some(out)
}

/// `value` cut to at most [`VALUE_MAX`] bytes, never inside a character.
fn cut(value: &str) -> &str {
    if value.len() <= VALUE_MAX {
        return value;
    }
    let mut end = VALUE_MAX;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// One owned copy of `text`.
fn owned(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    out.push_str(text);
    out
}

/// Configure the process from the boot document's `records:` block. The first call wins: the block
/// applies for the life of the process.
pub(crate) fn configure(cfg: &RecordsCfg) {
    let capture = Capture::of(cfg);
    if capture.keeps_user() || capture.keeps_labels() {
        tracing::info!(
            user = cfg.user.as_str(),
            labels = capture.labels.len(),
            "unit records keep the end user and request labels as configured (records:)"
        );
    }
    let _ = CONFIGURED.set(capture);
}

/// Keep `K_user`, derived from the deployment keyset when it is bound. The first call wins.
pub(crate) fn bind_user_key(key: [u8; 32]) {
    let _ = USER_KEY.set(Secret::held(key));
}

/// Warn, once the keyset is bound, when `records.user: pseudonymous` has no key to derive from:
/// every unit then keeps no user, never the plain value.
pub(crate) fn warn_unkeyed() {
    if CONFIGURED
        .get()
        .is_some_and(|c| c.user == RecordsUser::Pseudonymous)
        && USER_KEY.get().is_none()
    {
        tracing::warn!(
            "records.user is pseudonymous but this node has no deployment keyset to derive K_user \
             from: unit records keep no end user"
        );
    }
}

/// Whether this process keeps the end user on unit records.
pub(crate) fn keeps_user() -> bool {
    CONFIGURED.get().is_some_and(Capture::keeps_user)
}

/// The end user a unit's record keeps, as this process is configured.
pub(crate) fn user(value: &str) -> Option<String> {
    let capture = CONFIGURED.get()?;
    let key = USER_KEY.get().map(|key| key.expose_own(&Own::here()));
    capture.user_of(key, value)
}

/// The labels a unit's record keeps from its request's header fields, as this process is
/// configured; empty, with no allocation, when `records.labels` is off.
pub(crate) fn labels(fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Arc<str>, String)> {
    match CONFIGURED.get() {
        Some(capture) => capture.labels_of(fields),
        None => Vec::new(),
    }
}
