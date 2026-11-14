// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{HeaderMap, HeaderName};

/// What the auth gate holds of one request's credentials (request extension): the header names the
/// configured gate reads a credential from, and the credential it extracted, as a ref. Inserted by the gate on every request it judged;
/// absent on a route that bypassed it (a `RouteAuth::None` route consumed nothing, so a plane there
/// reads its own headers whole).
#[derive(Clone, Debug, Default)]
pub struct ConsumedCredentials {
    names: Vec<HeaderName>,
    /// The caller's credential the gate extracted, as a ref (`None`: the caller presented none).
    pub caller: Option<CallerCredential>,
    /// The record of the TICKET the gate spent admitting the caller (row 132); `None` when a key
    /// (or nothing) admitted it. Handed to the unit once, for `ticket.take`.
    pub ticket: Option<Vec<u8>>,
    /// Host custody is shared across context clones and removable exactly once.
    pub host_ticket_admission: Option<crate::host_services::HostTicketAdmission>,
}

impl ConsumedCredentials {
    pub(crate) fn carrying(carriers: &[HeaderName]) -> Self {
        let mut set = Self::default();
        set.carry(carriers);
        set
    }

    pub(crate) fn carry(&mut self, carriers: &[HeaderName]) {
        self.names.extend_from_slice(carriers);
    }

    pub(crate) fn carry_iter(&mut self, carriers: impl IntoIterator<Item = HeaderName>) {
        self.names.extend(carriers);
    }

    pub fn strip(&self, headers: &mut HeaderMap) {
        for name in &self.names {
            headers.remove(name);
        }
    }

    pub(crate) fn fields_of(consumed: Option<&Self>, headers: &HeaderMap) -> Vec<(String, String)> {
        let Some(consumed) = consumed else {
            return Vec::new();
        };
        consumed
            .names
            .iter()
            .filter_map(|name| {
                let value = headers.get(name)?;

                let scheme = (*name == axum::http::header::AUTHORIZATION)
                    .then(|| value.to_str().ok())
                    .flatten()
                    .and_then(|v| v.split_once(' '))
                    .map(|(word, _)| word.to_owned())
                    .unwrap_or_default();
                Some((name.as_str().to_owned(), scheme))
            })
            .collect()
    }

    pub(crate) fn strip_from(consumed: Option<&Self>, headers: &mut HeaderMap) {
        if let Some(consumed) = consumed {
            consumed.strip(headers);
        }
    }

    /// Strip consumed carriers without imposing HTTP field syntax on the remaining head.
    pub(crate) fn strip_neutral(&self, head: &mut crate::inbound::Head) {
        use zeroize::Zeroize as _;
        head.fields.retain_mut(|(name, value)| {
            // busbar:expect(bp::state_scan, reason = "config: the carrier names are the configured credential headers, a fixed handful per chain")
            let keep = !self
                .names
                .iter()
                .any(|carrier| carrier.as_str().eq_ignore_ascii_case(name));
            if !keep {
                value.zeroize();
            }
            keep
        });
    }
}

/// The caller's verified credential, retained in host request context. Its `Debug` prints
/// presence only; at egress the host lends the one buffer to the selected auth-kind binding.
///
/// ONE BUFFER, SHARED (SINGLE-PATH SP-AU6): `CallerCredential::verified` is the one copy from
/// transport custody into kernel custody. Every later holder (the data door, the unit's record,
/// the far end's route, the plugin lend at egress) clones a handle on that buffer, never its bytes:
/// [`CallerCredential::lend`] hands out a handle too.
///
/// ZEROISED AT EXIT (THE DESIGN §6: the kernel "holds it on the unit, zeroised at exit, for the
/// caller-credential style"; "auth material is zeroised"): the bytes live in ONE [`Secret`], shared,
/// so the plaintext is wiped once, when the last holder drops, never left behind in a copy.
///
/// [`Secret`]: busbar_contract::Secret
#[derive(Clone)]
pub struct CallerCredential(busbar_contract::SharedSecret);

impl CallerCredential {
    pub(super) fn verified(token: &str) -> Self {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::SecretCopy);
        Self(busbar_contract::Secret::new(token.as_bytes().to_vec()).share())
    }

    /// Bytes already in [`Secret`] custody, MOVED into the one shared buffer (no copy). There is
    /// no constructor from plain bytes.
    ///
    /// [`Secret`]: busbar_contract::Secret
    #[must_use]
    pub fn adopted(secret: busbar_contract::Secret<Vec<u8>>) -> Self {
        Self(secret.share())
    }

    /// The handle an egress input holds (an outbound auth call's caller credential): the one
    /// buffer, shared, never a copy of it.
    #[must_use]
    pub fn lend(&self) -> busbar_contract::SharedSecret {
        self.0.clone()
    }
}

impl std::fmt::Debug for CallerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerCredential(<present>)")
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "R23: test input differs: the test builds a credential directly"
)]
#[path = "tests/caller_credential_tests.rs"]
mod caller_credential_tests;
