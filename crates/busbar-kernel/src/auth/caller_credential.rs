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

    /// Whether the request presents any consumed carrier: asked in place, nothing built.
    pub(crate) fn present_in(consumed: Option<&Self>, headers: &HeaderMap) -> bool {
        consumed
            .is_some_and(|consumed| consumed.names.iter().any(|name| headers.contains_key(name)))
    }

    /// The consumed carriers the request presents, each with its `Authorization` scheme word
    /// (empty for any other carrier): what the request context keeps once the carriers are
    /// stripped. The name is the gate's own header name, shared, never copied.
    pub(crate) fn fields_of(
        consumed: Option<&Self>,
        headers: &HeaderMap,
    ) -> Vec<(HeaderName, String)> {
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
                Some((name.clone(), scheme))
            })
            .collect()
    }

    pub(crate) fn strip_from(consumed: Option<&Self>, headers: &mut HeaderMap) {
        if let Some(consumed) = consumed {
            consumed.strip(headers);
        }
    }

    /// Strip consumed carriers without imposing HTTP field syntax on the remaining head. One pass
    /// over the request's own field lines, kept lines in order; a consumed value is wiped (its
    /// whole allocation, through `busbar_contract::secure`) before it drops.
    pub(crate) fn strip_neutral(&self, head: &mut crate::inbound::Head) {
        let fields = &mut head.fields;
        let mut kept = 0;
        for read in 0..fields.len() {
            if self.carries(&fields[read].0) {
                let value = std::mem::take(&mut fields[read].1);
                drop(busbar_contract::secure::SecureVec::from(value));
            } else {
                fields.swap(kept, read);
                kept += 1;
            }
        }
        fields.truncate(kept);
    }

    /// Whether `name` is one of the consumed carriers (ASCII case-insensitive).
    fn carries(&self, name: &str) -> bool {
        for carrier in &self.names {
            if carrier.as_str().eq_ignore_ascii_case(name) {
                return true;
            }
        }
        false
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
    /// Private to this module (LINT-RULES R23 derive-once): only [`verified_caller_credential`]
    /// builds the caller credential, once per request.
    fn verified(token: &str) -> Self {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::SecretCopy);
        let bytes = busbar_contract::secure::SecureVec::from(token.as_bytes()).into_vec();
        Self(busbar_contract::Secret::new(bytes).share())
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

/// The request's caller credential, built once from the token the unit carried (or the plain
/// request's client token): the one owner of [`CallerCredential::verified`].
pub(super) fn verified_caller_credential(
    inbound: Option<Option<&busbar_contract::redacted::Secret<String>>>,
    client_token: Option<&str>,
) -> Option<CallerCredential> {
    let token = match inbound {
        Some(credential) => {
            credential.map(|credential| credential.expose(&crate::seal::lend()).as_str())
        }
        None => client_token,
    };
    token.map(CallerCredential::verified)
}

impl std::fmt::Debug for CallerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerCredential(<present>)")
    }
}

#[cfg(test)]
#[path = "tests/caller_credential_tests.rs"]
mod caller_credential_tests;
