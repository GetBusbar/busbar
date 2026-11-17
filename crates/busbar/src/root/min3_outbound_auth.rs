// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete native outbound bindings from the candidate's canonical plan and retained AuthSet.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::config::UpstreamCreds;
use busbar_contract::dest::DestinationId;
use busbar_kernel::auth_bindings::native::{
    NativeBinding, NativeBindingSpec, NativeRouteBindings, SelectedCredential, SelectedRouteKey,
};
use busbar_kernel::auth_bindings::{AttemptKey, ProviderBindings};
use busbar_kernel::custody::CredCache;
use busbar_kernel::plane_driver::AuthBinding;

use super::min3_auth::AuthSet;

/// Explicit no-auth and required canonical selections cannot be confused with failed lookup.
pub(crate) enum Selection {
    None,
    Required(AttemptKey),
}

pub(crate) struct SelectedRow {
    pub(crate) key: SelectedRouteKey,
    pub(crate) destination: DestinationId,
    pub(crate) upstream: Box<str>,
    pub(crate) selection: Selection,
    pub(crate) mode: UpstreamCreds,
    pub(crate) cache_max_s: Option<u32>,
}

/// Admitted selected style for an opened binding, keyed by its configured auth name.
pub(crate) struct AdmittedStyle {
    pub(crate) flags: u64,
}

pub(crate) struct Prepared {
    rows: BTreeMap<SelectedRouteKey, (DestinationId, SelectedCredential)>,
}

impl Prepared {
    /// Attach this value to the MemberRoute's sole auth slot before candidate publication.
    pub(crate) fn for_destination(
        &self,
        plane: &str,
        destination: DestinationId,
    ) -> Result<AuthBinding, String> {
        let rows: Vec<_> = self
            .rows
            .iter()
            .filter(|(key, (dest, _))| key.plane.as_ref() == plane && *dest == destination)
            .map(|(key, (dest, credential))| {
                (
                    key.pool.clone(),
                    key.member.clone(),
                    *dest,
                    credential.clone(),
                )
            })
            .collect();
        if rows.is_empty() {
            return Err("native outbound destination has no selected rows".into());
        }
        NativeRouteBindings::new(rows)
            .map(AuthBinding::Native)
            .map_err(|_| "native outbound selection is inconsistent".into())
    }
}

/// Called once for ALL participating planes using this generation's credential cache. The root
/// supplies that cache with its actual retry/audit owners; no fallback owners are manufactured here.
pub(crate) fn prepare(
    bindings: &ProviderBindings,
    rows: Vec<SelectedRow>,
    auth: &AuthSet,
    styles: &BTreeMap<Box<str>, AdmittedStyle>,
    cache: Arc<CredCache>,
) -> Result<Prepared, String> {
    let mut selected = BTreeMap::new();
    for row in rows {
        if selected.insert(row.key.clone(), row).is_some() {
            return Err("duplicate native outbound pool/member selection".into());
        }
    }
    let mut completed = BTreeMap::new();
    let mut namespace = 0_u64;
    for (key, row) in selected {
        // These modes require the separately adopted grant and verified-field producers, including
        // for an otherwise unauthenticated row. Candidate construction must not bypass that hold.
        if row.mode != UpstreamCreds::Own {
            return Err(
                "native caller credentials require the grant and verified-field producers".into(),
            );
        }
        namespace = namespace
            .checked_add(1)
            .ok_or("native credential namespace exhausted")?;
        let credential = match row.selection {
            Selection::None => SelectedCredential::None,
            Selection::Required(attempt) => {
                if attempt.0 != key.plane {
                    return Err("native outbound attempt belongs to another plane".into());
                }
                let name = bindings
                    .by_attempt
                    .get(&attempt)
                    .ok_or("required native outbound binding is absent")?;
                let opened = &auth
                    .get(name)
                    .ok_or("required native outbound instance is not open")?
                    .opened;
                if opened.methods & busbar_plugin_abi::auth::M_OUTBOUND == 0 {
                    return Err("native outbound instance does not declare outbound".into());
                }
                let style = styles
                    .get(name)
                    .ok_or("native outbound selected style is not admitted")?;
                let binding = NativeBinding::new(
                    NativeBindingSpec {
                        key: key.clone(),
                        destination: row.destination,
                        upstream: row.upstream,
                        auth_instance: opened.who.instance,
                        credential_namespace: namespace,
                        style_flags: style.flags,
                        mode: row.mode,
                        cache_max_s: row.cache_max_s,
                    },
                    Arc::clone(&opened.port),
                    Arc::clone(&cache),
                )
                .map_err(|_| "native outbound binding is not admissible")?;
                SelectedCredential::Required(Arc::new(binding))
            }
        };
        completed.insert(key, (row.destination, credential));
    }
    Ok(Prepared { rows: completed })
}
