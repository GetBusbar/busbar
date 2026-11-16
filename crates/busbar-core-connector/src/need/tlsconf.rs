// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT TLS CONFIG OF ONE NEED DIAL: the platform roots plus the instance's own trust anchor
//! (when the class allows one and the Need binds one), the client identity a mutual Need presents,
//! and the ALPN it offers, built through the crypto backend (`tls::client`).
//!
//! The unverified config is used for exactly one reason: the caller's core-held `Accept` waives
//! verification (`TlsPlan::waive`). A plugin never asks for it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::transport::trust::{ClientIdentity, EgressTrust};
use busbar_plugin_abi::host_side::needs::NeedErr;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::TlsPlan;
use crate::tls::client::{build_client_config, unverified_client_config};

/// Configs kept: one per (waived, trust anchor, ALPN). A client certificate is never cached.
const KEPT: usize = 64;

type CacheKey = (bool, [u8; 32], Vec<u8>);

/// The built configs, shared by every dial of the I/O.
#[derive(Debug, Default)]
pub struct Configs {
    kept: Mutex<HashMap<CacheKey, Arc<rustls::ClientConfig>>>,
}

/// The client identity a PEM bundle of certificate chain and private key holds.
fn identity(pem: &[u8]) -> Result<ClientIdentity, NeedErr> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .map(|c| c.map(|c| c.as_ref().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NeedErr::Invalid)?;
    if chain.is_empty() {
        return Err(NeedErr::Invalid);
    }
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|_| NeedErr::Invalid)?;
    Ok(ClientIdentity {
        cert_chain: chain,
        private_key: key.secret_der().to_vec().into(),
    })
}

impl Configs {
    /// The config for `plan` offering `alpn` (in order; empty offers none).
    ///
    /// # Errors
    /// `Invalid` for a client certificate that does not parse, or one asked for under a waiver
    /// (the unverified config presents no identity, and a Need that asked to present one does not
    /// silently connect without it); `Tls` when the crypto backend refuses the config.
    pub fn get(
        &self,
        plan: &TlsPlan<'_>,
        alpn: &[Vec<u8>],
    ) -> Result<Arc<rustls::ClientConfig>, NeedErr> {
        let anchor = plan.trust.as_ref().map_or([0; 32], |t| t.sha256);
        let key = (plan.waive, anchor, alpn.concat());
        if plan.cert.is_none() {
            let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(config) = kept.get(&key) {
                return Ok(Arc::clone(config));
            }
        }
        let mut config = if plan.waive {
            if plan.cert.is_some() {
                return Err(NeedErr::Invalid);
            }
            Arc::unwrap_or_clone(unverified_client_config().map_err(|_| NeedErr::Tls)?)
        } else {
            let trust = EgressTrust {
                extra_anchors: plan.trust.as_ref().map_or_else(Vec::new, |t| t.der.clone()),
                pinned_public_keys: Vec::new(),
                client_identity: plan
                    .cert
                    .as_deref()
                    .map(|c| identity(c.as_slice()))
                    .transpose()?,
            };
            build_client_config(&trust).map_err(|_| NeedErr::Tls)?
        };
        config.alpn_protocols = alpn.to_vec();
        let config = Arc::new(config);
        if plan.cert.is_none() {
            let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            if kept.len() >= KEPT {
                kept.clear();
            }
            kept.insert(key, Arc::clone(&config));
        }
        Ok(config)
    }
}
