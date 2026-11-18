// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native TLS configurations belong to one immutable network owner and withdrawal epoch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use busbar_plugin_abi::host_side::needs::NeedErr;

use super::TlsPlan;
use crate::tls::store::TrustStore;

const KEPT: usize = 64;

#[derive(Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    epoch: u64,
    host: String,
    waived: bool,
    anchor: [u8; 32],
    alpn: Vec<Vec<u8>>,
}

/// TLS configs for one network generation. Neither client identity is cached.
#[derive(Debug)]
pub struct Configs {
    trust: Arc<TrustStore>,
    kept: Mutex<HashMap<CacheKey, Arc<rustls::ClientConfig>>>,
}

impl Configs {
    /// Construct from the complete operator policy for this network generation.
    #[must_use]
    pub fn new(trust: Arc<TrustStore>) -> Self {
        Self {
            trust,
            kept: Mutex::default(),
        }
    }

    /// Current withdrawal epoch, also used to fence native pooled connections.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.trust.withdrawal_epoch()
    }

    /// Compose TLS by logical destination, preserving exact ordered ALPN and policy epoch.
    pub fn get(
        &self,
        host: &str,
        plan: &TlsPlan<'_>,
        alpn: &[Vec<u8>],
    ) -> Result<Arc<rustls::ClientConfig>, NeedErr> {
        if plan.waive && plan.cert.is_some() {
            return Err(NeedErr::Invalid);
        }
        let cacheable = plan.cert.is_none() && !self.trust.has_client_identity(host);
        let epoch = self.epoch();
        let key = CacheKey {
            epoch,
            host: crate::need::dialled_host(host),
            waived: plan.waive,
            anchor: plan.trust.as_ref().map_or([0; 32], |anchor| anchor.sha256),
            alpn: alpn.to_vec(),
        };
        if cacheable {
            let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(config) = kept.get(&key) {
                if self.epoch() == epoch {
                    return Ok(Arc::clone(config));
                }
            }
        }
        let config = self
            .trust
            .config_for_need(host, plan, alpn)
            .map_err(|error| match error {
                crate::tls::store::TrustRefusal::InvalidNeed => NeedErr::Invalid,
                _ => NeedErr::Tls,
            })?;
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if self.epoch() != epoch {
            return Err(NeedErr::Tls);
        }
        if cacheable {
            if kept.len() >= KEPT {
                kept.clear();
            }
            kept.insert(key, Arc::clone(&config));
        }
        Ok(config)
    }
}
