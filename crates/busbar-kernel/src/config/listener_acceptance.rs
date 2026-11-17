// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A root listener serves plaintext only on an explicit, audited acceptance (#359 SEC-L1; owner ruling L1
//! "Refuse, give remedy"; DES-359 r3 §L1).
//!
//! The data listener (`listen`) and the admin listener (`admin_listen`) each refuse to boot without TLS
//! (`tls:` / `admin_tls:`) unless their acceptance is written beside them:
//! `listen_insecure_transport: { accept: [plaintext], reason: "..." }` and
//! `admin_listen_insecure_transport: { ... }`. There is no address exemption (loopback included) and nothing
//! writes the acceptance for the operator: the upgrade does not, and the refusal gives the one-line remedy.
//!
//! The acceptance is file-only. It is not a Store overlay setting (the overlay's root settings refuse the key
//! as unknown), so an admin overlay can never turn a TLS listener into a plaintext one. An overlay that SETS
//! `tls` wins: the file's acceptance is then inert and the boot warns that it can be removed. TLS and an
//! acceptance written together in the file contradict each other and are refused.

use busbar_plugin_abi::host_side::caller::Accept;

use super::min3::{insecure_transport_at, InsecureTransport};
use crate::diagnostics::coded;

/// One root listener: its address setting, the TLS key that secures it and the key that accepts it in the
/// clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootListener {
    /// `listen` or `admin_listen`.
    pub setting: &'static str,
    /// `tls` or `admin_tls`.
    pub tls: &'static str,
    /// `listen_insecure_transport` or `admin_listen_insecure_transport`.
    pub acceptance: &'static str,
}

/// The data listener.
pub const DATA: RootListener = RootListener {
    setting: "listen",
    tls: "tls",
    acceptance: "listen_insecure_transport",
};

/// The admin listener.
pub const ADMIN: RootListener = RootListener {
    setting: "admin_listen",
    tls: "admin_tls",
    acceptance: "admin_listen_insecure_transport",
};

/// The root listeners, in the order their refusals are reported.
pub const ROOT_LISTENERS: [RootListener; 2] = [DATA, ADMIN];

impl RootListener {
    /// The one-line remedy the refusal and the upgrade report print for this listener.
    #[must_use]
    pub fn remedy(&self) -> String {
        format!(
            "add `{tls}:` (cert and key), or to serve it in the clear deliberately add \
             `{key}: {{ accept: [plaintext], reason: \"<why>\" }}` with your real reason",
            tls = self.tls,
            key = self.acceptance,
        )
    }

    /// The coded refusal of this listener bound at `address` with neither TLS nor an acceptance.
    #[must_use]
    pub fn refusal(&self, address: &str) -> String {
        coded::config_plaintext_listener(format!(
            "`{setting}` {address} has no TLS and no acceptance: it would serve plaintext, so anything \
             sent to it, credentials included, could be read and altered on the network path; {remedy}",
            setting = self.setting,
            remedy = self.remedy(),
        ))
        .into()
    }
}

/// The root listeners' accepted plaintext, as resolved from the configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListenerAcceptances {
    /// `listen_insecure_transport`, when written and valid.
    pub listen: Option<InsecureTransport>,
    /// `admin_listen_insecure_transport`, when written and valid.
    pub admin_listen: Option<InsecureTransport>,
    /// The acceptance keys the file wrote that an overlay `tls` made inert: each is warned as removable.
    pub inert: Vec<&'static str>,
}

impl ListenerAcceptances {
    /// The acceptance of `listener`, if one is in force.
    #[must_use]
    pub fn of(&self, listener: &RootListener) -> Option<&InsecureTransport> {
        if *listener == ADMIN {
            self.admin_listen.as_ref()
        } else {
            self.listen.as_ref()
        }
    }
}

/// An overlay set `listener`'s TLS over `deploy`: the file's acceptance no longer applies. It is kept only as
/// the name the boot warns about, never as a contradiction to refuse.
pub fn supersede(deploy: &mut super::DeployCfg, listener: &RootListener) {
    let written = if *listener == ADMIN {
        &mut deploy.admin_listen_insecure_transport
    } else {
        &mut deploy.listen_insecure_transport
    };
    if written.take().is_some()
        && !deploy
            .inert_listener_acceptances
            .contains(&listener.acceptance)
    {
        deploy.inert_listener_acceptances.push(listener.acceptance);
    }
}

/// Judges each acceptance `deploy` writes: its grammar (BUSBAR-3163, the `insecure_transport` grammar), the
/// only word a listener may accept (`plaintext`: it serves either TLS or the clear, so `unverified_tls` has no
/// meaning here), and that TLS is not written beside it. Every refusal joins `errors`.
pub(crate) fn resolve(deploy: &super::DeployCfg, errors: &mut Vec<String>) -> ListenerAcceptances {
    let mut out = ListenerAcceptances {
        inert: deploy.inert_listener_acceptances.clone(),
        ..ListenerAcceptances::default()
    };
    for listener in ROOT_LISTENERS {
        let (written, tls) = if listener == ADMIN {
            (
                deploy.admin_listen_insecure_transport.as_ref(),
                deploy.admin_tls.is_some(),
            )
        } else {
            (
                deploy.listen_insecure_transport.as_ref(),
                deploy.tls.is_some(),
            )
        };
        let Some(written) = written else { continue };
        if tls {
            errors.push(
                coded::config_plaintext_listener(format!(
                    "`{key}` is written beside `{tls}`: a listener with TLS has no plaintext to accept; \
                     remove `{key}`",
                    key = listener.acceptance,
                    tls = listener.tls,
                ))
                .into(),
            );
            continue;
        }
        match insecure_transport_at(listener.acceptance, written) {
            Ok(accepted) if accepted.accept == Accept(Accept::PLAINTEXT) => {
                if listener == ADMIN {
                    out.admin_listen = Some(accepted);
                } else {
                    out.listen = Some(accepted);
                }
            }
            Ok(_) => errors.push(format!(
                "BUSBAR-3163: {key}.accept names unverified_tls: a listener serves TLS or plaintext, so the \
                 only word it accepts is plaintext",
                key = listener.acceptance,
            )),
            Err(why) => errors.push(why),
        }
    }
    out
}

/// The validation pass: each root listener with neither TLS nor an acceptance refuses, with its remedy.
#[must_use]
pub fn refusals(cfg: &super::RootCfg) -> Vec<String> {
    ROOT_LISTENERS
        .iter()
        .filter_map(|listener| {
            let (address, tls) = if *listener == ADMIN {
                (&cfg.admin_listen, cfg.admin_tls.is_some())
            } else {
                (&cfg.listen, cfg.tls.is_some())
            };
            (!tls && cfg.listener_acceptances.of(listener).is_none())
                .then(|| listener.refusal(address))
        })
        .collect()
}

/// The root listeners a configuration serves in the clear under its acceptance, as `(listener, acceptance)`.
#[must_use]
pub fn accepted(cfg: &super::RootCfg) -> Vec<(RootListener, &InsecureTransport)> {
    ROOT_LISTENERS
        .iter()
        .filter_map(|listener| {
            cfg.listener_acceptances
                .of(listener)
                .map(|accepted| (*listener, accepted))
        })
        .collect()
}

/// The audit action of a setting that runs with an insecure-transport acceptance (TRANSPORT-SECURITY-POLICY §4),
/// shared with the plane seats' acceptance rows.
pub const INSECURE_ACCEPTED: &str = "config.insecure_transport_accepted";

/// The audit resource of `listener` served in the clear: `listener:<setting>:accept=plaintext`.
#[must_use]
pub fn audit_resource(listener: &RootListener) -> String {
    format!("listener:{}:accept=plaintext", listener.setting)
}

/// The ERROR banner of `listener` served in the clear at `address` under `accepted`.
#[must_use]
pub fn banner(listener: &RootListener, address: &str, accepted: &InsecureTransport) -> String {
    format!(
        "`{setting}` {address} serves PLAINTEXT under `{key}` (reason: \"{reason}\"): anything sent to it, \
         credentials included, can be read and altered by anyone who can intercept the network path. Add \
         `{tls}:` and remove `{key}` to secure it",
        setting = listener.setting,
        key = listener.acceptance,
        tls = listener.tls,
        reason = accepted.reason,
    )
}

/// The WARN line of an acceptance an overlay `tls` made inert.
#[must_use]
pub fn inert_line(key: &str) -> String {
    format!(
        "`{key}` in config.yaml is inert: the Store overlay sets TLS for its listener, so the listener is not \
         served in the clear. Remove `{key}` from config.yaml"
    )
}

/// The build of a generation: each root listener served in the clear under its acceptance gets its ERROR
/// banner and its `config.insecure_transport_accepted` row; each inert acceptance is warned as removable.
pub fn announce(cfg: &super::RootCfg) {
    for (listener, accepted) in accepted(cfg) {
        let address = if listener == ADMIN {
            &cfg.admin_listen
        } else {
            &cfg.listen
        };
        let line = banner(&listener, address, accepted);
        tracing::error!("{line}");
        crate::audit_ring::AUDIT.record_by(
            INSECURE_ACCEPTED,
            &audit_resource(&listener),
            crate::audit_ring::OUTCOME_APPLIED,
            "system",
        );
    }
    for key in &cfg.listener_acceptances.inert {
        tracing::warn!("{}", inert_line(key));
    }
}

#[cfg(test)]
#[path = "tests/listener_acceptance_tests.rs"]
mod tests;
