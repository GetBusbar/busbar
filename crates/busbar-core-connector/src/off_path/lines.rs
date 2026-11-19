// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the carrier, the host's I/O, the pools, the process's connector, member programs, held
//! spawn environments and the child job build off the request path: a program's spawn arrays, the
//! handle table's segments and an owner's reap, the pools' shards, idle sweep and owner release,
//! the boot proxy posture, the node's own ports, a member's lease tail and spawn dial, a program's
//! resolved environment and the Windows system directory.

/// A held environment's references as a debug line names them: each name and its reference's
/// source, never a value. Rendered only into a debug line.
pub(crate) fn described_refs(
    refs: &[(String, busbar_contract::secret_ref::SecretRef)],
) -> Vec<String> {
    refs.iter()
        .map(|(name, reference)| format!("{name} = {}", reference.describe()))
        .collect()
}

/// A program's environment references, held for its spawns: copied once, at load.
pub(crate) fn held_refs(
    refs: &[(String, busbar_contract::secret_ref::SecretRef)],
) -> Vec<(String, busbar_contract::secret_ref::SecretRef)> {
    refs.to_vec()
}

/// Every reference of a program's environment resolved through `secrets`: at load and at config
/// time (a reload or the refresher's renewal), off every request path. A refusal's reason is made
/// shared text here, once, so every spawn it later refuses shares the words.
pub(crate) fn resolve_spawn_env(
    refs: &[(String, busbar_contract::secret_ref::SecretRef)],
    secrets: Option<crate::spawn_env::SpawnSecretFn>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Vec<(String, busbar_contract::redacted::Secret<String>)>, busbar_contract::kept::Text> {
    let shared = |why: String| busbar_contract::kept::Text::from(std::sync::Arc::<str>::from(why));
    let mut env = Vec::with_capacity(refs.len());
    for (name, reference) in refs {
        let secret = secrets.ok_or_else(|| {
            shared(format!(
                "the program's environment `{name}` is a secret reference and no secret \
                 resolver is installed"
            ))
        })?;
        let value = reference
            .resolve_template(&|r| secret(r, scope))
            .map_err(|e| {
                shared(format!(
                    "the program's environment `{name}` ({}) did not resolve: {e}",
                    reference.describe()
                ))
            })?;
        env.push((name.clone(), value));
    }
    Ok(env)
}

/// When a held environment the refresher keeps is first due: one lease after its load, which has
/// just resolved it.
pub(crate) fn first_spawn_env_due() -> std::time::Instant {
    std::time::Instant::now() + crate::spawn_env::SPAWN_ENV_LEASE
}

// The pools are made once per connector and their posture replaced only by bootstrap recovery or a
// config commit: off the request path (callers: the connector's construction and its `pooling`
// builder at boot, `Connector::reconfigure_pools` in recovery and commit).
impl crate::pool::Pools {
    /// The pools for `posture`.
    pub(crate) fn new(posture: crate::pool::PoolPosture) -> Self {
        Self {
            posture: std::sync::RwLock::new(posture),
            shards: crate::pool::shard_count(),
            keys: foldhash::fast::RandomState::default(),
        }
    }

    /// Bootstrap recovery replaces the posture without replacing the connector.
    pub(crate) fn reconfigure(&self, posture: crate::pool::PoolPosture) {
        *self.posture.write().expect("pool posture") = posture;
    }
}

/// THE PROXY POSTURE, said once at boot and audited ([`crate::process::note_proxy_posture`]): the
/// proxy endpoints (never their credentials), `NO_PROXY`, and how the guard judges a proxied
/// target. Nothing when no proxy is configured.
pub(crate) fn note_proxy_posture(by_address: bool) {
    let Ok(env) = crate::proxy::ProxyEnvValues::from_process_env() else {
        return;
    };
    let mut hops = String::new();
    for hop in [
        env.https.as_deref(),
        env.http.as_deref(),
        env.all.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|v| crate::proxy::parse_proxy(v).ok())
    {
        if !hops.is_empty() {
            hops.push(',');
        }
        hops.push_str(hop.endpoint());
    }
    if hops.is_empty() {
        return;
    }
    let no_proxy = env.no.unwrap_or_default();
    let mode = if by_address { "local" } else { "proxy" };
    tracing::info!(
        diag = %busbar_kernel::diagnostics::CONFIG_PROXY_DELEGATES_ADDRESS_CHECK.banner(),
        proxies = %hops,
        no_proxy = %no_proxy,
        proxy_resolution = mode,
        "outbound connections go through a proxy: {}",
        if by_address {
            "every target is resolved here, each address it answers is judged, and the CONNECT \
             names the judged address"
        } else {
            "each target's name is judged; its addresses are judged when it resolves here, and \
             the address check of a name that does not is delegated to the proxy"
        }
    );
    busbar_kernel::audit_ring::AUDIT.record_by(
        "config.egress_proxy",
        &format!("proxy:{hops}:no_proxy={no_proxy}:resolution={mode}"),
        busbar_kernel::audit_ring::OUTCOME_APPLIED,
        "system",
    );
}

/// The node's own ports as the dial judge holds them: replaced only on a config commit.
pub(crate) fn own_ports_held(ports: &[u16]) -> std::sync::Arc<[u16]> {
    ports.into()
}

/// The ports the node listens on, read off its listen addresses (`listen`, `admin_listen`), once
/// per config.
#[must_use]
pub fn own_ports(listens: &[&str]) -> Vec<u16> {
    listens
        .iter()
        .filter_map(|l| l.rsplit_once(':').and_then(|(_, p)| p.parse().ok()))
        .collect()
}

/// The native system directory GetSystemDirectoryW wrote as `wide` UTF-16: read once per process
/// (the child job's trusted Windows system directory).
#[cfg(windows)]
pub(crate) fn system_directory_path(wide: &[u16]) -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    std::path::PathBuf::from(std::ffi::OsString::from_wide(wide))
}

// A held environment is loaded when its program is declared, at a config commit, and a debug line is no
// request's: both off the request path (callers of `load`: the connector's program declaration and member
// programs' declaration).
impl crate::spawn_env::HeldEnv {
    /// `refs` RESOLVED NOW through `secrets` (the resolver the connector was handed; `None`
    pub fn load(
        refs: &[(String, busbar_contract::secret_ref::SecretRef)],
        secrets: Option<crate::spawn_env::SpawnSecretFn>,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<Self, &'static str> {
        if refs.is_empty() {
            return Ok(Self::written_only());
        }
        let held = Self(std::sync::Arc::new(crate::spawn_env::SpawnEnv {
            refs: held_refs(refs),
            secrets,
            held: arc_swap::ArcSwap::from_pointee(crate::spawn_env::resolve(refs, secrets, scope)),
            reloading: std::sync::Mutex::new(()),
        }));
        // An environment that cannot be kept fresh is not held: the declaration that asked for
        // it is refused, and the reason is said here (the declaration's own error carries none).
        if let Err(why) = crate::spawn_env::keep(&held.0) {
            tracing::error!(
                reason = why,
                "a program's environment cannot be kept fresh; its declaration is refused"
            );
            return Err(why);
        }
        Ok(held)
    }
}

impl std::fmt::Debug for crate::spawn_env::HeldEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let refs = described_refs(&self.0.refs);
        f.debug_struct("HeldEnv")
            .field("refs", &refs)
            .field("resolved", &self.0.held.load().0.is_ok())
            .finish()
    }
}
