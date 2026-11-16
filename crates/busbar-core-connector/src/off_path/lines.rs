// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the carrier, the host's I/O, the pools, the process's connector, member programs, held
//! spawn environments and the child job build off the request path: a program's spawn arrays, the
//! handle table's segments and an owner's reap, the pools' shards, idle sweep and owner release,
//! the boot proxy posture, the node's own ports, a member's lease tail and spawn dial, a program's
//! resolved environment and the Windows system directory.

use busbar_contract::abi::mechanism::call::{AbiStr, Field};
use busbar_contract::conn::Program;

use crate::carrier::abi;

/// A program destination's argument and environment arrays, as the carrier's `dial` hands them to
/// the entry: built once per program spawn (process spawn setup), each naming `program`'s own
/// bytes.
pub(crate) fn program_destination(program: &Program) -> (Vec<AbiStr>, Vec<Field>) {
    (
        program.args.iter().map(|a| abi(a.as_bytes())).collect(),
        program
            .env
            .iter()
            .map(|(k, v)| Field {
                name: abi(k.as_bytes()),
                value: abi(v.as_bytes()),
            })
            .collect(),
    )
}

/// One segment of the host's handle table, `len` empty slots: allocated once in the process's
/// life, the first time the table grows into it.
pub(crate) fn handle_segment<T>(len: usize) -> Box<[arc_swap::ArcSwapOption<T>]> {
    (0..len).map(|_| arc_swap::ArcSwapOption::empty()).collect()
}

/// Release every handle `owner` holds (the host's I/O table's reap): run only when the owner (a
/// plugin instance) is unloaded. Each slot released names its next generation.
pub(crate) fn reap_handles(
    segments: &[std::sync::OnceLock<Box<[arc_swap::ArcSwapOption<crate::hostio::Entry>]>>],
    free: &mut crate::hostio::Free,
    owner: u64,
) -> Vec<std::sync::Arc<crate::hostio::Entry>> {
    let mut gone = Vec::new();
    for slot in segments
        .iter()
        .filter_map(std::sync::OnceLock::get)
        .flat_map(|s| s.iter())
    {
        if !slot.load_full().is_some_and(|e| e.owner == owner) {
            continue;
        }
        if let Some(e) = slot.swap(None) {
            if let Some(next) = e.id.checked_add(crate::hostio::GENERATION) {
                free.released.push(next);
            }
            free.live -= 1;
            gone.push(e);
        }
    }
    gone
}

/// A host listener's bound address, spelled once: a listener is bound at boot or at a config
/// commit.
pub(crate) fn bound_address(local: &std::net::SocketAddr) -> String {
    local.to_string()
}

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
/// time (a reload or the refresher's renewal), off every request path.
pub(crate) fn resolve_spawn_env(
    refs: &[(String, busbar_contract::secret_ref::SecretRef)],
    secrets: Option<crate::spawn_env::SpawnSecretFn>,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Vec<(String, busbar_contract::redacted::Secret<String>)>, String> {
    let mut env = Vec::with_capacity(refs.len());
    for (name, reference) in refs {
        let secret = secrets.ok_or_else(|| {
            format!(
                "the program's environment `{name}` is a secret reference and no secret \
                 resolver is installed"
            )
        })?;
        let value = reference
            .resolve_template(&|r| secret(r, scope))
            .map_err(|e| {
                format!(
                    "the program's environment `{name}` ({}) did not resolve: {e}",
                    reference.describe()
                )
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

/// The pools' shards, `count` empty maps: made once, with the connector, and shared with every
/// claimed dial's leader.
pub(crate) fn pool_shards<T: Default>(count: usize) -> std::sync::Arc<[std::sync::Mutex<T>]> {
    (0..count)
        .map(|_| std::sync::Mutex::new(T::default()))
        .collect()
}

/// Every shard's map taken out, each shard left empty: the pools' posture is replaced only by
/// bootstrap recovery or a config commit.
pub(crate) fn take_shards<T: Default>(shards: &[std::sync::Mutex<T>]) -> Vec<T> {
    shards
        .iter()
        .map(|shard| std::mem::take(&mut *shard.lock().expect("pool")))
        .collect()
}

/// THE POOLS' IDLE SWEEP: every shard swept once the earliest idle deadline has passed (the reaper
/// claimed that deadline, so one sweep runs per deadline, as a tick does), each idle line whose
/// time ran out taken out, and the next deadline named. The lines taken out are answered for the
/// caller to close once it holds no pool lock.
pub(crate) fn sweep_idle_lines(
    pools: &crate::pool::Pools,
    timeout: std::time::Duration,
    now: std::time::Instant,
) -> crate::pool::Spent {
    let mut spent = crate::pool::Spent::take();
    let mut next: Option<std::time::Instant> = None;
    for shard in &*pools.shards {
        let mut map = shard.lock().expect("pool");
        map.retain(|_, slot| {
            let mut i = slot.lines().len();
            while i > 0 {
                i -= 1;
                match slot.lines()[i].idle {
                    Some(since) if now.duration_since(since) >= timeout => {
                        spent.push(slot.remove(i));
                    }
                    Some(since) => {
                        if let Some(ends) = since.checked_add(timeout) {
                            next = Some(next.map_or(ends, |n| n.min(ends)));
                        }
                    }
                    None => {}
                }
            }
            // A claimed dial in flight keeps its slot (WASTE-EGRESS rule 6).
            !slot.vacant()
        });
    }
    if let Some(next) = next {
        pools
            .reap_due
            .fetch_min(pools.since_epoch(next), std::sync::atomic::Ordering::AcqRel);
    }
    spent
}

/// `owner` is gone (its instance is unloaded): every line dialled for it leaves the pools, and
/// each nobody holds is closed. Every claimed dial in flight for it ends with its slot, and its
/// followers are woken once no shard lock is held (WASTE-EGRESS rule 6).
pub(crate) fn forget_pooled(pools: &crate::pool::Pools, owner: busbar_contract::conn::InstanceId) {
    let mut gone = crate::pool::Spent::take();
    let mut ended = Vec::new();
    for shard in &*pools.shards {
        shard.lock().expect("pool").retain(|key, slot| {
            if key.owner != owner {
                return true;
            }
            slot.empty_into(&mut gone, &mut ended);
            false
        });
    }
    gone.close();
    for opening in ended {
        crate::pool::wake_all(opening.end());
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

/// The ports the node listens on, read off its listen addresses once per config
/// ([`crate::process::own_ports`]).
pub(crate) fn own_ports(listens: &[&str]) -> Vec<u16> {
    listens
        .iter()
        .filter_map(|l| l.rsplit_once(':').and_then(|(_, p)| p.parse().ok()))
        .collect()
}

/// The instance and identity field lines every lease of the member keyed `supervision_key` running
/// `program` carries in its head: spelled once, when the member is declared at a config commit.
pub(crate) fn lease_tail(supervision_key: u64, program: &Program) -> Vec<u8> {
    use base64::Engine as _;
    use busbar_contract::abi::transport::fields::{LINE_END, SEPARATOR};
    use busbar_contract::conn::{PROGRAM_IDENTITY_FIELD, PROGRAM_INSTANCE_FIELD};
    let identity = base64::engine::general_purpose::STANDARD.encode(program.command.as_bytes());
    let mut tail = Vec::new();
    tail.extend_from_slice(PROGRAM_INSTANCE_FIELD.as_bytes());
    tail.extend_from_slice(SEPARATOR);
    let _ = std::io::Write::write_fmt(&mut tail, format_args!("{supervision_key}"));
    tail.extend_from_slice(LINE_END);
    tail.extend_from_slice(PROGRAM_IDENTITY_FIELD.as_bytes());
    tail.extend_from_slice(SEPARATOR);
    tail.extend_from_slice(identity.as_bytes());
    tail.extend_from_slice(LINE_END);
    tail
}

/// The dial that spawns a member's program `command` over its carrier, offering `alpn`: built once
/// per program generation (process spawn setup), never per lease.
pub(crate) fn member_spawn_dial(command: &str, alpn: &[Vec<u8>]) -> crate::compose::Dial {
    crate::compose::Dial {
        target: command.to_owned(),
        tls: None,
        alpn: alpn.to_vec(),
        open_timeout: crate::compose::DEFAULT_OPEN_TIMEOUT,
        opening: None,
        head_words: (Vec::new(), Vec::new()),
        anchors: None,
    }
}

/// The native system directory GetSystemDirectoryW wrote as `wide` UTF-16: read once per process
/// (the child job's trusted Windows system directory).
#[cfg(windows)]
pub(crate) fn system_directory_path(wide: &[u16]) -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    std::path::PathBuf::from(std::ffi::OsString::from_wide(wide))
}
