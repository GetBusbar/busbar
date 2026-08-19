//! THE BOOT SEAM — the entry points `run()` in the `busbar` binary calls, one `pub fn` per boot
//! action, so the internals each action composes stay `pub(crate)`.
//!
//! THE RULE: where the binary needs N internals to perform ONE boot action,
//! expose one function here and leave the N internals crate-private. The alternative — widening
//! `admin::audit::AUDIT`, its `set_sink`/`restore_from_store`, the `a2a::taskstore::TASKS` and
//! `mcp::calllog::CALLS` statics, `governance::signing::TokenSigner`, and the trust sweeper's
//! machinery to `pub` — would put the one append-only hash chain's storage handle, the token
//! master-key mint and the quarantine loop on the public surface of this crate, where a protocol
//! crate could reach them. A split that forces twenty new `pub`s on security-relevant internals
//! is a design problem; a split that forces a few `boot::*` entry points is a mechanical one.

use std::sync::Arc;

/// A store READ failure and a chain-VERIFICATION failure on audit restore are different events: the
/// first is a hiccup, the second is tamper evidence. Reporting both as "chain verification" trains
/// an operator to ignore the one that matters, so `hydrate_all`'s restore-error match keys on this
/// to pick `tracing::warn!` vs `tracing::error!`. Module-level (not inlined in the match guard) so
/// it's unit-testable; see the boot tests.
pub(crate) fn is_audit_restore_read_hiccup(e: &str) -> bool {
    e.starts_with("audit restore read failed")
}

/// DURABLE-STATE HYDRATION, whole and in order: the audit ring, the A2A task table, the MCP
/// per-call log, and the MCP demotion + spent-approval records — restored from the configured
/// governance store, sinks attached write-through, chain verification narrated (hiccup vs tamper)
/// exactly as each block's comment states. Called ONCE from `run()`, BEFORE a listener is bound,
/// so every restored quarantine and spent approval is in force for the first request.
pub fn hydrate_all(app: &Arc<crate::state::App>) {
    // DURABLE AUDIT (#17): the audit log is STATEFUL, so its single durable home is the configured
    // governance store — never a side-car file (store-or-RAM rule). When a durable store is configured
    // (sqlite/postgres/valkey), attach it as the write-through SINK (every future admin mutation
    // persists as it is appended) and RESTORE the ring from it: the store is the source of truth, so
    // its history (which can exceed the RAM ring bound) survives restart with the hash chain intact.
    // The RAM default (`store: memory`) has no durable audit — the sink no-ops and the restore reads
    // nothing — so the log is ephemeral BY DESIGN, started fresh on every boot. A chain-verification
    // failure on restore is logged as a tamper signal; there is no file fallback to fall back to.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::admin::audit::AUDIT.set_sink(store.clone());
        match crate::admin::audit::AUDIT.restore_from_store(store.as_ref()) {
            Ok(0) => {} // no durable audit (memory default / empty) — start with an empty ring
            Ok(n) => tracing::info!(
                entries = n,
                "audit log restored from the durable governance store"
            ),
            // A store READ failure and a chain-VERIFICATION failure are different events: the first
            // is a hiccup, the second is tamper evidence. Reporting both as "chain verification"
            // trains an operator to ignore the one that matters.
            Err(e) if is_audit_restore_read_hiccup(&e) => tracing::warn!(
                error = %e,
                "could not read the durable audit log; starting with an empty audit ring"
            ),
            Err(e) => tracing::error!(
                error = %e,
                "durable audit CHAIN VERIFICATION failed — the persisted log does not verify \
                 against its own hash chain; starting with an empty audit ring"
            ),
        }
    }

    // DURABLE A2A TASK STATE. A2A is ASYNC BY DESIGN: a task spans turns, can be interrupted
    // waiting on a human, and can outlive the process that started it. An in-memory task table
    // therefore loses every in-flight task and every interrupt on restart, which is the difference
    // between a suspend/resume that is real and one that is nominal. Same shape as the durable audit
    // above and for the same reasons: the configured governance store is the single durable home
    // (store-or-RAM rule), attached as a write-through SINK and read back here.
    //
    // The RAM default (`store: memory`) implements none of the task methods, so the sink no-ops and
    // the restore reads nothing — in-flight tasks are ephemeral BY DESIGN there, exactly as the
    // audit log is. That is reported rather than papered over.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::a2a::taskstore::TASKS.set_sink(store.clone());
        match crate::a2a::taskstore::TASKS.restore_from_store(store.as_ref()) {
            Ok(r) if r == crate::a2a::taskstore::Rehydrated::default() => {}
            Ok(r) => {
                tracing::info!(
                    active = r.active,
                    terminal = r.terminal,
                    unreadable = r.unreadable,
                    "A2A in-flight tasks rehydrated from the durable governance store"
                );
                // An UNREADABLE row is an in-flight task that this binary cannot resume. Reported
                // separately and at WARN, because summing it into the restored count is how a task
                // that silently ceased to exist across a deploy stays invisible.
                if r.unreadable > 0 {
                    tracing::warn!(
                        rows = r.unreadable,
                        "persisted A2A task rows could not be read back and are NOT resumable; \
                         they were most likely written by a different engine version"
                    );
                }
                // A chain break is TAMPER EVIDENCE and is a different event from a read hiccup, so
                // it is logged at ERROR and names the task rather than being folded into a count.
                for brk in &r.chain_breaks {
                    tracing::error!(
                        task_id = %brk.scope,
                        break_detail = %brk,
                        "A2A per-task provenance CHAIN VERIFICATION FAILED on restore"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "could not read durable A2A task state; in-flight tasks start empty"
            ),
        }
    }

    // DURABLE MCP PER-CALL LOG. The tamper-evident record of who called which tool, under which
    // approved digest, and whether it went out — the Art 26(6) record-keeping pillar, and the thing
    // that makes "tamper-evident audit" a property an operator can exercise rather than a sentence.
    //
    // Attached here for the same reason and in the same shape as the two blocks above: the
    // configured governance store is the single durable home (store-or-RAM rule), attached as a
    // write-through sink and READ BACK, because a write's `Ok(())` proves nothing about a trait
    // whose defaults accept and keep nothing.
    //
    // THE RESTORE IS NOT A FORMALITY. It is the only place in a running deployment where a persisted
    // chain is recomputed, so it is also the only place a tamper is detected — every break it finds
    // is logged at ERROR, naming the principal, while the records stay restored (refusing to restore
    // them would let anyone able to write to the store DELETE a caller's history by corrupting one
    // byte). With `store: memory` nothing is implemented, the sink no-ops and this reports zero: the
    // call log is ephemeral BY DESIGN there, exactly as the audit ring and the task table are.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        crate::mcp::calllog::CALLS.set_sink(store.clone());
        match crate::mcp::calllog::CALLS.restore_from_store(store.as_ref()) {
            Ok(r) if r == crate::mcp::calllog::Restored::default() => {}
            Ok(r) => {
                tracing::info!(
                    principals = r.principals,
                    records = r.records,
                    "MCP per-call log restored from the durable governance store"
                );
                // An ENUMERATED-BUT-EMPTY chain is the one shape the verifier cannot judge alone,
                // and it is what one caller's evidence being deleted wholesale looks like. Counted
                // and surfaced separately rather than summed into `principals`.
                if r.empty_chains > 0 {
                    tracing::warn!(
                        principals = r.empty_chains,
                        "the durable MCP call log enumerates these principals but holds NO records \
                         for them; their chains reopen at seq 1"
                    );
                }
                for brk in &r.chain_breaks {
                    tracing::error!(
                        break_detail = %brk,
                        "MCP per-call CHAIN VERIFICATION FAILED on restore — TAMPER EVIDENCE"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "could not read the durable MCP per-call log; chains start at their persisted \
                 tail being unknown, which means a principal with rows in the store may reopen at \
                 seq 1 and collide"
            ),
        }
    }

    // THE DURABLE MCP DEMOTION RECORD, and the SPENT-APPROVAL LEDGER. Two security properties that
    // were process-local, attached to the same single durable home for the same reason as the three
    // blocks above, and each closing a window that a restart used to re-open:
    //
    //   * A DEMOTED UPSTREAM stays demoted. Drift quarantine is derived from a live observation, and
    //     a restarted process has none — so a server nobody has looked at and a server somebody
    //     looked at and demoted became indistinguishable, and the declarative fallback (which is
    //     right for the first) handed the second its approval back. The record is replayed here,
    //     BEFORE a listener is bound, so the quarantine is in force for the first request.
    //
    //   * A SPENT APPROVAL stays spent, across a restart AND across a fleet. The in-process ledger
    //     makes a sealed confirmation single-use per node for the life of the process; two nodes
    //     share the signing key, so they share the seal, and without a shared ledger one approval
    //     was redeemable once per node. On a money-moving tool that is the defect the gate exists to
    //     stop.
    //
    // With `store: memory` both no-op and the pre-existing process-local behaviour is exactly what
    // remains — the same documented posture the audit ring, the task table and the call log have.
    if let Some(gov) = app.governance.as_ref() {
        let store = gov.store();
        app.plane_approvals.set_sink(store.clone());
        app.mcp_demotions.set_sink(store.clone());
        match crate::mcp::demotion::hydrate(app) {
            0 => {}
            n => tracing::warn!(
                servers = n,
                "MCP upstream demotions restored from the durable governance store: these servers \
                 were quarantined before the last restart and are refused until an operator works \
                 the change or a sweep observes them serving what was approved"
            ),
        }
    }
}

/// THE A2A RE-VERIFICATION JOB. Spawned only when `agents:` defines a plane; resolves the outbound
/// client identities ONCE (an identity that does not resolve is a boot refusal — the returned
/// `Err` — never a warning), publishes busbar's card-issuer key beside the plane start, builds the
/// per-agent transports once, and starts the one sweep loop. The sweeper type, the live-fetch
/// transport and the identity resolver all stay `pub(crate)`: this function is the only doorway.
pub fn spawn_a2a_reverify(
    app_handle: &crate::state::AppHandle,
    shutdown: &tokio::sync::broadcast::Sender<()>,
) -> Result<(), String> {
    // THE A2A RE-VERIFICATION JOB. An approval is a statement about a document at a moment and
    // nothing keeps it true; the pin catches a change only when somebody looks, and this is what
    // makes somebody look. Spawned only when `agents:` defines a plane — a deployment that fronts
    // no agents starts no job — and spawned once here rather than on apply, for the same reason the
    // flusher is: a second job against the same registry would double every fetch and race every
    // ledger stamp.
    if let Some(plane) = app_handle.load().a2a.clone() {
        tracing::info!(
            agents = plane.len(),
            tick_secs = crate::trust::sweep::SWEEP_TICK.as_secs(),
            "a2a: re-verification job started"
        );
        // PUBLISH BUSBAR'S AGENT-CARD ISSUER KEY, once, at the one moment an operator is watching.
        //
        // busbar signs the cards it serves so external callers have something to pin it BY, and a
        // pin is only a root if the pinning party got the key OUT OF BAND — which means a human has
        // to be able to read it off this deployment and hand it over. It is a PUBLIC key, so a log
        // line is the right place for it; the secret it is derived from never appears here or
        // anywhere else. Logged beside the plane's start rather than at key resolution, because
        // this value only means anything where an A2A plane is actually serving cards.
        if let Some(signer) = app_handle
            .load()
            .governance
            .as_ref()
            .and_then(|g| g.a2a_card_signer())
        {
            tracing::info!(
                kid = signer.kid(),
                issuer_key = signer.issuer_spki_base64(),
                "a2a: agent cards served by this deployment are signed with this key; give it to \
                 callers out of band so they can pin busbar"
            );
        }
        // THE OUTBOUND CLIENT CERTIFICATES, resolved ONCE, HERE, and fatal if they do not.
        //
        // Same discipline as `tls::build_server_config` on the inbound side: a cert/key that does
        // not load is a startup failure naming its source, never a warning. A registration whose
        // `client_identity:` did not resolve could never complete a handshake with its endpoint, so
        // booting past it would produce a deployment that re-verifies nothing for that agent while
        // reading, in config and in the admin API, as though mutual TLS were configured.
        let a2a_identities = crate::a2a::transport::resolve_client_identities(
            &app_handle.load().agent_defs,
            &app_handle.load().secret_resolver,
        )
        .map_err(|e| format!("a2a: outbound client identity: {e}"))?;
        // Handle intentionally dropped, exactly as the flusher's is: the job runs for the process
        // lifetime and exits its own loop on the shutdown broadcast.
        // THE PER-AGENT TRANSPORTS, BUILT ONCE for the job's lifetime rather than per tick. The
        // identities were resolved at boot and the plane the job holds is this generation's, so
        // rebuilding the bundle every thirty seconds would re-derive a constant — and, now that a
        // transport can carry a private key, would do so with key material in hand on every tick.
        let live = std::sync::Arc::new(crate::a2a::transport::LiveCardFetch::presenting(
            plane.fetch_policy().clone(),
            &a2a_identities,
        ));
        std::mem::drop(crate::trust::sweep::spawn(
            crate::a2a::verify::ReverifySweeper { plane, live },
            shutdown.subscribe(),
        ));
    }

    Ok(())
}

/// `--generate-signing-key`'s mint: a fresh ed25519 signing secret from the OS RNG, returned as 64
/// hex chars. The signer type and `DEFAULT_KID` stay `pub(crate)`; the CLI needs a hex string, not
/// a `TokenSigner`.
pub fn generate_signing_key_hex() -> Result<String, String> {
    let signer =
        crate::governance::signing::TokenSigner::generate(crate::governance::signing::DEFAULT_KID)
            .map_err(|e| e.to_string())?;
    Ok(hex::encode(signer.secret_bytes()))
}
