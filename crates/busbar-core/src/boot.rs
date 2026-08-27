//! THE BOOT SEAM — the entry points `run()` in the `busbar` binary calls, one `pub fn` per boot
//! action, so the internals each action composes stay `pub(crate)`.
//!
//! THE RULE: where the binary needs N internals to perform ONE boot action,
//! expose one function here and leave the N internals crate-private. The alternative — widening
//! `admin::audit::AUDIT`, its `set_sink`/`restore_from_store`, the `plane::taskstore::TASKS` and
//! `calllog::CALLS` statics, `governance::signing::TokenSigner`, and the trust sweeper's
//! machinery to `pub` — would put the one append-only hash chain's storage handle, the token
//! master-key mint and the quarantine loop on the public surface of this crate, where a protocol
//! crate could reach them. A split that forces twenty new `pub`s on security-relevant internals
//! is a design problem; a split that forces a few `boot::*` entry points is a mechanical one.

use std::sync::Arc;

/// DURABLE-STATE HYDRATION, whole and in order: the audit ring FIRST (core, the append-only chain),
/// then every registered plane's own durable state through its [`PlaneDecl::hydrate`] hook — the A2A
/// task table, the MCP per-call log, and the MCP demotion + spent-approval records. Called ONCE from
/// `run()`, BEFORE a listener is bound, so every restored quarantine and spent approval is in force
/// for the first request. A plane hook returning `Err` REFUSES BOOT (propagated with `?`): a plane
/// that cannot restore its durable state must not go on to serve half of it.
///
/// The plane loop replaces four hand-written blocks that each named `crate::mcp::`/`crate::a2a::`
/// directly. The blocks did not change — they MOVED, each into its plane's own `hydrate` hook beside
/// the code it restores — and this function now names no plane: it folds over [`plane_decls`] and
/// calls the hook each plane declared. What each hook may touch of the durable home is narrowed at the
/// seam: [`BootCtx`]'s store is `PlaneStore`, never the `append_audit`-carrying `Store` (invariant
/// (a)), so only the audit block below — which IS the chain — holds the full `Store`.
pub fn hydrate_all(app: &Arc<crate::state::App>) -> Result<(), String> {
    // DURABLE AUDIT (#17): the admin audit log's ONE durable path is the neutral journal seam
    // ([`crate::plane::auditlog`]). Register the `audit` stream, run the ONE-TIME legacy-table →
    // `plane_records` migration (idempotent; a no-op on a migrated / fresh / memory store), and RESTORE
    // the audit log FROM `plane_records` — seeding both the seam chain position (so a later append
    // continues the same chain) and the `AUDIT_LOG` read-model ring `GET /audit` serves. The RAM
    // default (`store: memory`) keeps nothing durable, so the log is ephemeral BY DESIGN, started fresh
    // on every boot. A chain-verification failure on restore is logged as a tamper signal inside the
    // seam restore; there is no file fallback to fall back to.
    //
    // This is NOT a plane and is deliberately NOT a `hydrate` hook: the audit chain's migration reads
    // the FULL `Store` (the legacy `list_audit` table it copies from), the one durable-state block that
    // must hold what every plane hook is narrowed away from.
    if let Some(gov) = app.governance.as_ref() {
        crate::plane::auditlog::register_and_migrate(app, &gov.store());
    }

    // THE PLANE HYDRATION FOLD. Each plane restores its OWN durable state through the `hydrate` hook
    // it declared, in plane-list order (the audit ring, above, already went first). The store handed
    // to every hook is NARROWED to the plane surface at the seam: an `Arc<dyn PlaneStore>` (task /
    // provenance / mcp-call / demotion / spent methods only), never the `Arc<dyn Store>` that also
    // carries `append_audit`. It is `None` when governance configured no store — the same
    // `if let Some(gov)` gate the four blocks used to have, hoisted to one narrowing here — so a hook
    // then skips its restore and the plane's durable state is ephemeral BY DESIGN, exactly as the
    // audit ring is.
    let plane_store = app
        .governance
        .as_ref()
        .map(|gov| crate::plane::store::PlaneStoreView::narrow(gov.store()));
    let ctx = crate::plane::registry::BootCtx::for_hydrate(plane_store, app);
    run_hydrate_hooks(crate::plane::registry::plane_decls(), &ctx)
}

/// THE HYDRATE FOLD. Split from [`hydrate_all`] and taking its decl list by argument for the reason
/// [`crate::plane::registry::build_dispatch`] is split from `appbuild`: the boot-refuses-on-`Err`
/// ratchet (R2-boot) is then drivable over an INJECTED decl — a plane whose `hydrate` returns `Err` —
/// without the process plane `OnceLock`, which can be initialised only once per test binary. A hook's
/// `Err` aborts the fold with `?`; a plane that half-restored its durable state must not serve.
pub(crate) fn run_hydrate_hooks(
    decls: &[&'static crate::plane::registry::PlaneDecl],
    ctx: &crate::plane::registry::BootCtx,
) -> Result<(), String> {
    for decl in decls {
        if let Some(hydrate) = decl.hydrate {
            hydrate(ctx)?;
        }
    }
    Ok(())
}

/// START EVERY REGISTERED PLANE'S BACKGROUND WORK, AFTER the listeners are built — the MCP tool-list
/// refresh sweep and the A2A re-verification job — by folding over [`plane_decls`] and calling each
/// plane's [`PlaneDecl::start`] hook in plane-list order (MCP before A2A, the order these two jobs
/// have always started in). A hook returning `Err` REFUSES BOOT (propagated with `?`): an A2A
/// outbound client identity that does not resolve is a startup failure naming its source, never a
/// warning — a deployment that re-verifies nothing for an agent while reading as though mutual TLS
/// were configured is exactly what booting past it would produce.
///
/// This function names no plane. Each plane's job MOVED into its own `start` hook beside the code it
/// starts; the live-fetch transport and the identity resolver all stay `pub(crate)` in their planes.
/// The one capability the A2A hook needs without reaching into the engine is handed on the
/// [`BootCtx`]: busbar's PUBLIC card-issuer key (its `kid` and SPKI, computed core-side HERE — the
/// signing seed never crosses the seam, invariant (a)). Verify-on-call replaced the background sweep,
/// so no reverify-loop spawner crosses this seam any more.
pub fn start_planes(app_handle: &Arc<crate::state::AppHandle>) -> Result<(), String> {
    // BUSBAR'S PUBLISHED CARD-ISSUER KEY, computed core-side from the card signer and reduced to its
    // PUBLIC halves before it crosses the seam. The signer (and the seed it derives from) never
    // leaves core; a start hook receives only the `kid` and the base64 SPKI it publishes for callers
    // to pin busbar by. `None` when this deployment mints no card-issuer key.
    // The card-issuer key exists only to feed the A2A `start` hook (the sole consumer of the SPKI a
    // caller pins busbar by). `a2a_card_issuer` derives it through the A2A plane's `card_signer` seam
    // and reduces it to its PUBLIC halves core-side; with the A2A plane compiled out no plane derives
    // one and it is `None` — no plane's `start` hook reads it — so no `#[cfg]` is needed here.
    let card_issuer = app_handle
        .load()
        .governance
        .as_ref()
        .and_then(|g| g.a2a_card_issuer());
    let ctx = crate::plane::registry::BootCtx::for_start(app_handle, card_issuer);
    run_start_hooks(crate::plane::registry::plane_decls(), &ctx)
}

/// THE START FOLD. Split from [`start_planes`] and taking its decl list by argument, exactly as
/// [`run_hydrate_hooks`] is, so R2-boot — a plane whose `start` returns `Err` REFUSES BOOT — is
/// drivable over an injected decl without the process plane `OnceLock` and without booting real
/// listeners. A hook's `Err` aborts the fold with `?`, which is how an A2A outbound identity that
/// does not resolve stops the boot rather than yielding a deployment that re-verifies nothing.
pub(crate) fn run_start_hooks(
    decls: &[&'static crate::plane::registry::PlaneDecl],
    ctx: &crate::plane::registry::BootCtx,
) -> Result<(), String> {
    for decl in decls {
        if let Some(start) = decl.start {
            start(ctx)?;
        }
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
