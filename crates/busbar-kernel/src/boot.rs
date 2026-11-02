use std::sync::Arc;

pub fn hydrate_all(app: &Arc<crate::state::App>) -> Result<(), String> {
    if let Some(gov) = app.governance.as_ref() {
        crate::audit::auditlog::register_and_migrate(app, &gov.store());
    }

    let plane_store = app
        .governance
        .as_ref()
        .map(|gov| crate::store::plane_view::PlaneStoreView::narrow(gov.store()));

    if let Some(store) = &plane_store {
        app.demotion_record.set_sink(Arc::clone(store));
    }
    let ctx = crate::plane_driver::registry::BootCtx::for_hydrate(plane_store, app);
    run_hydrate_hooks(&configured_decls(app), &ctx)
}

fn configured_decls(
    app: &crate::state::App,
) -> Vec<&'static crate::plane_driver::registry::PlaneDecl> {
    crate::plane_driver::registry::plane_decls()
        .iter()
        .copied()
        .filter(|d| app.plane_configured(d))
        .collect()
}

pub fn run_hydrate_hooks(
    decls: &[&'static crate::plane_driver::registry::PlaneDecl],
    ctx: &crate::plane_driver::registry::BootCtx,
) -> Result<(), String> {
    for decl in decls {
        if let Some(hydrate) = decl.hydrate {
            hydrate(ctx)?;
        }
    }
    Ok(())
}

pub fn start_planes(app_handle: &Arc<crate::state::AppHandle>) -> Result<(), String> {
    let card_issuer = app_handle
        .load()
        .governance
        .as_ref()
        .and_then(|g| g.card_issuer());
    let ctx = crate::plane_driver::registry::BootCtx::for_start(app_handle, card_issuer);
    run_start_hooks(&configured_decls(&app_handle.load()), &ctx)
}

pub fn run_start_hooks(
    decls: &[&'static crate::plane_driver::registry::PlaneDecl],
    ctx: &crate::plane_driver::registry::BootCtx,
) -> Result<(), String> {
    for decl in decls {
        if let Some(start) = decl.start {
            start(ctx)?;
        }
    }
    Ok(())
}

pub fn generate_signing_key_hex() -> Result<String, String> {
    let signer =
        crate::governance::signing::TokenSigner::generate(crate::governance::signing::DEFAULT_KID)
            .map_err(|e| e.to_string())?;
    Ok(hex::encode(signer.secret_bytes()))
}

#[cfg(test)]
#[path = "tests/boot_tests.rs"]
mod boot_tests;
