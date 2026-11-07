// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual product Store and canonical transaction queue; no timing sleeps or substitute Store.
use crate::root::test_plugins as plugins;
use busbar_contract::Secret;
use busbar_kernel::auth::{effect, AdminDoor};
use busbar_kernel::config::transaction::{config_transaction, effect_lock, Outcome, TxnError};
use busbar_kernel::persistence::scoped::{Outcome as StoreOutcome, ScopedStore};
use busbar_kernel::state::AppHandle;
use std::sync::Arc;

const SCHEMA: &str = "busbar.admin-effect-test.v1";

async fn persist(store: Arc<ScopedStore>, id: &'static str) -> Result<(), String> {
    match store
        .put(SCHEMA, id.as_bytes(), Secret::new(b"committed".to_vec()))
        .await
    {
        Ok(StoreOutcome::Applied) => Ok(()),
        other => Err(format!("effect persistence was not confirmed: {other:?}")),
    }
}
async fn recorded(store: &ScopedStore, id: &str) -> Option<Vec<u8>> {
    store
        .get(SCHEMA, id.as_bytes())
        .await
        .expect("actual native effect read")
        .map(|bytes| bytes.expose(&busbar_kernel::seal::lend()).clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_store_queued_effect_rechecks_revoked_provider_and_preserves_committed_receipt() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-effect-authority-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the node book and rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }

    let handle = Arc::new(AppHandle::new(Arc::new(app)));
    let original = handle.load();
    let store = Arc::new(
        ScopedStore::host_private(
            original
                .governance
                .as_ref()
                .unwrap()
                .core_store_handle()
                .unwrap(),
            "busbar.admin-effect-test",
            [SCHEMA.to_string()],
        )
        .unwrap(),
    );
    let headers = axum::http::HeaderMap::from_iter([(
        axum::http::HeaderName::from_static("x-admin-token"),
        "admintok".parse().unwrap(),
    )]);
    let target = "/api/v1/admin/config/settings";
    let door = busbar_kernel::auth::admin_verdict_async(&original, "PUT", target, &headers)
        .await
        .door;
    assert!(effect::full_operator(&door));
    let context = effect::Context::new("PUT", target, headers, &door);

    independent_store_effects(&original, &store, operator).await;

    // Every representation reaches Commit with a resolved generation. Refusal precedes the
    // exact persistence closure and the pointer swap, including a whole-parent replacement.
    for sensitive in ["protected-empty", "ceiling-raise"] {
        let mut next = (*handle.load()).clone();
        next.config_version += 1;
        if sensitive == "protected-empty" {
            next.admin_chain.clear();
        } else {
            next.identity_providers
                .get_mut(operator)
                .unwrap()
                .max_admin_scope = Some("full".into());
        }
        let next = Arc::new(next);
        let result: Result<(), TxnError> = effect::scope(
            Some(context.clone()),
            config_transaction(&handle, |_| {
                Ok(Outcome::commit_async(
                    next,
                    persist(store.clone(), "denied-security"),
                    (),
                ))
            }),
        )
        .await;
        assert!(
            matches!(result, Err(TxnError::Conflict(_))),
            "{sensitive}: {result:?}"
        );
        assert!(recorded(&store, "denied-security").await.is_none());
        assert!(Arc::ptr_eq(&original, &handle.load()));
    }

    // A real chain verdict with only the config-edit verb must remain limited at the shared
    // semantic boundary, even when its subject happens to spell the builtin operator id.
    let mut delegated = (*original).clone();
    let issuer = Arc::new(RoleProvider);
    delegated.admin_chain = vec!["scoped-provider".into()];
    delegated.admin_modules = Arc::new(busbar_kernel::auth::AdminAuthChain {
        operator: busbar_kernel::auth::Operator::new(operator),
        modules: [(
            "scoped-provider".into(),
            busbar_kernel::auth::AdminModule { calls: issuer },
        )]
        .into_iter()
        .collect(),
    });
    delegated
        .auth_scope_caps
        .insert("scoped-provider".into(), "full".into());
    delegated.role_bindings.insert(
        "scoped-provider".into(),
        [(
            "editor".into(),
            busbar_kernel::config::RoleBindingCfg {
                verbs: Some(serde_json::json!(["put_config_settings"])),
                ..Default::default()
            },
        )]
        .into_iter()
        .collect(),
    );
    let delegated_handle = Arc::new(AppHandle::new(Arc::new(delegated)));
    let delegated_door = busbar_kernel::auth::admin_verdict_async(
        &delegated_handle.load(),
        "PUT",
        target,
        &Default::default(),
    )
    .await
    .door;
    assert!(busbar_kernel::auth::admin_door_admits(
        &delegated_door,
        "PUT",
        target
    ));
    assert!(!effect::full_operator(&delegated_door));
    let delegated_context =
        effect::Context::new("PUT", target, Default::default(), &delegated_door);
    for change in [
        "role-parent-replacement",
        "provider-settings",
        "provider-remove",
    ] {
        let result: Result<(), TxnError> = effect::scope(
            Some(delegated_context.clone()),
            config_transaction(&delegated_handle, |txn| {
                let mut next = (**txn.app()).clone();
                match change {
                    "role-parent-replacement" => {
                        next.role_bindings
                            .get_mut("scoped-provider")
                            .unwrap()
                            .get_mut("editor")
                            .unwrap()
                            .admin_scope = Some("full".into());
                    }
                    "provider-settings" => {
                        next.identity_providers
                            .get_mut(operator)
                            .unwrap()
                            .settings
                            .insert("replacement".into(), serde_json::json!(true));
                    }
                    _ => {
                        next.identity_providers.shift_remove(operator);
                    }
                }
                Ok(Outcome::commit_async(
                    Arc::new(next),
                    persist(store.clone(), "delegated-security"),
                    (),
                ))
            }),
        )
        .await;
        assert_eq!(result, Err(TxnError::Forbidden), "{change}");
        assert!(recorded(&store, "delegated-security").await.is_none());
    }
    // Denied plugin-trust candidates must be refused before the builder can open their code,
    // not merely at the final pointer swap. This exercises the existing String builder error
    // path and verifies that the transaction retains its typed Forbidden admission result.
    let cfg = busbar_kernel::config::resolve(
        &busbar_kernel::config::deploy_from_deserializer(document.clone()).unwrap(),
        &Default::default(),
    )
    .unwrap();
    let mut unsafe_plugins = plugins::trusted_config(&directory);
    unsafe_plugins.trust.allow_unsigned = true;
    unsafe_plugins.dir = directory
        .join("must-not-be-opened")
        .to_string_lossy()
        .into_owned();
    let refused_build: Result<(), TxnError> = effect::scope(
        Some(delegated_context.clone()),
        config_transaction(&delegated_handle, |txn| {
            let snapshot = txn.app().clone();
            Ok(txn.store_write_async(async move {
                let (_unexpected_app, _unexpected_rotate, _uncommitted_limits) =
                    crate::root::real_store::build_app(
                        cfg,
                        unsafe_plugins,
                        None,
                        Default::default(),
                        Default::default(),
                        (None, None),
                        Some(&snapshot),
                        &snapshot.root_rules,
                    )
                    .await
                    .map_err(TxnError::Validation)?;
                Ok(Outcome::Value(()))
            }))
        }),
    )
    .await;
    assert_eq!(refused_build, Err(TxnError::Forbidden));
    assert!(!directory.join("must-not-be-opened").exists());

    // Revoking the role while the write is waiting changes no credential and still denies it.
    {
        let gate = effect_lock().await;
        let revoke_role = config_transaction(&delegated_handle, |txn| {
            let mut next = (**txn.app()).clone();
            next.role_bindings.clear();
            Ok::<_, TxnError>(Outcome::commit_async(
                Arc::new(next),
                persist(store.clone(), "role-revoked"),
                (),
            ))
        });
        tokio::pin!(revoke_role);
        assert!(futures::poll!(&mut revoke_role).is_pending());
        let role_queued = effect::scope(
            Some(delegated_context),
            config_transaction(&delegated_handle, |txn| {
                Ok::<_, TxnError>(Outcome::commit_async(
                    txn.app().clone(),
                    persist(store.clone(), "role-queued"),
                    (),
                ))
            }),
        );
        tokio::pin!(role_queued);
        assert!(futures::poll!(&mut role_queued).is_pending());
        drop(gate);
        let (revocation, result) = tokio::join!(revoke_role, role_queued);
        revocation.unwrap();
        assert_eq!(result, Err(TxnError::Forbidden));
        assert!(recorded(&store, "role-queued").await.is_none());
    }

    // A completed receipt remains true after later revocation.
    let completed: Result<(), TxnError> = effect::scope(
        Some(context.clone()),
        config_transaction(&handle, |txn| {
            let mut next = (**txn.app()).clone();
            next.config_version += 1;
            Ok(Outcome::commit_async(
                Arc::new(next),
                persist(store.clone(), "completed"),
                (),
            ))
        }),
    )
    .await;
    completed.unwrap();

    // FIFO queue is deterministic: hold the real gate, poll the revocation first, then poll
    // the already-authorized write. Removing the opened provider models credential retirement.
    {
        let gate = effect_lock().await;
        let revoke = config_transaction(&handle, |txn| {
            let mut next = (**txn.app()).clone();
            next.config_version += 1;
            next.admin_modules = Arc::new(busbar_kernel::auth::AdminAuthChain {
                operator: busbar_kernel::auth::Operator::new(operator),
                modules: Default::default(),
            });
            Ok::<_, TxnError>(Outcome::commit_async(
                Arc::new(next),
                persist(store.clone(), "revoked"),
                (),
            ))
        });
        tokio::pin!(revoke);
        assert!(futures::poll!(&mut revoke).is_pending());
        let queued = effect::scope(
            Some(context.clone()),
            config_transaction(&handle, |txn| {
                let mut next = (**txn.app()).clone();
                next.config_version += 1;
                Ok::<_, TxnError>(Outcome::commit_async(
                    Arc::new(next),
                    persist(store.clone(), "queued"),
                    (),
                ))
            }),
        );
        tokio::pin!(queued);
        assert!(futures::poll!(&mut queued).is_pending());
        drop(gate);
        let (revoked, refused) = tokio::join!(revoke, queued);
        revoked.unwrap();
        assert_eq!(refused, Err(TxnError::Forbidden));
        assert!(recorded(&store, "queued").await.is_none());
        assert_eq!(
            recorded(&store, "completed").await,
            Some(b"committed".to_vec())
        );
        assert_eq!(
            recorded(&store, "revoked").await,
            Some(b"committed".to_vec())
        );
        assert!(
            context.revalidate(&handle.load()).await.is_err(),
            "new admission is denied too"
        );
    }

    // The explicit open development posture is still a usable startup posture.
    let mut open = (*original).clone();
    open.admin_chain.clear();
    let open_handle = Arc::new(AppHandle::new(Arc::new(open)));
    let open_context = effect::Context::new("PUT", target, Default::default(), &AdminDoor::Open);
    let result: Result<(), TxnError> = effect::scope(
        Some(open_context),
        config_transaction(&open_handle, |txn| {
            let mut next = (**txn.app()).clone();
            next.config_version += 1;
            Ok(Outcome::commit_async(
                Arc::new(next),
                persist(store.clone(), "open-development"),
                (),
            ))
        }),
    )
    .await;
    result.unwrap();
    drop(delegated_handle);
    drop(book);
    drop(handle);
    drop(open_handle);
    drop(original);
    drop(store);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn named_config_verbs_never_become_full_operator_authority() {
    use busbar_contract::auth::Principal;
    use busbar_contract::authz::{Grants, Scope};
    let p = Principal::from_id("admin"); // An arbitrary id spelling confers no operator privilege.
    let limited = AdminDoor::Listed(
        p.clone(),
        Grants::of(Scope::Full),
        busbar_kernel::auth::VerbAllowList {
            rungs: Grants::default(),
            named: ["put_config_settings".to_string()].into_iter().collect(),
        },
    );
    assert!(!effect::full_operator(&limited));
    assert!(!effect::full_operator(&AdminDoor::Identified(
        p.clone(),
        Grants::default()
    )));
    assert!(effect::full_operator(&AdminDoor::Identified(
        p,
        Grants::of(Scope::Full)
    )));
}

// A controlled issuer for policy assertions; persistence and queueing use the actual product
// Store and production transaction. No local cache is modeled by this issuer.
struct RoleProvider;
impl busbar_contract::auth_calls::AuthCalls for RoleProvider {
    fn name(&self) -> &str {
        "scoped-provider"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::VerifyAnswer::from(
            busbar_contract::auth_calls::Verified::Identity(
                busbar_contract::auth_calls::VerifiedIdentity {
                    subject: "admin".into(),
                    groups: vec!["editor".into()],
                    ..Default::default()
                },
            ),
        ))
    }
    fn verify(
        &self,
        request: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Ready(self.verify_now(&request)))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}
struct Ready(Option<busbar_contract::auth_calls::VerifyAnswer>);
impl std::future::Future for Ready {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().unwrap())
    }
}
impl busbar_contract::auth_calls::Verifying for Ready {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.take()
    }
}

// Uses the actual product Store with a controlled issuer whose revocation record lives there.
// The same production admission and per-resource claim primitive used by the key handlers run
// on blocking workers. No Store substitute or timing sleep supplies the ordering assertions.
async fn independent_store_effects(
    original: &Arc<busbar_kernel::state::App>,
    store: &Arc<ScopedStore>,
    operator: &str,
) {
    use busbar_contract::auth_calls::AuthCalls;
    use busbar_kernel::auth::effect::PinnedEffect;
    for (case, revoked, written) in [
        ("before-config", "pin-revoke-config", "pin-write-config"),
        ("before-store", "pin-revoke-store", "pin-write-store"),
        ("after-both", "pin-revoke-after", "pin-write-after"),
        ("during-auth", "pin-revoke-auth", "pin-write-auth"),
        (
            "during-store-auth",
            "pin-revoke-suspended",
            "pin-write-suspended",
        ),
    ] {
        let issuer = Arc::new(StoreAuthority {
            store: store.clone(),
            revoked,
            gate: std::sync::Mutex::new(None),
        });
        let mut app = (**original).clone();
        app.admin_chain = vec![issuer.name().into()];
        app.admin_modules = Arc::new(busbar_kernel::auth::AdminAuthChain {
            operator: busbar_kernel::auth::Operator::new(operator),
            modules: [(
                issuer.name().into(),
                busbar_kernel::auth::AdminModule {
                    calls: issuer.clone(),
                },
            )]
            .into_iter()
            .collect(),
        });
        app.auth_scope_caps
            .insert(issuer.name().into(), "full".into());
        app.role_bindings.insert(
            issuer.name().into(),
            [(
                "editor".into(),
                busbar_kernel::config::RoleBindingCfg {
                    admin_scope: Some("full".into()),
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
        );
        let handle = Arc::new(AppHandle::new(Arc::new(app)));
        let snapshot = handle.load();
        let target = "/api/v1/admin/keys/example";
        let door = busbar_kernel::auth::admin_verdict_async(
            &snapshot,
            "DELETE",
            target,
            &Default::default(),
        )
        .await
        .door;
        assert!(busbar_kernel::auth::admin_door_admits(
            &door, "DELETE", target
        ));
        let context = effect::Context::new("DELETE", target, Default::default(), &door);
        // A parked config transaction must not serialize an independent key's admission.
        let config_gate = effect_lock().await;
        let admitted = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            PinnedEffect::admit(&handle, Some(context.clone())),
        )
        .await
        .expect("independent admission does not take the config lock")
        .unwrap();
        drop(config_gate);
        assert!(Arc::ptr_eq(admitted.app(), &snapshot));

        if matches!(case, "during-auth" | "during-store-auth") {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            *issuer.gate.lock().unwrap() = Some((entered_tx, release_rx));
            let task_handle = handle.clone();
            let task_store = store.clone();
            let task = tokio::spawn(async move {
                let _completion = admitted.start(&task_handle).await?;
                persist(task_store, written)
                    .await
                    .map_err(TxnError::Validation)
            });
            entered_rx.await.unwrap();
            if case == "during-store-auth" {
                let revoke = busbar_kernel::config::transaction::admit_effect(&handle, None)
                    .await
                    .unwrap();
                persist(store.clone(), revoked).await.unwrap();
                drop(revoke);
                assert!(Arc::ptr_eq(&snapshot, &handle.load()));
            } else {
                let mut next = (*snapshot).clone();
                next.auth_scope_caps
                    .insert(issuer.name().into(), "read-only".into());
                handle.swap(Arc::new(next)).await;
            }
            release_tx.send(()).unwrap();
            assert_eq!(task.await.unwrap(), Err(TxnError::Forbidden));
        } else {
            let claims = Arc::new(busbar_kernel::governance::claims::ClaimSet::new());
            let mut held = Some(claims.claim("example"));
            let task_claims = claims.clone();
            let task_handle = handle.clone();
            let task_store = store.clone();
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
            let (finish_tx, finish_rx) = std::sync::mpsc::channel();
            let task = tokio::task::spawn_blocking(move || {
                entered_tx.send(()).unwrap();
                let _key_claim = task_claims.claim("example");
                let _completion =
                    tokio::runtime::Handle::current().block_on(admitted.start(&task_handle))?;
                if case == "after-both" {
                    admitted_tx.send(()).unwrap();
                    finish_rx.recv().unwrap();
                }
                tokio::runtime::Handle::current()
                    .block_on(persist(task_store, written))
                    .map_err(TxnError::Validation)
            });
            entered_rx.await.unwrap();
            if case == "after-both" {
                drop(held.take());
                admitted_rx.await.unwrap();
            } else {
                // The queued worker cannot revalidate until we release this exact key claim.
                assert!(!task.is_finished());
            }
            if case != "before-config" {
                let revoke = busbar_kernel::config::transaction::admit_effect(&handle, None)
                    .await
                    .unwrap();
                persist(store.clone(), revoked).await.unwrap();
                drop(revoke);
                assert!(
                    Arc::ptr_eq(&snapshot, &handle.load()),
                    "Store revoke changes no App"
                );
            }
            if case != "before-store" {
                let mut next = (*snapshot).clone();
                next.auth_scope_caps
                    .insert(issuer.name().into(), "read-only".into());
                handle.swap(Arc::new(next)).await;
            }
            if case == "after-both" {
                finish_tx.send(()).unwrap();
                assert_eq!(
                    task.await.unwrap(),
                    Ok(()),
                    "admitted custody must complete"
                );
            } else {
                drop(held.take());
                assert_eq!(task.await.unwrap(), Err(TxnError::Forbidden));
            }
        }
        assert_eq!(
            recorded(&store, written).await,
            (case == "after-both").then(|| b"committed".to_vec()),
            "{case}: denied work writes nothing; admitted work retains its receipt",
        );
        assert!(PinnedEffect::admit(&handle, Some(context)).await.is_err());
    }
}

type VerificationGate = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);
struct StoreAuthority {
    store: Arc<ScopedStore>,
    revoked: &'static str,
    gate: std::sync::Mutex<Option<VerificationGate>>,
}
impl busbar_contract::auth_calls::AuthCalls for StoreAuthority {
    fn name(&self) -> &str {
        "store-authority"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None // The authoritative revocation read is an asynchronous native Store call.
    }
    fn verify(
        &self,
        request: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        let store = self.store.clone();
        let revoked = self.revoked;
        let gate = self.gate.lock().unwrap().take();
        Box::new(PendingVerification(Box::pin(async move {
            let answer = match store.get(SCHEMA, revoked.as_bytes()).await {
                Ok(None) => RoleProvider.verify_now(&request).unwrap(),
                Ok(Some(_)) => busbar_contract::auth_calls::Verified::Reject.into(),
                Err(_) => busbar_contract::auth_calls::Verified::Failed.into(),
            };
            if let Some((entered, release)) = gate {
                entered.send(()).unwrap();
                release.await.unwrap();
            }
            answer
        })))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}
struct PendingVerification(
    std::pin::Pin<
        Box<dyn std::future::Future<Output = busbar_contract::auth_calls::VerifyAnswer> + Send>,
    >,
);
impl std::future::Future for PendingVerification {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
impl busbar_contract::auth_calls::Verifying for PendingVerification {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
}
