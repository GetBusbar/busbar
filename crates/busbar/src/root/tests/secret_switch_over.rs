// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-SECRET red-first: the boot's secret kind on the MIN-3 path. A configured `secret-env` and
//! `secret-vault` instance (kind-level doubles of their `SecretPort`, STAGE23 Δ4) are opened into the process
//! table, and a kernel-internal reference to each resolves through custody to that instance's port. The port
//! sees the reference's settings only (I2); a module that is not open is refused without a name.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::{CustodyDenied, SecretSource};
use busbar_ports::secret::{SecretAnswer, SecretPort};
use busbar_ports::{CallCx, PortError};

use super::BootSecrets;
use busbar_kernel::plugin_config::{Binder, ConfigBinder};

/// A secret kind over the boot's own binder.
fn secrets() -> Arc<BootSecrets> {
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(Default::default()), Vec::new()));
    BootSecrets::empty(
        binder,
        Arc::new(busbar_plugin_loader::instance::SlotTable::new()),
    )
}

/// One configured secret instance, as the kernel sees it through its port.
struct Port {
    value: &'static str,
    seen: Mutex<Vec<Vec<u8>>>,
}

impl Port {
    fn new(value: &'static str) -> Arc<Self> {
        Arc::new(Port {
            value,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<String> {
        let seen = self.seen.lock().expect("seen");
        seen.iter()
            .map(|reference| String::from_utf8_lossy(reference).into_owned())
            .collect()
    }
}

impl SecretPort for Port {
    fn resolve<'a>(
        &'a self,
        _cx: CallCx,
        reference: &'a [u8],
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = Result<SecretAnswer, PortError>> + Send + 'a>,
    > {
        self.seen.lock().expect("seen").push(reference.to_vec());
        Box::pin(core::future::ready(Ok(SecretAnswer {
            value: SecureVec::from(self.value.as_bytes()),
            lease_s: None,
        })))
    }
}

fn source(module: &str, settings: &str) -> SecretRef {
    let json = format!(r#"{{"module":"{module}","settings":{settings}}}"#);
    busbar_contract::json::parse(json.as_bytes()).expect("a source reference")
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

async fn resolved(secrets: &BootSecrets, reference: &SecretRef) -> Result<String, CustodyDenied> {
    let value = secrets.resolve_ref(deadline(), reference).await?;
    Ok(String::from_utf8(value.as_slice().to_vec()).expect("utf-8"))
}

#[tokio::test]
async fn a_secret_env_and_a_secret_vault_instance_resolve_through_their_ports() {
    let secrets = secrets();
    let env = Port::new("env-material-0001");
    let vault = Port::new("vault-material-0002");
    let secrets = secrets
        .with_opened(
            "secret-env",
            SecretSource {
                instance: 11,
                port: Arc::clone(&env) as Arc<dyn SecretPort>,
            },
        )
        .unwrap();
    let secrets = secrets
        .with_opened(
            "secret-vault",
            SecretSource {
                instance: 12,
                port: Arc::clone(&vault) as Arc<dyn SecretPort>,
            },
        )
        .unwrap();

    let from_env = resolved(&secrets, &source("secret-env", r#"{"name":"DB_PASSWORD"}"#)).await;
    let from_vault = resolved(
        &secrets,
        &source("secret-vault", r#"{"path":"kv/db","key":"password"}"#),
    )
    .await;

    assert_eq!(from_env.as_deref(), Ok("env-material-0001"));
    assert_eq!(from_vault.as_deref(), Ok("vault-material-0002"));
    let env_seen = env.seen();
    let vault_seen = vault.seen();
    assert_eq!(env_seen.len(), 1, "one resolve reaches the secret-env port");
    assert_eq!(
        vault_seen.len(),
        1,
        "one resolve reaches the secret-vault port"
    );
    assert!(env_seen[0].contains("DB_PASSWORD"));
    assert!(vault_seen[0].contains("kv/db"));
    for seen in env_seen.iter().chain(&vault_seen) {
        assert!(
            !seen.contains("module") && !seen.contains("secret-"),
            "a port sees its settings only, never the module: {seen}"
        );
    }
}

#[tokio::test]
async fn a_module_that_is_not_open_is_refused_without_a_name() {
    let secrets = secrets();
    let env = Port::new("env-material-0001");
    let secrets = secrets
        .with_opened(
            "secret-env",
            SecretSource {
                instance: 11,
                port: Arc::clone(&env) as Arc<dyn SecretPort>,
            },
        )
        .unwrap();
    let reference = source("secret-env", r#"{"name":"DB_PASSWORD"}"#);

    assert_eq!(
        resolved(&secrets, &source("secret-file", r#"{"path":"/run/x"}"#)).await,
        Err(CustodyDenied::NoSuchSecretSource)
    );
    assert_eq!(
        resolved(&secrets, &reference).await.as_deref(),
        Ok("env-material-0001")
    );
    let secrets = secrets.without("secret-env");
    assert_eq!(
        resolved(&secrets, &reference).await,
        Err(CustodyDenied::NoSuchSecretSource),
        "a closed instance serves nothing"
    );
    assert_eq!(env.seen().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn synchronous_config_resolution_progresses_on_the_owned_io_executor() {
    use busbar_contract::secret::SecretResolve;
    let io = crate::root::boot::process::ProcessIo::new().unwrap();
    let secrets = Box::leak(Box::new(secrets()));
    let secrets = secrets
        .with_opened(
            "configured-source",
            SecretSource {
                instance: 41,
                port: Port::new("owned-source-material"),
            },
        )
        .expect("a reserved open extends custody");
    let resolver = secrets.resolver(io.handle(), Default::default());
    let held = resolver
        .resolve(&source("configured-source", "{}"))
        .unwrap();
    assert_eq!(
        held.expose(&busbar_kernel::seal::lend()),
        b"owned-source-material"
    );
}

#[tokio::test]
async fn a_later_open_does_not_change_the_prefix_captured_by_an_existing_need() {
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(Default::default()), Vec::new()));
    let before = BootSecrets::empty(
        binder,
        Arc::new(busbar_plugin_loader::instance::SlotTable::new()),
    );
    let captured = super::BootCustody(Arc::clone(&before));
    let after = before
        .with_opened(
            "later",
            SecretSource {
                instance: 21,
                port: Port::new("later-material"),
            },
        )
        .unwrap();
    let reference = source("later", r#"{"key":"value"}"#);
    assert_eq!(
        resolved(&before, &reference).await,
        Err(CustodyDenied::NoSuchSecretSource)
    );
    assert_eq!(
        resolved(&captured.0, &reference).await,
        Err(CustodyDenied::NoSuchSecretSource)
    );
    assert_eq!(
        resolved(&after, &reference).await.as_deref(),
        Ok("later-material")
    );
    assert!(after
        .with_opened(
            "later",
            SecretSource {
                instance: 22,
                port: Port::new("replacement")
            }
        )
        .is_err());
    assert!(after
        .with_opened(
            "another",
            SecretSource {
                instance: 21,
                port: Port::new("same-id")
            }
        )
        .is_err());
}

#[tokio::test]
async fn an_immutable_prefix_keeps_cycle_refusal_and_releases_its_ports_on_drop() {
    use busbar_kernel::custody::SecretCustody;
    use busbar_plugin_abi::host_side::caller::CallStack;
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(Default::default()), Vec::new()));
    let before = BootSecrets::empty(
        binder,
        Arc::new(busbar_plugin_loader::instance::SlotTable::new()),
    );
    let port = Port::new("secret-material");
    let weak = Arc::downgrade(&port);
    let after = before
        .with_opened("source", SecretSource { instance: 31, port })
        .unwrap();
    let cx = CallCx {
        deadline: deadline(),
        request_id: 0,
        stack: CallStack::default().push(31).unwrap(),
        mono_ns: 0,
    };
    let custody = super::BootCustody(Arc::clone(&after));
    assert!(matches!(
        custody.resolve_ref(cx, &source("source", "{}")).await,
        Err(CustodyDenied::Cycle)
    ));
    let retired = after.without("source");
    assert_eq!(
        resolved(&retired, &source("source", "{}")).await,
        Err(CustodyDenied::NoSuchSecretSource)
    );
    drop(after);
    assert!(
        weak.upgrade().is_some(),
        "the captured prefix owns its live source lease"
    );
    drop(custody);
    assert!(
        weak.upgrade().is_none(),
        "no leaked BootSecrets keeps the source alive"
    );
}

#[tokio::test]
async fn reference_config_is_scrubbed_per_binding_before_it_is_returned() {
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_loader::instance::{ErrorBook, SlotRecord, SlotTable};
    use busbar_ports::binder::RefSource;
    let slots = Arc::new(SlotTable::new());
    let scrub = Arc::new(Scrub::new());
    let lease = slots.alloc(
        SlotRecord {
            kind: busbar_plugin_abi::types::KindCode::Plane,
            name: Arc::from("consumer"),
            scrub: Arc::clone(&scrub),
            errors: &ErrorBook::None,
            undeclared_warned: std::sync::atomic::AtomicBool::new(false),
        },
        &[u32::MAX; 64],
    );
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(Default::default()), Vec::new()));
    let mut prefix = BootSecrets::empty(binder, slots);
    for (id, name, value) in [
        (1, "first", "first-reference-material"),
        (2, "second", "second-reference-material"),
        (3, "third", "third-reference-material"),
    ] {
        prefix = prefix
            .with_opened(
                name,
                SecretSource {
                    instance: id,
                    port: Port::new(value),
                },
            )
            .unwrap();
    }
    let refs = super::BootRefs(Arc::clone(&prefix));
    for (binding, name, value) in [
        (0, "first", "first-reference-material"),
        (1, "second", "second-reference-material"),
        (2, "third", "third-reference-material"),
    ] {
        let reference = source(name, "{}");
        assert_eq!(
            refs.resolve(17, lease.slot(), binding, &reference)
                .await
                .unwrap()
                .as_slice(),
            value.as_bytes()
        );
        assert_eq!(scrub.text(value), "***");
    }
    assert_eq!(
        scrub.text("first-reference-material second-reference-material third-reference-material"),
        "*** *** ***"
    );
    let slot = lease.slot();
    drop(lease);
    assert!(
        refs.resolve(18, slot, 0, &source("first", "{}"))
            .await
            .is_none(),
        "a released slot cannot receive reference plaintext"
    );
}

#[tokio::test]
async fn effective_binding_keeps_bootstrap_bindings_and_source_leases_immutable() {
    let make_binder = || -> Arc<dyn ConfigBinder> {
        Arc::new(Binder::new(
            Arc::new(Default::default()),
            vec![(Arc::from("source"), Box::from(r#"{"type":"object"}"#))],
        ))
    };
    let bootstrap = make_binder();
    let effective = make_binder();
    bootstrap
        .bind(
            41,
            br#"{"token":{"module":"source","settings":{"key":"boot"}}}"#,
            &["/token"],
            &[],
            &[],
            &[],
        )
        .unwrap();
    effective
        .bind(
            42,
            br#"{"token":{"module":"source","settings":{"key":"serve"}}}"#,
            &["/token"],
            &[],
            &[],
            &[],
        )
        .unwrap();
    let port = Port::new("retained-material");
    let before = BootSecrets::empty(
        Arc::clone(&bootstrap),
        Arc::new(busbar_plugin_loader::instance::SlotTable::new()),
    )
    .with_opened(
        "source",
        SecretSource {
            instance: 51,
            port: Arc::clone(&port) as Arc<dyn SecretPort>,
        },
    )
    .unwrap();
    let after = before.with_binder(Arc::clone(&effective));
    assert!(Arc::ptr_eq(&before.binder, &bootstrap));
    assert!(Arc::ptr_eq(&after.binder, &effective));
    assert_eq!(
        before.binder.secret(41, 1),
        Some(source("source", r#"{"key":"boot"}"#))
    );
    assert!(before.binder.secret(42, 1).is_none());
    assert_eq!(
        after.binder.secret(42, 1),
        Some(source("source", r#"{"key":"serve"}"#))
    );
    assert!(after.binder.secret(41, 1).is_none());
    assert!(Arc::ptr_eq(&before.slots, &after.slots));
    assert!(Arc::ptr_eq(
        &before.port("source").unwrap(),
        &after.port("source").unwrap()
    ));
    let reference = source("source", "{}");
    assert_eq!(
        resolved(&before, &reference).await.as_deref(),
        Ok("retained-material")
    );
    assert_eq!(
        resolved(&after, &reference).await.as_deref(),
        Ok("retained-material")
    );
    assert_eq!(
        port.seen().len(),
        2,
        "each immutable binding generation has fresh custody"
    );
}
