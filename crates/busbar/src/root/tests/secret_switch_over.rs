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

use super::{BootRefs, BootSecrets};
use busbar_kernel::plugin_config::{Binder, ConfigBinder};

/// A secret kind over the boot's own binder.
fn secrets() -> BootSecrets {
    let binder: Arc<dyn ConfigBinder> = Arc::new(Binder::new(Arc::new(BootRefs)));
    BootSecrets::new(
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
    secrets.table().opened(
        "secret-env",
        SecretSource {
            instance: 11,
            port: Arc::clone(&env) as Arc<dyn SecretPort>,
        },
    );
    secrets.table().opened(
        "secret-vault",
        SecretSource {
            instance: 12,
            port: Arc::clone(&vault) as Arc<dyn SecretPort>,
        },
    );

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
    secrets.table().opened(
        "secret-env",
        SecretSource {
            instance: 11,
            port: Arc::clone(&env) as Arc<dyn SecretPort>,
        },
    );
    let reference = source("secret-env", r#"{"name":"DB_PASSWORD"}"#);

    assert_eq!(
        resolved(&secrets, &source("secret-file", r#"{"path":"/run/x"}"#)).await,
        Err(CustodyDenied::NoSuchSecretSource)
    );
    assert_eq!(
        resolved(&secrets, &reference).await.as_deref(),
        Ok("env-material-0001")
    );
    secrets.closed("secret-env");
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
    secrets.table().opened(
        "configured-source",
        SecretSource {
            instance: 41,
            port: Port::new("owned-source-material"),
        },
    );
    let resolver = secrets.resolver(io.handle(), Default::default());
    let held = resolver
        .resolve(&source("configured-source", "{}"), None)
        .unwrap();
    assert_eq!(
        held.expose(&busbar_kernel::seal::lend()),
        b"owned-source-material"
    );
}
