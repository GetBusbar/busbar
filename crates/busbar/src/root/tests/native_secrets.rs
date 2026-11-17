// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WP3 step 2: the kernel's secret seam over native secret images. A reference to an admitted native secret
//! image resolves through custody to that image's open instance, which sees the reference's settings only (I2);
//! its settings are judged against the image's reference schema; a module no native image answers is refused.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_contract::secret::SecretAxis;
use busbar_contract::secure::SecureVec;
use busbar_kernel::config::grammar::SecretSource as ImageSource;
use busbar_kernel::custody::SecretSource;
use busbar_kernel::plugin_config::{Binder, ConfigBinder};
use busbar_ports::secret::{SecretAnswer, SecretPort};
use busbar_ports::{CallCx, PortError};

use super::{NativeSecrets, Opened};
use crate::root::secret_custody::BootSecrets;

struct Port {
    seen: Mutex<Vec<Vec<u8>>>,
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
            value: SecureVec::from(b"vault-material-0003".as_slice()),
            lease_s: None,
        })))
    }
}

const SCHEMA: &str =
    r#"{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}"#;

/// An axis whose one admitted native image, `secret-vault`, answers to `vault`, with `vault` open as instance 21.
fn axis(runtime: &tokio::runtime::Runtime) -> (NativeSecrets, Arc<Port>) {
    let axis = NativeSecrets {
        admitted: arc_swap::ArcSwapOption::const_empty(),
        opened: arc_swap::ArcSwapOption::const_empty(),
    };
    let grammar = busbar_kernel::config::Grammar::empty().with_secret_sources(BTreeMap::from([(
        "vault".to_owned(),
        ImageSource {
            identity: "secret-vault".to_owned(),
            ref_schema: SCHEMA.to_owned(),
        },
    )]));
    axis.publish_images(&grammar, ["secret-vault"].into_iter());
    let port = Arc::new(Port {
        seen: Mutex::new(Vec::new()),
    });
    let binder: Arc<dyn ConfigBinder> =
        Arc::new(Binder::new(Arc::new(Default::default()), Vec::new()));
    let prefix = BootSecrets::empty(
        binder,
        Arc::new(busbar_plugin_loader::instance::SlotTable::new()),
    )
    .with_opened(
        "vault",
        SecretSource {
            instance: 21,
            port: Arc::clone(&port) as Arc<dyn SecretPort>,
        },
    )
    .expect("the vault instance opens into the prefix");
    axis.opened.store(Some(Arc::new(Opened {
        prefix,
        runtime: runtime.handle().clone(),
    })));
    (axis, port)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("a runtime")
}

#[test]
fn a_reference_resolves_through_the_native_image_with_its_settings_only() {
    let runtime = runtime();
    let (axis, port) = axis(&runtime);
    assert!(axis.answers("vault"));
    assert!(axis.linked("vault"), "a linked image's names are linked");
    let value = axis
        .shared("vault")
        .expect("the native image answers")
        .resolve(br#"{"path":"kv/db"}"#)
        .expect("the instance resolves");
    let seal = busbar_kernel::seal::lend();
    assert_eq!(value.expose(&seal).as_slice(), b"vault-material-0003");
    let seen = port.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 1, "one resolve reaches the port");
    let seen = String::from_utf8(seen[0].clone()).expect("utf-8");
    assert!(seen.contains("kv/db"), "{seen}");
    assert!(
        !seen.contains("module") && !seen.contains("vault\""),
        "the port sees its settings only: {seen}"
    );
}

#[test]
fn settings_are_judged_against_the_reference_schema() {
    let runtime = runtime();
    let (axis, _) = axis(&runtime);
    let good: busbar_contract::plugin_settings::Settings =
        busbar_contract::json::parse(br#"{"path":"kv/db"}"#).expect("settings");
    let bad: busbar_contract::plugin_settings::Settings =
        busbar_contract::json::parse(br#"{"key":"x"}"#).expect("settings");
    assert!(axis.check("vault", &good).is_ok());
    assert!(axis.check("vault", &bad).is_err());
}

#[test]
fn a_module_no_native_image_answers_is_refused() {
    let runtime = runtime();
    let (axis, _) = axis(&runtime);
    assert!(!axis.answers("door-vault"));
    assert!(axis.shared("door-vault").is_err());
}
