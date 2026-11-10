// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SDK lifecycle refusal must preserve the connector's committed declaration.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND};
use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{
    self as life, OpenIn, OpenOut, RefreshIn, ReleaseIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_contract::conn::{DeclaredConns, NeedId};
use busbar_contract::plugin::markers::SecretKind;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow,
    NoSink, Plugin, NO_BLOB,
};

use crate::registry::{Entry, Transports};
use crate::support::TestDoor;
use crate::Connector;

struct Witness(Mutex<Vec<u8>>);

impl Life for Witness {
    type Kind = SecretKind;
    const CANCEL: u32 = secret::cancel::ABORTED;

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self(Mutex::new(settings.to_vec())))
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let settings_value = busbar_contract::abi::sdk::life::settings_value(settings)?;
        if settings_value["accept"] == false {
            return Err(Refusal::failed("witness refuses the candidate"));
        }
        *self.0.lock().unwrap() = settings.to_vec();
        Ok(Refreshed::default())
    }
}

struct Resolve;
impl SafeSlot for Resolve {
    type Kind = SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Witness>;

    fn call(
        instance: Instance<'_, Self::State, SecretKind>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        busbar_contract::abi::sdk::cred::resolved(
            input,
            &mut out,
            busbar_contract::abi::sdk::cred::Held::new(held.life().0.lock().unwrap().clone()),
        )
    }
}

const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    transport: abi_str("witness"),
    target_from: abi_str("settings.target"),
    ..Need::ZERO
}];

busbar_contract::plugin_door! {
    ops: secret::Ops,
    statement: Statement {
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        ..statement("refresh-witness", "0", 1)
    },
    lifecycle: life(Witness),
    kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
}

fn release(plugin: &Plugin<Secret>, lease: u64) {
    if lease != 0 {
        let mut frame: Frame<ReleaseIn, OutHead> = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        assert_eq!(
            plugin.call(life::slot::RELEASE, &mut frame).outcome,
            Outcome::Ready
        );
    }
}

fn refresh(plugin: &Plugin<Secret>, settings: &[u8], generation: u64) -> Outcome {
    let mut frame: Frame<RefreshIn, OutHead> = Frame::new(
        RefreshIn {
            head: in_head(),
            generation,
            settings: Blob {
                ptr: settings.as_ptr(),
                len: settings.len(),
                fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
                flags: 0,
            },
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    let called = plugin.call(life::slot::REFRESH, &mut frame);
    release(plugin, called.lease);
    called.outcome
}

fn resolve(plugin: &Plugin<Secret>) -> Vec<u8> {
    let mut material = [0; 256];
    let mut frame = Frame::new(
        ResolveIn {
            head: in_head(),
            settings: NO_BLOB,
            secret_buf: material.as_mut_ptr(),
            secret_cap: material.len(),
        },
        ResolveOut {
            head: out_head(),
            secret: NO_BLOB,
            error_kind: 0,
            _reserved: 0,
            needed: 0,
        },
    );
    let called = plugin.call(secret::slot::RESOLVE, &mut frame);
    release(plugin, called.lease);
    assert_eq!(called.outcome, Outcome::Ready);
    assert_eq!(frame.out.secret.ptr, material.as_ptr());
    assert!(frame.out.secret.len <= material.len());
    material[..frame.out.secret.len].to_vec()
}

#[test]
fn refused_refresh_preserves_the_committed_connector_binding() {
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    );
    let table = Arc::new(Connector::serving(
        Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("witness")),
            alpn: Vec::new(),
        }])
        .unwrap(),
        crate::tests::loopback_literals(),
        None,
        dispatcher.conn_waker(),
    ));
    let plugin = load_linked::<Secret>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: Arc::from("refresh-witness"),
            max_inflight_cap: 1,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(
                busbar_contract::conn::admissions::AdmissionAuthority::issue(
                    &busbar_kernel::seal::acquire(),
                    table.clone(),
                    Default::default(),
                ),
            ),
        },
    )
    .unwrap();
    let owner = plugin.instance();
    let committed = br#"{"target":"127.0.0.1:12001","accept":true}"#;
    let mut open = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: Blob::json(committed),
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    let opened = plugin.call(life::slot::OPEN, &mut open);
    release(&plugin, opened.lease);
    assert_eq!(opened.outcome, Outcome::Ready);
    let target = || {
        table
            .over
            .lock()
            .unwrap()
            .get(&(owner, NeedId(0)))
            .and_then(|bound| bound.declared_target.clone())
    };
    assert_eq!(table.declared(owner, NeedId(0)), Some(Ok(())));
    assert_eq!(target().as_deref(), Some("127.0.0.1:12001"));
    for _ in 0..5 {
        assert_eq!(resolve(&plugin), committed);
    }
    assert_eq!(
        refresh(
            &plugin,
            br#"{"target":"127.0.0.1:12002","accept":false}"#,
            2
        ),
        Outcome::Failed
    );
    assert_eq!(
        plugin.instance(),
        owner,
        "the public identity remains stable"
    );
    assert_eq!(table.declared(owner, NeedId(0)), Some(Ok(())));
    assert_eq!(
        target().as_deref(),
        Some("127.0.0.1:12001"),
        "the refused candidate cannot replace the committed target"
    );
    assert_eq!(resolve(&plugin), committed);
    let moved = br#"{"target":"127.0.0.1:12002","accept":true}"#;
    assert_eq!(refresh(&plugin, moved, 3), Outcome::Ready);
    // The public owner remains stable; an accepted generation has its own declaration.
    assert!(
        table
            .over
            .lock()
            .unwrap()
            .iter()
            .any(|((generation, need), bound)| {
                *generation != owner
                    && *need == NeedId(0)
                    && bound.declared_target.as_deref() == Some("127.0.0.1:12002")
            }),
        "the accepted generation owns the newly committed target"
    );
    assert_eq!(resolve(&plugin), moved);
    let mut close: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
    let closed = plugin.call(life::slot::CLOSE, &mut close);
    release(&plugin, closed.lease);
    assert_eq!(closed.outcome, Outcome::Ready);
}
