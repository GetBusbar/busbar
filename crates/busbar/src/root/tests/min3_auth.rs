// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::secure::SecureVec;
use busbar_kernel::auth::verdicts::{VerdictPolicy, Verdicts};
use busbar_kernel::plugin_records::RecordsDenied;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::records::{tag, Records, Reply, U64Rec, Writer};
use busbar_ports::auth::{
    decode_verify_ok, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verify,
    VerifyAnswer, VerifyOk,
};
use busbar_ports::PortError;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Owners(AtomicUsize);
impl IssuedCredentials for Owners {
    fn lookup<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> BoxFut<'a, SecureVec> {
        panic!("an identity answer must not perform issued lookup");
    }
}
impl ReplayGuard for Owners {
    fn claim_until<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        panic!("eager chain fixture must use its original relative replay policy")
    }
    fn claim<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(true) })
    }
}

struct Port {
    calls: AtomicUsize,
    not_mine: bool,
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        ))
    })
}
impl AuthPort for Port {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, req: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        assert_eq!(req.path, "/resource");
        assert_eq!(req.body, b"body");
        assert_eq!(req.peer, "peer");
        assert_eq!(req.tls_peer_cert, b"certificate");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.not_mine {
            return Verify::Done(Ok(VerifyAnswer::NotMine));
        }
        let mut records = Reply::new();
        records.put_text(tag::ID_SUBJECT, "client").unwrap();
        records
            .put_pod_tail(
                busbar_plugin_abi::auth::tag::REPLAY,
                &U64Rec { value: 60 },
                b"nonce",
            )
            .unwrap();
        let VerifyOk::Identity(identity) =
            decode_verify_ok(Records::new(records.as_bytes())).unwrap()
        else {
            panic!("identity");
        };
        Verify::Done(Ok(VerifyAnswer::Identity(identity)))
    }
    fn login<'a>(
        &'a self,
        _: CallCx,
        _: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }
    fn outbound<'a>(
        &'a self,
        _: CallCx,
        _: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }
    fn serve<'a>(
        &'a self,
        _: CallCx,
        _: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

fn instance(id: u64, port: Arc<Port>) -> Arc<AuthInstance> {
    Arc::new(AuthInstance {
        opened: OpenedAuth {
            who: Namespace {
                plugin: "verified-image".into(),
                name: format!("provider-{id}").into(),
                instance: id,
                slot: 4,
            },
            port,
            methods: busbar_plugin_abi::auth::M_VERIFY,
            out_of_process: false,
            limits: InstanceLimits::default(),
        },
        keys: Arc::new(KeyRefresh::new(Duration::from_secs(30))),
        holds: Box::default(),
    })
}

#[tokio::test]
async fn retained_native_chain_snapshots_request_and_rejects_before_replay() {
    let first = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: true,
    });
    let second = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
    });
    let owners = Arc::new(Owners(AtomicUsize::new(0)));
    let chain = NativeChain {
        instances: vec![
            instance(41, Arc::clone(&first)),
            instance(42, Arc::clone(&second)),
        ],
        policy: ChainPolicy::new(7, Vec::new()),
        owners: Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners.clone(),
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    };
    let cx = CallCx {
        deadline: std::time::Instant::now() + Duration::from_secs(30),
        request_id: 1,
        stack: Default::default(),
    };
    let future = {
        let body = b"body".to_vec();
        chain.verify(
            cx,
            &AuthIn {
                method: "POST",
                path: "/resource",
                query: "",
                authority: "node",
                headers: &[],
                peer: "peer",
                tls_peer_cert: b"certificate",
                body: &body,
                now_s: 1,
            },
        )
    };
    assert!(matches!(
        future.await,
        ChainEnd::PolicyRejected { instance: 42, .. }
    ));
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
}
