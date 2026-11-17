// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real SDK -> Registry CHECK/live OPEN -> Driver -> HostNeeds admission ordering.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::{CustodyDenied, SecretCustody};
use busbar_kernel::plugin_config::{Binder, ConfigBinder};
use busbar_kernel::plugin_records::{
    ChainRead, CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope,
};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller, InstanceLimits};
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};
use busbar_plugin_loader::instance::{
    Ceilings, ImagesBuilder, InstanceSpec, OpenPurpose, Registry,
};
use busbar_ports::binder::RefSource;
use busbar_ports::CallCx;

use crate::guard::{Guard, Resolve, Resolved};
use crate::need::judge::Judge;
use crate::need::{Admission, Dial, Dialled, FetchReq, HostNeeds, NeedIo, NeedLimits, TlsPlan};

mod fixture {
    use busbar_plugin_abi::fail::refused::R_INVALID;
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::{need, ChainBytes, SecretHandle, TrustHandle};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::Reply;
    use busbar_plugin_abi::Secret;
    use serde_json::Value;

    pub struct Probe;

    fn config(bytes: &[u8]) -> Result<Value, Fail> {
        serde_json::from_slice(bytes)
            .map_err(|_| Fail::refused_because(R_INVALID, "fixture config"))
    }

    fn class(config: &Value, key: &str) -> u32 {
        config[key].as_u64().unwrap_or(0) as u32
    }

    impl Open for Probe {
        async fn open(_: &'static Host, bytes: ChainBytes) -> Result<Self, Fail> {
            let config = bytes.with(config)?;
            let Some(op) = config["op"].as_str() else {
                return Ok(Self);
            };
            let dest = config["dest"].as_str().unwrap();
            let egress = class(&config, "class");
            let mutual = class(&config, "tls") == 2;
            let expected = if egress > 4 {
                need::NeedErr::Invalid
            } else {
                need::NeedErr::Denied
            };
            let denied = match op {
                "open" => {
                    let tls = if mutual {
                        need::Tls::Mutual {
                            sni: "",
                            alpn: &[],
                            trust: TrustHandle(0),
                            cert: SecretHandle(1),
                        }
                    } else {
                        need::Tls::Required {
                            sni: "",
                            alpn: &[],
                            trust: TrustHandle(0),
                        }
                    };
                    if config["allow"].as_bool() == Some(true) {
                        let first = need::open(dest, tls, egress).await.map_err(Fail::from)?;
                        need::close(first.conn, true).await.map_err(Fail::from)?;
                        let second = need::open(dest, tls, egress).await.map_err(Fail::from)?;
                        if !second.reused {
                            return Err(Fail::refused_because(
                                R_INVALID,
                                "expected real pool reuse",
                            ));
                        }
                        need::close(second.conn, true).await.map_err(Fail::from)?;
                        return Ok(Self);
                    }
                    need::open(dest, tls, egress).await.err() == Some(expected)
                }
                "fetch" => {
                    let request = need::Fetch {
                        method: "GET",
                        url: dest,
                        headers: &[],
                        body: &[],
                        max_body: 32,
                        trust: TrustHandle(0),
                        cert: mutual.then_some(SecretHandle(1)),
                        egress,
                    };
                    need::fetch(&request).await.err() == Some(expected)
                }
                _ => return Err(Fail::refused_because(R_INVALID, "fixture operation")),
            };
            if !denied {
                return Err(Fail::refused_because(R_INVALID, "expected denied Need"));
            }
            Ok(Self)
        }

        fn check(_: &Host, bytes: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            let config = config(bytes)?;
            if let Some(op) = config["check_op"].as_str() {
                let dest = config["check_dest"].as_str().unwrap();
                let egress = class(&config, "check_class");
                match op {
                    "open" => {
                        ends.open(dest, class(&config, "check_tls"), egress);
                    }
                    "fetch" => {
                        ends.fetch(dest, egress);
                    }
                    _ => return Err(Fail::refused_because(R_INVALID, "fixture check operation")),
                }
            }
            Ok(())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.item_text(
                busbar_plugin_abi::secret::tag::D_REF_SCHEMA,
                r#"{"type":"object"}"#,
            );
        }
    }

    impl Secret for Probe {
        async fn resolve(&self, _: &'static Host, _: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::refused_because(R_INVALID, "unused fixture resolve"))
        }
    }

    busbar_plugin_abi::plugin!(Secret, Probe, name: "fixture-network-authority");
}

#[derive(Default)]
struct Effects {
    dns: AtomicUsize,
    dial: AtomicUsize,
    fetch: AtomicUsize,
    pool: AtomicUsize,
    custody: AtomicUsize,
}

impl Effects {
    fn snapshot(&self) -> [usize; 5] {
        [
            &self.dns,
            &self.dial,
            &self.fetch,
            &self.pool,
            &self.custody,
        ]
        .map(|value| value.load(Ordering::SeqCst))
    }
}

struct Resolver(Arc<Effects>);
impl Resolve for Resolver {
    fn resolve(&self, _: &str, done: Resolved) {
        self.0.dns.fetch_add(1, Ordering::SeqCst);
        done(Ok(vec!["10.20.30.40".parse().unwrap()]));
    }
}

struct Io(Arc<Effects>);
impl NeedIo for Io {
    type Conn = ();
    async fn timeout<F: Future + Send>(
        &self,
        _: Duration,
        future: F,
    ) -> Result<F::Output, NeedErr> {
        Ok(future.await)
    }
    async fn dial(&self, _: Dial<'_>) -> Result<Dialled<()>, NeedErr> {
        self.0.dial.fetch_add(1, Ordering::SeqCst);
        Ok(Dialled {
            conn: (),
            alpn: "".into(),
            resumed: false,
        })
    }
    async fn upgrade(&self, _: (), _: TlsPlan<'_>, _: Duration) -> Result<Dialled<()>, NeedErr> {
        panic!("denied OPEN cannot upgrade")
    }
    async fn write(&self, _: &mut (), _: &[u8], _: Duration) -> Result<usize, NeedErr> {
        panic!("denied OPEN cannot write")
    }
    async fn read(&self, _: &mut (), _: &mut [u8], _: Duration) -> Result<usize, NeedErr> {
        panic!("denied OPEN cannot read")
    }
    fn healthy(&self, _: &()) -> bool {
        self.0.pool.fetch_add(1, Ordering::SeqCst);
        true
    }
    async fn fetch(
        &self,
        req: FetchReq<'_>,
        admission: &dyn Admission,
        _: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        self.0.fetch.fetch_add(1, Ordering::SeqCst);
        let (host, port) = crate::need::judge::split_url(req.need.url)?;
        admission.dial(&host, port, true).await?;
        Err(NeedErr::Denied)
    }
}

struct Custody(Arc<Effects>);
impl SecretCustody for Custody {
    async fn resolve(&self, _: &Caller<'_>, _: u32) -> Result<Arc<SecureVec>, CustodyDenied> {
        self.0.custody.fetch_add(1, Ordering::SeqCst);
        Err(CustodyDenied::Denied)
    }
    fn generation(&self, _: &Caller<'_>, _: u32) -> u64 {
        self.0.custody.fetch_add(1, Ordering::SeqCst);
        0
    }
    fn resolve_ref<'a>(
        &'a self,
        _: CallCx,
        _: &'a SecretRef,
    ) -> BoxFut<'a, Result<SecureVec, CustodyDenied>> {
        panic!("network test cannot resolve a core secret")
    }
}

struct DeniedRefs;
impl RefSource for DeniedRefs {
    fn resolve<'a>(
        &'a self,
        _: u64,
        _: u32,
        _: u32,
        _: &'a SecretRef,
    ) -> BoxFut<'a, Option<SecureVec>> {
        panic!("fixture config has no reference paths")
    }
}

#[derive(Clone, Copy)]
struct DeniedRecords;

impl PluginRecords for DeniedRecords {
    fn claim_until(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _value: &[u8],
        _expires_at_s: u64,
    ) -> impl core::future::Future<Output = Result<bool, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn get(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl core::future::Future<Output = Result<bool, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn put(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _value: &[u8],
        _ttl_s: u64,
    ) -> impl core::future::Future<Output = Result<(), RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn claim(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _value: &[u8],
        _ttl_s: u64,
    ) -> impl core::future::Future<Output = Result<bool, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn del(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
    ) -> impl core::future::Future<Output = Result<(), RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn list(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _prefix: &[u8],
        _limit: u32,
        _sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl core::future::Future<Output = Result<u32, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn commit(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _ops: &[CommitOp<'_>],
    ) -> impl core::future::Future<Output = Result<CommitOutcome, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn append(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _chain: &[u8],
        _entry: &[u8],
    ) -> impl core::future::Future<Output = Result<u64, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn chain(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _chain: &[u8],
        _after: u64,
        _limit: u32,
        _sink: &mut (dyn FnMut(u64, &[u8]) + Send),
    ) -> impl core::future::Future<Output = Result<ChainRead, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
}

#[derive(Clone, Copy)]
struct DeniedDirectory;

impl busbar_kernel::directory::PluginDirectory for DeniedDirectory {
    fn apply(
        &self,
        _who: &Caller<'_>,
        _need: DirNeed<'_>,
        _out: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        std::future::ready(Err(NeedErr::Unavailable))
    }
}

type NativeNeeds = HostNeeds<Custody, DeniedRecords, DeniedDirectory, Io, Resolver>;

struct Harness {
    registry: Registry,
    needs: Arc<NativeNeeds>,
    effects: Arc<Effects>,
    refs: Arc<dyn RefSource>,
    _process: busbar_plugin_loader::process::ProcessResources,
}

impl Harness {
    fn new() -> Self {
        let process = busbar_plugin_loader::process::ProcessResources::new().unwrap();
        let binder: Arc<dyn ConfigBinder> = Arc::new(Binder::new(Arc::default(), Vec::new()));
        let mut images = ImagesBuilder::new(
            &busbar_plugin_abi::host_side::HOST,
            Arc::clone(process.slots()),
            Ceilings::DEFAULT,
        );
        images
            .admit(busbar_plugin_loader::admit::admit_linked(&fixture::PLUGIN).unwrap())
            .unwrap();
        let registry = Registry::new(
            images.finish(),
            Arc::clone(&binder),
            Arc::clone(process.ids()),
        );
        let effects = Arc::new(Effects::default());
        let guard = Guard::default();
        guard.publish_own(&[9443], &["10.20.30.40".parse().unwrap()]);
        let needs = Arc::new(HostNeeds::new(
            Io(Arc::clone(&effects)),
            Judge::new(guard, Resolver(Arc::clone(&effects))),
            Custody(Arc::clone(&effects)),
            DeniedRecords,
            DeniedDirectory,
            binder,
            NeedLimits::default(),
        ));
        Self {
            registry,
            needs,
            effects,
            refs: Arc::new(DeniedRefs),
            _process: process,
        }
    }

    async fn open(
        &self,
        name: &str,
        config: serde_json::Value,
    ) -> Arc<dyn busbar_ports::secret::SecretPort> {
        let bytes = serde_json::to_vec(&config).unwrap();
        let spec = InstanceSpec {
            purpose: OpenPurpose::Canonical,
            identity: "fixture-network-authority",
            name,
            config_json: &bytes,
            limits: InstanceLimits::default(),
            public_url: None,
            caller_upstreams: &[],
            store_migration: None,
        };
        self.registry
            .open_secret(&spec, &self.needs, &self.refs)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error:?}"))
    }
}

#[tokio::test]
async fn real_native_driver_admits_exact_check_authority_before_network_and_custody() {
    use serde_json::json;
    let harness = Harness::new();
    let host = "private.example:8443";
    let url = "https://private.example:8443/secret";

    // Retain real opened instances with each privileged endpoint. Another runtime identity
    // claiming exactly the same hostname/class must not inherit either frozen registration.
    let foreign_open = harness
        .open(
            "registered-open",
            json!({
                "check_op":"open", "check_dest":host, "check_class":2, "check_tls":1
            }),
        )
        .await;
    let foreign_fetch = harness
        .open(
            "registered-fetch",
            json!({
                "check_op":"fetch", "check_dest":url, "check_class":4
            }),
        )
        .await;
    assert_eq!(harness.effects.snapshot(), [0; 5]);

    // Positive controls prove the same real Driver reaches the counting transport only when
    // CHECK and the live Need agree. Keep its actual reusable pool entry alive for foreign attempts.
    let open = harness
        .open(
            "allowed-open",
            json!({
                "check_op":"open","check_dest":host,"check_class":2,"check_tls":1,
                "op":"open","dest":host,"class":2,"tls":1,"allow":true
            }),
        )
        .await;
    assert_eq!(harness.effects.snapshot(), [1, 1, 0, 3, 0]);

    for op in ["open", "fetch"] {
        for class in [2, 4, 15] {
            for tls in [1, 2] {
                let before = harness.effects.snapshot();
                let port = harness.open(&format!("forged-{op}-{class}-{tls}"), json!({
                    "op":op, "dest":if op=="open" {host} else {url}, "class":class, "tls":tls
                })).await;
                assert_eq!(
                    harness.effects.snapshot(),
                    before,
                    "{op} class {class} TLS {tls}"
                );
                drop(port);
            }
        }
    }

    for (index, config) in [
        json!({"check_op":"open","check_dest":host,"check_class":2,"check_tls":1,
               "op":"open","dest":"private.example:8444","class":2,"tls":1}),
        json!({"check_op":"open","check_dest":host,"check_class":2,"check_tls":1,
               "op":"open","dest":host,"class":4,"tls":1}),
        json!({"check_op":"open","check_dest":host,"check_class":2,"check_tls":1,
               "op":"open","dest":host,"class":2,"tls":2}),
        json!({"check_op":"open","check_dest":host,"check_class":2,"check_tls":1,
               "op":"fetch","dest":url,"class":2,"tls":1}),
        json!({"check_op":"fetch","check_dest":url,"check_class":2,
               "op":"open","dest":host,"class":2,"tls":1}),
        json!({"check_op":"fetch","check_dest":url,"check_class":2,
               "op":"fetch","dest":url,"class":2,"tls":2}),
        json!({"check_op":"fetch","check_dest":url,"check_class":4,
               "op":"fetch","dest":url,"class":2,"tls":1}),
    ]
    .into_iter()
    .enumerate()
    {
        let before = harness.effects.snapshot();
        let port = harness
            .open(&format!("changed-intent-{index}"), config)
            .await;
        assert_eq!(harness.effects.snapshot(), before);
        drop(port);
    }

    let fetch = harness
        .open(
            "allowed-fetch",
            json!({
                "check_op":"fetch","check_dest":url,"check_class":2,
                "op":"fetch","dest":url,"class":2,"tls":1
            }),
        )
        .await;
    assert_eq!(harness.effects.snapshot(), [2, 1, 1, 3, 0]);
    // Checked privileges still pass immutable metadata, own-listener and class4 address policy.
    for (index, (dest, class, additional_dns)) in [
        ("169.254.169.254:443", 2, 0),
        ("private.example:9443", 2, 1),
        (host, 4, 1),
    ]
    .into_iter()
    .enumerate()
    {
        let mut expected = harness.effects.snapshot();
        expected[0] += additional_dns;
        let port = harness
            .open(
                &format!("protected-{index}"),
                json!({
                    "check_op":"open","check_dest":dest,"check_class":class,"check_tls":1,
                    "op":"open","dest":dest,"class":class,"tls":1
                }),
            )
            .await;
        assert_eq!(harness.effects.snapshot(), expected);
        drop(port);
    }
    drop((foreign_open, foreign_fetch, open, fetch));
}
