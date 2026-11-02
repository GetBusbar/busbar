// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::auth_calls::{FieldsRequest, Verified, VerifyRequest};
use busbar_contract::secret::SecretAxis as _;
use busbar_contract::secret_ref::{SECRET_MODULE_ENV, SECRET_MODULE_FILE, SECRET_MODULE_TEMPLATE};
use busbar_core_connector::{doors::Dispatched, process, registry::Entry, Connector};
use busbar_kernel::host_services::KernelServices;
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{
    kinds::transport::Transport, load_linked, DispatchConfig, Dispatcher, LinkedRow,
};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

use crate::canary::{Canary, Sink};
use crate::{common, recorder};

struct Doors {
    webhook_signature: (String, DoorFn),
    header: (String, DoorFn),
    oidc: (String, DoorFn),
}

fn stated_name(door: DoorFn) -> String {
    let rendering =
        busbar_plugin_loader::dispatch::rendering_of(door).expect("the door renders its Statement");
    busbar_contract::abi::mechanism::rendering::read(&rendering)
        .expect("its rendering reads")
        .name
}

fn doors() -> &'static Doors {
    static ONE: OnceLock<Doors> = OnceLock::new();
    ONE.get_or_init(|| {
        let linked = |label: &str, door: DoorFn| {
            // SAFETY: a linked crate's door lives for the process.
            let wrapped = unsafe { recorder::wrap(label, door() as *const Door) };
            (stated_name(door), wrapped)
        };
        let webhook_signature = linked(
            "busbar-auth-webhook-signature (linked)",
            busbar_auth_webhook_signature::compiled_in::door::door,
        );
        let header = linked(
            "busbar-auth-header (linked)",
            busbar_auth_header::compiled_in::door::door,
        );

        let path = common::plugins::token_verifier_cdylib_path().unwrap_or_else(|| {
            common::plugins::missing(
                "pinned token-verifying `kind: auth` plugin's",
                common::plugins::BUILD_PINNED,
            )
        });
        // SAFETY: the pinned first-party cdylib; its initialisers are the SDK's.
        let lib = unsafe { libloading::Library::new(&path) }.expect("dlopen the OIDC cdylib");
        // SAFETY: `busbar_plugin_door` is typed `RawDoorFn` by the mechanism.
        let raw: RawDoorFn = unsafe {
            *lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("the cdylib exports its door")
        };
        std::mem::forget(lib);
        // SAFETY: the library is never unloaded, so its door lives for the process.
        let oidc_door = unsafe { recorder::wrap("busbar-auth-oidc (dropped-in cdylib)", raw()) };
        let oidc = (stated_name(oidc_door), oidc_door);
        Doors {
            webhook_signature,
            header,
            oidc,
        }
    })
}

fn registry() -> Arc<PluginRegistry> {
    let d = doors();
    let rows = [&d.webhook_signature, &d.header, &d.oidc]
        .iter()
        .map(|(name, door)| LinkedPlugin::auth_door_named(name, name, *door))
        .collect();
    Arc::new(
        PluginRegistry::empty()
            .link(rows)
            .expect("the wrapped doors admit as linked rows"),
    )
}

fn tracing_capture() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&buf);
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || Capture(Arc::clone(&sink)))
            .try_init();
        buf
    })
}

struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct AbiCanaries {
    pub secret_ref_file: Canary,

    pub settings_env_ref: Canary,

    pub settings_template: Canary,

    pub settings_interp: Canary,

    pub outbound_credential: Canary,

    pub passthrough: Canary,
}

impl AbiCanaries {
    pub fn all(&self) -> Vec<Canary> {
        vec![
            self.secret_ref_file.clone(),
            self.settings_env_ref.clone(),
            self.settings_template.clone(),
            self.settings_interp.clone(),
            self.outbound_credential.clone(),
            self.passthrough.clone(),
        ]
    }
}

// The ABI observer owns its FFI boundary, while all services and I/O are the
// public product implementations. It never installs a substitute kernel root.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the canary I/O runtime")
    })
}

fn host() -> &'static (Arc<Dispatcher>, Arc<Connector>) {
    static HOST: OnceLock<(Arc<Dispatcher>, Arc<Connector>)> = OnceLock::new();
    HOST.get_or_init(|| {
        let guard = process::dest_judge(&busbar_kernel::config::Destinations {
            allow: vec!["127.0.0.1".into()],
            ..Default::default()
        })
        .expect("the local IdP destination policy");
        let services = Arc::new(KernelServices::new().with_dest_judge(guard.clone()));
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            services,
        ));
        assert!(dispatcher.lend_seal(busbar_kernel::seal::lend()));
        dispatcher.install_runtime(runtime().handle().clone());
        busbar_core_connector::io::install_process_reactor(runtime().handle().clone());
        let settings = busbar_contract::transport::TransportSettings::default();
        let row = LinkedRow::of(busbar_transport_http::linked::door)
            .expect("the actual HTTP transport states itself");
        let plugin =
            load_linked::<Transport>(&row, busbar_core_connector::doors::bind_on(&dispatcher))
                .expect("the actual HTTP transport admits");
        let door = Dispatched::open_on(plugin, &settings, dispatcher.clone())
            .expect("the actual HTTP transport opens");
        let connector = process::build_with_secrets(
            || {
                Ok(vec![Entry {
                    door: Arc::new(door),
                    alpn: Vec::new(),
                }])
            },
            guard,
            &[],
            dispatcher.conn_waker(),
            busbar_core_connector::pool::PoolPosture::NONE,
            busbar_core_connector::spawn_env::linked_spawn_secret,
        )
        .expect("the real connector builds");
        (dispatcher, connector)
    })
}

fn dispatcher() -> Arc<Dispatcher> {
    host().0.clone()
}

fn connections() -> Option<Arc<dyn busbar_contract::conn::DeclaredConns>> {
    Some(host().1.clone())
}

fn sources() -> &'static busbar_plugin_loader::secret_calls::SecretRows {
    static SOURCES: OnceLock<busbar_plugin_loader::secret_calls::SecretRows> = OnceLock::new();
    SOURCES.get_or_init(|| {
        let mut sources =
            busbar_plugin_loader::secret_calls::SecretRows::new(dispatcher, connections)
                .with_disk_lane(|job| {
                    static DISK: OnceLock<busbar_kernel::host_disk::DiskLane> = OnceLock::new();
                    DISK.get_or_init(Default::default)
                        .run(job)
                        .map_err(str::to_string)
                });
        sources
            .link(busbar_secret_env::door::door)
            .expect("the real env source");
        sources
            .link(busbar_secret_file::door::door)
            .expect("the real file source");
        sources
            .declare_linked(busbar_secret_file::door::door, busbar_secret_file::DECLARES)
            .expect("the file source's own disk declaration");
        sources
    })
}

fn source(module: &str, settings: serde_json::Value) -> String {
    let value = sources()
        .shared(module)
        .expect("the actual secret source opens")
        .resolve_at_config(
            settings.to_string().as_bytes(),
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("the actual secret source resolves the canary");
    String::from_utf8(value.into_exposed(&busbar_kernel::seal::lend()))
        .expect("the canary source is UTF-8")
}

fn open(
    rows: &AuthRows,
    module: &str,
    settings: serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    rows.open(module, module, &serde_json::Value::Object(settings))
        .map(|_| ())
}

pub fn run(c: &AbiCanaries) -> (Vec<Sink>, Vec<String>) {
    let tracing = tracing_capture();
    let traced_from = tracing.lock().unwrap_or_else(|p| p.into_inner()).len();
    let d = doors();
    let reg = registry();
    let rows = AuthRows::new(reg.clone(), dispatcher()).with_table(host().1.clone());
    let mut sinks = Vec::new();
    let mut notes = Vec::new();
    let mut outcome = |what: &str, r: Result<(), String>| match r {
        Ok(()) => notes.push(format!("{what}: opened")),
        Err(e) => {
            notes.push(format!("{what}: refused"));
            sinks.push(Sink::text(format!("refusal:{what}"), "AuthRows::open", e));
        }
    };
    let pid = std::process::id();

    static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = crate::blackbox::scratch("abi");

    let secret_file = dir.join("signing-secret");
    std::fs::write(&secret_file, &c.secret_ref_file.value).expect("the secret file");
    let mut s = serde_json::Map::new();
    s.insert("variant".into(), "twilio".into());
    s.insert("origin".into(), "wss://edge.canary.invalid".into());
    s.insert(
        "signing-secret".into(),
        source(
            SECRET_MODULE_FILE,
            serde_json::json!({"path": secret_file.display().to_string()}),
        )
        .into(),
    );
    outcome(
        "webhook-signature secret_refs (file ref)",
        open(&rows, &d.webhook_signature.0, s),
    );

    let audience = "api://canary";
    let env_var = format!("BUSBAR_CANARY_AUD_{pid}_{run}");
    std::env::set_var(&env_var, &c.settings_env_ref.value);
    let mut s = common::credentials::settings(audience);
    s.insert(
        "audience".into(),
        source(SECRET_MODULE_ENV, serde_json::json!({"key": env_var})).into(),
    );
    outcome("oidc settings (env ref)", open(&rows, &d.oidc.0, s));

    let tpl_var = format!("BUSBAR_CANARY_TPL_{pid}_{run}");
    std::env::set_var(&tpl_var, &c.settings_template.value);
    let mut s = common::credentials::settings(audience);
    s.insert(
        "audience".into(),
        serde_json::json!({ SECRET_MODULE_TEMPLATE: format!("aud-${{{tpl_var}}}") }),
    );
    outcome(
        "oidc settings (env-template ref)",
        open(&rows, &d.oidc.0, s),
    );

    let interp_var = format!("BUSBAR_CANARY_INTERP_{pid}_{run}");
    std::env::set_var(&interp_var, &c.settings_interp.value);
    let text =
        busbar_kernel::config::interpolate_env(&format!("audience: \"${{{interp_var}}}\"\n"))
            .expect("the config text interpolates");
    let parsed: serde_json::Map<String, serde_json::Value> =
        serde_yaml::from_str(&text).expect("the interpolated settings parse");
    let mut s = common::credentials::settings(audience);
    s.extend(parsed);
    outcome(
        "oidc settings (${VAR} interpolation)",
        open(&rows, &d.oidc.0, s),
    );
    // Prove that the observed dropped-in OIDC door reaches the TLS JWKS server
    // through the actual connector, rather than only recording a refused open.
    let oidc = rows
        .open(
            &d.oidc.0,
            "canary-live-oidc",
            &serde_json::Value::Object(common::credentials::settings(audience)),
        )
        .expect("the observed OIDC plugin opens on actual host services");
    let mut request = VerifyRequest::default();
    request.credential = Some(busbar_contract::redacted::Secret::new(
        common::credentials::token_for("canary", &["privacy"], audience).into_bytes(),
    ));
    request.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock")
        .as_secs();
    let answer = runtime().block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(15), oidc.verify(request))
            .await
            .expect("the real OIDC verification answers")
    });
    assert!(
        matches!(answer.verified, Verified::Identity(ref identity) if identity.subject == "oidc:canary"),
        "the observed dropped-in door verifies a signed token over the real TLS connection: {:?}",
        answer.verified,
    );
    drop(oidc);

    for v in [&env_var, &tpl_var, &interp_var] {
        std::env::remove_var(v);
    }

    let outbound = AuthRows::new(reg, dispatcher()).with_table(host().1.clone());
    let settings = serde_json::json!({});
    match outbound.serving("api-key", &settings) {
        Ok(Some(serving)) => {
            let request = || {
                let mut request = FieldsRequest::default();
                request.method = b"POST".to_vec();
                request.authority = "api.canary.invalid".into();
                request.path = b"/v1/messages".to_vec();
                request
            };
            match serving.auth.open_outbound(
                "api-key",
                c.outbound_credential.value.as_bytes(),
                &settings,
            ) {
                Ok(handle) => {
                    if serving.auth.fields_now(handle, &request()).is_none() {
                        notes.push("outbound fields did not answer on the spot".into());
                    }
                }
                Err(e) => sinks.push(Sink::text("refusal:open_outbound", "api-key", e)),
            }
            match serving.auth.open_outbound("api-key", b"", &settings) {
                Ok(handle) => {
                    let mut r = request();
                    r.caller_credential = Some(busbar_contract::redacted::Secret::new(
                        c.passthrough.value.as_bytes().to_vec(),
                    ));
                    if serving.auth.fields_now(handle, &r).is_none() {
                        notes.push("passthrough fields did not answer on the spot".into());
                    }
                }
                Err(e) => sinks.push(Sink::text(
                    "refusal:open_outbound (passthrough)",
                    "api-key",
                    e,
                )),
            }
        }
        Ok(None) => notes.push("no outbound row serves `api-key`".into()),
        Err(e) => sinks.push(Sink::text("refusal:serving", "api-key", e)),
    }

    let traced = tracing.lock().unwrap_or_else(|p| p.into_inner())[traced_from..].to_vec();
    sinks.push(Sink::raw(
        "log:in-process tracing",
        "kernel + loader",
        traced,
    ));
    for x in recorder::crossings() {
        sinks.push(Sink::raw(
            format!("abi:{}:{}", x.dir.arrow(), x.site),
            x.plugin,
            x.bytes,
        ));
    }
    let calls = recorder::calls();
    let mut seen: Vec<String> = calls.iter().map(|(p, s)| format!("{p} {s}")).collect();
    seen.sort();
    seen.dedup();
    notes.push(format!(
        "the shim forwarded {} call(s) over {} distinct (plugin, site) pairs",
        calls.len(),
        seen.len()
    ));
    notes.extend(seen.into_iter().map(|s| format!("  shim saw: {s}")));
    let _ = std::fs::remove_dir_all(&dir);
    (sinks, notes)
}
