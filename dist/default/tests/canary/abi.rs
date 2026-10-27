// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ABI SINKS (settings, declared secrets, outbound and passthrough credentials): the kernel's own resolution and the loader's own dispatch, in
//! process, over doors wrapped by the recording shim ([`crate::recorder`]).
//!
//! * a LINKED door: the compiled-in `busbar-auth-webhook-signature` and `busbar-auth-header` doors
//!   the composition root links;
//! * a DROPPED-IN door: the token-verifying OIDC plugin's cdylib (the pinned git dev-dependency the
//!   other auth suites package as a tarball), `dlopen`ed here and its `busbar_plugin_door` wrapped.
//!
//! Each runs through the path the boot takes: `AuthMiddleware::new` resolves the chain entry's
//! settings (`config::secret::resolve_settings`) and opens the plugin over the loader's auth axis
//! (its settings, and the Statement's `secret_refs` as `OpenIn.secrets`); the loader's outbound
//! rows bind a provider credential (`open_outbound`) and lend a caller's credential on a passthrough
//! `fields`.

use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::auth_calls::FieldsRequest;
use busbar_contract::plugin_rows::PluginRows;
use busbar_contract::secret_ref::{SECRET_MODULE_ENV, SECRET_MODULE_FILE, SECRET_MODULE_TEMPLATE};
use busbar_kernel::auth::AuthMiddleware;
use busbar_kernel::config::{AuthCfg, AuthChainEntry};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

use crate::canary::{Canary, Sink};
use crate::{common, recorder};

/// The wrapped doors, made once per process: (registry name, recording door).
struct Doors {
    webhook_signature: (String, DoorFn),
    header: (String, DoorFn),
    oidc: (String, DoorFn),
}

/// The name `door`'s Statement states.
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
        // THE DROPPED-IN DOOR: the cdylib a `plugins/` tarball carries, opened as the loader opens
        // it and never unloaded (the wrapped door points into it for the process's life).
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

/// The registry the root would build over these doors: each a linked auth row.
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

/// The local issuer the OIDC plugin's settings name, its JWKS served over the stand-in conns.
fn issuer() -> &'static busbar_test_kit::test_issuer::Issuer {
    static ONE: OnceLock<busbar_test_kit::test_issuer::Issuer> = OnceLock::new();
    ONE.get_or_init(|| {
        let issuer =
            busbar_test_kit::test_issuer::Issuer::start("https://issuer.canary.invalid", "canary");
        let conns = busbar_test_kit::https_conns::HttpsConns::new();
        conns.serve_issuer(&issuer);
        busbar_plugin_loader::auth_axis::stand_in_conns(Arc::new(conns));
        issuer
    })
}

/// Everything the process's tracing writes (every level), captured from the first call on: the
/// in-process log sink. The subscriber is this test binary's own global default.
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

/// One write into the captured tracing buffer.
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

/// The canaries the ABI scenario plants.
pub struct AbiCanaries {
    /// DECLARED SECRETS: a Statement `secret_refs` value (`signing-secret`), planted as a FILE SecretRef.
    pub secret_ref_file: Canary,
    /// SETTINGS: a dropped-in plugin's setting as an ENV SecretRef.
    pub settings_env_ref: Canary,
    /// SETTINGS: a dropped-in plugin's setting as an `env-template` SecretRef.
    pub settings_template: Canary,
    /// SETTINGS, INTERPOLATED: a dropped-in plugin's setting through `${VAR}` interpolation of the config text.
    pub settings_interp: Canary,
    /// OUTBOUND: a provider credential bound through `open_outbound`.
    pub outbound_credential: Canary,
    /// PASSTHROUGH: the caller's own credential on a passthrough binding.
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

/// One chain over `module` with `settings`, built as the boot builds it.
fn chain(
    rows: &Arc<dyn PluginRows>,
    module: &str,
    settings: serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings;
    let cfg = AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    };
    AuthMiddleware::new(
        &cfg,
        rows,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .map(|_| ())
}

/// RUN the in-process scenarios and answer the sinks: every recorded crossing, every refusal text.
pub fn run(c: &AbiCanaries) -> (Vec<Sink>, Vec<String>) {
    common::root_install::install();
    let tracing = tracing_capture();
    let traced_from = tracing.lock().unwrap_or_else(|p| p.into_inner()).len();
    let issuer = issuer();
    let d = doors();
    let reg = registry();
    let rows: Arc<dyn PluginRows> = reg.clone();
    let mut sinks = Vec::new();
    let mut notes = Vec::new();
    let mut outcome = |what: &str, r: Result<(), String>| match r {
        Ok(()) => notes.push(format!("{what}: opened")),
        Err(e) => {
            notes.push(format!("{what}: refused"));
            sinks.push(Sink::text(
                format!("refusal:{what}"),
                "AuthMiddleware::new",
                e,
            ));
        }
    };
    let pid = std::process::id();
    // One run's variable names, never a canary's own bytes (a name is not a sink of its value).
    static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = crate::blackbox::scratch("abi");

    // DECLARED SECRETS: the signing secret, a FILE reference the kernel resolves and the loader lends as
    // `OpenIn.secrets`.
    let secret_file = dir.join("signing-secret");
    std::fs::write(&secret_file, &c.secret_ref_file.value).expect("the secret file");
    let mut s = serde_json::Map::new();
    s.insert("variant".into(), "twilio".into());
    s.insert("origin".into(), "wss://edge.canary.invalid".into());
    s.insert(
        "signing-secret".into(),
        serde_json::json!({ SECRET_MODULE_FILE: secret_file.display().to_string() }),
    );
    outcome(
        "webhook-signature secret_refs (file ref)",
        chain(&rows, &d.webhook_signature.0, s),
    );

    // SETTINGS, dropped-in: a setting as an ENV reference.
    let audience = "api://canary";
    let env_var = format!("BUSBAR_CANARY_AUD_{pid}_{run}");
    std::env::set_var(&env_var, &c.settings_env_ref.value);
    let mut s = issuer.settings(audience);
    s.insert(
        "audience".into(),
        serde_json::json!({ SECRET_MODULE_ENV: env_var }),
    );
    outcome("oidc settings (env ref)", chain(&rows, &d.oidc.0, s));

    // SETTINGS, dropped-in: a setting as an `env-template` reference.
    let tpl_var = format!("BUSBAR_CANARY_TPL_{pid}_{run}");
    std::env::set_var(&tpl_var, &c.settings_template.value);
    let mut s = issuer.settings(audience);
    s.insert(
        "audience".into(),
        serde_json::json!({ SECRET_MODULE_TEMPLATE: format!("aud-${{{tpl_var}}}") }),
    );
    outcome(
        "oidc settings (env-template ref)",
        chain(&rows, &d.oidc.0, s),
    );

    // SETTINGS, dropped-in: `${VAR}` interpolated into the config text, then parsed.
    let interp_var = format!("BUSBAR_CANARY_INTERP_{pid}_{run}");
    std::env::set_var(&interp_var, &c.settings_interp.value);
    let text =
        busbar_kernel::config::interpolate_env(&format!("audience: \"${{{interp_var}}}\"\n"))
            .expect("the config text interpolates");
    let parsed: serde_json::Map<String, serde_json::Value> =
        serde_yaml::from_str(&text).expect("the interpolated settings parse");
    let mut s = issuer.settings(audience);
    s.extend(parsed);
    outcome(
        "oidc settings (${VAR} interpolation)",
        chain(&rows, &d.oidc.0, s),
    );
    for v in [&env_var, &tpl_var, &interp_var] {
        std::env::remove_var(v);
    }

    // OUTBOUND and PASSTHROUGH: the provider credential bound on the outbound rows, a request's fields asked for,
    // then a passthrough binding lent the caller's credential.
    let dispatcher = busbar_plugin_loader::dispatch::Dispatcher::new(
        busbar_plugin_loader::dispatch::DispatchConfig::default(),
    );
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let outbound = busbar_plugin_loader::auth_axis::AuthRows::new(reg, Arc::new(dispatcher));
    let settings = serde_json::json!({});
    match outbound.serving("api-key", &settings) {
        Ok(Some(serving)) => {
            let request = || FieldsRequest {
                method: b"POST".to_vec(),
                authority: "api.canary.invalid".into(),
                path: b"/v1/messages".to_vec(),
                ..FieldsRequest::default()
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
