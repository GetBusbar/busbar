// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CREDENTIAL FROM THE ENVIRONMENT, FOR A STYLE THAT TAKES ITS TOKEN ENDPOINT FROM IT (Q128
//! ruling (a), the coordinator's approved design). 1.5.5's `api_key_env: VAR` read VAR at runtime:
//! a value that starts with `{` after leading whitespace was the service-account JSON inline, any
//! other was the path of its key file, read from disk (v1.5.5
//! `crates/busbar/src/egress_auth/jwt_bearer.rs:249-256`, `read_credential`). 1.6.0 spells that
//! `api_key: {env: VAR}`. The host resolves it sealed, and only for a style whose declaration
//! states [`STYLE_ENDPOINT_FROM_CREDENTIAL`] does it look at the value: inline JSON is handed on as
//! it is, a path is read as a `{file: <path>}` reference through the secret kind's file source. A
//! style that does not state the flag is never looked at, whatever its name.

use busbar_contract::abi::auth::STYLE_ENDPOINT_FROM_CREDENTIAL;
use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;

/// The token endpoint every service account here names.
const TOKEN_URI: &str = "https://oauth2.example.com/token";

/// A unique tag per test, so tests that share the process (its environment, the double's record)
/// never read each other's.
fn tag(what: &str) -> String {
    format!("q128-{what}-{}", std::process::id())
}

/// The service account a test's credential carries: its `client_email` names `tag`.
fn service_account(tag: &str) -> String {
    serde_json::json!({
        "client_email": format!("{tag}@proj.iam.gserviceaccount.com"),
        "private_key": super::TEST_SA_KEY_PEM,
        "token_uri": TOKEN_URI,
    })
    .to_string()
}

/// A key file holding `json`, named for `tag`; removed when dropped.
struct KeyFile(std::path::PathBuf);

impl KeyFile {
    fn new(tag: &str, json: &str) -> Self {
        let path = std::env::temp_dir().join(format!("busbar-{tag}.json"));
        std::fs::write(&path, json).expect("the key file");
        Self(path)
    }

    fn path(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// An environment variable holding `value`, named for `tag`; removed when dropped.
struct EnvVar(String);

impl EnvVar {
    fn new(tag: &str, value: &str) -> Self {
        let name = format!("BUSBAR_{}", tag.replace('-', "_").to_uppercase());
        std::env::set_var(&name, value);
        Self(name)
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        std::env::remove_var(&self.0);
    }
}

/// THE MEMBER'S ROUTES, sealed by the composition: one provider whose `api_key` is `{env: var}`
/// (1.5.5's `api_key_env: var`, migrated), under `style`, served by `auths`.
fn routes(
    var: &EnvVar,
    style: &'static str,
    auths: super::super::OutboundAuths,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    let providers: std::collections::BTreeMap<String, super::super::ProviderRoute> = [(
        "p".to_string(),
        super::super::ProviderRoute {
            base_url: "http://127.0.0.1:9".to_string(),
            userinfo: None,
            protocol: "d".to_string(),
            error_map: Default::default(),
            credential: busbar_kernel::test_support::secrets::fill_ref(var.0.clone()),
            style: Some(style.to_string()),
            params: super::super::StyleParams::default(),
            metadata: busbar_kernel::config_validate::MetadataPosture::default(),
        },
    )]
    .into();
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let reach = super::super::DoorReach {
        providers: &providers,
        secrets,
        auths: std::sync::Arc::new(auths),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let section: serde_yaml::Value =
        serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, style)],
        dialects: vec!["d"],
        ..Default::default()
    };
    super::super::member_routes(
        &section,
        &super::super::DoorPools::of(&section),
        &facts,
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
}

// ── a style declared by a recording double: which bytes and settings its binding is opened with ──

/// An auth plugin that serves two outbound styles and records what each binding is opened with:
/// [`recorder::FLAGGED`] states [`STYLE_ENDPOINT_FROM_CREDENTIAL`] under a name that is not
/// `jwt-bearer`; [`recorder::UNFLAGGED`] is named `jwt-bearer` and states no flag.
mod recorder {
    use busbar_contract::abi::auth::{
        ranked, AuthTail, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
        OutboundReadyOut, StyleDecl, CAP_INBOUND, CAP_OUTBOUND, LOGIN_KIND_NONE, POINT_HEAD,
        STYLE_ENDPOINT_FROM_CREDENTIAL,
    };
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::door::KindTailHead;
    use busbar_contract::abi::mechanism::lifecycle::slot as life;
    use busbar_contract::abi::sdk::auth_door::{
        Answer, Verdict, Verifier, VerifyPlugin, VerifyView,
    };
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::sdk::lent::Lent;
    use busbar_contract::abi::sdk::life::Held;
    use busbar_contract::abi::sdk::safe::{Instance, SafeSlot};
    use busbar_contract::abi::sdk::Out;
    use std::marker::PhantomData;

    /// The style that takes its token endpoint from its credential, under a name of its own.
    pub(super) const FLAGGED: &str = "sa-from-credential";
    /// A style named `jwt-bearer` that states no endpoint bit.
    pub(super) const UNFLAGGED: &str = "jwt-bearer";

    /// One binding opened: its style, the credential it was handed, its settings.
    pub(super) type Opened = (String, Vec<u8>, serde_json::Value);

    /// Every binding opened, across the tests that share the process.
    pub(super) static OPENED: std::sync::Mutex<Vec<Opened>> = std::sync::Mutex::new(Vec::new());

    /// The plugin: its verdicts pass; its bindings record what they were opened with.
    pub struct Recorder;

    impl VerifyPlugin for Recorder {
        fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
            Ok(Recorder)
        }
        fn verify(&self, _: &VerifyView<'_>) -> Answer {
            Verdict::Pass.into()
        }
    }

    type Inst = Held<Verifier<Recorder>>;

    /// `open_outbound`: records the style, the credential and the settings, and binds handle 1.
    pub struct Open(PhantomData<Recorder>);
    impl SafeSlot for Open {
        type In = OpenOutboundIn;
        type Out = OpenOutboundOut;
        type State = Inst;
        fn call(
            _: Instance<'_, Inst>,
            input: Lent<'_, OpenOutboundIn>,
            mut out: Out<'_, OpenOutboundOut>,
        ) -> Outcome {
            let style = String::from_utf8_lossy(input.field(|i| &i.style).bytes()).into_owned();
            let credential = input.field(|i| &i.credential).bytes().to_vec();
            let settings = serde_json::from_slice(input.field(|i| &i.settings).bytes())
                .unwrap_or(serde_json::Value::Null);
            OPENED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((style, credential, settings));
            out.set(|o| &o.handle, 1);
            Outcome::Ready
        }
    }

    const STYLES: &[StyleDecl] = &[
        StyleDecl {
            name: abi_str(FLAGGED),
            flags: ranked(1) | STYLE_ENDPOINT_FROM_CREDENTIAL,
            points: POINT_HEAD,
        },
        StyleDecl {
            name: abi_str(UNFLAGGED),
            flags: 0,
            points: POINT_HEAD,
        },
    ];
    const TAIL: &AuthTail = &AuthTail {
        head: KindTailHead {
            size: std::mem::size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: CAP_INBOUND | CAP_OUTBOUND,
        facts: 0,
        login_kind: LOGIN_KIND_NONE,
        inbound_points: POINT_HEAD,
        styles: STYLES.as_ptr(),
        styles_len: STYLES.len(),
        operator_principal: abi_str(""),
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };

    use busbar_contract::abi::sdk::auth_door as a;
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: a::with_tail(statement("q128-endpoint-recorder", "1.0.0", 8), TAIL),
        lifecycle: life(a::Verifier<Recorder>),
        kind_ops: {
            verify: busbar_contract::abi::sdk::Safe<a::Verify<Recorder>>,
            begin_login: busbar_contract::abi::sdk::Safe<a::NotServed<
                Recorder, busbar_contract::abi::auth::BeginLoginIn,
                busbar_contract::abi::auth::BeginLoginOut>>,
            complete_login: busbar_contract::abi::sdk::Safe<a::NotServed<
                Recorder, busbar_contract::abi::auth::CompleteLoginIn,
                busbar_contract::abi::auth::IdentifyOut>>,
            open_outbound: busbar_contract::abi::sdk::Safe<Open>,
            outbound_ready: busbar_contract::abi::sdk::Safe<a::NotServed<
                Recorder, OutboundReadyIn, OutboundReadyOut>>,
            fields: busbar_contract::abi::sdk::Safe<a::NotServed<Recorder, FieldsIn, FieldsOut>>,
        },
    }
}

/// The recording double, linked alone on the auths axis, no need granted.
fn recording_auths() -> super::super::OutboundAuths {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    crate::root::connector::install_io(&dispatcher);
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let name = "q128-endpoint-recorder";
    let linked: [busbar_kernel::preflight::LinkedAuth; 1] = [(name, name, recorder::door)];
    super::super::OutboundAuths::new(
        dispatcher,
        &linked,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
    )
}

/// The one binding the double opened whose credential names `tag` (the key file's path or the
/// service account's `client_email` both carry it).
fn opened_naming(tag: &str) -> recorder::Opened {
    let opened = recorder::OPENED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mine: Vec<&recorder::Opened> = opened
        .iter()
        .filter(|(_, credential, _)| String::from_utf8_lossy(credential).contains(tag))
        .collect();
    assert_eq!(mine.len(), 1, "one binding opened for {tag}");
    mine[0].clone()
}

/// RED (1), the flag decides, not the name: `VAR` holds the PATH of a service-account key file, and
/// the style serving the provider states [`STYLE_ENDPOINT_FROM_CREDENTIAL`] under a name that is
/// not `jwt-bearer`. The host reads the key file through the file source and hands the binding the
/// JSON, never the path, with the service account's `token_uri` judged and set (1.5.5's
/// `read_credential`).
#[test]
fn a_flagged_style_is_handed_the_key_file_its_env_credential_names() {
    let tag = tag("flagged-path");
    let json = service_account(&tag);
    let file = KeyFile::new(&tag, &json);
    let var = EnvVar::new(&tag, &file.path());
    routes(&var, recorder::FLAGGED, recording_auths()).expect("the member resolves");
    let (style, credential, settings) = opened_naming(&tag);
    assert_eq!(style, recorder::FLAGGED);
    assert_eq!(
        String::from_utf8_lossy(&credential),
        json,
        "the binding is handed the key file's JSON, never its path"
    );
    assert_eq!(
        settings["token_uri"], TOKEN_URI,
        "the token_uri the credential names is judged and set: {settings}"
    );
}

/// RED (2): `VAR` holds the service-account JSON INLINE, after leading whitespace. The flagged
/// style's binding is handed it as it is (no file opened), with its `token_uri` judged and set.
#[test]
fn a_flagged_style_is_handed_the_inline_json_its_env_credential_holds() {
    let tag = tag("flagged-inline");
    let json = service_account(&tag);
    let var = EnvVar::new(&tag, &format!("\n  {json}"));
    routes(&var, recorder::FLAGGED, recording_auths()).expect("the member resolves");
    let (style, credential, settings) = opened_naming(&tag);
    assert_eq!(style, recorder::FLAGGED);
    assert_eq!(
        String::from_utf8_lossy(&credential).trim(),
        json,
        "the inline JSON is handed on as it is"
    );
    assert_eq!(
        settings["token_uri"], TOKEN_URI,
        "the token_uri the credential names is judged and set: {settings}"
    );
}

/// RED (3): a style that does NOT state [`STYLE_ENDPOINT_FROM_CREDENTIAL`] is never looked at,
/// even when it is named `jwt-bearer`. Given the same `VAR` (a key file's path), its binding is
/// handed the value unchanged, and no `token_uri` is read out of it.
#[test]
fn a_style_without_the_flag_is_handed_its_env_credential_unchanged() {
    let tag = tag("unflagged-path");
    let file = KeyFile::new(&tag, &service_account(&tag));
    let var = EnvVar::new(&tag, &file.path());
    routes(&var, recorder::UNFLAGGED, recording_auths()).expect("the member resolves");
    let (style, credential, settings) = opened_naming(&tag);
    assert_eq!(style, recorder::UNFLAGGED);
    assert_eq!(
        String::from_utf8_lossy(&credential),
        file.path(),
        "a style without the flag is handed the value unchanged: the path, not the file"
    );
    assert!(
        settings.get("token_uri").is_none(),
        "no token_uri is read out of a credential the style does not take its endpoint from: \
         {settings}"
    );
}

// ── the real `jwt-bearer`, the linked mint plugin: it signs and mints as 1.5.5 did ──────────────

/// 1.5.5's scope when the provider names none (`egress_auth/jwt_bearer.rs:19`, v1.5.5).
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The member under the real `jwt-bearer`, its credential `{env: var}`: the first bearer it
/// presents is the one minted at the service account's `token_uri`, and that mint is 1.5.5's
/// (v1.5.5 `egress_auth/jwt_bearer.rs:147-181`): ONE form POST to `token_uri`, `grant_type` then
/// `assertion`; the assertion an RS256 JWT, header `{"alg":"RS256","typ":"JWT"}`, claims exactly
/// `iss` (the `client_email`), `scope` (the default), `aud` (the `token_uri`), `iat` and `exp` one
/// hour on (no `sub`: none was configured), signed with the account's 2048-bit key.
async fn signs_as_1_5_5(var: &EnvVar, client_email: &str) {
    use base64::Engine as _;
    use busbar_contract::auth_calls::FieldsRequest;
    let b64 = |part: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .expect("base64url")
    };
    let table = std::sync::Arc::new(super::TokenEndpoint::default());
    let routes = routes(var, "jwt-bearer", super::linked_mint_plugin(&table))
        .expect("the member resolves, as 1.5.5 booted");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if super::presented(now.as_ref())
                .is_some_and(|a| a.starts_with("Bearer oracle-minted-"))
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        minted.is_ok(),
        "a bearer minted at the token_uri is presented"
    );
    let (_, target, words, body) = table.opened.lock().unwrap()[0].clone();
    assert_eq!(
        target, TOKEN_URI,
        "the mint POSTs to the service account's token_uri"
    );
    assert_eq!(words, b"/token");
    let pairs: Vec<&str> = body.split('&').collect();
    assert_eq!(
        pairs.len(),
        2,
        "grant_type and assertion, nothing else: {body}"
    );
    assert_eq!(
        pairs[0],
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
    );
    let assertion = pairs[1]
        .strip_prefix("assertion=")
        .expect("the RFC 7523 form carries the assertion");
    let parts: Vec<&str> = assertion.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWT");
    let header: serde_json::Value = serde_json::from_slice(&b64(parts[0])).expect("JSON header");
    assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
    let claims: serde_json::Value = serde_json::from_slice(&b64(parts[1])).expect("JSON claims");
    let mut keys: Vec<&str> = claims
        .as_object()
        .expect("a claim set")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["aud", "exp", "iat", "iss", "scope"], "{claims}");
    assert_eq!(claims["iss"], client_email);
    assert_eq!(claims["aud"], TOKEN_URI);
    assert_eq!(claims["scope"], DEFAULT_SCOPE);
    let iat = claims["iat"].as_u64().expect("iat");
    assert_eq!(claims["exp"].as_u64(), Some(iat + 3600), "{claims}");
    assert_eq!(
        b64(parts[2]).len(),
        256,
        "an RS256 signature by a 2048-bit key"
    );
}

/// (1), THE REAL STYLE: `VAR` holds the PATH of the key file. The member boots and signs exactly as
/// 1.5.5's `api_key_env: VAR` did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_bearer_from_an_env_var_naming_its_key_file_signs_as_1_5_5() {
    let tag = tag("jwt-path");
    let file = KeyFile::new(&tag, &service_account(&tag));
    let var = EnvVar::new(&tag, &file.path());
    signs_as_1_5_5(&var, &format!("{tag}@proj.iam.gserviceaccount.com")).await;
}

/// (2), THE REAL STYLE: `VAR` holds the service-account JSON inline, after leading whitespace. The
/// member boots and signs exactly as 1.5.5 did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_bearer_from_an_env_var_holding_inline_json_signs_as_1_5_5() {
    let tag = tag("jwt-inline");
    let var = EnvVar::new(&tag, &format!("\n  {}", service_account(&tag)));
    signs_as_1_5_5(&var, &format!("{tag}@proj.iam.gserviceaccount.com")).await;
}

/// The real `jwt-bearer` states the flag the host reads (the linked mint plugin, u29 F1): without
/// it the host would hand the plugin the path, which it refuses (ruling 11: no plugin file I/O).
#[test]
fn the_real_jwt_bearer_takes_its_endpoint_from_its_credential() {
    let table = std::sync::Arc::new(super::TokenEndpoint::default());
    let flags = super::linked_mint_plugin(&table)
        .declared()
        .into_iter()
        .find(|s| s.name == "jwt-bearer")
        .map(|s| s.flags)
        .expect("the linked mint plugin declares jwt-bearer");
    assert_ne!(flags & STYLE_ENDPOINT_FROM_CREDENTIAL, 0, "{flags:#x}");
}
