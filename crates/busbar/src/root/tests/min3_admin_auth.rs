// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn grants() -> BTreeMap<Box<str>, BTreeSet<Box<str>>> {
    BTreeMap::from([("reader".into(), BTreeSet::from(["signed".into()]))])
}

fn instance<'a>(name: &'a str, id: u64, kind: Option<&'a str>) -> GrantInstance<'a> {
    GrantInstance {
        name,
        id,
        kind,
        verifies: true,
    }
}

#[test]
fn issued_grants_require_explicit_matching_instance_kind_and_custody() {
    let allowed =
        resolve_grants(&grants(), [instance("reader", 41, Some("signed"))], true).unwrap();
    assert_eq!(
        allowed,
        BTreeMap::from([(41, BTreeSet::from(["signed".into()]))])
    );
    let no_grants = resolve_grants(
        &BTreeMap::new(),
        [instance("reader", 41, Some("signed"))],
        false,
    )
    .unwrap();
    assert!(no_grants.is_empty(), "a describe grants nothing");
    for opened in [
        vec![],
        vec![instance("other", 41, Some("signed"))],
        vec![instance("reader", 41, Some("other"))],
        vec![instance("reader", 41, None)],
        vec![instance("reader", 0, Some("signed"))],
        vec![GrantInstance {
            verifies: false,
            ..instance("reader", 41, Some("signed"))
        }],
    ] {
        assert!(resolve_grants(&grants(), opened, true).is_err());
    }
    assert!(resolve_grants(&grants(), [instance("reader", 41, Some("signed"))], false).is_err());
}

#[test]
fn issued_grants_refuse_duplicate_runtime_reservations_and_builtin_keys() {
    for opened in [
        vec![
            instance("reader", 41, Some("signed")),
            instance("reader", 42, Some("signed")),
        ],
        vec![
            instance("reader", 41, Some("signed")),
            instance("other", 41, Some("signed")),
        ],
    ] {
        assert!(resolve_grants(&grants(), opened, true).is_err());
    }
    let keys = BTreeMap::from([(
        busbar_kernel::config::KEYS_MODULE.into(),
        BTreeSet::from(["signed".into()]),
    )]);
    assert!(resolve_grants(
        &keys,
        [instance(
            busbar_kernel::config::KEYS_MODULE,
            41,
            Some("signed")
        )],
        true
    )
    .is_err());
}

#[test]
fn issued_grants_keep_explicit_empty_policy_without_inventing_custody() {
    let empty = BTreeMap::from([("reader".into(), BTreeSet::new())]);
    assert!(
        resolve_grants(&empty, [instance("reader", 41, None)], false)
            .unwrap()
            .get(&41)
            .unwrap()
            .is_empty()
    );
    assert!(
        resolve_grants(&empty, [], false).is_err(),
        "explicit policy still names an actual instance"
    );
}

/// A deployment of the operator-credential reload test: the operator credential is the definition
/// whose settings digest is `token`'s, or, with `None`, the default chain's bare operator with no
/// definition.
fn operator_deployment(operator: &str, token: Option<&str>) -> busbar_kernel::config::RootCfg {
    crate::root::linked::register_stores();
    // Written as the operator writes it: config.yaml text.
    let mut document = format!(
        "providers: {{}}\nmodels: {{}}\nstore:\n  module: memory\nauth:\n  chain: []\n  \
         admin_auth: [\"{operator}\"]\n"
    );
    if let Some(token) = token {
        let digest = crate::root::test_plugins::sha256(token.as_bytes());
        document.push_str(&format!(
            "identity-providers:\n  \"{operator}\":\n    module: \"{operator}\"\n    settings:\n      \
             sha256: \"{digest}\"\n"
        ));
    }
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the operator deployment parses");
    crate::root::test_plugins::plaintext_listeners(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the operator deployment resolves"),
    )
}

/// The generation an operator-credential reload test starts with, built as a boot builds it.
async fn booted_with(
    cfg: busbar_kernel::config::RootCfg,
    rules: &Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> App {
    let store = crate::root::real_store::core().await;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        rules,
        Some(store),
        false,
    )
    .await
    .expect("the boot builds");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD
        .keep_in_store(
            app.governance
                .as_ref()
                .expect("the deployment configures governance")
                .core_store_handle()
                .expect("the configured Store exposes its rate-history slots"),
            123,
        )
        .expect("native rate history attaches");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the configured Store boots its rate history");
    limits.keep().await.expect("the boot commits its limits");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    app
}

/// A reload candidate built over the running generation `running`, as every rebuild (`POST
/// /config/reload`, `PUT /config/settings`, the plugin reload and rollback) builds it.
async fn reloaded(
    cfg: busbar_kernel::config::RootCfg,
    running: &App,
    rules: &Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> Result<(), String> {
    busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(running),
        rules,
        Some(crate::root::real_store::core().await),
        false,
    )
    .await
    .map(drop)
}

/// THE OPERATOR CREDENTIAL IS BOUND AT START (owner's ruling, 18 Nov 2026), the fixture of its two
/// tests: a reload whose operator credential differs from the running one's (its settings digest
/// changed, the definition removed, or one added where start had none) is refused as a whole,
/// naming the definition and that a restart is required, and revealing nothing of either
/// credential; the running generation keeps its credential. Before the ruling the candidate was
/// applied and its admin chain rebuilt from the new settings at once: the new digest took over the
/// admin plane, and a removed one left the position unset so every admin request was refused. A
/// reload that leaves the binding byte-identical is applied as before.
struct OperatorReload {
    operator: &'static str,
    rules: Arc<dyn busbar_kernel::appbuild::RootRules>,
}

const TOKEN_A: &str = "operator-token-a";
const TOKEN_B: &str = "operator-token-b";

impl OperatorReload {
    /// The linked first-party operator bound through the production process-start binding, its
    /// image published as a native auth image (as the start stage's image prepare publishes it).
    fn new() -> Self {
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let operator = crate::root::test_plugins::bind_operator();
        assert!(!operator.is_empty(), "the linked operator credential binds");
        crate::root::native_operator::NATIVE
            .publish_auth_names(std::iter::once(operator.to_owned()).collect());
        Self {
            operator,
            rules: Arc::new(crate::root::door_steps::Rules::default()),
        }
    }

    fn deployment(&self, token: Option<&str>) -> busbar_kernel::config::RootCfg {
        operator_deployment(self.operator, token)
    }

    /// `refusal` refuses the candidate as a whole for `what` it does to the operator credential,
    /// says a restart is required, and reveals neither credential.
    fn refused_as_a_whole(&self, refusal: &str, what: &str) {
        let operator = self.operator;
        assert!(
            refusal.starts_with(&format!(
                "identity-providers.{operator} is the operator credential, which is bound at \
                 process start: this configuration {what}, so the change was refused and nothing \
                 was changed"
            )),
            "{refusal}"
        );
        assert!(
            refusal.contains("Restart the process to change the operator credential"),
            "{refusal}"
        );
        no_credential_in(refusal);
    }
}

fn no_credential_in(text: &str) {
    for token in [TOKEN_A, TOKEN_B] {
        let digest = crate::root::test_plugins::sha256(token.as_bytes());
        assert!(
            !text.contains(token) && !text.contains(&digest),
            "a credential is revealed: {text}"
        );
    }
}

fn held_refusals() -> Vec<String> {
    busbar_kernel::audit::auditlog::held_operator_rows()
        .into_iter()
        .filter(|row| row.starts_with("auth.operator.refused"))
        .collect()
}

#[tokio::test]
async fn a_reload_that_changes_or_removes_the_operator_credential_is_refused_and_it_stays() {
    let test = OperatorReload::new();
    let operator = test.operator;
    let rules = &test.rules;
    let booted = booted_with(test.deployment(Some(TOKEN_A)), rules).await;
    let bound = booted.identity_providers.get(operator).cloned();
    assert!(bound.is_some(), "the boot binds credential A");

    assert_eq!(
        reloaded(test.deployment(Some(TOKEN_A)), &booted, rules).await,
        Ok(()),
        "a byte-identical operator credential reloads as before"
    );
    assert!(held_refusals().is_empty(), "nothing refused yet");

    let changed = reloaded(test.deployment(Some(TOKEN_B)), &booted, rules)
        .await
        .expect_err("a reload that changes the operator credential is refused");
    test.refused_as_a_whole(&changed, "changes it");
    let removed = reloaded(test.deployment(None), &booted, rules)
        .await
        .expect_err("a reload that removes the operator credential is refused");
    test.refused_as_a_whole(&removed, "removes it");
    assert_eq!(
        booted.identity_providers.get(operator).cloned(),
        bound,
        "the running generation keeps credential A"
    );
    let rows = held_refusals();
    assert_eq!(
        rows.len(),
        2,
        "one refusal row per refused reload: {rows:?}"
    );
    for row in &rows {
        assert!(
            row.contains(operator),
            "the row names the definition: {row}"
        );
        no_credential_in(row);
    }
}

#[tokio::test]
async fn a_reload_that_adds_an_operator_credential_where_start_had_none_is_refused() {
    let test = OperatorReload::new();
    let rules = &test.rules;
    let unset = booted_with(test.deployment(None), rules).await;
    assert_eq!(
        reloaded(test.deployment(None), &unset, rules).await,
        Ok(()),
        "no credential at start and none in the reload: applied as before"
    );
    let added = reloaded(test.deployment(Some(TOKEN_B)), &unset, rules)
        .await
        .expect_err("a reload that adds an operator credential where start had none is refused");
    test.refused_as_a_whole(&added, "adds it");
    assert_eq!(held_refusals().len(), 1, "the refused reload is audited");
}

/// SECURITY-OWED `a_role_shadowing_the_operator_principal_is_refused` (ci/owed/cut-root): a role
/// binding named as the operator principal would let a data-plane credential be judged as the
/// operator. Validation refuses the deployment and names the binding. The deleted test reached
/// this through the old linked auth axis; the rule is the kernel's and is reached here over the
/// natively bound operator.
#[test]
fn a_role_named_as_the_operator_principal_is_refused_by_validation() {
    use busbar_kernel::config::{self, AuthCfg, AuthChainEntry, RoleBindingCfg};
    let fixture = OperatorReload::new();
    let mut cfg = fixture.deployment(None);
    let mut auth = AuthCfg::default_none();
    auth.chain = vec![AuthChainEntry::bare(config::KEYS_MODULE)];
    auth.role_bindings.insert(
        config::KEYS_MODULE.to_string(),
        std::iter::once((
            config::operator_principal_id().to_string(),
            RoleBindingCfg::default(),
        ))
        .collect(),
    );
    cfg.auth = Some(auth);
    let errs = busbar_kernel::config_validate::validate(&cfg)
        .expect_err("a role named as the operator principal is refused");
    assert!(
        errs.iter().any(|e| e.contains("role_bindings.keys")
            && e.contains(&format!("'{}'", config::operator_principal_id()))
            && e.contains("reserved")),
        "expected the reserved-role-name refusal; got: {errs:?}"
    );
}

/// SECURITY-OWED `an_unregistered_auth_module_is_refused_with_the_1_5_5_bytes` (ci/owed/cut-root):
/// an identity provider naming an auth module nothing answers, with the plugin subsystem off, is
/// refused before anything opens, in the words v1.5.5 printed (golden cell BOOT-133). The deleted
/// test reached the refusal with the old linked auth axis installed; here only the native
/// operator is bound, so the built-ins the refusal lists are the native ones. If they differ from
/// v1.5.5's this test is red and the difference is the owner's to accept or fix.
#[test]
fn an_unregistered_auth_module_is_refused_with_the_1_5_5_words_on_the_native_binding() {
    const GOLDEN: &str = include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../testing/shadow-oracle/golden/1.5.5/cells/boot.refusal__BOOT-133__boot.json"
    ));
    let cell: serde_json::Value = serde_json::from_str(GOLDEN).expect("the golden cell parses");
    let golden = cell["effects"]["stderr"]
        .as_str()
        .expect("the cell records stderr")
        .lines()
        .find_map(|line| line.strip_prefix("[error] "))
        .expect("an [error] line")
        .to_string();

    let _native = OperatorReload::new();
    let mut providers = busbar_kernel::config::IdentityProviders::new();
    let definition: busbar_kernel::config::IdentityProviderCfg =
        busbar_contract::yaml::from_str("module: oidc").expect("a provider definition");
    providers.insert("oracle-oidc".to_string(), definition);
    let refused = busbar_kernel::preflight::plugins_preflight(
        None,
        None,
        &providers,
        &std::collections::HashMap::new(),
        &busbar_kernel::config::PluginsCfg::default(),
        &busbar_kernel::config::ExportCfg::default(),
    )
    .err()
    .expect("an unregistered auth module is refused");
    assert_eq!(refused, golden);
}

/// The admin door `app` answers one `GET /api/v1/admin/info` presenting `bearer` (none: no
/// credential), judged as the admin listener judges a request: the original request's charged
/// snapshot handed to the generation's native admin chain (`admin_verdict_for`).
async fn admin_door(app: Arc<App>, bearer: Option<&str>) -> busbar_kernel::auth::AdminDoor {
    use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let value = bearer.map(|token| format!("Bearer {token}"));
    let mut headers = axum::http::HeaderMap::new();
    if let Some(value) = &value {
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    let process = ProcessAdmission::new(2);
    let lease = process
        .try_enter(AdmissionClass::Operator)
        .expect("an operator admission");
    let request = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "GET",
            path: INFO,
            query: "",
            query_present: false,
            authority: "",
            headers: value.iter().map(|value| ("authorization", value.as_bytes())),
            peer: "",
            tls_peer_cert: &[],
            body: b"",
            now_s: busbar_kernel::store::now(),
        },
        &lease,
    )
    .expect("the request snapshot");
    let id = busbar_kernel::state::InvocationId::from_request_id(
        std::num::NonZeroU64::new(app.next_request_id()).expect("a request id"),
    );
    let invocation = busbar_kernel::auth::native_admin::Invocation {
        handle: Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&app))),
        selected: app,
        id,
        cx: busbar_kernel::auth::admin_call_context(id),
        request,
    };
    busbar_kernel::auth::admin_verdict_for(invocation, &headers)
        .await
        .door
}

const INFO: &str = "/api/v1/admin/info";

/// Whether `door` admits the admin read, and earns the operator's full scope.
fn operator_admitted(door: &busbar_kernel::auth::AdminDoor) -> bool {
    matches!(door, busbar_kernel::auth::AdminDoor::Identified(_, grants)
        if grants.allows(busbar_contract::authz::Scope::Full))
        && busbar_kernel::auth::admin_door_admits(door, "GET", INFO)
}

/// PROOF-093-D:139 (cut-root/TESTS.tsv:36, SECURITY; LEDGER S-C2, P094 flip): an admin token is
/// admitted only under the operator credential in force when the process started. The reload half
/// (a reload that changes it is refused and the old credential stays) is
/// `a_reload_that_changes_or_removes_the_operator_credential_is_refused_and_it_stays`; this is the
/// restart half: a token minted under credential A, admitted before the restart, is refused by the
/// generation a restart under credential B builds, which admits B's token.
#[tokio::test]
async fn admin_token_secret_ref_re_resolves_on_apply() {
    let test = OperatorReload::new();
    let rules = &test.rules;
    let before = Arc::new(booted_with(test.deployment(Some(TOKEN_A)), rules).await);
    assert!(
        operator_admitted(&admin_door(Arc::clone(&before), Some(TOKEN_A)).await),
        "credential A's token is the operator before the restart"
    );
    assert!(
        !busbar_kernel::auth::admin_door_admits(
            &admin_door(Arc::clone(&before), Some(TOKEN_B)).await,
            "GET",
            INFO
        ),
        "credential B's token is nobody before the restart"
    );

    // The restart: a fresh boot under the changed credential, no running generation carried over.
    let after = Arc::new(booted_with(test.deployment(Some(TOKEN_B)), rules).await);
    let refused = admin_door(Arc::clone(&after), Some(TOKEN_A)).await;
    assert!(
        !busbar_kernel::auth::admin_door_admits(&refused, "GET", INFO),
        "the pre-restart token is refused after the restart: {refused:?}"
    );
    assert!(
        operator_admitted(&admin_door(after, Some(TOKEN_B)).await),
        "the restart's credential admits its own token"
    );
}

/// A deployment whose operator credential is the provider `provider`, defined with `module:
/// module` and the digest of [`TOKEN_A`], and which is the whole admin chain.
fn renamed_operator_deployment(provider: &str, module: &str) -> busbar_kernel::config::RootCfg {
    crate::root::linked::register_stores();
    let digest = crate::root::test_plugins::sha256(TOKEN_A.as_bytes());
    let document = format!(
        "providers: {{}}\nmodels: {{}}\nstore:\n  module: memory\nauth:\n  chain: []\n  \
         admin_auth: [\"{provider}\"]\nidentity-providers:\n  \"{provider}\":\n    module: \
         \"{module}\"\n    settings:\n      sha256: \"{digest}\"\n"
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the renamed operator deployment parses");
    crate::root::test_plugins::plaintext_listeners(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the renamed operator deployment resolves"),
    )
}

/// v1.5.5 docs/configuration.md (`identity-providers.<name>.module`): "The SAME module may back
/// SEVERAL named providers ... the NAME is the instance", and `token` is meaningful "on a provider
/// whose `module` is the built-in `admin-tokens`". A provider under another name backed by the
/// operator module is the operator credential: it boots, the operator's token earns full admin
/// scope through it, and a wrong token is refused.
async fn renamed_provider_is_the_operator_credential(module: &str) {
    let test = OperatorReload::new();
    let app = booted_with(renamed_operator_deployment("ops", module), &test.rules).await;
    assert!(
        app.admin_modules.operator.is("ops"),
        "{module}: the renamed provider is the operator credential"
    );
    let app = Arc::new(app);
    let door = admin_door(Arc::clone(&app), Some(TOKEN_A)).await;
    assert!(
        operator_admitted(&door),
        "{module}: the operator token earns full scope through the renamed provider: {door:?}"
    );
    for wrong in [Some(TOKEN_B), None] {
        let door = admin_door(Arc::clone(&app), wrong).await;
        assert!(
            !busbar_kernel::auth::admin_door_admits(&door, "GET", INFO),
            "{module}: {wrong:?} is refused: {door:?}"
        );
    }
}

/// PROOF-093-D:142 (cut-root/TESTS.tsv:39, SECURITY; P094 ruling: restore what 1.5.5 documents).
#[tokio::test]
async fn a_renamed_provider_backed_by_the_operator_module_is_the_operator_credential() {
    OperatorReload::new();
    renamed_provider_is_the_operator_credential(busbar_kernel::config::operator_provider()).await;
}

/// PROOF-093-D:143 (cut-root/TESTS.tsv:40, SECURITY): as D:142, the provider's `module:` naming the
/// operator row by its canonical plugin name.
#[tokio::test]
async fn the_operator_module_named_by_its_canonical_name_is_the_operator_credential() {
    OperatorReload::new();
    let words = busbar_kernel_identity::operator::words();
    assert!(
        !words.canonical.is_empty() && words.canonical != words.provider,
        "the operator row's canonical name is not its key: {words:?}"
    );
    renamed_provider_is_the_operator_credential(words.canonical).await;
}

/// A non-operator native admin module: identifies `client-<id>` (group `reader`) for exactly the
/// bearer `cred-<id>`, and answers not-mine to anything else.
struct Module(u64);

impl busbar_ports::auth::AuthPort for Module {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(
        &'a self,
        _: busbar_ports::CallCx,
        req: &busbar_ports::auth::AuthIn<'_>,
        _: Option<&[u8]>,
    ) -> busbar_ports::auth::Verify<'a> {
        use busbar_plugin_abi::records::{tag, Records, Reply, U64Rec};
        use busbar_ports::auth::{decode_verify_ok, Verify, VerifyAnswer, VerifyOk};
        let mine = format!("Bearer cred-{}", self.0);
        let presented = req.headers.iter().any(|pair| {
            pair.name.get().eq_ignore_ascii_case("authorization")
                && pair.value.get() == mine.as_bytes()
        });
        if !presented {
            return Verify::Done(Ok(VerifyAnswer::NotMine));
        }
        let mut records = Reply::new();
        records
            .put_text(tag::ID_SUBJECT, &format!("client-{}", self.0))
            .unwrap();
        records.put_text(tag::ID_GROUP, "reader").unwrap();
        records
            .put_pod_tail(
                busbar_plugin_abi::auth::tag::REPLAY,
                &U64Rec { value: 60 },
                b"nonce",
            )
            .unwrap();
        let Ok(VerifyOk::Identity(identity)) = decode_verify_ok(Records::new(records.as_bytes()))
        else {
            panic!("an identity record")
        };
        Verify::Done(Ok(VerifyAnswer::Identity(identity)))
    }
    fn login<'a>(
        &'a self,
        _: busbar_ports::CallCx,
        _: busbar_ports::auth::LoginIn<'a>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_ports::auth::LoginAnswer, busbar_ports::PortError>,
    > {
        Box::pin(async { Err(not_declared()) })
    }
    fn outbound<'a>(
        &'a self,
        _: busbar_ports::CallCx,
        _: &'a busbar_ports::auth::UpstreamIn<'a>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_ports::auth::OutboundAnswer, busbar_ports::PortError>,
    > {
        Box::pin(async { Err(not_declared()) })
    }
    fn refresh<'a>(
        &'a self,
        _: busbar_ports::CallCx,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Result<Option<u32>, busbar_ports::PortError>>
    {
        Box::pin(async { Err(not_declared()) })
    }
    fn serve<'a>(
        &'a self,
        _: busbar_ports::CallCx,
        _: &'a busbar_ports::auth::ServeIn<'a>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_ports::auth::ServeOut, busbar_ports::PortError>,
    > {
        Box::pin(async { Err(not_declared()) })
    }
}

fn not_declared() -> busbar_ports::PortError {
    busbar_ports::PortError::Call(busbar_plugin_abi::fail::CallError::NotDeclared)
}

/// Owners no admin door verdict reaches: the swap test never completes a claim or looks up an
/// issued credential.
struct Unreached;

impl busbar_kernel::issued::IssuedCredentials for Unreached {
    fn lookup<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: &'a str,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, busbar_contract::secure::SecureVec> {
        panic!("an identity answer performs no issued lookup")
    }
}

impl busbar_kernel::plane_grants::ReplayGuard for Unreached {
    fn claim<'a>(
        &'a self,
        _: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<bool, busbar_kernel::plugin_records::RecordsDenied>,
    > {
        panic!("the door verdict claims no replay")
    }
    fn claim_until<'a>(
        &'a self,
        _: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<bool, busbar_kernel::plugin_records::RecordsDenied>,
    > {
        panic!("the door verdict claims no replay")
    }
}

/// The candidate a reload publishes over `base`: its admin chain is the non-operator modules
/// `ids` (`provider-<id>`, each granting its `reader` role full admin scope), installed by the
/// same `install` every candidate runs before it is published.
async fn swapped_chain(base: &App, ids: &[u64]) -> Arc<App> {
    use busbar_kernel::auth::native_chain::{AuthOwners, OpenedAuth};
    let mut app = base.clone();
    app.admin_chain = ids.iter().map(|id| format!("provider-{id}")).collect();
    for name in &app.admin_chain {
        app.auth_scope_caps.insert(name.clone(), "full".into());
        app.role_bindings.insert(
            name.clone(),
            BTreeMap::from([(
                "reader".into(),
                busbar_kernel::config::RoleBindingCfg {
                    allowed_pools: None,
                    group: None,
                    admin_scope: Some("full".into()),
                    verbs: None,
                    plane_grants: Default::default(),
                },
            )]),
        );
    }
    let opened = ids
        .iter()
        .map(|&id| OpenedAuth {
            who: busbar_kernel::plane_driver::port_intents::Namespace {
                plugin: "admin-module".into(),
                name: format!("provider-{id}").into(),
                instance: id,
                slot: 4,
            },
            port: Arc::new(Module(id)),
            methods: busbar_plugin_abi::auth::M_VERIFY,
            out_of_process: false,
            limits: busbar_plugin_abi::host_side::caller::InstanceLimits::default(),
        })
        .collect();
    let (_directory, holds, _refresh) = busbar_kernel::directory::KernelDirectory::prepare(
        crate::root::real_store::core().await,
        Arc::new(busbar_kernel::directory::LogEvents),
        Vec::new(),
    )
    .await
    .expect("the directory prepares");
    let set = super::AuthSet::new(
        opened,
        &holds,
        AuthOwners {
            issued: Arc::new(Unreached),
            replay: Arc::new(Unreached),
            cache: Arc::new(busbar_kernel::auth::verdicts::Verdicts::new(
                busbar_kernel::auth::verdicts::VerdictPolicy::DEFAULT,
            )),
        },
        std::time::Duration::from_secs(30),
    )
    .expect("the candidate's auth set");
    let epoch = app
        .config_generation
        .load(std::sync::atomic::Ordering::Acquire);
    install(&mut app, Arc::new(set), epoch).expect("the swapped admin chain installs");
    Arc::new(app)
}

/// PROOF-093-D:148 (cut-root/TESTS.tsv:45, SECURITY): after a reload swaps the admin chain
/// (non-operator modules), the next admin request on the same handle is judged by the new chain:
/// a removed module's credential is refused, a kept one still admits, and an empty chain admits no
/// one. Each request is judged on the generation the handle holds when it arrives (`load`), as
/// the admin listener selects it.
#[tokio::test]
async fn a_swapped_admin_chain_is_the_loops_next_door() {
    let test = OperatorReload::new();
    let base = booted_with(test.deployment(None), &test.rules).await;
    let handle = busbar_kernel::state::AppHandle::new(swapped_chain(&base, &[41, 42]).await);
    let ask = |bearer: Option<&'static str>| {
        let selected = handle.load();
        async move {
            busbar_kernel::auth::admin_door_admits(&admin_door(selected, bearer).await, "GET", INFO)
        }
    };
    assert!(ask(Some("cred-41")).await, "module 41 admits its caller");
    assert!(ask(Some("cred-42")).await, "module 42 admits its caller");
    assert!(!ask(None).await, "no credential admits no one");

    handle.swap(swapped_chain(&base, &[41]).await).await;
    assert!(
        !ask(Some("cred-42")).await,
        "the removed module's credential is refused by the next request"
    );
    assert!(ask(Some("cred-41")).await, "the kept module still admits");

    handle.swap(swapped_chain(&base, &[]).await).await;
    for bearer in [None, Some("cred-41"), Some("cred-42")] {
        assert!(
            !ask(bearer).await,
            "the swapped-in empty chain admits no one ({bearer:?})"
        );
    }
}
