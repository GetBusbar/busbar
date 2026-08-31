/// The re-key union semantics under role_bindings: pools union (OMITTED `allowed_pools` on
/// any granting binding = every pool; explicit `[]` contributes nothing), the synthesized key
/// carries NO inline caps (keys are pure auth; limits live on `groups:`), the first bound
/// `group` becomes the key's group binding, and a principal whose roles all bind `[]` (or bind
/// nothing) gets NO synthetic key (fail closed).
#[test]
fn synthesize_principal_key_union_semantics() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    table.insert(
        "a".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["p1".to_string()]),
            group: Some("finance".to_string()),
            ..Default::default()
        },
    );
    table.insert(
        "b".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["p2".to_string()]),
            ..Default::default()
        },
    );
    // An ADMIN-ONLY role: admin scope, but an explicit [] pool grant = NO data-plane access.
    table.insert(
        "admin-only".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec![]),
            admin_scope: Some("full".to_string()),
            ..Default::default()
        },
    );
    // OMITTED allowed_pools = ALL pools.
    table.insert("all-pools".to_string(), RoleBindingCfg::default());

    let mut p = crate::auth::Principal::from_id("test:u");
    p.roles = vec!["a".to_string(), "b".to_string()];
    let k = synthesize_principal_key(&p, Some(&table)).expect("bound roles synthesize");
    assert_eq!(k.id, "test:u", "keyed by the principal id");
    let mut pools: Vec<String> = k
        .allowed_scopes
        .clone()
        .expect("an explicit union list")
        .into_iter()
        .map(|s| s.value)
        .collect();
    pools.sort();
    assert_eq!(
        pools,
        vec!["p1".to_string(), "p2".to_string()],
        "pools union"
    );
    // Keys are PURE AUTH: no caps of any kind ride the synthesized key (limits live on groups) -
    // the struct no longer even has cap fields; the group binding is the only policy handle.
    assert_eq!(
        k.group.as_deref(),
        Some("finance"),
        "the bound group becomes the key's group"
    );
    assert!(k.enabled);

    // An OMITTED allowed_pools on any granting binding = every pool (the None encoding).
    p.roles = vec!["a".to_string(), "all-pools".to_string()];
    let k = synthesize_principal_key(&p, Some(&table)).expect("granting");
    assert!(
        k.allowed_scopes.is_none(),
        "omitted allowed_pools grants every pool (None encoding)"
    );

    // All granting bindings say []: the EMPTY SET - no synthetic key (fail closed).
    p.roles = vec!["admin-only".to_string(), "unbound".to_string()];
    assert!(
        synthesize_principal_key(&p, Some(&table)).is_none(),
        "an all-[] pool grant = no synthetic key (fail closed)"
    );
    p.roles = vec![];
    assert!(synthesize_principal_key(&p, Some(&table)).is_none());
    // No bindings table for the identifying module at all: nothing to grant.
    p.roles = vec!["a".to_string()];
    assert!(synthesize_principal_key(&p, None).is_none());
}

/// A principal whose id literally
/// starts with `group:` must NEVER get a synthetic key. The synthetic key's `id` is its ledger
/// bucket id, and budget-group buckets share that namespace as `group:<name>` - an IdP-supplied
/// id like `group:acme` would otherwise charge/read/alias the `acme` budget group's cell.
/// Fail closed: no key, no data-plane access, no collision.
#[test]
fn group_prefixed_principal_id_cannot_alias_a_budget_group_bucket() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    // OMITTED allowed_pools = ALL pools: the broadest possible grant.
    table.insert("eng".to_string(), RoleBindingCfg::default());

    // Control: the same grants under a benign id DO synthesize, and the bucket id is the
    // principal id - which is exactly why the reserved prefix must be rejected.
    let mut ok = crate::auth::Principal::from_id("sso:alice");
    ok.roles = vec!["eng".to_string()];
    let k = synthesize_principal_key(&ok, Some(&table)).expect("benign id synthesizes");
    assert_eq!(k.id, "sso:alice", "the key id IS the ledger bucket id");

    // The attack shape: identical grants, but the id sits in the budget-group bucket namespace.
    // It must produce NO key at all (fail closed), so no ledger cell keyed `group:acme` can ever
    // be created or charged on behalf of this principal.
    let mut evil = crate::auth::Principal::from_id("group:acme");
    evil.roles = vec!["eng".to_string()];
    assert!(
        synthesize_principal_key(&evil, Some(&table)).is_none(),
        "a group:-prefixed principal id must be refused, never keyed into the ledger"
    );

    // The bare prefix is equally reserved.
    let mut bare = crate::auth::Principal::from_id("group:");
    bare.roles = vec!["eng".to_string()];
    assert!(synthesize_principal_key(&bare, Some(&table)).is_none());
}

/// A principal whose id starts with `vk_` must NEVER get a
/// synthetic key. A real virtual key's id is `vk_<16 hex>` and IS its ledger/rate bucket id, so an
/// IdP-supplied subject shaped `vk_<...>` would alias a real virtual key's ledger + rate bucket
/// (charging/reading it, or riding its rate window). Fail closed like the `group:` guard.
#[test]
fn vk_prefixed_principal_id_cannot_alias_a_virtual_key_bucket() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    table.insert("eng".to_string(), RoleBindingCfg::default());

    // A `vk_`-shaped id (the exact shape of a real minted virtual key) must produce NO key.
    let mut evil = crate::auth::Principal::from_id("vk_deadbeefdeadbeef");
    evil.roles = vec!["eng".to_string()];
    assert!(
        synthesize_principal_key(&evil, Some(&table)).is_none(),
        "a vk_-prefixed principal id must be refused, never keyed into a virtual key's bucket"
    );

    // The bare prefix is equally reserved.
    let mut bare = crate::auth::Principal::from_id("vk_");
    bare.roles = vec!["eng".to_string()];
    assert!(synthesize_principal_key(&bare, Some(&table)).is_none());
}
use super::*;

fn sample_key(id: &str, hash: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: hash.to_string(),
        name: "test-key".to_string(),
        allowed_scopes: Some(vec![ScopeRef::pool("prod"), ScopeRef::pool("cheap")]),
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

/// Flat cost model: no rate card (tokens derive to 0), no groups, the given per-request fee.
fn flat_cost(fee: i64) -> crate::cost::CostModel {
    crate::cost::CostModel::flat(fee)
}

/// A one-entry rate card (input tier only, `input_utok` micro-units/token).
fn one_entry_card(
    model: &str,
    input_utok: f64,
) -> std::collections::BTreeMap<String, crate::config::RateEntryCfg> {
    std::collections::BTreeMap::from([(
        model.to_string(),
        crate::config::RateEntryCfg {
            input_utok,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
        },
    )])
}

/// A `groups:` entry carrying one BUDGET limit (cap in cents on the given window noun:
/// total | day | month | minute | hour) and an optional parent.
fn budget_group_cfg(cap: i64, period: &str, parent: Option<&str>) -> crate::config::GroupCfg {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let per = match period {
        "day" => LimitWindow::Day,
        "month" => LimitWindow::Month,
        "minute" => LimitWindow::Minute,
        "hour" => LimitWindow::Hour,
        _ => LimitWindow::Total,
    };
    crate::config::GroupCfg {
        parent: parent.map(String::from),
        enabled: true,
        limits: vec![LimitCfg {
            metric: LimitMetric::Budget,
            amount: u64::try_from(cap).unwrap_or(0),
            per: Some(per),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
        }],
        ..Default::default()
    }
}

/// A cost model with ONE rate-card entry (input tier only, `input_utok` micro-units/token) and no
/// flat fee - the minimal token-priced model.
fn card_cost(model: &str, input_utok: f64) -> crate::cost::CostModel {
    crate::cost::CostModel::resolve_parts(
        Some(&one_entry_card(model, input_utok)),
        0,
        &std::collections::BTreeMap::new(),
    )
}

/// A cost model with budget GROUPS (name, cap, period, parent) and a flat fee, no rate card.
fn group_cost(fee: i64, groups: &[(&str, i64, &str, Option<&str>)]) -> crate::cost::CostModel {
    let groups_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> = groups
        .iter()
        .map(|(name, cap, period, parent)| {
            (name.to_string(), budget_group_cfg(*cap, period, *parent))
        })
        .collect();
    crate::cost::CostModel::resolve_parts(None, fee, &groups_cfg)
}

/// A cost model with BOTH a one-entry rate card and budget groups, no flat fee.
fn card_and_group_cost(
    model: &str,
    input_utok: f64,
    groups: &[(&str, i64, &str, Option<&str>)],
) -> crate::cost::CostModel {
    let groups_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> = groups
        .iter()
        .map(|(name, cap, period, parent)| {
            (name.to_string(), budget_group_cfg(*cap, period, *parent))
        })
        .collect();
    crate::cost::CostModel::resolve_parts(Some(&one_entry_card(model, input_utok)), 0, &groups_cfg)
}

/// An input-only tier split of `n` tokens (the scalar-total shorthand old tests used).
fn tt(n: u64) -> TierTokens {
    TierTokens {
        input: n,
        output: 0,
        cache_read: 0,
        cache_write: 0,
    }
}

/// The store ledger's total tokens for (bucket, window) - the old scalar `tokens` view.
fn ledger_tokens(store: &MemoryStore, bucket: &str, window: u64) -> u64 {
    store.get_usage(bucket, window).unwrap().total_tokens()
}

/// CONCURRENCY through the REAL admission wrapper. Fires N concurrent tasks through
/// `GovState::try_admit` on a SHARED `Arc<GovState>`, the exact admission entrypoint the route
/// path calls. With a 1c flat fee and a 5c GROUP budget cap (keys are pure auth: the cap lives on
/// the bound group), exactly 5 of 20 concurrent admissions may land and the group's final derived
/// spend must be EXACTLY 5 (cap-respecting, no overshoot: the whole chain check-and-charge is one
/// critical section).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_govstate_admission_respects_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cost = Arc::new(group_cost(1, &[("team", 5, "total", None)])); // 1c fee, 5c group cap
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("team".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    let mut handles = Vec::new();
    for _ in 0..20 {
        let gov = gov.clone();
        let cost = cost.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            gov.try_admit(&cost, &key, "", at).is_ok()
        }));
    }
    let mut admitted = 0u32;
    for h in handles {
        if h.await.unwrap() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 5,
        "exactly 5 of 20 concurrent GovState admissions fit under a 5c group cap at 1c/request"
    );
    // The hard cap is enforced by the AUTHORITATIVE in-memory cells; flush them to the durable
    // ledger. Spend is DERIVED (fee x requests), so the durable proof is the request count on
    // BOTH the key's attribution bucket and the group's window bucket.
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().requests,
        5,
        "exactly 5 requests ledgered on the key bucket - no overshoot"
    );
    assert_eq!(
        store.get_usage("group:team@total", 0).unwrap().requests,
        5,
        "and 5 on the group's total-window bucket (the capped one)"
    );
    assert_eq!(
        gov.usage_for(&cost, &key.id, at)
            .unwrap()
            .unwrap()
            .spend_cents,
        5,
        "derived spend = 5 requests x 1c fee"
    );
}

/// The charge -> refund -> re-admit money cycle through `GovState`. Charge a key's GROUP to
/// its cap so the next request is rejected; `refund_request` reverses one charge; a new request is
/// admitted again. Proves a refunded fee genuinely frees budget on the live admission path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_charge_refund_readmit_cycle() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cost = group_cost(1, &[("solo", 1, "total", None)]); // 1c fee, 1c cap: one request fits
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("solo".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    // Charge to the cap.
    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "1st (1c) admitted, spends the whole 1c group cap"
    );
    // At cap - next request rejected, NAMING the group's budget bucket.
    match gov.try_admit(&cost, &key, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "solo"),
        other => panic!("expected the group budget to block, got {other:?}"),
    }
    // Refund reverses the in-memory charge synchronously (the fee derives from the request count).
    gov.refund_request(&cost, &key, "", at);
    assert_eq!(
        gov.usage_for(&cost, &key.id, at)
            .unwrap()
            .unwrap()
            .spend_cents,
        0,
        "refund must reverse the derived charge back to 0 spend"
    );
    // Budget is free again - a new request is re-admitted.
    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "post-refund request re-admitted: the refunded fee freed the budget"
    );
}

/// The admission wrapper charges the flat fee and rejects atomically at the group cap.
/// 1c/request flat fee, 2c group cap -> 2 admitted, 3rd rejected naming the group's budget.
#[tokio::test]
async fn test_try_admit_rejects_at_group_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let cost = group_cost(1, &[("g", 2, "total", None)]); // 1c fee, 2c cap
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("g".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "1st (1c) admitted"
    );
    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "2nd (2c) admitted"
    );
    assert_eq!(
        gov.try_admit(&cost, &key, "", at).unwrap_err(),
        LimitBlocked::Limit {
            group: "g".to_string(),
            metric: "budget",
            window: Some("total"),
            pool: None,
            downgrade_to: None,
            retry_after: None,
        },
        "3rd (would be 3c > 2c cap) rejected atomically, naming the exact bucket"
    );
}

/// The metering series: `add_metering` UPSERTs per (key, bucket, model, provider) with the raw
/// token SPLIT preserved and +1 request per call; `list_metering` reads exactly one bucket; a
/// second bucket never bleeds in.
#[test]
fn test_metering_accumulates_split_per_key_model_and_bucket() {
    let s = MemoryStore::new();
    let day = metering_bucket(1_700_000_123); // mid-day epoch floors to its bucket start
    assert_eq!(day % METERING_BUCKET_SECS, 0);
    let d = |model: &str, input: u64, output: u64| MeteringDelta {
        key_id: "vk_a".into(),
        bucket: day,
        model: model.into(),
        provider: "openai".into(),
        tokens_input: input,
        tokens_output: output,
        tokens_cache_read: 7,
        tokens_cache_write: 3,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    // Two responses on the same (key, model) accumulate; a different model is its own row.
    s.add_metering(&d("gpt-x", 100, 20)).unwrap();
    s.add_metering(&d("gpt-x", 50, 10)).unwrap();
    s.add_metering(&d("gpt-y", 1, 2)).unwrap();
    // A different bucket must NOT appear in this bucket's read.
    s.add_metering(&MeteringDelta {
        bucket: day + METERING_BUCKET_SECS,
        ..d("gpt-x", 999, 999)
    })
    .unwrap();

    let mut rows = s.list_metering(day).unwrap();
    rows.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(rows.len(), 2, "two models in this bucket: {rows:?}");
    let x = &rows[0];
    assert_eq!((x.model.as_str(), x.provider.as_str()), ("gpt-x", "openai"));
    assert_eq!(
        (x.tokens_input, x.tokens_output, x.requests),
        (150, 30, 2),
        "raw split accumulates + one request per response"
    );
    assert_eq!(
        (x.tokens_cache_read, x.tokens_cache_write),
        (14, 6),
        "cache reads/writes carry separately (they price differently)"
    );
    assert_eq!(rows[1].model, "gpt-y");
    assert_eq!(rows[1].requests, 1);
}

/// `GovState::record_metering` end-to-end, write-behind: `record_metering` only accumulates into
/// `pending_metering`, so an explicit `flush_metering()` is required before the store reflects it.
/// The IrUsage split lands in the store under the request's day bucket; a `None` usage (flat-fee
/// op) still counts the request; and the `requests` count on the store row must survive coalescing
/// N `record_metering` calls into one flushed `MeteringDelta` (this is what a coalescing bug
/// destroys — the four stores used to invent a literal `+1` per store call instead of carrying the
/// real count on the wire).
#[test]
fn test_record_metering_from_ir_usage_and_flat() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_500;
    let usage = crate::billing::TokenUsage {
        input: 11,
        output: 22,
        cache_read: Some(5),
        cache_creation: None,
        ..Default::default()
    };
    gov.record_metering("vk_m", "claude-z", "anthropic", Some(&usage), now);
    gov.record_metering("vk_m", "claude-z", "anthropic", None, now); // flat-fee op
    gov.flush_metering();
    let rows = gov.metering_for(metering_bucket(now)).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (r.key_id.as_str(), r.model.as_str(), r.provider.as_str()),
        ("vk_m", "claude-z", "anthropic")
    );
    assert_eq!(
        (
            r.tokens_input,
            r.tokens_output,
            r.tokens_cache_read,
            r.tokens_cache_write,
            r.requests
        ),
        (11, 22, 5, 0, 2),
        "split preserved; the flat-fee response still counted its request; requests==N survives coalescing"
    );
}

#[test]
fn test_virtualkey_debug_redacts_key_hash() {
    // VirtualKey's Debug must NOT print `generation_hash` (the stored authenticator
    // for the key's secret). A derived Debug leaked it in plaintext; the manual impl prints
    // presence only. The hash value is deliberately distinctive so a substring check catches it.
    let mut k = sample_key("vk_dbg", "SECRET-key-hash-value-zzz");
    let dbg = format!("{k:?}");
    assert!(
        !dbg.contains("SECRET-key-hash-value-zzz"),
        "VirtualKey Debug leaked generation_hash: {dbg}"
    );
    assert!(
        dbg.contains("<redacted; present>"),
        "VirtualKey Debug should mark generation_hash present-but-redacted: {dbg}"
    );
    // Non-secret fields are still shown so the struct stays diagnosable.
    assert!(dbg.contains("vk_dbg"), "id must still appear: {dbg}");
    assert!(dbg.contains("test-key"), "name must still appear: {dbg}");

    // Redaction holds TRANSITIVELY through GovCtx (its derived Debug delegates to VirtualKey's).
    let ctx = GovCtx {
        key: Some(std::sync::Arc::new(k.clone())),
    };
    let ctx_dbg = format!("{ctx:?}");
    assert!(
        !ctx_dbg.contains("SECRET-key-hash-value-zzz"),
        "GovCtx Debug leaked the embedded generation_hash: {ctx_dbg}"
    );

    // An empty hash is marked absent (defensive; the request path never builds such a key).
    k.generation_hash = String::new();
    let dbg_empty = format!("{k:?}");
    assert!(
        dbg_empty.contains("<absent>"),
        "empty generation_hash should read as absent: {dbg_empty}"
    );
}

#[test]
fn test_create_key_with_aws_issues_and_resolves_credential() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let (key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock-key".to_string(),
                allowed_pools: Some(vec!["prod".to_string()]),
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    // AccessKeyId is AKIA-prefixed, 20 chars; secret is 40 chars.
    assert!(akid.starts_with("AKIA"), "akid shape: {akid}"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(akid.len(), 20); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(secret.len(), 40); // golden wire-contract literal (kept bare on purpose)
                                  // The AccessKeyId resolves to the SAME key + its secret.
    let (resolved_key, cred) = gov
        .lookup_credential("sigv4", &akid)
        .expect("akid resolves");
    assert_eq!(resolved_key.id, key.id);
    assert_eq!(cred.secret, format!("v1:plain:{secret}"));
    assert!(resolved_key.enabled);
    // An unknown AccessKeyId resolves to None.
    assert!(gov
        .lookup_credential("sigv4", "AKIAdoesnotexist0000")
        .is_none());
}

/// Contract guard for the OS-CSPRNG-backed credential generators (`getrandom`). Pins the exact
/// wire shapes that downstream AWS SDKs and busbar's bearer scheme validate, so a future
/// `getrandom` major (or any change to these minting fns) that alters length, prefix, or charset
/// fails HERE with a clear cause — instead of surfacing later as a confusing auth rejection.
#[test]
fn test_credential_generators_contract() {
    // Bearer secret: `sk-bb-` prefix + 64 lowercase-hex chars (32 random bytes = 256-bit secret).
    let s = generate_secret().expect("OS entropy available");
    assert!(s.starts_with(SK_SECRET_PREFIX), "bearer prefix: {s}");
    let hex_part = &s[SK_SECRET_PREFIX.len()..];
    assert_eq!(hex_part.len(), 64, "32 random bytes -> 64 hex chars");
    assert!(
        hex_part
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "bearer body is lowercase hex: {hex_part}"
    );

    // AWS AccessKeyId: `AKIA` prefix + uppercase-alphanumeric body, fixed total length 20.
    let akid = generate_aws_access_key_id().expect("OS entropy available");
    assert_eq!(akid.len(), AWS_ACCESS_KEY_ID_LEN);
    assert!(
        akid.starts_with(AWS_ACCESS_KEY_PREFIX),
        "akid prefix: {akid}"
    );
    assert!(
        akid.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "akid is uppercase-alphanumeric: {akid}"
    );

    // AWS secret access key: fixed 40 chars (240 bits over a base64-ish alphabet).
    let sak = generate_aws_secret_access_key().expect("OS entropy available");
    assert_eq!(sak.len(), AWS_SECRET_ACCESS_KEY_LEN);

    // Each draw differs — proves the CSPRNG is actually read, not returning a constant.
    assert_ne!(generate_secret().unwrap(), s, "secrets must not repeat");
    assert_ne!(
        generate_aws_access_key_id().unwrap(),
        akid,
        "akids must not repeat"
    );
}

#[test]
fn test_aws_credential_persists_across_reload() {
    // A credential minted in one GovState must be visible to a fresh GovState over the same store
    // (durable + rebuilt into the AccessKeyId index at construction).
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let akid = {
        let gov = GovState::new(store.clone(), None).unwrap();
        let (_k, _b, akid, _s) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: None,
                    group: None,
                    labels: std::collections::BTreeMap::new(),
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        akid
    };
    let gov2 = GovState::new(store, None).unwrap();
    assert!(
        gov2.lookup_credential("sigv4", &akid).is_some(),
        "credential must survive a reload"
    );
}

#[test]
fn test_delete_key_removes_aws_credential() {
    // Revoking a key must remove its AWS credential so it can no longer authenticate via SigV4.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let (key, _b, akid, _s) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    assert!(gov.lookup_credential("sigv4", &akid).is_some());
    gov.delete_key(&key.id).unwrap();
    assert!(
        gov.lookup_credential("sigv4", &akid).is_none(),
        "a revoked key's AWS credential must be gone"
    );
    // And the durable credential row is gone too.
    assert!(gov.store().list_credentials(&key.id).unwrap().is_empty());
}

#[test]
fn test_refresh_updates_both_indices_atomically() {
    // A key minted WITH an AWS credential is resolvable through BOTH auth
    // indices (the subject-id `by_id` index AND the AccessKeyId `by_access_key_id` index), and a
    // `delete_key` (which calls `refresh`) clears it from BOTH in the same swap. This pins the
    // single-lock atomic refresh against a future split-lock regression where one index could be
    // updated without the other.
    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = GovState::new_with_signer(store, None, Some(signer)).unwrap();
    let (key, _token, akid, _secret) = gov
        .mint_signed_with_aws(
            NewKeySpec {
                name: "dual-index-key".to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            2_000_000_000,
            1_700_000_000,
        )
        .unwrap();

    // Present in BOTH indices before deletion.
    assert_eq!(
        gov.lookup_by_sub(&key.id).map(|k| k.id.clone()),
        Some(key.id.clone()),
        "subject id must resolve via by_id before delete"
    );
    assert_eq!(
        gov.lookup_credential("sigv4", &akid)
            .map(|(k, _)| k.id.clone()),
        Some(key.id.clone()),
        "akid must resolve via by_access_key_id before delete"
    );

    // delete_key -> refresh swaps both indices under the single caches lock.
    gov.delete_key(&key.id).unwrap();

    // Absent from BOTH indices after deletion — neither lags the other.
    assert!(
        gov.lookup_by_sub(&key.id).is_none(),
        "subject id must be gone from by_id after delete"
    );
    assert!(
        gov.lookup_credential("sigv4", &akid).is_none(),
        "akid must be gone from by_credential after delete"
    );
}

#[test]
fn test_aws_credential_debug_redacts_secret() {
    // The symmetric SigV4 secret must NEVER appear in Debug output. `busbar_api::CredentialSecret`
    // is the generalized successor to the old AWS-specific `AwsCredential`/`AwsKeyEntry` pair (its
    // own redaction test lives in `busbar_api::store::tests::debug_redacts_secret_equivalents`) —
    // this regression stays at the governance-crate level too since it's the type actually flowing
    // through `create_key_with_aws`/`mint_signed_with_aws`.
    let cred = CredentialSecret {
        meta: CredentialMeta {
            id: "cred_x".to_string(),
            key_id: "vk_x".to_string(),
            kind: "sigv4".to_string(),
            slot: 0,
            public_id: "AKIAPUBLIC1234567890".to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:SUPER-SECRET-SIGNING-KEY-zzz".to_string(),
    };
    let dbg = format!("{cred:?}");
    assert!(
        !dbg.contains("SUPER-SECRET-SIGNING-KEY-zzz"),
        "CredentialSecret Debug leaked the secret: {dbg}"
    );
    assert!(dbg.contains("<redacted; present>"));
    assert!(dbg.contains("AKIAPUBLIC1234567890"), "akid is not secret");
}

#[test]
fn test_generated_aws_credentials_are_distinct() {
    // Two mints must produce distinct AccessKeyIds and secrets (CSPRNG-sourced, not constant).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let mk = |gov: &GovState, n: &str| {
        gov.create_key_with_aws(
            NewKeySpec {
                name: n.to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            0,
        )
        .unwrap()
    };
    let (_k1, _b1, akid1, s1) = mk(&gov, "a");
    let (_k2, _b2, akid2, s2) = mk(&gov, "b");
    assert_ne!(akid1, akid2);
    assert_ne!(s1, s2);
}

#[test]
fn test_govstate_lookup_pool_allowed_refresh() {
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "binding:k1:gen1");
    k.allowed_scopes = Some(vec![ScopeRef::pool("prod")]);
    store.put_key(&k).unwrap();

    let gov = GovState::new(store, None).unwrap();
    // subject-id lookup hits the cache.
    assert_eq!(gov.lookup_by_sub("k1").unwrap().id, "k1");
    assert!(gov.lookup_by_sub("no-such-id").is_none());

    let resolved = gov.lookup_by_sub("k1").unwrap();
    assert!(pool_allowed(&resolved, "prod"));
    assert!(!pool_allowed(&resolved, "other"));

    // A key added after construction isn't visible until refresh().
    let mut k2 = sample_key("k2", "binding:k2:gen1");
    k2.allowed_scopes = None; // omitted grant = all pools
    gov.store().put_key(&k2).unwrap();
    assert!(gov.lookup_by_sub("k2").is_none(), "not cached pre-refresh");
    gov.refresh().unwrap();
    let r2 = gov.lookup_by_sub("k2").unwrap();
    assert!(pool_allowed(&r2, "anything"), "None allowed_pools = all");
    // And the empty-set arm: an explicit [] admits NO pool.
    let mut k3 = sample_key("k3", "h3");
    k3.allowed_scopes = Some(vec![]);
    assert!(
        !pool_allowed(&k3, "prod"),
        "explicit [] = NO pools, never all"
    );
}

/// `civil_from_days`/`days_from_civil` (Howard Hinnant's public-domain civil-calendar algorithm,
/// same shape `budget_window`'s `WINDOW_MONTH` arm relies on) — a table of known epoch-day <->
/// date pairs spanning the epoch itself, both sides of it (the `z >= 0` branch and its negative
/// counterpart), a non-leap month boundary, a leap-year Feb 29 (both a leap century, 2000, and an
/// ordinary leap year, 2024), and a NON-leap century (1900 - divisible by 100 but not 400, the
/// exact case the `- doe / 36_524` / `- doe / 146_096` correction terms exist for) plus the very
/// distant 2400 (also a leap century) to pin the `era` math far from the epoch on both axes.
#[test]
fn test_civil_from_days_and_days_from_civil_known_dates() {
    let cases: &[(i64, (i64, i64, i64))] = &[
        (0, (1970, 1, 1)),
        (-1, (1969, 12, 31)),
        (-365, (1969, 1, 1)),
        (11_016, (2000, 2, 29)), // leap century
        (11_017, (2000, 3, 1)),
        (-25_508, (1900, 3, 1)),  // non-leap century boundary
        (-25_509, (1900, 2, 28)), // 1900 has no Feb 29
        (19_691, (2023, 11, 30)), // ordinary month boundary
        (19_692, (2023, 12, 1)),
        (19_782, (2024, 2, 29)), // ordinary leap year
        (19_783, (2024, 3, 1)),
        (157_113, (2400, 2, 29)), // leap century, far future
        // Deep negative z (year -768): the ONLY case where `z + 719_468` (the internal offset)
        // itself goes negative, exercising the `era`/`doe` negative-branch correction terms —
        // every other case above stays positive after the offset and can't reach this branch.
        // Expected value taken from the real (unmutated) algorithm's own output, not a hand-ported
        // reference: Rust's `/` truncates toward zero for negative operands (unlike e.g. Python's
        // `//`, which floors), so an independently-authored reference for deep negative inputs is
        // easy to get subtly wrong here.
        (-1_000_000, (-768, 2, 4)),
    ];
    for &(z, ymd) in cases {
        assert_eq!(civil_from_days(z), ymd, "civil_from_days({z})");
        assert_eq!(
            days_from_civil(ymd.0, ymd.1, ymd.2),
            z,
            "days_from_civil{ymd:?}"
        );
    }
}

#[test]
fn test_budget_window_periods() {
    assert_eq!(budget_window(WINDOW_TOTAL, 1_700_000_000), 0);
    assert_eq!(budget_window("unknown", 1_700_000_000), 0);
    assert_eq!(budget_window(WINDOW_DAY, 1_700_000_000), 1_699_920_000);
    // 1700000000 = 2023-11-14 → 2023-11-01 00:00Z = 1698796800.
    assert_eq!(budget_window(WINDOW_MONTH, 1_700_000_000), 1_698_796_800);
    // WINDOW_HOUR: floor to the containing hour, `now / 3600 * 3600` (integer-division floor, NOT
    // `now * 3600 * 3600` nor `now / 3600 + 3600` - a non-hour-aligned timestamp catches either).
    // 1_700_000_000 = 2023-11-14 22:13:20 UTC → hour start 2023-11-14 22:00:00 UTC = 1_699_999_200.
    assert_eq!(budget_window(WINDOW_HOUR, 1_700_000_000), 1_699_999_200);
    // window_end: the Retry-After source. A minute rolls at the next :00; total never rolls.
    assert_eq!(
        window_end(WINDOW_MINUTE, 1_700_000_010),
        Some(1_700_000_040)
    );
    // WINDOW_HOUR rolls to the NEXT hour boundary (`+ 3600`, not `* 3600`).
    assert_eq!(
        window_end(WINDOW_HOUR, 1_700_000_000),
        Some(1_699_999_200 + 3600)
    );
    assert_eq!(
        window_end(WINDOW_DAY, 1_700_000_000),
        Some(1_699_920_000 + SECS_PER_DAY)
    );
    // 2023-11 rolls to 2023-12-01 00:00Z = 1701388800.
    assert_eq!(window_end(WINDOW_MONTH, 1_700_000_000), Some(1_701_388_800));
    assert_eq!(window_end(WINDOW_TOTAL, 1_700_000_000), None);
}

/// DERIVED-SPEND admission: the cap check recomputes spend = fee x requests from the ledger on
/// every admission (no stored spend). 30c fee, 100c GROUP cap: 3 admissions land (90c derived);
/// the 4th (would derive 120c) is rejected naming the group. A key with NO group is never blocked.
#[test]
fn test_derived_spend_enforces_cap_from_request_ledger() {
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    store.put_key(&k).unwrap();
    let gov = GovState::new(store, None).unwrap();
    let cost = group_cost(30, &[("team", 100, "total", None)]); // 30 cents/request, 100c cap

    for i in 0..3 {
        assert!(
            gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok(),
            "admission {i} fits (derived spend stays under 100c)"
        );
    }
    assert_eq!(
        gov.usage_for(&cost, "k1", 1_700_000_000)
            .unwrap()
            .unwrap()
            .spend_cents,
        90,
        "derived spend = 3 requests x 30c"
    );
    match gov.try_admit(&cost, &k, "", 1_700_000_000).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "team"),
        other => panic!("expected the group budget to block, got {other:?}"),
    }

    let mut unlimited = k.clone();
    unlimited.id = "k_free".to_string();
    unlimited.group = None;
    assert!(
        gov.try_admit(&cost, &unlimited, "", 1_700_000_000).is_ok(),
        "a key with no group is authed + unlimited"
    );
}

/// FLEET-ADDITIVE FLUSH (1.5.0): TWO GovStates ("nodes") sharing ONE durable store each accrue
/// spend and flush — the durable record must hold the SUM of both nodes' accruals, not whichever
/// node flushed last (the lost-update the old absolute `put_usage` overwrite caused). Also: a
/// re-flush with nothing new is a no-op (the acked baseline advances), so nothing double-counts.
#[test]
fn test_two_node_flush_is_additive_no_lost_update() {
    let store = Arc::new(MemoryStore::new());
    let k = sample_key("k_fleet", "h_fleet");
    store.put_key(&k).unwrap();

    // Two independent GovStates over the SAME store = two busbar nodes sharing a cluster store.
    let node_a = GovState::new(store.clone(), None).unwrap();
    let node_b = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(10); // 10c flat fee

    // Node A charges 3 requests + per-model tokens; node B charges 2 + tokens on TWO models.
    for _ in 0..3 {
        assert!(node_a.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    }
    node_a.record_usage(&cost, &k, "", "gpt-5", &tt(100), 1_700_000_000);
    for _ in 0..2 {
        assert!(node_b.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    }
    node_b.record_usage(&cost, &k, "", "gpt-5", &tt(40), 1_700_000_000);
    node_b.record_usage(&cost, &k, "", "haiku", &tt(7), 1_700_000_000);
    node_a.flush_budgets();
    node_b.flush_budgets();

    let u = store.get_usage("k_fleet", 0).unwrap();
    assert_eq!(
        u.requests, 5,
        "the durable record is the FLEET SUM (3 + 2), not last-writer-wins"
    );
    assert_eq!(
        u.tokens_for("gpt-5").unwrap().input,
        140,
        "per-model token deltas SUM across nodes (100 + 40)"
    );
    assert_eq!(
        u.tokens_for("haiku").unwrap().input,
        7,
        "a model only one node used still lands"
    );

    // Re-flushing with nothing new must not double-count (the acked baselines advanced).
    node_a.flush_budgets();
    node_b.flush_budgets();
    let u = store.get_usage("k_fleet", 0).unwrap();
    assert_eq!(u.requests, 5, "an idle re-flush adds nothing");
    assert_eq!(u.tokens_for("gpt-5").unwrap().input, 140);

    // More accrual on one node keeps accumulating correctly.
    assert!(node_a.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    node_a.flush_budgets();
    assert_eq!(store.get_usage("k_fleet", 0).unwrap().requests, 6);
}

/// A REFUND between flushes produces a NEGATIVE BILLABLE delta the additive flush carries through,
/// while the ADMISSION `requests` counter (the requests-limit truth) is NEVER refunded and stays
/// put. The durable record ends at the true net BILLABLE spend, never below zero.
#[test]
fn test_additive_flush_carries_refund_deltas() {
    let store = Arc::new(MemoryStore::new());
    let k = sample_key("k_refund", "h_refund");
    store.put_key(&k).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(10);

    // Charge 2 requests, flush (durable requests=2, billable=2), then refund one and flush again.
    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    gov.flush_budgets();
    let u = store.get_usage("k_refund", 0).unwrap();
    assert_eq!(u.requests, 2);
    assert_eq!(u.billable_requests, 2);

    gov.refund_request(&cost, &k, "", 1_700_000_000);
    gov.flush_budgets();
    let u = store.get_usage("k_refund", 0).unwrap();
    assert_eq!(
        u.requests, 2,
        "the ADMISSION count is never refunded (the requests-limit truth)"
    );
    assert_eq!(
        u.billable_requests, 1,
        "the refund's negative BILLABLE delta lands durably"
    );
    assert_eq!(
        gov.usage_for(&cost, "k_refund", 1_700_000_000)
            .unwrap()
            .unwrap()
            .spend_cents,
        10,
        "derived spend follows the refunded BILLABLE count (1 x 10c fee)"
    );
}

/// Under a SUSTAINED metering-store outage with diverse keys, `pending_metering` stays BOUNDED and
/// loses NO billable usage. Before the cap, `flush_metering` re-queued every failed cell each tick
/// while `record_metering` kept adding new ones, so the map grew without bound. Now both routes go
/// through `accrue_pending`, which caps the map and COALESCES the overflow into a per-bucket sentinel
/// (totals preserved, per-key attribution collapsed) and counts it on a metric — so the map is
/// bounded, the loss of attribution is visible, and not one token or request is dropped.
#[test]
fn test_metering_accumulator_is_bounded_and_lossless_under_sustained_store_outage() {
    crate::metrics::init();

    /// A store whose `add_metering` ALWAYS fails — a metering-write outage that never recovers.
    struct MeteringDownStore {
        inner: MemoryStore,
    }
    impl busbar_api::Store for MeteringDownStore {
        fn put_key(&self, k: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(k)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(&self, id: &str, w: u64) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(id, w)
        }
        fn put_usage(
            &self,
            id: &str,
            w: u64,
            l: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(id, w, l)
        }
        fn add_metering(&self, _d: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            Err(busbar_api::StoreError("metering store down".into()))
        }
        fn list_metering(&self, b: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(b)
        }
    }

    let store = Arc::new(MeteringDownStore {
        inner: MemoryStore::new(),
    });
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_000;
    let per = crate::billing::TokenUsage {
        input: 3,
        output: 5,
        cache_read: Some(1),
        cache_creation: Some(2),
        ..Default::default()
    };
    // Drive well past the cap with DISTINCT keys — the "diverse keys/models" outage shape.
    let n = MAX_PENDING_METERING + 5_000;
    for i in 0..n {
        gov.record_metering(&format!("k{i}"), "m", "p", Some(&per), now);
    }

    // The RECORD path alone already bounds the map (record_metering coalesces past the cap), and the
    // summed totals still equal everything accrued — coalescing MOVES counts, it never drops them.
    let (len_rec, sum_rec) = gov.pending_metering_totals();
    let n64 = n as u64;
    assert!(
        len_rec <= MAX_PENDING_METERING + GOV_SHARDS,
        "the accrual path holds the map at the cap (+ at most one per-bucket sentinel per shard), not one cell per key: {len_rec}"
    );
    assert_eq!(
        sum_rec.requests, n64,
        "every accrued request is still counted"
    );
    assert_eq!(
        sum_rec.tokens_input,
        n64 * 3,
        "no input tokens lost to the cap"
    );
    assert_eq!(
        sum_rec.tokens_output,
        n64 * 5,
        "no output tokens lost to the cap"
    );
    assert_eq!(
        sum_rec.tokens_cache_read, n64,
        "no cache-read tokens lost to the cap"
    );
    assert_eq!(
        sum_rec.tokens_cache_write,
        n64 * 2,
        "no cache-write tokens lost to the cap"
    );

    // The FLUSH re-queue path: every write fails, every drained cell is re-queued through the same
    // bound. This is precisely where the map used to grow without bound.
    let flushed = gov.flush_metering();
    assert_eq!(
        flushed, 0,
        "the store is down, so nothing persisted this tick"
    );
    let (len_flush, sum_flush) = gov.pending_metering_totals();
    assert!(
        len_flush <= MAX_PENDING_METERING + GOV_SHARDS,
        "the failed-flush re-queue stays bounded rather than growing unbounded: {len_flush}"
    );
    assert_eq!(
        sum_flush.requests, n64,
        "retry preserves every request across the failed flush (nothing dropped, nothing doubled)"
    );
    assert_eq!(
        sum_flush.tokens_input,
        n64 * 3,
        "no billable input tokens lost across the failed flush"
    );

    // The loss of ATTRIBUTION is COUNTED, not silent: the coalesce metric is exported and non-zero.
    let rendered = crate::metrics::render();
    let coalesced = rendered
        .lines()
        .find(|l| l.starts_with("busbar_metering_pending_coalesced_total "))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(
        coalesced > 0,
        "coalesced cells are exported on busbar_metering_pending_coalesced_total so the degradation \
         is observable; got:\n{rendered}"
    );
}

/// The sharded metering accumulator counts EVERY concurrent accrual EXACTLY ONCE: N threads accrue
/// in parallel (with keys that both spread across shards and collide on shared cells across threads),
/// and the summed totals equal the arithmetic sum of all accruals — nothing lost to a race, nothing
/// doubled. Then one flush DRAINS every shard to the store, and the store total equals the same sum.
#[test]
fn test_sharded_metering_accrual_is_exactly_once_under_concurrency() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    // A CURRENT bucket: the memory store amortized-evicts buckets older than its retention window, and
    // thousands of writes here would trip that sweep on a stale (2023) bucket.
    let now = crate::store::now();
    let threads = 16u64;
    let per_thread = 5_000u64;
    let key_space = 64u64; // spread across shards; cross-thread collisions on shared cells

    let mut handles = Vec::new();
    for t in 0..threads {
        let gov = gov.clone();
        handles.push(std::thread::spawn(move || {
            let usage = crate::billing::TokenUsage {
                input: 2,
                output: 3,
                ..Default::default()
            };
            for i in 0..per_thread {
                let k = format!("k{}", (t * 7 + i) % key_space);
                gov.record_metering(&k, "m", "p", Some(&usage), now);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let total = threads * per_thread;
    let (_, sum) = gov.pending_metering_totals();
    assert_eq!(
        sum.requests, total,
        "every one of the {total} concurrent accruals is counted exactly once"
    );
    assert_eq!(
        sum.tokens_input,
        total * 2,
        "input tokens summed exactly once"
    );
    assert_eq!(
        sum.tokens_output,
        total * 3,
        "output tokens summed exactly once"
    );

    // A single flush drains ALL shards; the store total equals the sum, and the accumulator empties.
    let flushed = gov.flush_metering();
    assert!(flushed > 0, "the flush wrote the drained cells");
    let rows = gov.metering_for(metering_bucket(now)).unwrap();
    let store_reqs: u64 = rows.iter().map(|r| r.requests).sum();
    assert_eq!(
        store_reqs, total,
        "flush drained every shard exactly once — the store total equals the sum of accruals"
    );
    let (len_after, sum_after) = gov.pending_metering_totals();
    assert_eq!(len_after, 0, "drain emptied every shard");
    assert_eq!(sum_after.requests, 0);
}

/// Accrual RACING a concurrent flusher loses and doubles nothing: while N threads accrue, a separate
/// thread drains-and-writes in a tight loop. Because a key never migrates shards and each shard is
/// swapped atomically under its own lock, every accrual lands either in a drain (→ store) or in the
/// residual pending set exactly once. At the end, store total + still-pending total == the sum.
#[test]
fn test_sharded_metering_no_loss_with_a_concurrent_flusher() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    // A CURRENT bucket (see the sibling concurrency test): stale buckets get amortized-evicted by the
    // memory store under the many writes a concurrent flusher makes.
    let now = crate::store::now();
    let threads = 8u64;
    let per_thread = 10_000u64;

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flusher = {
        let gov = gov.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                gov.flush_metering();
                std::thread::yield_now();
            }
        })
    };

    let mut handles = Vec::new();
    for t in 0..threads {
        let gov = gov.clone();
        handles.push(std::thread::spawn(move || {
            let usage = crate::billing::TokenUsage {
                input: 1,
                ..Default::default()
            };
            for i in 0..per_thread {
                let k = format!("k{}", (t * 13 + i) % 200);
                gov.record_metering(&k, "m", "p", Some(&usage), now);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flusher.join().unwrap();
    gov.flush_metering(); // final drain of whatever the accruals left behind

    let total = threads * per_thread;
    let rows = gov.metering_for(metering_bucket(now)).unwrap();
    let store_reqs: u64 = rows.iter().map(|r| r.requests).sum();
    let (_, pending) = gov.pending_metering_totals();
    assert_eq!(
        store_reqs + pending.requests,
        total,
        "no accrual was lost or double-counted across a flush running concurrently with accrual \
         (store {store_reqs} + pending {} == {total})",
        pending.requests
    );
    assert_eq!(
        store_reqs, total,
        "the final drain flushed everything, so the store alone holds the full sum"
    );
}

/// A FAILED flush re-marks the cell dirty WITHOUT advancing the acked baseline, so the unacked
/// delta is retried (not lost) on the next tick once the store recovers.
#[test]
fn test_failed_flush_retries_the_unacked_delta() {
    /// A store whose add_usage fails until `healthy` flips true.
    struct FlakyStore {
        inner: MemoryStore,
        healthy: std::sync::atomic::AtomicBool,
    }
    impl busbar_api::Store for FlakyStore {
        fn put_key(&self, k: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(k)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(&self, id: &str, w: u64) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(id, w)
        }
        fn put_usage(
            &self,
            id: &str,
            w: u64,
            l: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(id, w, l)
        }
        fn add_usage(
            &self,
            id: &str,
            w: u64,
            d: &busbar_api::UsageDelta,
        ) -> busbar_api::StoreResult<()> {
            if !self.healthy.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(busbar_api::StoreError("store down".into()));
            }
            self.inner.add_usage(id, w, d)
        }
        fn add_metering(&self, d: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(d)
        }
        fn list_metering(&self, b: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(b)
        }
        fn append_audit(&self, e: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
            self.inner.append_audit(e)
        }
        fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit()
        }
    }
    let store = Arc::new(FlakyStore {
        inner: MemoryStore::new(),
        healthy: std::sync::atomic::AtomicBool::new(false),
    });
    let k = sample_key("k_flaky", "h_flaky");
    store.inner.put_key(&k).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(10);

    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    gov.flush_budgets(); // store down: delta stays unacked, cell re-marked dirty
    assert_eq!(store.inner.get_usage("k_flaky", 0).unwrap().requests, 0);

    store
        .healthy
        .store(true, std::sync::atomic::Ordering::Relaxed);
    gov.flush_budgets(); // retried: the full unacked delta lands exactly once
    assert_eq!(store.inner.get_usage("k_flaky", 0).unwrap().requests, 1);
    gov.flush_budgets(); // and does not double-count afterwards
    assert_eq!(store.inner.get_usage("k_flaky", 0).unwrap().requests, 1);
}

/// Token accrual + derived spend: 2000 input tokens at 500 micro-units/token derive to exactly
/// 100 cents; the LEDGER stores only tokens (no spend column exists to assert). Then the
/// REPRICE-ON-READ proof: the SAME ledger derived under a corrected (halved) rate card yields the
/// corrected spend - no data migration, tokens never changed.
#[test]
fn test_record_usage_derives_spend_and_reprices_on_read() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let k = sample_key("k1", "h1");
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("gpt-5", 500.0); // 500 micro-units/token
    gov.record_usage(&cost, &k, "", "gpt-5", &tt(2000), 1_700_000_000);
    gov.flush_budgets();
    let ledger = store.get_usage("k1", 0).unwrap();
    assert_eq!(ledger.tokens_for("gpt-5").unwrap().input, 2000);
    let u = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(u.spend_cents, 100, "2000 x 500 micro = 100 cents derived");
    assert_eq!(u.tokens, 2000);

    // REPRICE-ON-READ: correct the rate (halve it) and the SAME ledger derives half the spend.
    let corrected = card_cost("gpt-5", 250.0);
    let u = gov
        .usage_for(&corrected, "k1", 1_700_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        u.spend_cents, 50,
        "historical derived spend halves on the next read under the corrected rate"
    );
    assert_eq!(u.tokens, 2000, "tokens never changed - they are the truth");
}

/// SUB-CENT PRECISION WITHOUT A CARRY (the millicent carry map is GONE): the ledger stores RAW
/// tokens, so no precision is ever truncated or carried. At 10 micro-units/token (the old
/// 1 cent/1k), one 500-token request derives 0 whole cents but the 500 tokens are fully recorded;
/// after a second 500-token request the SAME ledger derives exactly 1 cent - no truncation loss,
/// no carry state.
#[test]
fn test_sub_cent_precision_via_ledger_no_carry() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let k = sample_key("k1", "h1");
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("m", 10.0); // 10 micro-units/token = the old 1 cent per 1k tokens

    gov.record_usage(&cost, &k, "", "m", &tt(500), 1_700_000_000);
    let u1 = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(u1.spend_cents, 0, "0.5 cents derives to 0 whole cents");
    assert_eq!(
        u1.tokens, 500,
        "but every token is recorded - nothing truncated"
    );

    gov.record_usage(&cost, &k, "", "m", &tt(500), 1_700_000_000);
    let u2 = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(
        u2.spend_cents, 1,
        "two 0.5-cent requests derive a whole cent from the raw ledger - no carry needed"
    );
    assert_eq!(u2.tokens, 1000);
}

/// Window isolation without a carry: tokens accrue to the window they were charged in. Keys
/// attribute in the all-time window now, so the per-window behavior lives on GROUP buckets: a
/// day-window group cell rolls at midnight and one day's tokens can never leak into the next
/// day's derived spend.
#[test]
fn test_ledger_windows_are_isolated_across_days() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let mut k = sample_key("k1", "h1");
        k.group = Some("g".to_string());
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_and_group_cost("m", 10.0, &[("g", 1_000_000, "day", None)]);
    let day1 = 1_700_000_000;
    let day2 = day1 + 86_400;
    let w1 = budget_window(WINDOW_DAY, day1);
    let w2 = budget_window(WINDOW_DAY, day2);
    assert_ne!(w1, w2);

    gov.record_usage(&cost, &k, "", "m", &tt(500), day1);
    gov.flush_budgets(); // persist the day-1 cell before it rolls over
    gov.record_usage(&cost, &k, "", "m", &tt(500), day2);
    gov.flush_budgets();
    assert_eq!(
        ledger_tokens(&store, "group:g@day", w1),
        500,
        "day-1 tokens stay in day 1"
    );
    assert_eq!(
        ledger_tokens(&store, "group:g@day", w2),
        500,
        "day-2 window holds only its own tokens (no cross-window leak)"
    );
    // The key's attribution bucket (all-time) accumulated both days' tokens.
    assert_eq!(ledger_tokens(&store, "k1", 0), 1000);
}

/// Token-ledger write-behind UNDER a real Tokio runtime: `record_usage` accrues to the
/// AUTHORITATIVE in-memory cell (no store round-trip); the durable ledger is updated only by
/// `flush_budgets` (the flusher's per-tick body). Pins the
/// `record_usage -> in-memory cell -> flush_budgets -> add_usage` path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_record_usage_write_behind_under_runtime() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let k = sample_key("k1", "h1");
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("gpt-5", 500.0);
    gov.record_usage(&cost, &k, "", "gpt-5", &tt(2000), 1_700_000_000);
    assert_eq!(
        store.get_usage("k1", 0).unwrap(),
        UsageLedger::default(),
        "write-behind: the durable ledger is untouched until a flush"
    );
    assert_eq!(gov.flush_budgets(), 1, "one dirty cell flushed");
    let u = store.get_usage("k1", 0).unwrap();
    assert_eq!(
        u.tokens_for("gpt-5").unwrap().input,
        2000,
        "the per-model tier split lands durably"
    );
    assert_eq!(
        gov.usage_for(&cost, "k1", 1_700_000_000)
            .unwrap()
            .unwrap()
            .spend_cents,
        100,
        "2000 tokens at 500 micro/token derive exactly 100c"
    );
}

/// `rate_headroom` (routing `usage` signal) over the GROUP CHAIN: pure observation of the
/// remaining requests/tokens fraction, `[0,1]`. `None` when the chain carries no such limit;
/// never mutates a cell; clamps at 0.0; takes the MIN across limits when several are set.
#[test]
fn test_rate_headroom_reports_fraction_remaining() {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040; // mid-window

    // No group -> no limits -> no headroom signal.
    let unl = sample_key("ku", "hu");
    let no_groups = crate::cost::CostModel::flat(0);
    assert_eq!(gov.rate_headroom(&no_groups, &unl, None, now), None);

    // requests=0: a fully-closed limit. The code guards the divide-by-zero (cap==0 -> no
    // headroom); assert 0.0 rather than a panic, so a future removal of that guard is caught.
    let zero_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([(
            "z".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Requests,
                    amount: 0,
                    per: Some(LimitWindow::Minute),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        )]);
    let zero = crate::cost::CostModel::resolve_parts(None, 0, &zero_cfg);
    let mut kz = sample_key("kz", "hz");
    kz.group = Some("z".to_string());
    assert_eq!(
        gov.rate_headroom(&zero, &kz, None, now),
        Some(0.0),
        "requests=0 is fully closed -> 0.0 headroom, not a divide-by-zero panic"
    );

    // requests=4 per minute + a loose tokens cap: fresh window is fully available (1.0), and the
    // observation must NOT consume budget.
    let cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([(
            "g".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![
                    LimitCfg {
                        metric: LimitMetric::Requests,
                        amount: 4,
                        per: Some(LimitWindow::Minute),
                        scope: None,
                        on_exhaust: None,
                        downgrade_to: None,
                    },
                    LimitCfg {
                        metric: LimitMetric::Tokens,
                        amount: 100_000,
                        per: Some(LimitWindow::Minute),
                        scope: None,
                        on_exhaust: None,
                        downgrade_to: None,
                    },
                ],
                ..Default::default()
            },
        )]);
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &cfg);
    let mut k = sample_key("k1", "h1");
    k.group = Some("g".to_string());
    assert_eq!(gov.rate_headroom(&cost, &k, None, now), Some(1.0));
    assert_eq!(
        gov.rate_headroom(&cost, &k, None, now),
        Some(1.0),
        "rate_headroom is read-only; repeated reads must not drain the window"
    );

    // Consume 1 of 4 via the admission path -> 3/4 headroom = 0.75 (the loose tokens cap does
    // not tighten the min).
    assert!(gov.try_admit(&cost, &k, "", now).is_ok());
    let h = gov.rate_headroom(&cost, &k, None, now).unwrap();
    assert!((h - 0.75).abs() < 1e-9, "expected 0.75 headroom, got {h}");

    // Drive requests to the cap -> 0.0, clamped.
    for _ in 0..3 {
        assert!(gov.try_admit(&cost, &k, "", now).is_ok());
    }
    let hb = gov.rate_headroom(&cost, &k, None, now).unwrap();
    assert!(
        hb.abs() < 1e-9,
        "requests at cap must yield 0.0 headroom, got {hb}"
    );
}

/// REGRESSION: the budget shard sweep must be WINDOW-AGNOSTIC.
/// The original sweep retained only cells matching THIS bucket's window, so a day-window bucket's
/// Nth admission evicted the valid CURRENT cells of `total`/`month` buckets sharing the shard,
/// silently resetting their accrued spend (the hard cap) and dropping dirty unflushed spend.
/// The fix mirrors the carry-map rule: age-based retain, `total` (window 0) never
/// ages out. This test seeds current-window co-tenants of BOTH other windows plus one genuinely
/// stale cell into the admitting key's shard, fires the sweep, and asserts only the stale cell
/// dies.
#[test]
fn test_budget_sweep_is_window_agnostic_across_cotenants() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;

    // The admitting key charges its own (all-time) attribution bucket, which acquires its shard
    // and can fire that shard's sweep.
    let survivor = sample_key("survivor", "hs");

    // A seeded ledger cell with `requests` accrued (spend derives from requests x fee).
    let seeded = |window_start: u64, requests: u64, dirty: bool| BudgetCell {
        window_start,
        requests,
        billable_requests: requests,
        flushed_requests: 0,
        flushed_billable_requests: 0,
        models: Vec::new(),
        dirty,
        last_touch: now,
    };

    // Seed co-tenants directly INTO the survivor's shard (same idiom as the old rate sweep test).
    {
        let mut map = gov.budget.write("survivor");
        // A `total`-window bucket: window_start == 0, nearly-exhausted accrual. The buggy sweep
        // evicted this cell (0 != the admitting window) - resetting a nearly-exhausted hard cap.
        map.insert("total-cotenant".to_string(), seeded(0, 4999, true));
        // A `month`-window bucket in its CURRENT window: also evicted by the buggy sweep despite
        // being live and authoritative.
        map.insert(
            "monthly-cotenant".to_string(),
            seeded(budget_window(WINDOW_MONTH, now), 1234, true),
        );
        // A genuinely stale bounded-window cell (older than 31 d): the sweep SHOULD evict this.
        map.insert(
            "stale-cotenant".to_string(),
            seeded(now - 32 * SECS_PER_DAY, 1, false),
        );
    }

    // Force the survivor's next admission to run this shard's sweep (post-increment semantics).
    gov.budget.sweep_ticker_for("survivor").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&flat_cost(1), &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor");
    let total = map
        .get("total-cotenant")
        .expect("total-window cell must survive the sweep (window 0 never ages out)");
    assert_eq!(
        (total.requests, total.dirty),
        (4999, true),
        "total-window accrual + dirty flag intact"
    );
    let monthly = map
        .get("monthly-cotenant")
        .expect("current month cell must survive the sweep");
    assert_eq!(monthly.requests, 1234, "month accrual intact");
    assert!(
        !map.contains_key("stale-cotenant"),
        "genuinely stale (>31 d) bounded-window cell is still evicted"
    );
    assert!(
        map.contains_key("survivor"),
        "the charging key's own cell exists"
    );
}

/// The sweep's staleness boundary is EXACT: a bounded-window cell aged exactly `max_window`
/// (31 days) to the second is evicted (`window_start + max_window > now` is false at equality,
/// so `retain` drops it); one second younger survives. A mutated `>` -> `>=` would keep the
/// exactly-31-day cell one extra sweep cycle. Same boundary, `last_touch`-aged form for the
/// all-time (`window_start == 0`) attribution-cell branch just below it.
#[test]
fn test_budget_sweep_staleness_boundary_is_exact() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    let max_window = 31 * SECS_PER_DAY;
    let survivor = sample_key("survivor2", "hs2");

    let seeded = |window_start: u64, last_touch: u64| BudgetCell {
        window_start,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 0,
        flushed_billable_requests: 0,
        models: Vec::new(),
        dirty: false,
        last_touch,
    };

    {
        let mut map = gov.budget.write("survivor2");
        // Bounded-window branch (`window_start != 0`): exactly at the boundary -> evicted; one
        // second younger -> survives.
        map.insert(
            "bounded-at-boundary".to_string(),
            seeded(now - max_window, now),
        );
        map.insert(
            "bounded-just-under".to_string(),
            seeded(now - max_window + 1, now),
        );
        // All-time branch (`window_start == 0`), aged by `last_touch` instead: same exact
        // boundary semantics.
        map.insert(
            "alltime-at-boundary".to_string(),
            seeded(0, now - max_window),
        );
        map.insert(
            "alltime-just-under".to_string(),
            seeded(0, now - max_window + 1),
        );
    }

    gov.budget.sweep_ticker_for("survivor2").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&flat_cost(1), &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor2");
    assert!(
        !map.contains_key("bounded-at-boundary"),
        "a bounded-window cell aged EXACTLY max_window must be evicted (> not >=)"
    );
    assert!(
        map.contains_key("bounded-just-under"),
        "a bounded-window cell one second younger than the boundary must survive"
    );
    assert!(
        !map.contains_key("alltime-at-boundary"),
        "an all-time cell last-touched EXACTLY max_window ago must be evicted (> not >=)"
    );
    assert!(
        map.contains_key("alltime-just-under"),
        "an all-time cell touched one second more recently than the boundary must survive"
    );
}

#[test]
fn test_budget_sweep_cadence_post_increment_no_off_by_one() {
    // Regression for the sweep-cadence off-by-one, now on the budget shard sweep (the rate map is
    // gone; the same amortized POST-increment machinery guards the budget cells):
    // - It must NOT fire on the very first admission (ticker starts at 0; the post-increment
    // value 1 is not a multiple of N), so startup against an empty map does no wasted scan.
    // - It must fire on admissions N, 2N, 3N, ...
    // - The u32 wrap boundary must NOT skip a cycle: when the pre-increment value is 0xFFFFFFFF,
    // the post-increment value wraps to 0 (a multiple of N) and the sweep still fires.
    const N: u32 = crate::config::DEFAULT_RATE_SWEEP_INTERVAL;
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let k = sample_key("k1", "h1");
    let now = 1_700_000_040u64;
    let stale = || BudgetCell {
        window_start: now - 40 * SECS_PER_DAY, // genuinely stale (>31 d)
        requests: 1,
        billable_requests: 1,
        flushed_requests: 0,
        flushed_billable_requests: 0,
        models: Vec::new(),
        dirty: false,
        last_touch: now,
    };

    // Seed a STALE co-tenant INTO k1's shard so k1's own admission runs the (per-shard) sweep
    // that would evict it. Distinct entry key so we observe whether the sweep ran.
    {
        let mut map = gov.budget.write("k1");
        map.insert("stale".to_string(), stale());
    }

    // FIRST admission: k1's shard ticker is 0, post-increment value is 1 (not a multiple of N) ->
    // NO sweep. The stale co-tenant must survive.
    assert_eq!(gov.budget.sweep_ticker_for("k1").load(Ordering::Relaxed), 0);
    assert!(gov.try_admit(&flat_cost(0), &k, "", now).is_ok());
    assert!(
        gov.budget.read("k1").contains_key("stale"),
        "first admission must NOT sweep (post-increment value 1 is not a multiple of N)"
    );

    // Drive k1's shard ticker to N-1 so the next admission's post-increment value is exactly N ->
    // sweep.
    gov.budget
        .sweep_ticker_for("k1")
        .store(N - 1, Ordering::Relaxed);
    assert!(gov.try_admit(&flat_cost(0), &k, "", now).is_ok());
    assert!(
        !gov.budget.read("k1").contains_key("stale"),
        "admission N must run the sweep and evict the stale entry"
    );

    // WRAP boundary: pre-increment value 0xFFFFFFFF is NOT a multiple of N, but post-increment
    // wraps to 0 (a multiple of N) so the sweep must still fire - no skipped cycle.
    {
        let mut map = gov.budget.write("k1");
        map.insert("stale2".to_string(), stale());
    }
    gov.budget
        .sweep_ticker_for("k1")
        .store(u32::MAX, Ordering::Relaxed);
    assert!(gov.try_admit(&flat_cost(0), &k, "", now).is_ok());
    assert_eq!(
        gov.budget.sweep_ticker_for("k1").load(Ordering::Relaxed),
        0,
        "ticker wrapped to 0"
    );
    assert!(
        !gov.budget.read("k1").contains_key("stale2"),
        "wrap boundary must still sweep (post-increment 0 is a multiple of N) - no skipped cycle"
    );
}

#[tokio::test]
async fn test_admission_charge_write_behind_under_runtime() {
    // Inside a Tokio runtime, the admission charge lands in the AUTHORITATIVE in-memory cell (no
    // store round-trip); the write-behind flusher persists the request-count delta. Spend derives.
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = group_cost(30, &[("team", 1000, "total", None)]);

    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    assert_eq!(
        store.get_usage("k1", 0).unwrap().requests,
        0,
        "write-behind: durable ledger untouched until a flush"
    );
    assert_eq!(gov.flush_budgets(), 2, "key + group cells flushed");
    assert_eq!(
        store.get_usage("k1", 0).unwrap().requests,
        1,
        "the request-count delta lands durably after the flush"
    );
    assert_eq!(
        store.get_usage("group:team@total", 0).unwrap().requests,
        1,
        "the group's window bucket flushed too"
    );
    // Derived spend follows: 1 request x 30c fee, still under the 1000c group cap.
    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
}

#[test]
fn test_negative_fee_and_rate_clamp_to_zero() {
    // A hostile/misconfigured NEGATIVE per-request fee or per-token rate must clamp to 0, never
    // derive negative spend that could evade a cap. (`CostModel::flat` clamps the fee;
    // `RateNanos::from_cfg` clamps a negative rate.)
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    store.put_key(&k).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    // Hostile negative fee -> clamped to 0 by CostModel; a 100c group cap must never be evaded
    // by negative derived spend.
    let cost = {
        let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
            std::collections::BTreeMap::from([(
                "team".to_string(),
                budget_group_cfg(100, "total", None),
            )]);
        crate::cost::CostModel::resolve_parts(None, -50, &groups)
    };

    for _ in 0..5 {
        assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    }
    let u = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(u.spend_cents, 0, "negative fee clamps to 0 derived spend");
    assert_eq!(u.requests, 5, "requests are still counted");

    // A negative per-token rate likewise derives 0 (never subtracts).
    let neg_rate = card_cost("m", -100.0);
    gov.record_usage(&neg_rate, &k, "", "m", &tt(5000), 1_700_000_000);
    let u = gov
        .usage_for(&neg_rate, "k1", 1_700_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(u.spend_cents, 0, "negative token rate clamps to 0");
    assert_eq!(u.tokens, 5000, "tokens are still counted");
}

#[test]
fn test_create_key_minted_id_is_free_so_mint_succeeds() {
    // A normal mint derives a fresh id and the collision guard does not fire (the id is free).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let spec = NewKeySpec {
        name: "first".to_string(),
        allowed_pools: None,
        group: None,
        labels: std::collections::BTreeMap::new(),
        ..Default::default()
    };
    let (key, _secret) = gov.create_key(spec, 1_700_000_000).unwrap();
    assert!(key.id.starts_with("vk_")); // golden wire-contract literal (kept bare on purpose)
                                        // The minted key resolves by its own subject id.
    assert_eq!(gov.lookup_by_sub(&key.id).unwrap().id, key.id);
}

#[test]
fn test_update_key_toggles_enabled_and_rebinds_group_in_place() {
    // PATCH /admin/keys/:id: a key can be disabled WITHOUT destroying it, and its group
    // binding changed, with the secret/hash preserved. Keys are pure auth, so `enabled` and
    // `group` are the whole mutable surface. A missing field leaves its value unchanged; a
    // present `null` (inner None) UNBINDS the group back to unlimited.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("growth".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    assert!(key.enabled, "new key starts enabled");
    let hash = key.generation_hash.clone();

    // Disable it; leave the binding untouched (outer None = field absent).
    let updated = gov
        .update_key(&key.id, Some(false), None)
        .unwrap()
        .expect("key exists");
    assert!(!updated.enabled, "key is now disabled");
    assert_eq!(
        updated.group.as_deref(),
        Some("growth"),
        "untouched binding preserved"
    );
    assert_eq!(updated.generation_hash, hash, "secret hash is not rotated");
    // The disabled state is enforced on the next lookup (the cache was refreshed).
    let looked = gov.lookup_by_sub(&key.id).unwrap();
    assert!(!looked.enabled, "lookup reflects the disabled key");

    // Re-enable and REBIND in one call (Some(Some(name)) = rebind).
    let re = gov
        .update_key(&key.id, Some(true), Some(Some("acme".to_string())))
        .unwrap()
        .expect("key exists");
    assert!(re.enabled);
    assert_eq!(re.group.as_deref(), Some("acme"));

    // UNBIND with a present null (Some(None)): the key becomes authed + unlimited.
    let unbound = gov
        .update_key(&key.id, None, Some(None))
        .unwrap()
        .expect("key exists");
    assert_eq!(unbound.group, None, "inner None unbinds to no group");
    // The unbind persisted through the store, not just the returned struct.
    assert_eq!(store.get_key(&key.id).unwrap().unwrap().group, None);

    // Updating a non-existent key returns Ok(None) (the handler maps this to 404).
    assert!(gov
        .update_key("vk_does_not_exist", Some(false), None)
        .unwrap()
        .is_none());
}

#[test]
fn test_ensure_id_free_for_hash_guards_silent_overwrite() {
    // The PRIMARY KEY `id` is a 64-bit prefix of the full generation_hash, so a collision can put a new
    // secret's id atop an unrelated key. The guard must REFUSE when the id already holds a
    // DIFFERENT generation_hash (rather than let put_key UPSERT-overwrite and invalidate the incumbent),
    // while allowing a free id or an idempotent same-hash re-mint.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();

    // A free id is allowed.
    gov.ensure_id_free_for_hash("vk_freshid", "HASH_A")
        .expect("a free id must be allowed");

    // Seed an incumbent key occupying that id under HASH_A.
    let incumbent = sample_key("vk_freshid", "HASH_A");
    store.put_key(&incumbent).unwrap();
    gov.refresh().unwrap();

    // Same id, SAME hash: idempotent re-mint is allowed.
    gov.ensure_id_free_for_hash("vk_freshid", "HASH_A")
        .expect("same-hash re-mint must be allowed");

    // Same id, DIFFERENT hash: must be rejected (the collision the fix guards against).
    let err = gov
        .ensure_id_free_for_hash("vk_freshid", "HASH_B_DIFFERENT")
        .expect_err("colliding id with a different hash must be rejected");
    assert!(
        err.to_string().contains("id collision"),
        "error must explain the id collision; got: {err}"
    );

    // The incumbent row is untouched (never overwritten).
    let still = store.get_key("vk_freshid").unwrap().unwrap();
    assert_eq!(
        still.generation_hash, "HASH_A",
        "incumbent must not be clobbered"
    );
}

#[test]
fn test_poisoned_budget_lock_recovers_not_panics() {
    // Regression: a panic while a budget shard lock is held poisons it. The hot-path accessors
    // must RECOVER (via into_inner) rather than `.unwrap()`-panic on every subsequent call, which
    // would cascade a single transient fault into a full governance outage. We deliberately
    // poison the shard the key's GROUP bucket resolves to, then assert try_admit still functions
    // and still enforces the cap.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());
    let cost = group_cost(1, &[("g", 2, "total", None)]); // 1c fee, 2c cap
    let mut k = sample_key("k1", "h1");
    k.group = Some("g".to_string());
    let now = 1_700_000_040;

    // Poison the budget SHARD the group's total bucket resolves to: panic inside its write guard.
    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.budget.shard_lock_for("group:g@total").write().unwrap();
        panic!("intentional poison");
    }));
    assert!(
        gov.budget.shard_lock_for("group:g@total").is_poisoned(),
        "the group bucket's shard lock must be poisoned for the test"
    );

    // Despite the poison, the hot path keeps working (no panic, the cap still enforced).
    assert!(
        gov.try_admit(&cost, &k, "", now).is_ok(),
        "1st admits after poison"
    );
    assert!(
        gov.try_admit(&cost, &k, "", now).is_ok(),
        "2nd admits after poison"
    );
    assert!(
        gov.try_admit(&cost, &k, "", now).is_err(),
        "2c cap still enforced on a recovered (poisoned) lock"
    );
}

#[test]
fn test_poisoned_by_hash_lock_recovers_not_panics() {
    // The auth-path key cache lock has the same hazard: a poisoned `by_id` must not make every
    // subsequent `lookup_by_sub` panic. Poison it, then confirm lookup still resolves a cached key.
    let store = Arc::new(MemoryStore::new());
    let k = sample_key("k1", "binding:k1:gen1");
    store.put_key(&k).unwrap();
    let gov = Arc::new(GovState::new(store, None).unwrap());

    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.caches.write().unwrap();
        panic!("intentional poison");
    }));
    assert!(gov.caches.is_poisoned(), "cache lock must be poisoned");

    // lookup still works (no panic) and refresh still succeeds on the recovered guard.
    assert_eq!(gov.lookup_by_sub("k1").unwrap().id, "k1");
    gov.refresh()
        .expect("refresh recovers the poisoned cache lock");
    assert_eq!(gov.lookup_by_sub("k1").unwrap().id, "k1");
}

/// A `Store` decorator that (1) RECORDS every `add_usage` requests-delta in call-COMPLETION order
/// and (2) can BLOCK the first `add_usage` until the test releases it. This lets the test hold one
/// flush in flight while it accrues NEWER requests, proving the flusher's serialization gate keeps
/// two flushes from overlapping and the additive deltas land exactly once. All other methods
/// delegate to an inner `MemoryStore`.
struct RecordingBarrierStore {
    inner: MemoryStore,
    block_first: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    writes: std::sync::Mutex<Vec<i64>>,
}

impl Store for RecordingBarrierStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // The FIRST flush's add_usage signals it has entered, then blocks until the test releases
        // it - pinning that flush "in flight" so the test can attempt an overlapping flush.
        if self
            .block_first
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
        }
        let r = self.inner.add_usage(bucket_id, window_start, delta);
        // Record in COMPLETION order so the test can audit exactly which deltas landed.
        self.writes.lock().unwrap().push(delta.requests);
        r
    }
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// The periodic flusher must never let two `flush_budgets`
/// runs overlap - overlapping snapshots could race baseline advancement and double- or
/// under-count deltas. We hold the first flush's `add_usage` paused, accrue NEWER requests, and
/// let the flusher fire (and SKIP) overlapping ticks; after release + shutdown the durable ledger
/// must hold EXACTLY the total accrued requests - nothing lost, nothing double-counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_write_behind_flush_serializes_and_counts_exactly_once() {
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(RecordingBarrierStore {
        inner: MemoryStore::new(),
        block_first: std::sync::atomic::AtomicBool::new(true),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
        writes: std::sync::Mutex::new(Vec::new()),
    });
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cost = flat_cost(1);
    let at = 1_700_000_000u64;
    let key = sample_key("k1", "h1"); // no group: uncapped, charges only its own (total) bucket

    // Accrue an OLDER 3 requests, then start the flusher: its first tick snapshots that cell and
    // its `add_usage` BLOCKS mid-write (holding the flush in flight).
    for _ in 0..3 {
        assert!(gov.try_admit(&cost, &key, "", at).is_ok());
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let flusher = crate::governance::spawn_budget_flusher(gov.clone(), shutdown_rx);

    // Wait until the first flush is paused inside add_usage.
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();

    // While that older flush is pinned, accrue 2 NEWER requests and re-mark the cell dirty.
    assert!(gov.try_admit(&cost, &key, "", at).is_ok());
    assert!(gov.try_admit(&cost, &key, "", at).is_ok());

    // Yield so any tick that fires while the first flush is pinned takes its SKIP (try_lock) arm
    // rather than racing it — not asserting how many ticks fired/skipped, only exactly-once below.
    tokio::task::yield_now().await;

    // Release the first (older) flush; it completes writing its 3-request delta.
    release_tx.send(()).unwrap();

    // Shut down and JOIN the flusher's own task instead of guessing a wall-clock duration for its
    // final flush — this makes the wait for "the final flush COMPLETED" exact rather than a guess
    // that can come up short under a loaded runner (the final flush is spawn_blocking work).
    shutdown_tx.send(()).unwrap();
    flusher.await.unwrap();

    // The durable ledger holds EXACTLY 5 requests: additive deltas, serialized, exactly once.
    let durable = store.inner.get_usage("k1", 0).unwrap().requests;
    assert_eq!(
        durable, 5,
        "additive flushes must sum to exactly the accrued requests - no loss, no double count"
    );
    // The completed deltas sum to 5 as well (e.g. [3, 2]) - never a duplicated snapshot.
    let writes = store.writes.lock().unwrap().clone();
    assert_eq!(
        writes.iter().sum::<i64>(),
        5,
        "the sum of flushed deltas equals the accrued total: {writes:?}"
    );
}

/// A `Store` decorator whose `add_denylist` BLOCKS until released, letting the test pause a
/// `revoke()` call INSIDE its store-write sequence — deep in the region `revoke`'s
/// `_refresh_guard` must span — so the test can probe, from another thread, whether
/// `refresh_lock` is actually held there. All other methods delegate to an inner `MemoryStore`.
struct BlockingDenylistStore {
    inner: MemoryStore,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Store for BlockingDenylistStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        // Signal the test that `revoke()` has reached this call (i.e. is inside the region that
        // must now be lock-protected), then block until the test releases it.
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv();
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

/// REGRESSION for the fan-out fix's lost-update guard: PROVES `revoke()` actually HOLDS
/// `refresh_lock` across its store-write sequence, not merely that it calls `.lock()` somewhere
/// in the function. We pause `revoke()` inside its `add_denylist` store call (via a blocking
/// `Store` double) from a background thread, then — from the test's main thread — attempt
/// `refresh_lock.try_lock()` while `revoke` is paused there: it MUST fail (`Err`, lock held).
///
/// Before the fix, `revoke()` never acquired `refresh_lock` at all, so this exact `try_lock()`
/// would have SUCCEEDED (`Ok`) even with `revoke` paused mid-store-write — that observable
/// difference is the red state this test is built to catch, and it is exactly the gap that let a
/// concurrent `refresh()` load a stale store snapshot and swap it in AFTER `revoke`'s targeted
/// cache patch, reverting a just-revoked key's cache entry back to enabled.
#[test]
fn revoke_holds_refresh_lock_across_its_store_writes() {
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BlockingDenylistStore {
        inner: MemoryStore::new(),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = Arc::new(GovState::new(store, None).unwrap());

    let gov2 = gov.clone();
    let handle = std::thread::spawn(move || {
        gov2.revoke("bob", "test").expect("revoke");
    });

    // Wait until `revoke` is paused inside `add_denylist` — i.e. inside the region the fix's
    // guard must span.
    entered_rx
        .recv()
        .expect("revoke reached add_denylist before this thread gave up waiting");

    // THE LOAD-BEARING ASSERTION. While `revoke()` is paused mid-store-write, `refresh_lock` must
    // be held (try_lock returns Err). Pre-fix, `revoke()` never touched this lock, so this
    // try_lock would have returned Ok even here — the exact bug the fix closes.
    assert!(
        gov.refresh_lock.try_lock().is_err(),
        "refresh_lock must be HELD while revoke() is paused mid-store-write; a concurrent \
         refresh() could otherwise load() a stale store snapshot and swap it in AFTER revoke()'s \
         targeted cache patch, silently reverting the just-revoked key's cache entry to enabled"
    );

    // Let revoke() finish.
    release_tx.send(()).unwrap();
    handle.join().unwrap();

    // The lock is released once revoke() returns.
    assert!(
        gov.refresh_lock.try_lock().is_ok(),
        "refresh_lock must be released once revoke() has returned"
    );
    assert!(gov.is_revoked("bob"), "revoke() still completed its work");
}

// ─── Budget-group CHAIN enforcement (1.5.0 cost model) ───────────────────────────────────────────

/// CHAIN ENFORCEMENT, AND semantics: a key inside bob -> growth must pass EVERY bucket. With the
/// key (always uncapped now) bound to bob capped at 2 requests' worth of fee, the third admission
/// is rejected NAMING the blocking bucket (group bob, budget, month), and NOTHING is charged on
/// the rejected attempt (all-or-nothing: no bucket in the chain gains a request).
#[test]
fn test_chain_enforcement_rejects_naming_the_blocking_group() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = group_cost(
        10, // 10c flat fee (counted into EVERY bucket's derived spend)
        &[
            ("growth", 1_000_000, "month", None),
            ("bob", 25, "month", Some("growth")), // 25c cap: two 10c-fee requests fit
        ],
    );
    let mut k = sample_key("vk_bob", "h_bob");
    k.group = Some("bob".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    // A ZERO-cap group blocks its very first request (derived 0 >= 0 cap) and is NAMED exactly.
    let zero = group_cost(10, &[("broke", 0, "month", None)]);
    let mut kb = sample_key("vk_broke", "h_broke");
    kb.group = Some("broke".to_string());
    store.put_key(&kb).unwrap();
    assert_eq!(
        gov.try_admit(&zero, &kb, "", at).unwrap_err(),
        LimitBlocked::Limit {
            group: "broke".to_string(),
            metric: "budget",
            window: Some("month"),
            pool: None,
            downgrade_to: None,
            retry_after: crate::governance::window_end("month", at)
                .map(|end| end.saturating_sub(at).max(1)),
        },
        "a zero-cap group blocks and the exact bucket is NAMED"
    );
    // All-or-nothing: the rejected attempt charged NOTHING anywhere.
    assert_eq!(
        gov.usage_for(&zero, "vk_broke", at)
            .unwrap()
            .unwrap()
            .requests,
        0
    );

    // The bob chain admits twice under every cap and charges EVERY bucket in the chain.
    assert!(gov.try_admit(&cost, &k, "", at).is_ok());
    assert!(gov.try_admit(&cost, &k, "", at).is_ok());
    // The 3rd would derive 30c > bob's 25c cap: rejected naming bob.
    match gov.try_admit(&cost, &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window: Some("month"),
            ..
        } => assert_eq!(group, "bob"),
        other => panic!("expected bob's month budget to block, got {other:?}"),
    }
    gov.flush_budgets();
    assert_eq!(
        store.get_usage("vk_bob", 0).unwrap().requests,
        2,
        "key attribution bucket charged (and only for the ADMITTED requests)"
    );
    let month_window = budget_window(WINDOW_MONTH, at);
    assert_eq!(
        store
            .get_usage("group:bob@month", month_window)
            .unwrap()
            .requests,
        2,
        "group bucket charged in ITS OWN (month) window"
    );
    assert_eq!(
        store
            .get_usage("group:growth@month", month_window)
            .unwrap()
            .requests,
        2,
        "the whole ancestor chain is charged atomically"
    );
}

/// TOKEN spend blocks a GROUP: with a rate card, tokens accrued through the chain push the
/// group's derived spend to its cap and the next admission is rejected naming that group - the
/// key's own (uncapped) attribution bucket never blocks. Proves group caps are enforced on
/// DERIVED token spend.
#[test]
fn test_group_token_spend_blocks_chain_admission() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    // 100 micro-units/token; group cap = 100 cents = 10_000 tokens' worth. No flat fee.
    let cost = card_and_group_cost("gpt-5", 100.0, &[("team", 100, "total", None)]);

    let mut k = sample_key("vk_t", "h_t");
    k.group = Some("team".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    assert!(gov.try_admit(&cost, &k, "", at).is_ok());
    // Accrue exactly the cap's worth of tokens: 10_000 x 100 micro = 100 cents.
    gov.record_usage(&cost, &k, "", "gpt-5", &tt(10_000), at);
    match gov.try_admit(&cost, &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window: Some("total"),
            pool: None,
            downgrade_to: None,
            retry_after: None,
        } => assert_eq!(group, "team"),
        other => panic!("expected team's budget to block, got {other:?}"),
    }
}

/// A boundary-STRADDLING admission - pinned `charged_at` in the
/// OLD window, arriving after a concurrent admission already rolled the live cell to the NEW
/// window - must charge the live cell IN PLACE. The pre-fix charge arm rewound the live cell to
/// the straddler's older window (`BudgetCell::fresh(old_window)`), wiping the new window's
/// accrued tokens/requests AND flush baselines; and the pre-fix check arm derived the straddler's
/// spend as 0 (fresh window), admitting past an exhausted cap. Keys attribute all-time now, so
/// the rolling-window cell under test is the bound group's DAY bucket.
#[test]
fn test_boundary_straddle_charge_never_rewinds_the_live_cell() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    // 100 micro-units/token, no flat fee: 10_000 tokens = 100 cents of derived spend; day cap 150.
    let cost = card_and_group_cost("m", 100.0, &[("g", 150, "day", None)]);
    let mut k = sample_key("vk_straddle", "h_s");
    k.group = Some("g".to_string());
    let w0_late = 3 * crate::governance::SECS_PER_DAY - 5; // just before the day boundary
    let w1_early = 3 * crate::governance::SECS_PER_DAY + 5; // just after (the LIVE window)
    let bucket = "group:g@day";

    // A W1 admission rolls the group cell to the new day and accrues real spend there.
    gov.try_admit(&cost, &k, "", w1_early)
        .expect("fresh window admits");
    gov.record_usage(&cost, &k, "", "m", &tt(10_000), w1_early);
    let before = gov
        .derived_bucket_usage(&cost, bucket, WINDOW_DAY, true, w1_early)
        .unwrap();
    assert_eq!((before.tokens, before.requests), (10_000, 1));

    // The straddler (charged_at still in W0) is admitted - 100c < 150c cap - and must charge the
    // LIVE cell without rewinding it.
    gov.try_admit(&cost, &k, "", w0_late)
        .expect("under-cap straddler admits");
    let after = gov
        .derived_bucket_usage(&cost, bucket, WINDOW_DAY, true, w1_early)
        .unwrap();
    assert_eq!(
        (after.tokens, after.requests),
        (10_000, 2),
        "the live window's ledger survives a straddling charge (no rewind); the straddler's \
         request lands in the live cell"
    );

    // Exhaust the live window's cap; a further STRADDLING admission must SEE that spend and
    // reject (pre-fix it derived 0 for the 'stale' window and admitted).
    gov.record_usage(&cost, &k, "", "m", &tt(10_000), w1_early); // now 200c > 150c cap
    match gov.try_admit(&cost, &k, "", w0_late).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "g"),
        other => panic!(
            "a straddler must be checked against the live cell's derived spend, not a phantom \
             fresh window; got {other:?}"
        ),
    }
}

/// The genuine-new-window roll (`window > c.window_start`, the sibling of the straddle case
/// above): an admission whose window is STRICTLY NEWER than an EXISTING cell's window must reset
/// that cell to a fresh one for the new window, not keep accumulating onto the old window's
/// spend/requests. A mutated match guard that never takes this branch would let a maxed-out
/// bounded-window cell block admission FOREVER, even long after that window ended.
#[test]
fn test_new_window_admission_rolls_the_stale_cell_fresh() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let cost = card_and_group_cost("m", 100.0, &[("g", 150, "day", None)]);
    let mut k = sample_key("vk_roll", "h_r");
    k.group = Some("g".to_string());
    let bucket = "group:g@day";
    let day0 = 3 * crate::governance::SECS_PER_DAY + 100; // well inside day 3
    let day5 = 8 * crate::governance::SECS_PER_DAY + 100; // well inside day 8 — a genuinely new window

    // Exhaust day 0's cap (well past it, to avoid any boundary ambiguity — this test is about
    // window rollover, not the cap comparison's own boundary).
    gov.try_admit(&cost, &k, "", day0).expect("day0 admits");
    gov.record_usage(&cost, &k, "", "m", &tt(20_000), day0); // 100 utok/token x 20_000 / 10_000 = 200c > 150c cap
    match gov.try_admit(&cost, &k, "", day0).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "g"),
        other => panic!("day0 must be at-cap and block; got {other:?}"),
    }

    // A day-5 admission is a genuinely NEW window — it must roll the cell fresh (not stay blocked
    // by day 0's exhausted spend) and the rolled cell's ledger must show ONLY the new charge.
    gov.try_admit(&cost, &k, "", day5)
        .expect("a genuinely new window must not be blocked by a stale window's exhausted cap");
    let after = gov
        .derived_bucket_usage(&cost, bucket, WINDOW_DAY, true, day5)
        .unwrap();
    assert_eq!(
        (after.tokens, after.requests),
        (0, 1),
        "the rolled cell must carry ONLY the new window's charge, not day 0's leftover spend"
    );
}

/// FAIL-CLOSED: a key bound to a group this node's config does not know is NOT admitted
/// (MissingGroup named), and accrual degrades to the key bucket only (tokens never lost).
#[test]
fn test_missing_group_fails_closed() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(1); // no groups configured
    let mut k = sample_key("vk_g", "h_g");
    k.group = Some("ghost".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    assert_eq!(
        gov.try_admit(&cost, &k, "", at).unwrap_err(),
        LimitBlocked::MissingGroup("ghost".to_string()),
        "an unresolvable chain is never admitted (fail closed), naming the missing group"
    );
    // Accrual (post-admission on another node, or a race) still ledgers to the key bucket.
    gov.record_usage(&cost, &k, "", "m", &tt(7), at);
    gov.flush_budgets();
    assert_eq!(ledger_tokens(&store, "vk_g", 0), 7, "tokens are never lost");
}

/// HYDRATION covers GROUP buckets: a group's durable ledger persists a restart (fresh GovState),
/// so chain enforcement resumes from the persisted group accrual, not zero.
#[test]
fn test_hydrate_budgets_restores_group_buckets() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let card = || card_and_group_cost("m", 100.0, &[("team", 25, "total", None)]);
    let mut k = sample_key("vk_h", "h_h");
    k.group = Some("team".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    {
        let gov = GovState::new(store.clone(), None).unwrap();
        // Seed the group's ledger with the cap's worth of tokens: 2500 x 100 micro = 25 cents.
        gov.record_usage(&card(), &k, "", "m", &tt(2_500), at);
        gov.flush_budgets();
    }

    // Restart: a fresh GovState hydrates key AND group cells from the durable ledger.
    let gov2 = GovState::new(store.clone(), None).unwrap();
    gov2.hydrate_budgets(&card(), at).expect("hydrate");
    match gov2.try_admit(&card(), &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(
            group, "team",
            "post-restart enforcement resumes from the PERSISTED group ledger (25c >= 25c cap)"
        ),
        other => panic!("expected the hydrated group budget to block, got {other:?}"),
    }
}

/// BOOT FAIL-OPEN: `hydrate_budgets` must PROPAGATE a store error, not warn-and-reset to empty
/// cells. A store that fails `get_usage` (a boot-time blip) previously left budgets at ZERO, letting
/// a maxed-out key spend its whole cap again. Now the error surfaces (boot fails).
#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_hydrate_budgets_propagates_store_error() {
    use busbar_api::{StoreError, StoreResult, UsageLedger, VirtualKey};

    /// A store that delegates to an inner MemoryStore but FAILS `get_usage` (simulating a boot blip).
    struct FailGetUsage {
        inner: MemoryStore,
    }
    impl Store for FailGetUsage {
        fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
            self.inner.put_key(k)
        }
        fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(&self, _bucket_id: &str, _window: u64) -> StoreResult<UsageLedger> {
            Err(StoreError("simulated store blip on get_usage".into()))
        }
        fn put_usage(&self, b: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
            self.inner.put_usage(b, w, l)
        }
        fn add_metering(&self, d: &busbar_api::MeteringDelta) -> StoreResult<()> {
            self.inner.add_metering(d)
        }
        fn list_metering(&self, bucket: u64) -> StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
    }

    let inner = MemoryStore::new();
    let k = sample_key("vk_m9", "m9_h");
    inner.put_key(&k).unwrap();
    let store: Arc<dyn Store> = Arc::new(FailGetUsage { inner });
    // The key must have a non-empty ledger so hydration actually reaches get_usage.
    store
        .put_usage(
            "vk_m9",
            budget_window(WINDOW_TOTAL, 0),
            &UsageLedger {
                requests: 1,
                billable_requests: 1,
                models: vec![],
            },
        )
        .ok(); // put_usage delegates to inner; ignore if the fault store had returned Err (it doesn't)
    let gov = GovState::new(store, None).unwrap();
    let err = gov
        .hydrate_budgets(&crate::cost::CostModel::flat(1), 0)
        .expect_err(
            "a store get_usage error must PROPAGATE (fail boot), not reset budgets to zero",
        );
    assert!(
        err.to_string().contains("simulated store blip"),
        "the store error must surface verbatim; got: {err}"
    );
}

/// `hydrate_budgets` must trust the persisted `billable_requests` EXACTLY as stored, never
/// re-derive it from `requests`. An earlier version of this function tried to detect a "pre-split
/// legacy row" via `billable_requests == 0 && requests > 0` and re-seeded `billable_requests` from
/// `requests` — a REAL billing bug, since that exact counter shape is ALSO what a bucket looks
/// like when every request in the window was legitimately REFUNDED (`refund_bucket` decrements
/// `billable_requests` but deliberately never touches `requests`, by design). Every restart would
/// silently re-bill correctly-refunded fees. Fixed by moving the one-time legacy backfill into
/// each durable store backend's own versioned `migrate()` (a real schema-version crossing, not a
/// per-boot value guess) and having this function trust the ledger unconditionally from then on.
/// This test proves the FIX: a row shaped exactly like a refunded-to-zero window
/// (`billable_requests: 0, requests: 7`) must hydrate to `billable_requests == 0`, NOT be
/// re-seeded to 7 — the opposite of what the old (buggy) behavior asserted.
#[test]
fn test_hydrate_budgets_trusts_billable_requests_even_when_it_looks_like_a_refunded_window() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let k = sample_key("vk_refunded", "refunded_h");
    store.put_key(&k).unwrap();
    // Shaped exactly like "7 requests admitted, all 7 refunded" (a real, legitimate state) — NOT
    // like a pre-split legacy row, even though the counter values are identical either way.
    store
        .put_usage(
            "vk_refunded",
            budget_window(WINDOW_TOTAL, 0),
            &UsageLedger {
                requests: 7,
                billable_requests: 0,
                models: vec![],
            },
        )
        .unwrap();
    let gov = GovState::new(store, None).unwrap();
    gov.hydrate_budgets(&flat_cost(1), 0).expect("hydrate");
    let cell = gov.budget.read("vk_refunded");
    let cell = cell.get("vk_refunded").expect("hydrated cell exists");
    assert_eq!(
        cell.requests, 7,
        "requests is always trusted verbatim from the ledger"
    );
    assert_eq!(
        cell.billable_requests, 0,
        "billable_requests must be trusted verbatim too - re-deriving it from requests here is \
         exactly the bug this test guards against (it would silently re-bill a refunded window \
         on every restart)"
    );

    // A normal, non-zero billable_requests row is also trusted verbatim, unchanged from before.
    let store2: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let k2 = sample_key("vk_split", "split_h");
    store2.put_key(&k2).unwrap();
    store2
        .put_usage(
            "vk_split",
            budget_window(WINDOW_TOTAL, 0),
            &UsageLedger {
                requests: 7,
                billable_requests: 3,
                models: vec![],
            },
        )
        .unwrap();
    let gov2 = GovState::new(store2, None).unwrap();
    gov2.hydrate_budgets(&flat_cost(1), 0).expect("hydrate");
    let cell2_billable = gov2
        .budget
        .read("vk_split")
        .get("vk_split")
        .expect("hydrated cell exists")
        .billable_requests;
    assert_eq!(
        cell2_billable, 3,
        "a normal partially-billable row must keep its own billable_requests, verbatim"
    );
}

/// The HOOK SEAM projection: `budget_state` reports the key's attribution bucket + every ancestor
/// group's window buckets with derived spend_micros + remaining_micros + each bucket's OWN window,
/// innermost first. The key bucket is uncapped (keys are pure auth) so its remaining is None; the
/// fee counts into EVERY bucket's derived spend (each bucket counts its own requests).
#[test]
fn test_budget_state_projects_the_whole_chain() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = group_cost(
        10,
        &[
            ("acme", 1_000, "month", None),
            ("growth", 500, "month", Some("acme")),
        ],
    );
    let mut k = sample_key("vk_s", "h_s");
    k.group = Some("growth".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    assert!(gov.try_admit(&cost, &k, "", at).is_ok());
    let state = gov.budget_state(&cost, &k, at);
    assert_eq!(state.len(), 3, "key + growth@month + acme@month");
    assert_eq!(state[0].bucket_id, "vk_s");
    assert_eq!(state[0].budget_group, None);
    assert_eq!(
        state[0].spend_micros_at_current_rate,
        10 * 10_000,
        "key bucket: 1 request x 10c fee = 100_000 micros"
    );
    assert_eq!(
        state[0].remaining_micros, None,
        "keys carry no cap: remaining is None"
    );
    assert_eq!(state[0].budget_period, "total");
    assert_eq!(state[1].bucket_id, "group:growth@month");
    assert_eq!(state[1].budget_group.as_deref(), Some("growth"));
    assert_eq!(
        state[1].spend_micros_at_current_rate,
        10 * 10_000,
        "the fee counts into the group bucket's own derived spend too"
    );
    assert_eq!(
        state[1].remaining_micros,
        Some(500 * 10_000 - 10 * 10_000),
        "remaining under growth's 500c cap after one 10c fee"
    );
    assert_eq!(state[1].budget_period, "month");
    assert_eq!(state[2].bucket_id, "group:acme@month");
}

/// Signed-token keys, end to end at the GovState seam: mint -> verify -> revoke/delete/tamper/
/// rotate/expiry. These drive the real `mint_signed`/`verify_token`/`revoke` path over the memory
/// store (with its durable denylist), so the whole stateless-verify + denylist contract is proven.
mod signed_token {
    use crate::governance::signing::{TokenSigner, DEFAULT_KID};
    use crate::governance::{GovState, MemoryStore, NewKeySpec, ScopeRef};
    use std::sync::Arc;

    fn gov() -> Arc<GovState> {
        let store = Arc::new(MemoryStore::new());
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        Arc::new(
            GovState::new_with_signer(store, Some("admintok".into()), Some(signer)).expect("gov"),
        )
    }

    fn spec(name: &str, group: Option<&str>, pools: Option<Vec<&str>>) -> NewKeySpec {
        NewKeySpec {
            name: name.into(),
            allowed_pools: pools.map(|p| p.into_iter().map(str::to_string).collect()),
            group: group.map(str::to_string),
            labels: std::collections::BTreeMap::new(),
            ..Default::default()
        }
    }

    /// THE PLANE BOUNDARY end-to-end through `GovState` (1.6.0 P1): an audience-bound token whose
    /// `sub` is a fully valid, enabled binding is STILL rejected by the data-plane
    /// `verify_token(.., None)` - the boundary is a claims property enforced in the verifier, not
    /// a binding property - while the SAME binding admits on the audience-checked plane, and the
    /// sibling plain token keeps working on the data plane.
    #[test]
    fn audience_bound_token_is_confined_to_its_plane_through_govstate() {
        use crate::governance::signing::TokenVerifier;

        let g = gov();
        let mcp = "https://busbar.example.com/mcp";
        let (binding, plain) = g
            .mint_signed(spec("agent", None, Some(vec!["fast"])), 2_000, 1_000)
            .expect("mint");

        // Recover the binding generation from the plain token's claims (same signer key as
        // `gov()`), then mint an audience-bound sibling for the SAME sub + generation.
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&plain, 1_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(&binding.id, 2_000, generation.as_deref(), mcp, None);

        // The plain token admits on the data plane; the bound one must not.
        assert!(g.verify_token(&plain, 1_000, None).is_some());
        assert!(
            g.verify_token(&bound, 1_000, None).is_none(),
            "an audience-bound token must be rejected on the data plane even with a valid binding"
        );
        // The bound token admits exactly on its own plane; the plain one must not.
        assert!(g.verify_token(&bound, 1_000, Some(mcp)).is_some());
        assert!(
            g.verify_token(&plain, 1_000, Some(mcp)).is_none(),
            "a plain data-plane key must be rejected on an audience-checked ingress"
        );
    }

    /// Mint issues a signed token; verify resolves the binding by `sub`; the binding carries the
    /// group + pools and NO inline limits.
    #[test]
    fn mint_then_verify_resolves_the_binding() {
        let g = gov();
        let (binding, token) = g
            .mint_signed(
                spec("bob", Some("growth"), Some(vec!["fast"])),
                2_000,
                1_000,
            )
            .expect("mint");
        assert!(token.starts_with("bbk_"), "token carries the prefix");
        assert!(binding.id.starts_with("vk_"));
        assert_eq!(binding.group.as_deref(), Some("growth"));
        assert_eq!(binding.allowed_scopes, Some(vec![ScopeRef::pool("fast")]));

        let resolved = g.verify_token(&token, 1_500, None).expect("verify");
        assert_eq!(resolved.id, binding.id);
        assert_eq!(resolved.group.as_deref(), Some("growth"));
    }

    /// A key with NO group is authed + unlimited (the binding resolves, group is None).
    #[test]
    fn no_group_key_is_authed_unlimited() {
        let g = gov();
        let (_b, token) = g
            .mint_signed(spec("free", None, None), 2_000, 1_000)
            .expect("mint");
        let resolved = g.verify_token(&token, 1_500, None).expect("verify");
        assert_eq!(resolved.group, None);
        // Omitted allowed_pools carries as None = all pools (intent intact in the binding).
        assert!(resolved.allowed_scopes.is_none());
    }

    /// An EXPIRED token is rejected by verify (stateless).
    #[test]
    fn expired_token_is_rejected() {
        let g = gov();
        let (_b, token) = g
            .mint_signed(spec("bob", None, None), 1_000, 500)
            .expect("mint");
        assert!(
            g.verify_token(&token, 999, None).is_some(),
            "valid before exp"
        );
        assert!(
            g.verify_token(&token, 1_000, None).is_none(),
            "rejected at exp"
        );
        assert!(
            g.verify_token(&token, 5_000, None).is_none(),
            "rejected past exp"
        );
    }

    /// A TAMPERED token fails verify (signature check).
    #[test]
    fn tampered_token_is_rejected() {
        let g = gov();
        let (_b, token) = g
            .mint_signed(spec("bob", None, None), 2_000, 1_000)
            .expect("mint");
        let mut chars: Vec<char> = token.chars().collect();
        // Flip a char in the middle (the payload segment).
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(g.verify_token(&tampered, 1_500, None).is_none());
    }

    /// REVOKE denylists the subject WITHOUT deleting the binding: verify now returns None, the
    /// binding still exists, and `is_revoked` reports true. Idempotent.
    #[test]
    fn revoke_denylists_and_keeps_binding() {
        let g = gov();
        let (binding, token) = g
            .mint_signed(spec("bob", None, None), 2_000, 1_000)
            .expect("mint");
        assert!(g.verify_token(&token, 1_500, None).is_some());
        g.revoke(&binding.id, "test").expect("revoke");
        g.revoke(&binding.id, "again").expect("idempotent");
        assert!(g.is_revoked(&binding.id));
        assert!(
            g.verify_token(&token, 1_500, None).is_none(),
            "a revoked subject's token is rejected"
        );
        // The binding row still exists (revoke keeps history).
        assert!(g.all_keys().unwrap().iter().any(|k| k.id == binding.id));
    }

    /// The denylist is DURABLE: a fresh GovState over the SAME store re-hydrates the revocation, so
    /// a restart keeps a revoked token rejected.
    #[test]
    fn revocation_survives_restart() {
        let store = Arc::new(MemoryStore::new());
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g = Arc::new(
            GovState::new_with_signer(store.clone(), Some("t".into()), Some(signer)).unwrap(),
        );
        let (binding, token) = g
            .mint_signed(spec("bob", None, None), 5_000, 1_000)
            .expect("mint");
        g.revoke(&binding.id, "test").expect("revoke");

        // Restart: new GovState, same store + same signing key.
        let signer2 = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g2 =
            Arc::new(GovState::new_with_signer(store, Some("t".into()), Some(signer2)).unwrap());
        assert!(g2.is_revoked(&binding.id), "denylist re-hydrated at boot");
        assert!(
            g2.verify_token(&token, 1_500, None).is_none(),
            "the revoked token is still rejected after restart"
        );
    }

    /// FLEET / ROTATION: a token minted by node A verifies on node B when both share the signing
    /// key; after B rotates to a DIFFERENT key, A's token fails on B (the signature/kid no longer
    /// matches).
    #[test]
    fn token_verifies_across_shared_key_and_fails_after_rotation() {
        let store_a = Arc::new(MemoryStore::new());
        let key_a = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
        let node_a = Arc::new(
            GovState::new_with_signer(store_a.clone(), Some("t".into()), Some(key_a)).unwrap(),
        );
        let (binding, token) = node_a
            .mint_signed(spec("bob", None, None), 5_000, 1_000)
            .expect("mint");

        // Node B shares the SAME signing key + a store that also has the binding (shared durable
        // store in a real fleet; here we re-put the binding so lookup_by_sub resolves).
        let store_b = Arc::new(MemoryStore::new());
        {
            use busbar_api::Store;
            store_b.put_key(&binding).unwrap();
        }
        let key_b_same = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
        let node_b = Arc::new(
            GovState::new_with_signer(store_b.clone(), Some("t".into()), Some(key_b_same)).unwrap(),
        );
        assert!(
            node_b.verify_token(&token, 1_500, None).is_some(),
            "a token signed by the shared key verifies on another node"
        );

        // Node B ROTATES to a different signing key: the old token no longer verifies.
        let key_b_rotated = TokenSigner::from_secret_bytes(&[2u8; 32], DEFAULT_KID);
        let node_b2 = Arc::new(
            GovState::new_with_signer(store_b, Some("t".into()), Some(key_b_rotated)).unwrap(),
        );
        assert!(
            node_b2.verify_token(&token, 1_500, None).is_none(),
            "after rotation, a token signed by the old key is rejected (revoke-all)"
        );
    }

    /// mint_signed_with_aws issues both a token and an AWS credential for the same subject.
    #[test]
    fn mint_with_aws_issues_token_and_credential() {
        let g = gov();
        let (binding, token, akid, secret) = g
            .mint_signed_with_aws(spec("bob", None, None), 2_000, 1_000)
            .expect("mint+aws");
        assert!(token.starts_with("bbk_"));
        assert!(akid.starts_with("AKIA"));
        assert!(!secret.is_empty());
        // The AWS credential resolves back to the same subject.
        let (resolved_key, _cred) = g.lookup_credential("sigv4", &akid).expect("akid resolves");
        assert_eq!(resolved_key.id, binding.id);
    }

    /// Minting without a signer fails closed (no token can be issued).
    #[test]
    fn mint_without_signer_fails_closed() {
        let store = Arc::new(MemoryStore::new());
        let g = Arc::new(GovState::new(store, Some("t".into())).unwrap());
        assert!(!g.signing_enabled());
        let err = g
            .mint_signed(spec("bob", None, None), 2_000, 1_000)
            .unwrap_err();
        assert!(err.0.contains("no signing key"), "got {}", err.0);
    }

    // ── REVOCATION IS AUTHORITATIVE, NOT A BOOT SNAPSHOT ─────────
    //
    // The denylist used to be hydrated ONCE in `GovState::new_with_signer` and thereafter mutated
    // only by a revoke performed by THIS process. Consequences, both live auth bypasses:
    // * a revoke (or a DELETE, which denylists before removing the binding) performed on ANOTHER
    // node of a fleet sharing one durable store never reached this node — the credential kept
    // authenticating for the entire life of the process;
    // * the same for any revocation written out-of-band directly against the store.
    // The fix makes every auth path re-read the store denylist once its copy is older than
    // `REVOCATION_SYNC_TTL_SECS`. These two cases are the class: (a) local revoke = zero window,
    // (b) peer revoke = bounded window.

    /// (a) A revoke performed on THIS node is authoritative on the VERY NEXT credential check —
    /// both on the signed-token path (`verify_token`) and on the shared `is_revoked` predicate the
    /// legacy-hash and inbound-SigV4 admit paths consult. No window at all.
    #[test]
    fn local_revoke_rejects_the_very_next_auth_attempt() {
        let g = gov();
        let base = crate::store::now();
        let (binding, token) = g
            .mint_signed(spec("bob", None, None), base + 10_000, base)
            .expect("mint");
        assert!(
            g.verify_token(&token, base + 1, None).is_some(),
            "admitted before the revoke"
        );

        g.revoke(&binding.id, "compromised").expect("revoke");

        assert!(
            g.verify_token(&token, base + 1, None).is_none(),
            "the very next signed-token check after a local revoke must reject — no window"
        );
        assert!(
            g.is_revoked_at(&binding.id, base + 1),
            "the predicate the legacy-hash and SigV4 admit paths consult must agree immediately"
        );
    }

    /// (b) A revoke written DIRECTLY to the shared store by a "peer" node (this node's in-memory set
    /// is never told) is honoured here within `REVOCATION_SYNC_TTL_SECS` — the documented staleness
    /// window — instead of never. Without the check-time re-sync, the final assertion below would
    /// admit forever.
    #[test]
    fn peer_revoke_written_to_the_store_is_honoured_within_the_window() {
        use crate::governance::{Store, REVOCATION_SYNC_TTL_SECS};
        let store = Arc::new(MemoryStore::new());
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g = Arc::new(
            GovState::new_with_signer(store.clone(), Some("t".into()), Some(signer)).unwrap(),
        );
        let base = crate::store::now();
        let (binding, token) = g
            .mint_signed(spec("bob", None, None), base + 10_000, base)
            .expect("mint");
        assert!(
            g.verify_token(&token, base, None).is_some(),
            "admitted at mint"
        );

        // THE PEER: another node revokes the subject. The write lands in the SHARED store only —
        // nothing touches this process's in-memory denylist.
        store
            .add_denylist(&binding.id, "revoked by a peer node")
            .expect("peer revoke persists");

        // Inside the window this node may still admit — that is the documented, bounded exposure.
        // (Asserted as a fact about the contract, not as a desirable property.)
        assert!(
            g.verify_token(&token, base, None).is_some(),
            "inside the staleness window the cached set still governs (documented)"
        );

        // Past the window the next credential check re-reads the store and rejects — on BOTH the
        // signed-token path and the `is_revoked` predicate.
        let past = base + REVOCATION_SYNC_TTL_SECS + 2;
        assert!(
            g.verify_token(&token, past, None).is_none(),
            "a peer's revoke must be honoured within REVOCATION_SYNC_TTL_SECS ({REVOCATION_SYNC_TTL_SECS}s)"
        );
        assert!(
            g.is_revoked_at(&binding.id, past),
            "the SigV4/legacy-hash admit predicate re-syncs on the same window"
        );
    }

    // ── ROTATION ACTUALLY ROTATES ─────────────────────────────────────────
    //
    // Rotation stamps a fresh binding GENERATION (durable, so every node agrees) and re-mints the
    // token against it. 1.5.0 has exactly one bearer-credential shape (a signed token), so rotation
    // has exactly one outcome — the legacy hashed-secret rotation arm this section used to also
    // cover was removed along with the legacy verify path itself (see `docs/migration-1.5.md`:
    // "1.4.x keys no longer authenticate").

    /// The PRE-ROTATION token is rejected immediately after rotate; the re-minted one is accepted;
    /// the id (and with it the ledger bucket / usage history) is unchanged.
    #[test]
    fn rotate_invalidates_the_outstanding_signed_token() {
        let g = gov();
        let (binding, old_token) = g
            .mint_signed(spec("bob", Some("growth"), None), 9_000, 1_000)
            .expect("mint");
        assert!(
            g.verify_token(&old_token, 1_500, None).is_some(),
            "valid at mint"
        );

        let rotated = g
            .rotate_key(&binding.id, 9_000)
            .expect("rotate")
            .expect("known id");
        let crate::governance::RotatedCredential { key, token, .. } = rotated;

        assert_eq!(
            key.id, binding.id,
            "the subject id is stable across rotation"
        );
        assert_eq!(
            key.group.as_deref(),
            Some("growth"),
            "policy carries over untouched"
        );
        assert!(
            g.verify_token(&old_token, 1_500, None).is_none(),
            "the PRE-ROTATION token must be rejected immediately after rotate"
        );
        assert!(
            g.verify_token(&token, 1_500, None).is_some(),
            "the re-minted token authenticates"
        );
    }
}

/// Deleting a key reclaims its budget cell. The cell is attribution-only (the key bucket carries no
/// caps), so dropping it cannot reset an enforcement limit — a group's cap lives in its own
/// `group:` cell and is untouched.
#[test]
fn delete_key_drops_its_budget_cell() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let cost = flat_cost(7);
    let key = sample_key("vk_doomed", "hs-doomed");
    gov.store.put_key(&key).expect("put");
    gov.refresh().expect("refresh");

    gov.record_usage(&cost, &key, "prod", "m", &tt(10), 1_700_000_000);
    assert!(
        gov.budget.read(&key.id).contains_key(&key.id),
        "precondition: use accrues an attribution cell"
    );

    gov.delete_key(&key.id).expect("delete");
    assert!(
        !gov.budget.read(&key.id).contains_key(&key.id),
        "the deleted key's budget cell is reclaimed, not retained for the process lifetime"
    );
}

/// Two bucket kinds live in the all-time window and so never aged out: a key's own attribution
/// bucket, and a synthesized SSO principal's. A deleted key can leave its cell behind (a request
/// admitted in the gap between the store delete and the in-memory removal re-inserts it), and a
/// synthesized principal is never written to the store at all, so nothing can ever name it for
/// removal. Both leaked for the process lifetime, one cell per distinct IdP subject.
///
/// Eviction is safe for these and only these: `cost::chain_for` pins a key bucket's caps to `None`,
/// so it enforces nothing, and the flush is additive against baselines the cell already wrote — a
/// re-created cell contributes only new accrual. A `group:` bucket in the same window is the
/// opposite: it holds an enforced cap, and hydrate is boot-only, so resetting it is cap evasion.
#[test]
fn test_budget_sweep_evicts_idle_attribution_cells_but_never_group_caps() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    let idle_for = 40 * SECS_PER_DAY;

    let survivor = sample_key("survivor", "hs");

    let all_time = |requests: u64, dirty: bool, last_touch: u64| BudgetCell {
        window_start: 0,
        requests,
        billable_requests: requests,
        flushed_requests: requests,
        flushed_billable_requests: requests,
        models: Vec::new(),
        dirty,
        last_touch,
    };

    {
        let mut map = gov.budget.write("survivor");
        // A deleted key's orphaned attribution cell, and a synthesized principal's: both idle, both
        // fully flushed. Nothing will ever name either again.
        map.insert(
            "vk_deleted".to_string(),
            all_time(17, false, now - idle_for),
        );
        map.insert(
            "user:alice@example.com".to_string(),
            all_time(3, false, now - idle_for),
        );
        // An equally idle GROUP cell holding enforced spend — must survive. `acme` is CONFIGURED in
        // `cost` below with an all-time budget cap: the exemption is "this cell still backs an
        // enforced cap", so the fixture has to actually declare the cap it claims to be protecting
        // (see `test_budget_sweep_only_exempts_group_cells_that_still_enforce_a_cap` for the
        // deleted/uncapped groups the exemption deliberately no longer covers).
        map.insert(
            "group:acme@total".to_string(),
            all_time(4999, false, now - idle_for),
        );
        // An idle-but-DIRTY attribution cell: its delta has not reached the store, so evicting it
        // would silently drop spend.
        map.insert(
            "vk_unflushed".to_string(),
            all_time(9, true, now - idle_for),
        );
    }

    gov.budget.sweep_ticker_for("survivor").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    let cost = crate::cost::CostModel::resolve_parts(
        None,
        1,
        &std::collections::BTreeMap::from([(
            "acme".to_string(),
            budget_group_cfg(5000, "total", None),
        )]),
    );
    assert!(gov.try_admit(&cost, &survivor, "", now).is_ok());

    let map = gov.budget.read("survivor");
    assert!(
        !map.contains_key("vk_deleted"),
        "an idle, fully-flushed key attribution cell must not be retained forever"
    );
    assert!(
        !map.contains_key("user:alice@example.com"),
        "a synthesized principal's cell has no other removal path and must age out"
    );
    assert_eq!(
        map.get("group:acme@total").map(|c| c.requests),
        Some(4999),
        "an enforced group cap must never be reset by the sweep"
    );
    assert_eq!(
        map.get("vk_unflushed").map(|c| c.requests),
        Some(9),
        "an unflushed cell must be retained until its delta lands"
    );
    assert!(
        map.contains_key("survivor"),
        "the cell just charged is not idle"
    );
}

/// Hydrated cells must carry a `last_touch`, or every restored key's history is discarded by the
/// first post-boot sweep — before that key has served a single request.
#[test]
fn test_hydrated_cells_survive_the_first_sweep() {
    let store = Arc::new(MemoryStore::new());
    let restored = sample_key("restored", "hr");
    store.put_key(&restored).unwrap();
    store
        .add_usage(
            "restored",
            0,
            &busbar_api::UsageDelta {
                requests: 42,
                billable_requests: 42,
                models: Vec::new(),
            },
        )
        .unwrap();

    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    gov.hydrate_budgets(&flat_cost(1), now).unwrap();
    assert_eq!(
        gov.budget
            .read("restored")
            .get("restored")
            .map(|c| c.requests),
        Some(42),
        "hydrate seeds the cell"
    );

    let driver = sample_key("restored", "hr");
    gov.budget.sweep_ticker_for("restored").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(gov.try_admit(&flat_cost(1), &driver, "", now).is_ok());

    assert_eq!(
        gov.budget
            .read("restored")
            .get("restored")
            .map(|c| c.requests),
        Some(43),
        "a hydrated cell must not be swept away before it is first used"
    );
}

/// A `Store` wrapper that instruments `add_metering` (concurrent-entry high-water mark, and an
/// optional scripted failure count) and delegates everything else to a `MemoryStore`. Shape copied
/// from `revocation.rs`'s private `HungDenylistStore` (an `AtomicUsize` counter + delegate-to-
/// `MemoryStore`), which is not reusable here because it instruments `list_denylist`, not
/// `add_metering`, and is private to `revocation.rs`'s own test module.
mod metering_fanout {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize};

    struct CountingStore {
        inner: MemoryStore,
        /// Sampled INSIDE `add_metering`, not derived from task counts — a mark taken outside the
        /// call would measure scheduling, not concurrency.
        in_flight: AtomicUsize,
        high_water: AtomicUsize,
        total_calls: AtomicUsize,
        /// Positive: fail this many times before delegating. Decremented via `fetch_sub`
        /// clamped at 0 by `saturating_sub`-style checked arithmetic.
        fail_n_times: AtomicI64,
    }

    impl CountingStore {
        fn new(fail_n_times: i64) -> Self {
            Self {
                inner: MemoryStore::new(),
                in_flight: AtomicUsize::new(0),
                high_water: AtomicUsize::new(0),
                total_calls: AtomicUsize::new(0),
                fail_n_times: AtomicI64::new(fail_n_times),
            }
        }
    }

    impl Store for CountingStore {
        fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
            self.inner.put_key(k)
        }
        fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(&self, id: &str, w: u64) -> StoreResult<UsageLedger> {
            self.inner.get_usage(id, w)
        }
        fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
            self.inner.put_usage(id, w, l)
        }
        fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
            self.total_calls.fetch_add(1, Ordering::SeqCst);
            let now_in = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.high_water.fetch_max(now_in, Ordering::SeqCst);
            // A trivial amount of real work so overlapping calls (if the SUT ever produced any)
            // have a chance to actually overlap in wall-clock time rather than the mark being an
            // artifact of two atomics executing back-to-back.
            std::thread::sleep(std::time::Duration::from_millis(2));
            let result = loop {
                let cur = self.fail_n_times.load(Ordering::SeqCst);
                if cur <= 0 {
                    break self.inner.add_metering(d);
                }
                if self
                    .fail_n_times
                    .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    break Err(StoreError("scripted failure".into()));
                }
            };
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            result
        }
        fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
            self.inner.list_metering(bucket)
        }
    }

    /// The metering write fan-out is bounded at 1, not N: with N responses metered concurrently on
    /// a live runtime, `add_metering` never sees more than one call in flight, and all N are
    /// eventually accounted once flushed.
    ///
    /// Under the previous `offload_store_write` per-response fire-and-forget `spawn_blocking`, N
    /// concurrent responses each spawned their OWN blocking task calling the store directly, so the
    /// high-water mark reached up to N. The accumulate-then-drain flusher replaces that fan-out, so
    /// exactly one thread ever calls `add_metering` at a time (the `flush_metering` loop is
    /// sequential).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn metering_write_fanout_is_bounded_at_one() {
        let store = std::sync::Arc::new(CountingStore::new(0));
        let gov = std::sync::Arc::new(GovState::new(store.clone(), None).unwrap());
        let now = 1_700_100_000u64;
        let n = 8usize;
        let mut handles = Vec::new();
        for i in 0..n {
            let gov = gov.clone();
            handles.push(tokio::spawn(async move {
                let usage = crate::billing::TokenUsage {
                    input: 1,
                    output: 1,
                    ..Default::default()
                };
                gov.record_metering(&format!("vk_{i}"), "m", "p", Some(&usage), now);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let flushed = gov.flush_metering();
        assert_eq!(
            flushed, n,
            "every distinct key's delta was written on the one flush"
        );
        assert!(
            store.high_water.load(Ordering::SeqCst) <= 1,
            "add_metering must never see more than one call in flight (observed {})",
            store.high_water.load(Ordering::SeqCst)
        );
        assert_eq!(
            store.total_calls.load(Ordering::SeqCst),
            n,
            "one add_metering call per distinct key, all eventually accounted"
        );
    }

    /// A store error re-queues the entry and neither loses it nor double-counts it. Assert on
    /// the STORE TOTAL (the discriminator that actually separates re-queue from double-send —
    /// "the entry exists" does not discriminate: a drain-with-no-add-back makes
    /// the delta vanish, and a re-queue-without-clearing double-sends. Only a total-count assertion
    /// across two flushes catches both).
    #[test]
    fn a_store_error_requeues_without_double_counting() {
        let store = std::sync::Arc::new(CountingStore::new(1)); // fail exactly once
        let gov = GovState::new(store.clone(), None).unwrap();
        let now = 1_700_200_000u64;
        let usage = crate::billing::TokenUsage {
            input: 10,
            output: 5,
            ..Default::default()
        };
        gov.record_metering("vk_err", "m", "p", Some(&usage), now);

        // Flush 1: the scripted failure fires; the store must be empty and the entry must be back
        // in `pending_metering` (assert via a successful flush 2, not via internal state).
        let n1 = gov.flush_metering();
        assert_eq!(n1, 0, "the failed flush wrote nothing");
        let rows = gov.metering_for(metering_bucket(now)).unwrap();
        assert!(rows.is_empty(), "a failed flush must not partially land");

        // Flush 2: the store now holds the FULL amount exactly once.
        let n2 = gov.flush_metering();
        assert_eq!(n2, 1, "the requeued entry flushes on the next tick");
        let rows = gov.metering_for(metering_bucket(now)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].tokens_input, rows[0].requests),
            (10, 1),
            "the full delta landed exactly once, not zero and not twice"
        );

        // Flush 3: nothing left to write.
        let n3 = gov.flush_metering();
        assert_eq!(
            n3, 0,
            "a third flush writes nothing — the entry is gone, not duplicated"
        );
    }

    /// `flush_metering`'s all-five-counters-zero skip check (`counts.requests == 0 && ... &&
    /// counts.tokens_cache_read == 0 && ...`) is UNREACHABLE via the only real writer,
    /// `record_metering` (it always increments `requests` by at least 1 before an entry can land
    /// in `pending_metering`) — so this isn't exercised by any public-API test above. It is real,
    /// intended defensive behavior, not dead code to delete: reach into the private
    /// `pending_metering` accumulator directly (same crate, `governance::tests` is a descendant
    /// module of `governance`, so this is a normal same-module-tree access, not a visibility hack) to
    /// insert a genuinely all-zero cell and prove it is skipped — never flushed, never a store row —
    /// rather than silently trusting the branch would work if it were ever reached.
    #[test]
    fn flush_metering_skips_a_genuinely_all_zero_entry() {
        let store = Arc::new(MemoryStore::new());
        let gov = GovState::new(store, None).unwrap();
        let now = 1_700_300_000u64;
        let key = (
            "vk_zero".to_string(),
            metering_bucket(now),
            "m".to_string(),
            "p".to_string(),
        );
        // `accrue` with an all-zero delta inserts a genuinely all-zero cell (key absent, under cap).
        gov.pending_metering.accrue(key, MeterCounts::default());

        let flushed = gov.flush_metering();
        assert_eq!(flushed, 0, "an all-zero entry must not count as flushed");
        let rows = gov.metering_for(metering_bucket(now)).unwrap();
        assert!(
            rows.is_empty(),
            "an all-zero entry must never become a store row"
        );
    }
}

// ── the self-serve mint offload wrapper + refresh's atomic rollback on a failed tombstone ────────

/// A `Store` that delegates everything to a `MemoryStore` except `delete_key`, which fails
/// EXACTLY ONCE after `arm()` — the next `delete_key` call errors and every call after that
/// delegates normally. One-shot (rather than "fail forever") so a test can arm it right before the
/// call that should fail (the old-binding tombstone) while leaving `refresh_self`'s OWN rollback
/// delete (of the just-written new binding) free to actually succeed against the store.
struct FailDeleteStore {
    inner: MemoryStore,
    fail_next_delete: std::sync::atomic::AtomicBool,
}

impl FailDeleteStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_next_delete: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn arm(&self) {
        self.fail_next_delete.store(true, Ordering::SeqCst);
    }
}

impl Store for FailDeleteStore {
    fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(k)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        if self
            .fail_next_delete
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(StoreError("store down: delete_key".into()));
        }
        self.inner.delete_key(id)
    }
    fn get_usage(&self, id: &str, w: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

fn self_serve_signer() -> crate::governance::signing::TokenSigner {
    crate::governance::signing::TokenSigner::from_secret_bytes(
        &[3u8; 32],
        crate::governance::signing::DEFAULT_KID,
    )
}

/// The ENABLED (live) self-serve `user:<sub>` binding among `all_keys()`, if any. `delete_key`
/// TOMBSTONES rather than removes a row (see `MemoryStore::delete_key`), so a subject can have
/// both a disabled/tombstoned row and a live one in the store at once — this mirrors
/// `current_self_binding`'s own `enabled && deleted_at.is_none()` filter so the test asserts on
/// the same "sole enabled binding" invariant the production code enforces.
fn self_binding_for(gov: &GovState, user_sub: &str) -> Option<VirtualKey> {
    let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
    gov.all_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str()))
}

/// `refresh_self` used to write+enable the NEW binding, THEN tombstone the old one; when the
/// tombstone (`store.delete_key`) failed, the fn returned `Err` but the new binding was already
/// live AND the old was never disabled — two valid tokens for one subject. Now, on a failed
/// tombstone, `refresh_self` rolls the new binding back before returning `Err`, so
/// exactly the OLD binding remains enabled (the caller's existing token keeps working and it can
/// retry the refresh).
#[test]
fn refresh_self_rolls_back_the_new_binding_when_the_old_tombstone_fails() {
    let store = Arc::new(FailDeleteStore::new());
    let gov = GovState::new_with_signer(store.clone(), None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:alice";
    let now = 1_700_000_000u64;

    // First issue: mints the one binding at epoch 0.
    let (first_binding, first_token) = gov.issue_self(sub, None, now + 3600, now).unwrap();
    assert!(gov.verify_token(&first_token, now, None).is_some());

    // Arm the failure: the NEXT `delete_key` call errors — that is `refresh_self`'s attempt to
    // tombstone the epoch-0 binding (it writes the new epoch-1 binding first, successfully, then
    // hits this). The one-shot arming means `refresh_self`'s OWN rollback delete (of the new
    // binding it just wrote) runs against a store that is healthy again, so the rollback itself
    // succeeds here — exercising the "rollback succeeded" arm, not the double-failure arm.
    store.arm();
    let err = gov
        .refresh_self(sub, None, now + 3600, now)
        .expect_err("a failed tombstone must surface as an Err, not a silent partial success");
    let msg = err.to_string();
    assert!(
        msg.contains("rolled back"),
        "the error must say the new binding was rolled back: {msg}"
    );

    // Exactly ONE self-serve binding is ENABLED for the subject, and it is the ORIGINAL one — the
    // new binding written before the failed tombstone must have been rolled back (tombstoned), not
    // left enabled alongside the old one.
    let enabled: Vec<VirtualKey> = gov
        .all_keys()
        .unwrap()
        .into_iter()
        .filter(|k| {
            k.enabled
                && k.deleted_at.is_none()
                && k.group.as_deref() == Some(format!("{SELF_KEY_GROUP_PREFIX}{sub}").as_str())
        })
        .collect();
    assert_eq!(
        enabled.len(),
        1,
        "the failed refresh must leave exactly one ENABLED binding for the subject: {enabled:?}"
    );
    let surviving = self_binding_for(&gov, sub).expect("the original binding still exists");
    assert_eq!(
        surviving.id, first_binding.id,
        "the surviving binding must be the ORIGINAL one, not a stranded new one"
    );
    assert!(
        surviving.enabled,
        "the original binding must still be enabled"
    );

    // The client's ORIGINAL token still verifies (it kept working through the failed refresh).
    assert!(
        gov.verify_token(&first_token, now, None).is_some(),
        "the prior token must remain valid after a rolled-back refresh"
    );
}

/// A self-serve (PERSONAL) key records the IdP subject for ATTRIBUTION and stamps the user-bound
/// binding mode (1.6.0) — the honest, buildable half of "user-bound". These are pure attribution
/// metadata: `verify_token` still succeeds exactly as before (they are not an enforcement input),
/// and a refresh carries the same attribution onto the rotated binding.
#[test]
fn self_serve_key_records_idp_subject_and_user_bound_mode() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:carol";
    let now = 1_700_000_000u64;

    let (binding, token) = gov.issue_self(sub, None, now + 3600, now).unwrap();
    assert_eq!(
        binding.idp_subject.as_deref(),
        Some(sub),
        "the personal key records the IdP subject for attribution"
    );
    assert_eq!(binding.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(
        binding.minted_by, None,
        "a self-minted personal token has no separate minter provenance"
    );
    // Attribution is metadata only: the token still verifies exactly as before.
    assert!(gov.verify_token(&token, now, None).is_some());

    // A refresh carries the same attribution onto the rotated binding.
    let (rotated, _t) = gov.refresh_self(sub, None, now + 3600, now).unwrap();
    assert_eq!(rotated.idp_subject.as_deref(), Some(sub));
    assert_eq!(rotated.binding_mode.as_deref(), Some("user-bound"));
}

/// The mirror-image happy path stays intact: a SUCCESSFUL refresh still tombstones the old
/// binding (the prior token stops verifying) and only the new one remains.
#[test]
fn refresh_self_tombstones_the_old_binding_on_success() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:bob";
    let now = 1_700_000_000u64;

    let (_first_binding, first_token) = gov.issue_self(sub, None, now + 3600, now).unwrap();
    let (second_binding, second_token) = gov.refresh_self(sub, None, now + 3600, now).unwrap();

    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "the prior token must stop verifying after a successful refresh"
    );
    assert!(gov.verify_token(&second_token, now, None).is_some());
    let surviving = self_binding_for(&gov, sub).expect("the new binding exists");
    assert_eq!(surviving.id, second_binding.id);
}

/// A `Store` that delegates everything to a `MemoryStore` except `list_keys`, which fails EXACTLY
/// ONCE right after a `delete_key` call succeeds (`delete_key` arms it; the very next `list_keys`
/// errors, then it's disarmed). Models a `refresh()` cache-reconcile round-trip failing
/// specifically AFTER the store-level tombstone already landed, while leaving the FIRST
/// `refresh()` inside `write_self_binding` (before the delete) unaffected.
struct FailListKeysAfterDeleteStore {
    inner: MemoryStore,
    fail_next_list_keys: std::sync::atomic::AtomicBool,
}

impl FailListKeysAfterDeleteStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_next_list_keys: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Store for FailListKeysAfterDeleteStore {
    fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(k)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        if self
            .fail_next_list_keys
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(StoreError("store down: list_keys".into()));
        }
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        let r = self.inner.delete_key(id);
        if r.is_ok() {
            // Arm: the tombstone landed in the store — the very next cache-reconcile `refresh()`
            // (which calls `list_keys` first) is what should now fail.
            self.fail_next_list_keys.store(true, Ordering::SeqCst);
        }
        r
    }
    fn get_usage(&self, id: &str, w: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// `refresh_self` used to tombstone the old binding in the STORE, then call `self.refresh()?` to
/// reconcile the cache — a bare `?`. If THAT refresh failed (e.g. a transient store round-trip
/// error), the fn returned `Err` while the cache still held BOTH the old binding (still `enabled`
/// from the refresh done earlier inside `write_self_binding`, before the delete) and the new one,
/// so the OLD token kept verifying even though the store had already tombstoned it. Now, on that
/// specific refresh failure, `refresh_self` surgically evicts the old id straight from the cache
/// (no store round-trip needed) before returning `Err`, so the old token stops verifying
/// immediately regardless of whether the full refresh ever succeeds.
#[test]
fn refresh_self_evicts_old_binding_from_cache_when_post_delete_refresh_fails() {
    let store = Arc::new(FailListKeysAfterDeleteStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:carol";
    let now = 1_700_000_000u64;

    let (_first_binding, first_token) = gov.issue_self(sub, None, now + 3600, now).unwrap();
    assert!(gov.verify_token(&first_token, now, None).is_some());

    // The tombstone succeeds (store-level), but the subsequent cache-reconcile `refresh()` fails.
    let err = gov
        .refresh_self(sub, None, now + 3600, now)
        .expect_err("a failed post-delete cache refresh must surface as an Err");
    let msg = err.to_string();
    assert!(
        msg.contains("evicted") || msg.contains("cache"),
        "the error must describe the cache-reconcile failure and the eviction fallback: {msg}"
    );

    // THE FIX: even though the full refresh failed, the surgical eviction means the OLD token no
    // longer verifies — the exact hazard this fix closes.
    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "the prior token must stop verifying even when the post-delete cache refresh fails"
    );
}

/// Structural: request-path callers must go through `mint_self_offloaded` (the blocking-pool
/// door), never call `issue_self`/`refresh_self` directly on the reactor. This proves the wrapper
/// exists, actually runs the mint (`spawn_blocking` + `.await`), and returns the SAME outcome the
/// sync fn would — i.e. it is a transparent async front door, not a behavior change.
#[tokio::test]
async fn mint_self_offloaded_issues_and_refreshes_through_the_blocking_pool() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap());
    let sub = "oidc:offloaded";
    let now = 1_700_000_000u64;

    let (issued, issued_token) = crate::governance::mint_self_offloaded(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        sub.to_string(),
        None,
        now + 3600,
        now,
    )
    .await
    .expect("issue via the offloaded wrapper succeeds");
    assert!(gov.verify_token(&issued_token, now, None).is_some());
    assert_eq!(
        issued.group.as_deref(),
        Some(format!("user:{sub}").as_str())
    );

    let (refreshed, refreshed_token) = crate::governance::mint_self_offloaded(
        gov.clone(),
        crate::governance::SelfMintOp::Refresh,
        sub.to_string(),
        None,
        now + 7200,
        now,
    )
    .await
    .expect("refresh via the offloaded wrapper succeeds");
    assert_ne!(
        issued.id, refreshed.id,
        "refresh rotates to a new binding id"
    );
    assert!(
        gov.verify_token(&issued_token, now, None).is_none(),
        "the offloaded refresh still tombstones the prior token"
    );
    assert!(gov.verify_token(&refreshed_token, now, None).is_some());
}

/// A `Store` that delegates everything to a `MemoryStore` except `put_key`, which PANICS. Used
/// ONLY to drive a real panic inside `mint_self_offloaded`'s `spawn_blocking` closure (via
/// `issue_self` -> `write_self_binding` -> `store.put_key`), so the JoinError-mapping test below
/// exercises the actual join-failure path rather than a synthetic one.
struct PanicOnPutKeyStore {
    inner: MemoryStore,
}

impl Store for PanicOnPutKeyStore {
    fn put_key(&self, _k: &VirtualKey) -> StoreResult<()> {
        panic!("intentional panic inside put_key, for the JoinError-mapping test");
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, id: &str, w: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(id, w)
    }
    fn put_usage(&self, id: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
        self.inner.put_usage(id, w, l)
    }
    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// `mint_self_offloaded` maps a `JoinError` (the `spawn_blocking` task PANICKED) to a
/// `StoreError`, per its `.unwrap_or_else` fallback, rather than propagating the panic across the
/// `.await` and crashing the calling task. Drive an actual panic inside the offloaded closure (via
/// a `Store::put_key` that panics) and assert the `.await` resolves to a plain `Err`, not a panic.
#[tokio::test]
async fn mint_self_offloaded_maps_a_join_panic_to_a_store_error() {
    let store = Arc::new(PanicOnPutKeyStore {
        inner: MemoryStore::new(),
    });
    let gov = Arc::new(GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap());
    let sub = "oidc:panics";
    let now = 1_700_000_000u64;

    let result = crate::governance::mint_self_offloaded(
        gov,
        crate::governance::SelfMintOp::Issue,
        sub.to_string(),
        None,
        now + 3600,
        now,
    )
    .await;

    let err = result.expect_err(
        "a panic inside the spawn_blocking closure must surface as an Err, never propagate",
    );
    assert!(
        err.to_string().contains("join"),
        "the mapped error should describe the join failure: {err}"
    );
}

/// A `Store` decorator whose `list_keys` can be ARMED to fail — the transient store blip that makes
/// `GovState::refresh` (a `list_keys` + `list_credentials_since` round-trip) return `Err` while
/// every DURABLE write beneath it has already committed. Everything else delegates to a real
/// `MemoryStore`, so `delete_key`/`put_key`/`get_key` behave exactly as in production.
struct RefreshBlipStore {
    inner: MemoryStore,
    fail_list: std::sync::atomic::AtomicBool,
}

impl RefreshBlipStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_list: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn arm(&self) {
        self.fail_list
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Store for RefreshBlipStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        if self.fail_list.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError("transient store blip".to_string()));
        }
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, since: u64) -> StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(since)
    }
}

/// REVOCATION HONESTY: `delete_key` commits a DURABLE tombstone and only then reconciles
/// the in-memory cache. When that reconcile fails the old code returned a bare `Err` — so the
/// operator saw a 500 (reasonable reading: "the revocation did not take") while the cache went on
/// resolving the key, i.e. the revoked credential KEPT WORKING and the operator was told it had not
/// been revoked. Both halves must be fixed: the credential must stop resolving immediately (a
/// targeted single-entry eviction, which needs no store I/O and so cannot fail the way `refresh`
/// can), and the error must say the revocation IS durable rather than implying nothing happened.
#[test]
fn delete_key_with_a_failing_refresh_still_stops_the_credential_and_says_so() {
    let store = Arc::new(RefreshBlipStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "doomed".to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    assert!(
        gov.lookup_by_sub(&key.id).is_some(),
        "the key resolves before revocation"
    );

    store.arm(); // the cache reconcile will now fail; the durable delete still commits
    let err = gov
        .delete_key(&key.id)
        .expect_err("a failing reconcile is still surfaced to the caller");

    // (1) THE SAFETY HALF: the revoked credential must NOT keep resolving.
    assert!(
        gov.lookup_by_sub(&key.id).is_none(),
        "a key whose durable tombstone committed must stop resolving even when the full cache \
         refresh failed — otherwise the revoked credential keeps authenticating"
    );
    // (2) THE HONESTY HALF: the operator must be able to tell "applied, cache degraded" from
    // "nothing happened".
    let msg = err.to_string();
    assert!(
        msg.contains(crate::governance::state::REVOCATION_DURABLE_MARKER),
        "the failure must be flagged as DEGRADED-BUT-APPLIED, not a bare error implying the \
         revocation did not take: {msg}"
    );
    assert!(
        msg.contains("transient store blip"),
        "and must still name the underlying cause: {msg}"
    );
}

/// ROTATION HONESTY — the same shape as the `delete_key` case above. `store.put_key` commits the
/// new `generation_hash` (so the PREVIOUS credential is durably dead) and only then is the cache
/// reconciled. A bare `Err` from that reconcile returned a 500 with no new secret, from which an
/// admin concludes "rotation did not happen" and the OLD credential is still fine — while the stale
/// cache in fact went on resolving that old credential. After the fix the old credential stops
/// resolving immediately and the error says plainly that the rotation IS durable.
#[test]
fn rotate_key_with_a_failing_refresh_kills_the_old_credential_and_says_so() {
    use crate::governance::signing::{TokenSigner, DEFAULT_KID};
    let store = Arc::new(RefreshBlipStore::new());
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = GovState::new_with_signer(store.clone(), None, Some(signer)).unwrap();
    let (binding, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "rotate-me".to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            2_000,
            1_000,
        )
        .expect("mint");
    assert!(
        gov.verify_token(&token, 1_500, None).is_some(),
        "the original token verifies before the rotation"
    );

    store.arm();
    let err = match gov.rotate_key(&binding.id, 3_000) {
        Err(e) => e,
        Ok(_) => panic!("a failing reconcile is still surfaced"),
    };

    // (1) SAFETY: the store already holds the NEW generation, so the old token is durably dead —
    // the cache must not go on honouring it.
    assert!(
        gov.verify_token(&token, 1_500, None).is_none(),
        "the PREVIOUS credential must stop verifying the moment the new generation is committed, \
         even when the cache refresh failed"
    );
    // (2) HONESTY: "rotated, but the new secret could not be returned" is a RE-ROTATE, not a
    // retry-because-nothing-happened.
    let msg = err.to_string();
    assert!(
        msg.contains(crate::governance::state::ROTATION_DURABLE_MARKER),
        "the failure must say the rotation IS durable: {msg}"
    );
    assert!(
        msg.contains("transient store blip"),
        "and must still name the underlying cause: {msg}"
    );
}

/// The amortized sweep's `group:` exemption is only as wide as its own stated rationale — "the
/// cell holds an ENFORCED cap whose spend must not reset".
///
/// It used to be the blanket `id.starts_with("group:")`, with no age check and no existence check.
/// That pinned, for the life of the process, the all-time cells of groups that had been DELETED and
/// of auto-provisioned groups that never carried a cap at all — neither of which enforces anything.
/// With SSO auto-provisioning (`max_auto_provisioned_groups` defaults to 0 = UNLIMITED) every
/// subject ever seen leaves one behind at offboarding, and `groups_registry.len()` stays flat so no
/// admin read reveals the growth: a monotonic leak on a ~5 MB-RSS product.
#[test]
fn test_budget_sweep_only_exempts_group_cells_that_still_enforce_a_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    let max_window = 31 * SECS_PER_DAY;
    let survivor = sample_key("survivor3", "hs3");

    // A live cost model: `capped` carries an all-time budget cap; `uncapped` is the shape SSO
    // auto-provisioning leaves behind (a real group, no limits of its own).
    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([
            ("capped".to_string(), budget_group_cfg(5000, "total", None)),
            ("uncapped".to_string(), crate::config::GroupCfg::default()),
        ]);
    let cost = crate::cost::CostModel::resolve_parts(None, 1, &groups);

    // Every seeded cell is an all-time (`window_start == 0`) cell, long idle and CLEAN — so the only
    // thing that can keep it alive is the `group:` exemption.
    let idle = || BudgetCell {
        window_start: 0,
        requests: 7,
        billable_requests: 7,
        flushed_requests: 7,
        flushed_billable_requests: 7,
        models: Vec::new(),
        dirty: false,
        last_touch: now - max_window - 1,
    };
    {
        let mut map = gov.budget.write("survivor3");
        map.insert("group:capped@total".to_string(), idle());
        map.insert("group:gone@total".to_string(), idle());
        map.insert("group:uncapped@total".to_string(), idle());
        // Same deleted group, but with an unflushed delta: `dirty` still protects it (the write-behind
        // flush has not carried its spend yet).
        map.insert("group:gone@month".to_string(), {
            let mut c = idle();
            c.window_start = 0;
            c.dirty = true;
            c
        });
    }

    gov.budget.sweep_ticker_for("survivor3").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&cost, &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor3");
    assert!(
        map.contains_key("group:capped@total"),
        "a cell that STILL backs an enforced cap must never be aged out — its spend must not reset"
    );
    assert!(
        !map.contains_key("group:gone@total"),
        "a DELETED group's cell enforces nothing; pinning it forever is a pure leak"
    );
    assert!(
        !map.contains_key("group:uncapped@total"),
        "an auto-provisioned group with NO cap enforces nothing either — same leak, one per subject"
    );
    assert!(
        map.contains_key("group:gone@month"),
        "a still-DIRTY cell is protected by the dirty check regardless of its group"
    );
}

/// Deleting a group RECLAIMS its in-memory budget cells — the group-shaped twin of the
/// reclamation `delete_key` has always done for a key's cell. Without it, nothing ever dropped them:
/// the sweep exempts cells that back an enforced cap, and a deleted group's cells simply stopped
/// being anything's business.
#[test]
fn test_reclaim_group_cells_drops_every_window_and_scope_of_that_group() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    let cell = BudgetCell {
        window_start: 0,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 1,
        flushed_billable_requests: 1,
        models: Vec::new(),
        dirty: false,
        last_touch: now,
    };
    // A group's cells are `group:<name>@<window>[#<scope>]` — one per (window, pool scope), spread
    // across shards by id, so reclamation is a prefix sweep over ALL shards, not one remove.
    for id in [
        "group:doomed@total",
        "group:doomed@month",
        "group:doomed@day#pool:frontier",
    ] {
        gov.budget.write(id).insert(id.to_string(), cell.clone());
    }
    // Neighbours that must NOT be collateral: a different group, and one whose name merely PREFIXES
    // the deleted one (the `@` in the prefix is what keeps `doomed-2` safe).
    for id in ["group:keeper@total", "group:doomed-2@total"] {
        gov.budget.write(id).insert(id.to_string(), cell.clone());
    }

    assert_eq!(
        gov.reclaim_group_cells("doomed"),
        3,
        "every window/scope cell of the deleted group is reclaimed"
    );
    for id in [
        "group:doomed@total",
        "group:doomed@month",
        "group:doomed@day#pool:frontier",
    ] {
        assert!(!gov.budget.read(id).contains_key(id), "{id} must be gone");
    }
    for id in ["group:keeper@total", "group:doomed-2@total"] {
        assert!(
            gov.budget.read(id).contains_key(id),
            "{id} must be untouched — a name-prefix neighbour is not the same group"
        );
    }
    assert_eq!(
        gov.reclaim_group_cells("doomed"),
        0,
        "idempotent: a second reclamation of the same group drops nothing"
    );
}

/// Deleting a capped group also reclaims its per-group in-flight `concurrent` gauge, not only its
/// budget cells. The gauge is materialised on the first admission of a `concurrent`-capped group and
/// used to be swept by NOTHING — a server that churns capped groups (SSO-template / operator-managed
/// groups, each admitting at least one request) grew that map by one entry per group forever. This
/// admits through, and deletes, many distinct capped groups and asserts the gauge map ends bounded
/// (every deleted group's entry gone), the group-shaped twin of the budget-cell reclamation above.
#[test]
fn test_reclaim_group_cells_drops_the_per_group_concurrent_gauge() {
    use crate::config::groups::{LimitCfg, LimitMetric};
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;

    let concurrent_group = || crate::config::GroupCfg {
        enabled: true,
        limits: vec![LimitCfg {
            metric: LimitMetric::Concurrent,
            amount: 4,
            per: None,
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
        }],
        ..Default::default()
    };

    const N: usize = 50;
    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> = (0..N)
        .map(|i| (format!("churny-{i}"), concurrent_group()))
        .collect();
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &groups);

    // Admit one request through each capped group — this is what materialises the gauge — then drop
    // the grant so nothing is left in flight. The gauge ENTRY survives the drop (only the count
    // returns to zero), which is exactly the residue that used to leak.
    for i in 0..N {
        let mut key = sample_key(&format!("k-{i}"), &format!("h-{i}"));
        key.group = Some(format!("churny-{i}"));
        let grant = gov
            .try_admit(&cost, &key, "", now)
            .expect("a capped group with an unused gauge admits");
        assert_eq!(grant.held(), 1, "one concurrent hold was taken");
        drop(grant);
    }

    assert_eq!(
        gov.concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        N,
        "every admitted capped group materialised exactly one gauge entry"
    );

    // Delete every group. Each reclamation must remove that group's gauge entry.
    for i in 0..N {
        gov.reclaim_group_cells(&format!("churny-{i}"));
    }
    assert!(
        gov.concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "a deleted group's concurrent gauge must be reclaimed — the map is bounded, not monotonic"
    );

    // A re-created group re-materialises a fresh gauge at zero rather than resurrecting a stale count.
    let mut revived = sample_key("k-revived", "h-revived");
    revived.group = Some("churny-0".to_string());
    let grant = gov
        .try_admit(&cost, &revived, "", now)
        .expect("a re-created capped group admits cleanly");
    assert_eq!(
        gov.concurrent_in_flight("churny-0"),
        1,
        "fresh gauge at one"
    );
    drop(grant);
}

/// The sweep's cap exemption must hold for a group whose NAME CONTAINS `@` — the
/// ORDINARY SSO case, not a pathological one. `sanitize_self_sub` permits `@` explicitly, no
/// charset check exists on a group name anywhere (`validate_groups` checks parent-existence /
/// acyclicity / amount > 0; `build_with_group` checks empty + length), and an IdP subject is
/// normally an email — so token exchange auto-provisions `user:alice@corp.com`, whose team's
/// `child_default` stamps an all-time budget on it.
///
/// The earlier exemption took "everything before the FIRST `@`" as the group name, resolved
/// `user:alice`, found nothing, and declared the cell uncapped: it was swept, and because hydrate is
/// boot-only its lifetime spend re-read as 0 — an EXHAUSTED all-time cap admitting again. A BUDGET
/// BYPASS, strictly worse than the leak the check closed. `#` (the scope-suffix delimiter) is
/// covered here too, for the same reason.
#[test]
fn test_sweep_exemption_survives_a_group_name_containing_the_id_delimiters() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    let max_window = 31 * SECS_PER_DAY;
    let survivor = sample_key("survivor-delim", "hs-delim");

    // Two live, all-time-BUDGET-CAPPED groups whose names carry the two characters the bucket id
    // uses as delimiters, plus the `user:alice` whose existence is what made the `@` split look
    // plausible.
    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([
            (
                "user:alice@corp.com".to_string(),
                budget_group_cfg(50000, "total", None),
            ),
            (
                "team#eng".to_string(),
                budget_group_cfg(50000, "total", None),
            ),
            ("user:alice".to_string(), crate::config::GroupCfg::default()),
        ]);
    let cost = crate::cost::CostModel::resolve_parts(None, 1, &groups);

    let idle = || BudgetCell {
        window_start: 0,
        requests: 7,
        billable_requests: 7,
        flushed_requests: 7,
        flushed_billable_requests: 7,
        models: Vec::new(),
        dirty: false,
        last_touch: now - max_window - 1,
    };
    {
        let mut map = gov.budget.write("survivor-delim");
        map.insert("group:user:alice@corp.com@total".to_string(), idle());
        map.insert("group:team#eng@total".to_string(), idle());
    }

    gov.budget.sweep_ticker_for("survivor-delim").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&cost, &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor-delim");
    assert!(
        map.contains_key("group:user:alice@corp.com@total"),
        "an EMAIL-named group's all-time budget cell still backs an enforced cap; sweeping it \
         resets lifetime spend to 0 on the next read (hydrate is boot-only) and an EXHAUSTED cap \
         starts admitting again"
    );
    assert!(
        map.contains_key("group:team#eng@total"),
        "a group name containing the SCOPE delimiter `#` is capped just the same"
    );
}

/// The same false premise, the other way round: `reclaim_group_cells` swept
/// `starts_with("group:<name>@")`, which is only a boundary if no name contains `@`. Deleting
/// `user:alice` therefore also dropped the cell of `user:alice@corp.com` — a DIFFERENT group that is
/// still live and still capped — resetting its spend to 0.
#[test]
fn test_reclaim_group_cells_never_takes_a_longer_name_that_shares_the_at_prefix() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_040u64;
    let cell = BudgetCell {
        window_start: 0,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 1,
        flushed_billable_requests: 1,
        models: Vec::new(),
        dirty: false,
        last_touch: now,
    };
    for id in [
        "group:user:alice@total",
        "group:user:alice@day#pool:frontier",
        "group:user:alice@corp.com@total",
        "group:user:alice@corp.com@day#pool:frontier",
    ] {
        gov.budget.write(id).insert(id.to_string(), cell.clone());
    }

    assert_eq!(
        gov.reclaim_group_cells("user:alice"),
        2,
        "ONLY the deleted group's own cells: `user:alice@corp.com` is a different group"
    );
    for id in [
        "group:user:alice@corp.com@total",
        "group:user:alice@corp.com@day#pool:frontier",
    ] {
        assert!(
            gov.budget.read(id).contains_key(id),
            "{id} belongs to a live, capped group and must survive the deletion of `user:alice`"
        );
    }
    // ...and deleting the email-named group reclaims exactly its own cells, leaving nothing behind.
    assert_eq!(
        gov.reclaim_group_cells("user:alice@corp.com"),
        2,
        "the longer name reclaims its own two cells"
    );
}

/// An admin deletion of a user's self-serve key must SURVIVE that user's next login.
///
/// The self-serve id is derived from `(sub, epoch)`, not random, and `issue_self` only looks for a
/// LIVE binding — so after an admin tombstones the epoch-0 key, the next login finds none, arrives
/// at epoch 0 again, and re-derives the very id that was just deleted. A plain upsert there writes a
/// live row straight over the tombstone: the admin's deletion is undone and every token minted
/// before it is valid again, with nothing reporting it. This is the concrete, reachable instance of
/// the resurrection hazard the `Store::put_key` contract now refuses at the row.
///
/// The correct outcome is not a failed login: it is a NEW binding at a later epoch, leaving the
/// tombstone intact.
#[test]
fn an_admin_deletion_of_a_self_serve_key_survives_the_next_login() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:carol";
    let now = 1_700_000_000u64;

    let (first, first_token) = gov.issue_self(sub, None, now + 3600, now).unwrap();
    assert!(gov.verify_token(&first_token, now, None).is_some());

    // The admin revokes it, exactly as `DELETE /api/v1/admin/keys/{id}` would.
    gov.delete_key(&first.id).unwrap();
    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "precondition: the deleted key's token must stop verifying"
    );

    // The user logs in again. This is the moment the old code resurrected the row.
    let (second, second_token) = gov
        .issue_self(sub, None, now + 3600, now)
        .expect("a login after an admin deletion must still succeed, with a NEW binding");

    assert_ne!(
        second.id, first.id,
        "the new binding must not reuse the deleted id — that id is never reissued"
    );
    let tombstone = gov
        .store()
        .get_key(&first.id)
        .unwrap()
        .expect("the tombstoned row is kept for attribution");
    assert!(
        tombstone.deleted_at.is_some(),
        "the admin's deletion must still stand after the login: {tombstone:?}"
    );
    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "the pre-deletion token must NOT come back to life"
    );
    assert!(
        gov.verify_token(&second_token, now, None).is_some(),
        "the freshly issued token must work"
    );
}

/// A rolled-back refresh must remain RETRYABLE.
///
/// `refresh_self`'s rollback tombstones the new binding so the client keeps its working token and
/// can retry — that is the documented contract of the rollback. But the retry recomputes the same
/// `(sub, epoch)` and therefore the same id, which the rollback just tombstoned. If a tombstoned
/// derived id were reused, the retry would resurrect it; if it were merely refused, the retry would
/// fail on every attempt and the user could never rotate again. Skipping to the next free epoch is
/// what makes both come out right.
#[test]
fn a_rolled_back_refresh_can_still_be_retried() {
    let store = Arc::new(FailDeleteStore::new());
    let gov = GovState::new_with_signer(store.clone(), None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:dave";
    let now = 1_700_000_000u64;

    let (first, first_token) = gov.issue_self(sub, None, now + 3600, now).unwrap();

    // Arm one delete failure: the refresh writes the new binding, fails to tombstone the old, and
    // rolls the new one back (tombstoning it).
    store.arm();
    gov.refresh_self(sub, None, now + 3600, now)
        .expect_err("precondition: the armed failure makes this refresh fail");

    // The retry, against a healthy store. It must succeed, and must not hand back either the
    // original id or the rolled-back one.
    let (retried, retried_token) = gov
        .refresh_self(sub, None, now + 3600, now)
        .expect("a refresh that was rolled back must remain retryable");

    assert_ne!(
        retried.id, first.id,
        "the retry must rotate away from the original binding"
    );
    assert!(
        gov.verify_token(&retried_token, now, None).is_some(),
        "the retried refresh's token must verify"
    );
    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "the original token must be dead once the retry succeeded"
    );

    // Exactly one enabled binding for the subject: no stranded rows from the failed attempt.
    let enabled: Vec<VirtualKey> = gov
        .all_keys()
        .unwrap()
        .into_iter()
        .filter(|k| {
            k.enabled
                && k.deleted_at.is_none()
                && k.group.as_deref() == Some(format!("{SELF_KEY_GROUP_PREFIX}{sub}").as_str())
        })
        .collect();
    assert_eq!(
        enabled.len(),
        1,
        "the retry must leave exactly one enabled binding: {enabled:?}"
    );
}

/// A long-lived account must not be permanently locked out by its own refresh history.
///
/// Every successful `refresh_self` tombstones its predecessor, so after N refreshes epochs `0..N-1`
/// are a CONTIGUOUS tombstone run with the one live binding at N. Both no-live-binding paths start
/// their epoch search at 0 (nothing else is available — the cache that would know the highest epoch
/// filters tombstoned rows out at load), so the moment that live binding is deleted the next login
/// rescans the entire run. A fixed-cap one-at-a-time scan fails there on ORDINARY use: enough
/// refreshes plus one admin deletion and the subject can never mint again through either door, and
/// only manual store surgery clears it.
///
/// 70 refreshes, deliberately past the 64-probe cap, so a linear scan cannot pass this.
#[test]
fn a_long_refresh_history_does_not_lock_a_subject_out_after_a_deletion() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:erin";
    let now = 1_700_000_000u64;

    gov.issue_self(sub, None, now + 3600, now).unwrap();
    for _ in 0..70 {
        gov.refresh_self(sub, None, now + 3600, now)
            .expect("each refresh rotates and tombstones its predecessor");
    }
    let live = self_binding_for(&gov, sub).expect("one live binding after the refresh run");

    // The admin door: exactly what `DELETE /api/v1/admin/keys/{id}` does.
    gov.delete_key(&live.id).unwrap();

    // Both doors must still work. Before the fix each returned StoreError -> MintFailed -> HTTP 500,
    // for this subject, forever.
    let (issued, issued_token) = gov
        .issue_self(sub, None, now + 3600, now)
        .expect("a login after a long refresh history plus a deletion must still mint");
    assert!(
        gov.verify_token(&issued_token, now, None).is_some(),
        "the freshly issued token must verify"
    );
    assert_ne!(
        issued.id, live.id,
        "the new binding must not reuse the deleted id"
    );

    let (_refreshed, refreshed_token) = gov
        .refresh_self(sub, None, now + 3600, now)
        .expect("refresh must work too, not just issue");
    assert!(gov.verify_token(&refreshed_token, now, None).is_some());

    // The deleted binding stays deleted through all of it.
    let tombstone = gov.store().get_key(&live.id).unwrap().unwrap();
    assert!(
        tombstone.deleted_at.is_some(),
        "the admin's deletion must still stand: {tombstone:?}"
    );
}

/// One subject must never end up with TWO enabled self-serve bindings.
///
/// `issue_self`'s changed-pools branch used to re-DERIVE the binding id by parsing an epoch back out
/// of `generation_hash`, reasoning that the same epoch gives the same deterministic id and therefore
/// still one row. That holds only while the generation IS an epoch counter -- and `rotate_key` writes
/// a random hex generation instead. The parse then fell to `unwrap_or(0)`, epoch 0 derived a
/// different id from the live binding's, and a SECOND enabled row was written: two valid self-serve
/// tokens for one subject, each with its own group and budget accounting, breaking the at-most-one
/// invariant `current_self_binding` relies on.
///
/// The sequence below is ordinary operator behaviour, not a contrived race: rotate a user's key, then
/// have them log in after their group's pools changed.
#[test]
fn an_admin_rotate_then_a_pools_change_does_not_fork_the_binding() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:zed";
    let now = 1_700_000_000u64;

    gov.issue_self(sub, None, now + 3600, now).unwrap();
    for _ in 0..3 {
        gov.refresh_self(sub, None, now + 3600, now).unwrap();
    }
    let live = self_binding_for(&gov, sub).expect("one live binding");

    // The admin rotates it. This replaces the epoch-shaped generation with a random one -- which is
    // the state the old id-derivation could not survive.
    gov.rotate_key(&live.id, now + 3600).unwrap().unwrap();

    // The user logs in and their pools have changed since the binding was made.
    let (issued, token) = gov
        .issue_self(sub, Some(vec!["poolA".to_string()]), now + 3600, now)
        .unwrap();

    // The SAME row is updated, not a second one written.
    assert_eq!(
        issued.id, live.id,
        "a pools change must update the existing binding, never mint a parallel one"
    );
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "the token issued over the updated binding must verify"
    );

    let group = format!("{SELF_KEY_GROUP_PREFIX}{sub}");
    let enabled: Vec<VirtualKey> = gov
        .all_keys()
        .unwrap()
        .into_iter()
        .filter(|k| {
            k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str())
        })
        .collect();
    assert_eq!(
        enabled.len(),
        1,
        "at most one enabled binding per subject: {enabled:?}"
    );
    // And the pools change actually took effect, so this is not passing by doing nothing.
    assert_eq!(
        enabled[0].allowed_scopes,
        Some(vec![busbar_api::ScopeRef::pool("poolA".to_string())]),
        "the changed pools must be persisted on the surviving binding"
    );
}

// ── LOG-SPAM REGRESSION GUARD: metering-flush failure aggregation ─────────────────────────────
//
// A store outage fails EVERY pending metering key on the same flush tick. The flusher must emit
// exactly ONE aggregate `warn!` carrying the failed count (per-key detail demoted to `debug!`),
// not one warn per key. This is the regression guard for the per-tick log-spam class.

/// A `Store` that FAILS `add_metering` (a metering-store outage) while delegating everything else to
/// a real in-memory store, so `flush_metering` exercises its failure/aggregation path deterministically.
struct MeteringFailStore {
    inner: MemoryStore,
}

impl Store for MeteringFailStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        Err(busbar_api::StoreError("metering store unavailable".into()))
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

#[test]
fn flush_metering_failure_warns_once_per_tick_not_per_key() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let store: Arc<dyn Store> = Arc::new(MeteringFailStore {
        inner: MemoryStore::new(),
    });
    let gov = GovState::new(store, None).unwrap();
    let now = 1_700_000_500;
    // Five DISTINCT pending metering keys — all will fail to persist on the same tick.
    for k in ["vk_a", "vk_b", "vk_c", "vk_d", "vk_e"] {
        gov.record_metering(k, "model-x", "prov", None, now);
    }

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let flushed = tracing::subscriber::with_default(subscriber, || gov.flush_metering());

    assert_eq!(flushed, 0, "every key failed to persist");
    assert_eq!(
        cap.count("metering flush:"),
        1,
        "exactly ONE aggregate warn per tick, not one per failed key: {:?}",
        cap.messages()
    );
    // And the aggregate warn carries the failed COUNT (5), proving it aggregated rather than
    // emitting per key.
    assert!(
        cap.contains("failed=5"),
        "the aggregate warn reports the failed-key count: {:?}",
        cap.messages()
    );
    // The retained deltas are still pending for the next tick (not lost on the store error).
    assert_eq!(
        gov.flush_metering(),
        0,
        "the deltas are retained and retried, still failing while the store is down"
    );
}

// ── PHASE-11 PROOF HARNESS: MANUAL REVOCATION (the honest, demonstrable enterprise story) ─────────
//
// The auth design review (C1/C2) is blunt: AUTOMATIC IdP-driven revocation (introspect the subject
// on every use) is NOT implementable on standard OIDC and is NOT built. What IS true, built, and
// demonstrable TODAY is MANUAL revocation: an operator revokes a minted key and it dies — on the
// issuing node immediately, and cluster-wide within REVOCATION_SYNC_TTL_SECS×2 (~10s). These tests
// are that proof: a freshly minted token VERIFIES, and after a manual revoke it is DEAD — on the
// minting node AND on a second fleet node over the shared store.
// No claim here that the review cut: no per-use IdP introspection, no SCIM/SET webhook.

/// SINGLE NODE: mint → use (verify OK, GREEN) → manual revoke → DEAD (verify fails). This is the
/// kill switch the enterprise "offboarding = revoke the key, access ends in seconds" story rests on.
#[test]
fn proof_manual_revoke_kills_a_minted_key() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:dave";
    let now = 1_700_000_000u64;

    // MINT + USE: a fresh personal token verifies — the dev can call through busbar.
    let (binding, token) = gov.issue_self(sub, None, now + 3600, now).unwrap();
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "precondition: the freshly minted token MUST verify before revoke, or the \
         post-revoke assertion proves nothing"
    );
    assert!(!gov.is_revoked(&binding.id));

    // MANUAL REVOKE: the operator kills the key (POST /keys/{id}/revoke → GovState::revoke).
    gov.revoke(&binding.id, "offboarded").unwrap();

    // DEAD: the same token no longer verifies, and the subject reads as revoked. Immediate on the
    // issuing node (no sync window on the node that performed the revoke).
    assert!(
        gov.verify_token(&token, now, None).is_none(),
        "after a manual revoke the token MUST be dead on the issuing node"
    );
    assert!(gov.is_revoked(&binding.id));
}

/// CLUSTER: the revoke is AUTHORITATIVE fleet-wide, not process-local. A second node sharing the
/// durable store (same signing key) hydrates the denylist from the store, so a token revoked on
/// node A is already dead on node B — the honest core of "cluster-wide within ~10s" (a live peer
/// closes the gap within REVOCATION_SYNC_TTL_SECS×2 via its staleness sync; a node hydrating fresh,
/// as modeled here, sees it at once). Before the fix this test guards, the denylist was hydrated
/// ONCE at construction and a peer's revoke never propagated — an auth bypass, not a lag.
#[test]
fn proof_manual_revoke_is_authoritative_across_the_fleet() {
    let store = Arc::new(MemoryStore::new());
    let node_a = GovState::new_with_signer(store.clone(), None, Some(self_serve_signer())).unwrap();
    let sub = "oidc:erin";
    let now = 1_700_000_000u64;

    // Node A mints; the token verifies on A AND on a peer B over the same store + signing key.
    let (binding, token) = node_a.issue_self(sub, None, now + 3600, now).unwrap();
    let node_b = GovState::new_with_signer(store.clone(), None, Some(self_serve_signer())).unwrap();
    assert!(
        node_b.verify_token(&token, now, None).is_some(),
        "a second fleet node over the shared store must accept the token BEFORE the revoke"
    );

    // Node A revokes (writes the denylist to the shared store).
    node_a.revoke(&binding.id, "offboarded").unwrap();

    // A fleet node hydrating from the store AFTER the revoke sees it immediately — the revoke is a
    // durable, fleet-authoritative fact, not a cache local to the node that issued it.
    let node_c = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    assert!(
        node_c.verify_token(&token, now, None).is_none(),
        "the revoke MUST be authoritative on every fleet node reading the shared store"
    );
    assert!(node_c.is_revoked(&binding.id));
}

/// MULTI-MINT PROOF (1.6.0): one app-admin session mints 1 PERSONAL (user-bound) key + N labeled,
/// independently-scoped APP tokens (app-bound: time-bound, minted-by the admin as provenance). This
/// is the two-token-type story on the mint engine: the app tokens are NOT the idempotent single
/// self-serve key — each is a DISTINCT, labeled, differently-scoped credential carrying provenance,
/// and revoking ONE leaves every sibling AND the personal token fully alive (independent
/// revocability). The store/VirtualKey plumbing for this is what the earlier increments landed.
#[test]
fn proof_one_session_mints_a_personal_key_plus_n_independent_app_tokens() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let admin = "oidc:matthew"; // the app-admin, minting many tokens in one session
    let now = 1_700_000_000u64;

    // ── 1 PERSONAL token: user-bound, records the IdP subject, no separate minter (self-minted). ──
    let (personal, personal_tok) = gov.issue_self(admin, None, now + 3600, now).unwrap();
    assert_eq!(personal.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(personal.idp_subject.as_deref(), Some(admin));
    assert_eq!(personal.minted_by, None);
    assert!(gov.verify_token(&personal_tok, now, None).is_some());

    // ── N APP tokens: each LABELED, independently SCOPED to its own pool, minted-by the admin
    //    (provenance), time-bound. Minted in the same session — NOT idempotent, NOT the personal key.
    let apps = [
        ("billing", "pool-billing"),
        ("search", "pool-search"),
        ("etl", "pool-etl"),
    ];
    let mut minted = Vec::new();
    for (label, pool) in apps {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), label.to_string());
        let spec = NewKeySpec {
            name: format!("app-token-{label}"),
            allowed_pools: Some(vec![pool.to_string()]),
            group: None,
            labels,
            minted_by: Some(admin.to_string()),
            binding_mode: Some("time-bound".to_string()),
        };
        let (key, token) = gov.mint_signed(spec, now + 30 * 86_400, now).unwrap();
        minted.push((label, pool, key, token));
    }

    // Every app token is a DISTINCT key (not an idempotent reuse), correctly attributed + scoped.
    let ids: std::collections::HashSet<String> =
        minted.iter().map(|(_, _, k, _)| k.id.clone()).collect();
    assert_eq!(
        ids.len(),
        apps.len(),
        "N app tokens minted in one session are N DISTINCT keys"
    );
    assert!(
        !ids.contains(&personal.id),
        "no app token collides with the personal key"
    );
    for (label, pool, key, token) in &minted {
        assert_eq!(key.minted_by.as_deref(), Some(admin), "provenance recorded");
        assert_eq!(key.binding_mode.as_deref(), Some("time-bound"));
        assert_eq!(key.labels.get("app").map(String::as_str), Some(*label));
        let scopes = key.allowed_scopes.as_ref().expect("scoped");
        assert!(
            scopes.iter().all(|s| s.value == *pool) && scopes.len() == 1,
            "each app token is scoped to EXACTLY its own pool: {scopes:?}"
        );
        assert!(
            gov.verify_token(token, now, None).is_some(),
            "each app token verifies"
        );
    }

    // ── INDEPENDENT REVOCATION: revoke ONE app token; only it dies. ──
    let (_, _, victim_key, victim_tok) = &minted[1];
    gov.revoke(&victim_key.id, "compromised app token").unwrap();
    assert!(
        gov.verify_token(victim_tok, now, None).is_none(),
        "the revoked app token is dead"
    );
    assert!(
        gov.verify_token(&personal_tok, now, None).is_some(),
        "the personal token is untouched by an app-token revoke"
    );
    for (i, (_, _, _, token)) in minted.iter().enumerate() {
        if i == 1 {
            continue;
        }
        assert!(
            gov.verify_token(token, now, None).is_some(),
            "a sibling app token is untouched by revoking a different one"
        );
    }
}

// ── PHASE-11 PROOF: TIME-BOUND EXPIRY IS ENFORCED LOCALLY (#1) ────────────────────────────────────
//
// A minted token names its own expiry (`exp`) and busbar enforces it PURELY LOCALLY inside
// `verify_token` (→ `TokenVerifier::verify`): no store round-trip for the time check, no IdP call.
// Verify at a clock BEFORE `exp` accepts; advance the clock PAST `exp` and the SAME token is dead.
// The pre-expiry `Some` is the precondition (without it the post-expiry `None` proves nothing); the
// post-expiry `None` is the claim — without the local expiry check a minted token would live forever.
#[test]
fn proof_time_bound_expiry_is_enforced_locally() {
    let store = Arc::new(MemoryStore::new());
    // No IdP wired (`None` admin token is unrelated; there is simply no identity provider in a
    // GovState) — the expiry decision is this node's alone.
    let gov = GovState::new_with_signer(store, None, Some(self_serve_signer())).unwrap();
    let now = 1_700_000_000u64;
    let exp = now + 30 * 86_400; // exp = now + 30d

    let spec = NewKeySpec {
        name: "expiry-probe".to_string(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (_binding, token) = gov.mint_signed(spec, exp, now).unwrap();

    // PRECONDITION (GREEN): at a clock strictly before `exp`, the token verifies. Purely local —
    // no network — so the accept can only be the local signature+expiry check passing.
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "precondition: the token MUST verify at mint time, or the post-expiry None proves nothing"
    );
    assert!(
        gov.verify_token(&token, exp - 1, None).is_some(),
        "precondition: the token MUST still verify one second before its expiry"
    );

    // CLAIM: advance the clock to exp+1 and the SAME token is dead — expiry is enforced by busbar
    // itself, locally, on every verify.
    assert!(
        gov.verify_token(&token, exp + 1, None).is_none(),
        "past exp the token MUST NOT verify — time-bound expiry is enforced locally"
    );
    // And exactly AT `exp` it is already expired (`exp` is exclusive: verify rejects when exp <= now).
    assert!(
        gov.verify_token(&token, exp, None).is_none(),
        "exp is exclusive: at exactly exp the token is already expired"
    );
}

// ── PHASE-11 PROOF: A MINTED KEY VERIFIES LOCALLY AND NEVER CALLS THE IdP (#8, anti-C1) ───────────
//
// The honesty proof behind "disable in Okta does NOTHING to a minted key": `verify_token` is 100%
// LOCAL. It reads only this node's signing material and store — signature, exp, denylist,
// generation, `enabled`, audience — and there is NO code path from it to an identity provider. We
// build a GovState with NO IdP wired (only a signer), mint, verify (Some), then flip EACH local
// gate INDEPENDENTLY (a fresh binding per gate so no mutation leaks) and assert `None` per gate.
// Every accept and every refusal here is a local decision; an operator disabling the IdP subject
// upstream cannot reach any of these gates, which is exactly why a minted `vk_` key survives it.
#[test]
fn proof_minted_key_verifies_locally_and_never_calls_the_idp() {
    let now = 1_700_000_000u64;
    let exp = now + 30 * 86_400;
    let spec = |name: &str| NewKeySpec {
        name: name.to_string(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    // A node with a signer but NO IdP configured: `verify_token` has no IdP to call even if it
    // wanted to — the whole decision is local to this store + signing key.
    let new_gov = || {
        GovState::new_with_signer(
            Arc::new(MemoryStore::new()),
            None,
            Some(self_serve_signer()),
        )
        .unwrap()
    };

    // GREEN precondition: a freshly minted key verifies locally.
    let gov = new_gov();
    let (_b, token) = gov.mint_signed(spec("baseline"), exp, now).unwrap();
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "precondition: a freshly minted key MUST verify locally with no IdP configured"
    );

    // GATE 1 — BAD SIGNATURE: tamper a payload byte; the local ed25519 check rejects it.
    {
        let gov = new_gov();
        let (_b, token) = gov.mint_signed(spec("sig"), exp, now).unwrap();
        assert!(gov.verify_token(&token, now, None).is_some());
        // Char 10 sits inside the base64url payload segment (past the `bbk_` prefix); flipping it
        // changes the signed bytes, so the signature over the ORIGINAL payload no longer matches.
        let mut chars: Vec<char> = token.chars().collect();
        chars[10] = if chars[10] == 'x' { 'y' } else { 'x' };
        let tampered: String = chars.into_iter().collect();
        assert_ne!(tampered, token, "the tamper actually changed the token");
        assert!(
            gov.verify_token(&tampered, now, None).is_none(),
            "signature gate: a tampered token fails the local ed25519 verify"
        );
    }

    // GATE 2 — EXPIRE: advance past exp. Local exp check.
    assert!(
        gov.verify_token(&token, exp + 1, None).is_none(),
        "expire gate: past exp the token is dead (local time check, no network)"
    );

    // GATE 3 — REVOKE (denylist): revoke the subject; the same token fails the local denylist read.
    {
        let gov = new_gov();
        let (b, token) = gov.mint_signed(spec("revoke"), exp, now).unwrap();
        assert!(gov.verify_token(&token, now, None).is_some());
        gov.revoke(&b.id, "offboarded").unwrap();
        assert!(
            gov.verify_token(&token, now, None).is_none(),
            "revoke gate: a denylisted subject fails the local denylist read"
        );
    }

    // GATE 4 — ROTATE (generation bump): rotating the binding invalidates the pre-rotation token
    // via the local generation match.
    {
        let gov = new_gov();
        let (b, token) = gov.mint_signed(spec("rotate"), exp, now).unwrap();
        assert!(gov.verify_token(&token, now, None).is_some());
        gov.rotate_key(&b.id, exp)
            .unwrap()
            .expect("rotate mints a new credential over the live binding");
        assert!(
            gov.verify_token(&token, now, None).is_none(),
            "rotate gate: the pre-rotation token fails the local generation match"
        );
    }

    // GATE 5 — DISABLE (enabled=false): the administrative kill switch, read locally after lookup.
    {
        let gov = new_gov();
        let (b, token) = gov.mint_signed(spec("disable"), exp, now).unwrap();
        assert!(gov.verify_token(&token, now, None).is_some());
        gov.update_key(&b.id, Some(false), None)
            .unwrap()
            .expect("disable updates the binding in place");
        assert!(
            gov.verify_token(&token, now, None).is_none(),
            "disable gate: an `enabled=false` binding fails the local admit check"
        );
    }

    // GATE 6 — WRONG EXPECTED AUD: a plain data-plane token presented on an audience-checked
    // ingress fails the local plane-boundary check — no IdP is consulted to make that call.
    {
        let gov = new_gov();
        let (_b, token) = gov.mint_signed(spec("aud"), exp, now).unwrap();
        assert!(
            gov.verify_token(&token, now, None).is_some(),
            "the plain token verifies on the plain data plane (expected_aud = None)"
        );
        assert!(
            gov.verify_token(&token, now, Some("mcp://example/canonical"))
                .is_none(),
            "audience gate: a plain token is refused where a specific audience is required (local)"
        );
    }
}

// ── PHASE-11 PROOF: ADMISSION IS STORE STATE; SIGNING IS CONFIG (#10) ─────────────────────────────
//
// The config-vs-store split, made concrete. The SIGNING KEY (config) decides whether a token's
// SIGNATURE is authentic; the STORE decides whether the subject is ADMITTED (has a live binding).
// Mint a key on store S, drop that GovState, then rebuild a NEW GovState with the SAME signing key
// but a FRESH, EMPTY store. The token's signature STILL validates against the shared key (config
// carried over) — yet `verify_token` returns `None`, because `lookup_by_sub` finds no binding in the
// empty store (admission is a store fact the new node never recorded). This is precisely why a
// memory-store restart LOSES admission even though every minted token is still cryptographically
// genuine: config declares the key, the store records the admission, and the two are independent.
#[test]
fn proof_minted_admission_is_store_state_config_signing_is_not() {
    use crate::governance::signing::{TokenVerifier, DEFAULT_KID};
    let now = 1_700_000_000u64;
    let exp = now + 30 * 86_400;

    // Mint on store S.
    let store_s = Arc::new(MemoryStore::new());
    let gov_s = GovState::new_with_signer(store_s, None, Some(self_serve_signer())).unwrap();
    let (binding, token) = gov_s
        .mint_signed(
            NewKeySpec {
                name: "config-vs-store".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            exp,
            now,
        )
        .unwrap();
    assert!(
        gov_s.verify_token(&token, now, None).is_some(),
        "precondition: the token verifies on the node that minted it (config + store agree)"
    );

    // Drop the minting node and its store entirely — the admission record is gone with it.
    drop(gov_s);

    // Rebuild a node with the SAME signing key (config) but a FRESH EMPTY store (no admission).
    let fresh_store = Arc::new(MemoryStore::new());
    let gov_fresh =
        GovState::new_with_signer(fresh_store, None, Some(self_serve_signer())).unwrap();

    // CONFIG half — the SIGNATURE is still authentic under the shared signing key. Check the raw
    // verifier directly to isolate "signature authentic" (crypto/config) from "subject admitted"
    // (store): the same public key that `SigningMaterial` derives from `self_serve_signer()`.
    let verifier = TokenVerifier::single(DEFAULT_KID, self_serve_signer().verifying_key());
    let claims = verifier
        .verify(&token, now, None)
        .expect("the signature is still authentic under the shared signing key");
    assert_eq!(
        claims.sub, binding.id,
        "the authentic claims still name the minted subject"
    );

    // STORE half — admission is GONE. The fresh store has no binding for this sub, so `verify_token`
    // (signature-authentic but store-unadmitted) returns None. `lookup_by_sub` is empty.
    assert!(
        gov_fresh.lookup_by_sub(&binding.id).is_none(),
        "the fresh store records NO binding for the minted subject"
    );
    assert!(
        gov_fresh.verify_token(&token, now, None).is_none(),
        "admission is store state: a genuinely-signed token is refused when the store has no binding"
    );
}
