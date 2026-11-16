// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;
mod linked;

use busbar_contract::json::{self, JsonContainerTrait};
use busbar_contract::yaml::prelude::{MappingExt, Value, ValueExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/upgrade_1_5_5")
        .join(name)
}

fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-upgrade-1-5-5-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"https://mock.example\"\n",
    )
    .unwrap();
    d
}

fn validate(dir: &Path, config: &Path) -> Output {
    Command::new(common::boot::exe())
        .arg("--validate")
        .arg("--providers")
        .arg(dir.join("providers.yaml"))
        .env("BUSBAR_CONFIG", config)
        .env("MOCK_KEY", "k")
        .env_remove("BUSBAR_T_UPGRADE_UNSET_KEY")
        .output()
        .expect("run busbar --validate")
}

fn validate_as_written(name: &str) -> Output {
    let dir = workdir(name);
    let out = validate(&dir, &fixture(name));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn yaml(text: &str) -> Value {
    busbar_contract::yaml::from_str(text).expect("YAML")
}

/// Exercise the same public plan and strict parsing used by boot. Fixture assertions below
/// retain their value without calling the retired, broader normalizer.
fn migrate(path: &Path) -> (String, String) {
    linked::install();
    let dir = workdir("plan");
    let config = dir.join("config.yaml");
    std::fs::write(&config, std::fs::read(path).unwrap()).unwrap();
    let grammar = busbar_kernel::config::Grammar::new(
        busbar_kernel::config::secret::live_axis()
            .map(busbar_contract::secret::SecretAxis::sugars)
            .unwrap_or_default(),
        Default::default(),
        Vec::new(),
    );
    let planes = busbar_kernel::plane_driver::registry::plane_decls();
    let units: std::collections::BTreeSet<String> = planes
        .iter()
        .filter(|plane| plane.fallback)
        .flat_map(|plane| {
            plane.billable_classes.iter().filter_map(|unit| {
                (!plane.fee_units.contains(&unit.class)
                    && !busbar_contract::records::RESERVED_UNITS.contains(&unit.class))
                .then(|| unit.class.to_owned())
            })
        })
        .collect();
    let mut keys: Vec<String> = busbar_kernel::config::providers::catalog_grammar_keys()
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    if let Some(declared) = busbar_kernel::plane_driver::door::provider_keys(planes) {
        keys.extend(declared.catalog.keys.iter().map(|key| key.name.clone()));
    }
    let facts = busbar_migrate::Facts::of_process(units.into_iter().collect(), keys);
    let check = |text: &str, catalog: Option<&str>| {
        busbar_kernel::config::deploy_from_yaml_str(text, &grammar)
            .map_err(|error| error.to_string())?;
        if let Some(catalog) = catalog {
            busbar_kernel::config::providers::catalog_from_str(catalog, &grammar)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    };
    let plan = busbar_migrate::plan(&busbar_migrate::Inputs::new(&config, &facts, &check))
        .expect("the supported fixture plans and strictly parses");
    assert!(
        plan.catalog().is_none(),
        "these fixtures retain their catalog"
    );
    let planned = plan.planned().to_owned();
    let report = plan
        .report()
        .iter()
        .map(|line| format!("  - {line}\n"))
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    (planned, report)
}

fn migrate_and_validate(name: &str) -> (String, String, String) {
    let dir = workdir(name);
    let (text, report) = migrate(&fixture(name));
    let config = dir.join("config.yaml");
    std::fs::write(&config, &text).unwrap();
    let out = validate(&dir, &config);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{stderr}\n{text}");
    let _ = std::fs::remove_dir_all(&dir);
    (text, report, stderr)
}
/// A 1.5.5 rate card with no `units:` validates as written: the unpriced classes are reported,
/// never made free and never refused.
#[test]
fn a_1_5_5_rate_card_without_units_validates_with_its_unpriced_units_reported() {
    let raw = validate_as_written("rate_card.yaml");
    let stderr = String::from_utf8_lossy(&raw.stderr);
    assert_eq!(
        raw.status.code(),
        Some(0),
        "missing rates warn without refusing validation; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("has no configured rate") && stderr.contains("classes remain unpriced"),
        "unpriced units are reported without being made free; stderr:\n{stderr}"
    );
}

fn chat_usage(prompt: u64, written: u64, split: Option<(u64, u64)>, out: u64) -> serde_json::Value {
    let mut details = serde_json::json!({"cache_write_tokens": written});
    if let Some((ttl_30m, ttl_12h)) = split {
        details["cached_tokens"] = serde_json::json!(0);
        details["cache_write_tokens_details"] =
            serde_json::json!({"ttl_30m_tokens": ttl_30m, "ttl_12h_tokens": ttl_12h});
    }
    serde_json::json!({
        "prompt_tokens": prompt, "completion_tokens": out, "total_tokens": prompt + out,
        "prompt_tokens_details": details
    })
}

/// Boot `doc` (made servable) against a mock Chat upstream answering `usage`, in `dir`.
fn boot_chat(
    dir: &Path,
    mut doc: Value,
    usage: serde_json::Value,
    env: &[(&str, &str)],
) -> common::chat_spend::Gateway {
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let signing = common::chat_spend::signing_key(dir);
    common::chat_spend::serve(&mut doc, data, admin, &signing);
    let config = dir.join("config.yaml");
    std::fs::write(&config, busbar_contract::yaml::to_string(&doc).unwrap()).unwrap();
    let providers = dir.join("providers.yaml");
    std::fs::write(
        &providers,
        common::chat_spend::providers_yaml(common::chat_spend::chat_upstream(usage)),
    )
    .unwrap();
    common::chat_spend::Gateway::spawn(dir, &config, &providers, data, admin, env)
}

/// A 1.5.5 YAML booted as written (not migrated): its root `cache_write_utok: 0` is the
/// 1.5.5 spelling of "no separate write tariff", so startup removes it with a WARN naming the model,
/// and the 20 Chat cache writes bill at input_utok, never 0.
#[test]
fn a_1_5_5_yaml_zero_cache_write_boots_at_input_rate() {
    let dir = workdir("zero-write-boot");
    let doc = yaml(&std::fs::read_to_string(fixture("rate_card_zero_write.yaml")).unwrap());
    assert_eq!(
        doc.at("rate_card").at("test-model").at("cache_write_utok"),
        &yaml("0"),
        "the fixture states the 1.5.5 zero"
    );
    let mut gateway = boot_chat(&dir, doc, chat_usage(100, 20, None, 9), &[]);
    gateway
        .ready()
        .unwrap_or_else(|log| panic!("the 1.5.5 YAML boots; log:\n{log}"));
    // (100 - 20) x 2.5 + 20 x 2.5 + 9 x 10 micro-units: the writes price at input_utok.
    assert_eq!(
        gateway.one_chat_spend_micros(),
        340,
        "log:\n{}",
        gateway.log()
    );
    let log = gateway.log();
    assert!(
        log.contains("startup converted a 1.5.5 configuration value")
            && log.contains("rate_card.test-model.cache_write_utok: 0 removed"),
        "the boot WARN names the removed zero; log:\n{log}"
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A root `cache_write_utok: 0` that arrives after startup (a reload of an edited config.yaml, or
/// an env-interpolated value at boot) is refused, audited and explained; it never makes cache
/// writes free.
#[test]
fn reload_refuses_a_root_yaml_zero_cache_write() {
    const REFUSAL: &str = "rate_card.test-model.cache_write_utok: 0 is refused";
    const REMEDY: &str = "Remove the key (writes price at input_utok)";
    let dir = workdir("zero-write-reload");
    let doc = yaml(
        "store: { module: memory }\n\
         providers:\n  mock:\n    api_key: { env: MOCK_KEY }\n\
         models:\n  test-model:\n    provider: mock\n\
         rate_card:\n  test-model: { input_utok: 2.5, output_utok: 10 }\n",
    );
    let mut gateway = boot_chat(&dir, doc, chat_usage(100, 20, None, 9), &[]);
    gateway
        .ready()
        .unwrap_or_else(|log| panic!("the clean config boots; log:\n{log}"));
    let version = |gateway: &common::chat_spend::Gateway| {
        let (status, info) = gateway.admin("GET", "/api/v1/admin/info", None);
        assert_eq!(status, 200, "{info}");
        json::parse_value(info.as_bytes()).unwrap()["config_version"].clone()
    };
    let before = version(&gateway);

    let config = dir.join("config.yaml");
    let clean = std::fs::read_to_string(&config).unwrap();
    let mut edited = yaml(&clean);
    *edited
        .at_mut("rate_card")
        .at_mut("test-model")
        .at_mut("cache_write_utok") = yaml("0");
    std::fs::write(&config, busbar_contract::yaml::to_string(&edited).unwrap()).unwrap();
    for (path, action) in [
        ("/api/v1/admin/config/reload", "config.reload"),
        ("/api/v1/admin/plugins/reload", "plugin.reload"),
    ] {
        let (status, body) = gateway.admin("POST", path, None);
        assert!(
            (400..500).contains(&status) && body.contains(REFUSAL) && body.contains(REMEDY),
            "{path} refuses with the reason and the remedy: {status} {body}"
        );
        let (status, audit) =
            gateway.admin("GET", &format!("/api/v1/admin/audit?action={action}"), None);
        assert_eq!(status, 200, "{audit}");
        let audit: json::Value = json::parse_value(audit.as_bytes()).unwrap();
        assert!(
            audit["items"]
                .as_array()
                .is_some_and(|items| items.iter().any(|e| e["outcome"] == "rejected")),
            "{path}: the refusal is audited: {audit}"
        );
    }
    assert_eq!(version(&gateway), before, "the running config is unchanged");
    // The running card still prices the 20 writes at input_utok: (80 + 20) x 2.5 + 9 x 10.
    assert_eq!(
        gateway.one_chat_spend_micros(),
        340,
        "log:\n{}",
        gateway.log()
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);

    // At boot, a root write rate that interpolates to 0 from the environment is refused the same
    // way (a literal 1.5.5 zero was already unfolded before this reader).
    let dir = workdir("zero-write-env");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{data}\"\nadmin_listen: \"127.0.0.1:{admin}\"\n\
             store: {{ module: memory }}\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n\
             rate_card:\n  test-model:\n    input_utok: 2.5\n    output_utok: 10\n    \
             cache_write_utok: ${{BUSBAR_T_ZERO_WRITE}}\n"
        ),
    )
    .unwrap();
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, common::chat_spend::providers_yaml(9)).unwrap();
    let mut gateway = common::chat_spend::Gateway::spawn(
        &dir,
        &config,
        &providers,
        data,
        admin,
        &[("BUSBAR_T_ZERO_WRITE", "0")],
    );
    let log = gateway
        .ready()
        .expect_err("a root write rate interpolated to 0 refuses boot");
    assert!(
        log.contains(REFUSAL) && log.contains(REMEDY),
        "the boot refusal names the key and the remedy; log:\n{log}"
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

/// C3 retains the serving assertion from `migrated_ttl_write_units_price_at_the_write_rate`.
/// The actual first boot now performs the migration; no deleted normalizer prepares its input.
#[test]
fn first_boot_migrates_ttl_write_units_and_bills_the_partitioned_write() {
    let dir = workdir("ttl-first-boot");
    let source = std::fs::read_to_string(fixture("rate_card.yaml")).unwrap();
    let mut gateway = boot_chat(
        &dir,
        yaml(&source),
        chat_usage(100, 20, Some((8, 12)), 9),
        &[],
    );
    gateway
        .ready()
        .unwrap_or_else(|log| panic!("the first boot migrates and serves; log:\n{log}"));
    let migrated = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    let doc = yaml(&migrated);
    assert_eq!(doc.at("config_version"), &yaml("1"));
    for unit in ["cache_write_30m", "cache_write_12h"] {
        assert_eq!(
            doc.at("rate_card").at("test-model").at("units").at(unit),
            &yaml("3"),
            "{unit}:\n{migrated}"
        );
    }
    assert_eq!(
        gateway.one_chat_spend_micros(),
        435,
        "log:\n{}",
        gateway.log()
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Keep the principal-admission assertions while replacing the deleted normalizer with the
/// approved migration plan. YAML equality alone does not prove that these principals are admitted.
#[test]
fn a_1_5_5_provider_with_no_bindings_keeps_its_users_after_migration() {
    use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg, ProviderDef};
    linked::install();
    let raw = std::fs::read_to_string(fixture("ungoverned_principals.yaml")).unwrap();
    let defs: std::collections::HashMap<String, ProviderDef> = busbar_contract::yaml::from_str(
        "mock:\n  protocol: anthropic\n  base_url: https://mock.example\n",
    )
    .expect("provider defs parse");
    let grammar = busbar_kernel::config::Grammar::new(
        busbar_kernel::config::secret::live_axis()
            .map(busbar_contract::secret::SecretAxis::sugars)
            .unwrap_or_default(),
        Default::default(),
        Vec::new(),
    );
    let resolved = |text: &str| {
        let deploy: DeployCfg = deploy_from_yaml_str(text, &grammar)
            .unwrap_or_else(|e| panic!("the config parses: {e}\n{text}"));
        let cfg = resolve(&deploy, &defs).unwrap_or_else(|e| panic!("resolves: {e:?}\n{text}"));
        busbar_kernel::config_validate::validate(&cfg)
            .unwrap_or_else(|e| panic!("validates: {e:?}\n{text}"));
        cfg
    };
    let user = |roles: &[&str]| busbar_kernel::auth::Principal {
        id: "alice".into(),
        name: None,
        roles: roles.iter().map(|r| r.to_string()).collect(),
        ttl_secs: None,
    };
    let admitted = |cfg: &busbar_kernel::config::RootCfg, roles: &[&str]| {
        let bindings = &cfg.auth.as_ref().expect("an auth block").role_bindings;
        busbar_kernel::governance::synthesize_bound_key("corp", &user(roles), bindings)
    };
    let before = resolved(&raw);
    assert!(admitted(&before, &[]).is_none() && admitted(&before, &["eng"]).is_none());

    let dir = workdir("principals-plan");
    let path = dir.join("config.yaml");
    std::fs::write(&path, &raw).unwrap();
    let facts = busbar_migrate::Facts::of_process(Vec::new(), Vec::new());
    let check = |text: &str, _: Option<&str>| {
        let _ = resolved(text);
        Ok(())
    };
    let plan = busbar_migrate::plan(&busbar_migrate::Inputs::new(&path, &facts, &check))
        .expect("the supported 1.5.5 document plans");
    assert!(
        plan.report()
            .iter()
            .any(|line| line.starts_with("auth.role_bindings.corp.\"*\": added")),
        "the new binding is reported: {:?}",
        plan.report()
    );
    assert!(
        plan.report()
            .iter()
            .any(|line| line.contains("keeps 1.5.5's access")),
        "the report explains the retained access: {:?}",
        plan.report()
    );
    let after = resolved(plan.planned());
    for roles in [&[][..], &["eng"][..]] {
        let key = admitted(&after, roles)
            .unwrap_or_else(|| panic!("a user with roles {roles:?} is admitted, as on 1.5.5"));
        assert!(key.allowed_scopes.is_none(), "on every pool, as on 1.5.5");
        assert!(key.group.is_none(), "with no budget, as on 1.5.5");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
/// The cache-write TTL units a migrated card prices at the entry's resolved write rate.
const WRITE_TIER_UNITS: [&str; 2] = ["cache_write_30m", "cache_write_12h"];

/// Why the migrator prices them at that rate, as its change line says.
const WRITE_UNITS_WHY: &str = "(the entry's cache_write_utok, else input_utok; 1.5.5 billed cache writes inside input, never at 0)";

/// The migration summary line that names both cache-write TTL units of `test-model`.
fn write_units_line(summary: &str) -> Option<&str> {
    summary.lines().find(|line| {
        line.starts_with("  - rate_card.test-model.units: ")
            && WRITE_TIER_UNITS.iter().all(|unit| line.contains(unit))
    })
}

#[test]
fn a_1_5_5_rate_card_without_units_migrates_to_one_that_bills_the_same() {
    let raw = validate_as_written("rate_card.yaml");
    let stderr = String::from_utf8_lossy(&raw.stderr);
    assert_eq!(
        raw.status.code(),
        Some(0),
        "missing rates warn without refusing validation; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("has no configured rate") && stderr.contains("classes remain unpriced"),
        "unpriced units are reported without being made free; stderr:\n{stderr}"
    );

    let (migrated, summary, _) = migrate_and_validate("rate_card.yaml");
    let doc = yaml(&migrated);
    let entry = doc.at("rate_card").at("test-model");
    assert_eq!(
        entry.at("input_utok"),
        &yaml("3.0"),
        "token prices are kept"
    );
    assert_eq!(
        entry.at("output_utok"),
        &yaml("15.0"),
        "token prices are kept"
    );
    let units = entry
        .at("units")
        .as_mapping()
        .unwrap_or_else(|| panic!("units were added:\n{migrated}"));
    assert!(!units.is_empty(), "units were added:\n{migrated}");
    // Owner LEDGER-100 / CHANGELOG "An unpriced class never silently bills 0": 1.5.5 billed cache
    // writes inside the input, so the two cache-write TTL units take the entry's resolved write
    // rate (here its input_utok, 3) as an exact UnitRate; every other added unit is 0.
    for (unit, rate) in units {
        let unit = unit.as_str().expect("a unit name");
        let want = if WRITE_TIER_UNITS.contains(&unit) {
            yaml("3")
        } else {
            yaml("0")
        };
        assert_eq!(rate, &want, "{unit}:\n{migrated}");
    }
    for unit in WRITE_TIER_UNITS {
        assert!(units.contains_key(unit), "{unit} is priced:\n{migrated}");
    }
    assert!(
        summary.contains("  - rate_card.test-model.units: added ")
            && summary.contains("1.5.5 billed these units at nothing"),
        "one change line names it and why; stderr:\n{summary}"
    );
    assert!(
        write_units_line(&summary)
            .is_some_and(|line| line.contains(&format!(" at 3 {WRITE_UNITS_WHY}"))),
        "the write units name their rate and why; stderr:\n{summary}"
    );
}

#[test]
fn a_1_5_5_metadata_entry_naming_no_host_migrates_away() {
    let raw = validate_as_written("metadata_no_host.yaml");
    let stderr = String::from_utf8_lossy(&raw.stderr);
    if raw.status.code() != Some(0) {
        assert!(
            stderr.contains("'db.1'"),
            "a refusal of the entry as written names it; stderr:\n{stderr}"
        );
    }

    let (migrated, summary, stderr) = migrate_and_validate("metadata_no_host.yaml");
    assert_eq!(
        yaml(&migrated).at("security").at("blocked_metadata_hosts"),
        &yaml("['169.254.169.254']"),
        "only the entry that named no host is removed:\n{migrated}"
    );
    assert!(
        !stderr.contains("db.1"),
        "the migrated configuration says nothing about it; stderr:\n{stderr}"
    );
    assert!(
        summary.contains("  - security.blocked_metadata_hosts: removed entry 'db.1' ")
            && summary.contains("never matched any destination on 1.5.5"),
        "one change line names it and why; stderr:\n{summary}"
    );
}
/// The migration prices the two cache-write TTL units at the entry's resolved write rate as an
/// exact UnitRate (never 0, and never a bare float `units:` would refuse), leaves them unpriced
/// with a reason when that rate is not an exact number, and the migrated card bills a partitioned
/// Chat write at that rate.
#[test]
fn migrated_ttl_write_units_price_at_the_write_rate() {
    // The fixture's input_utok 3.0 resolves to the integer 3 (see the pinned rate_card test).
    let (migrated, summary, _) = migrate_and_validate("rate_card.yaml");
    let units = yaml(&migrated)
        .at("rate_card")
        .at("test-model")
        .at("units")
        .clone();
    for unit in WRITE_TIER_UNITS {
        assert_eq!(units.at(unit), &yaml("3"), "{unit}:\n{migrated}");
    }
    assert!(write_units_line(&summary).is_some(), "{summary}");

    // An explicit write rate wins over input_utok, written as an exact decimal string.
    let dir = workdir("write-rate");
    let raw = std::fs::read_to_string(fixture("rate_card.yaml"))
        .unwrap()
        .replace(
            "{ input_utok: 3.0, output_utok: 15.0 }",
            "{ input_utok: 3.0, output_utok: 15.0, cache_write_utok: 3.75 }",
        );
    assert!(raw.contains("cache_write_utok: 3.75"), "{raw}");
    std::fs::write(dir.join("source.yaml"), &raw).unwrap();
    let (written, summary) = migrate(&dir.join("source.yaml"));
    let units = yaml(&written)
        .at("rate_card")
        .at("test-model")
        .at("units")
        .clone();
    for unit in WRITE_TIER_UNITS {
        assert_eq!(units.at(unit), &yaml("'3.75'"), "{unit}:\n{written}");
        let rate: busbar_kernel_ledger::cost::UnitRate =
            busbar_contract::yaml::from_value(units.at(unit).clone()).expect("an exact UnitRate");
        assert_eq!(
            rate,
            busbar_kernel_ledger::cost::UnitRate::from_nanos(3_750)
        );
    }
    assert!(
        write_units_line(&summary).is_some_and(|l| l.contains(" at 3.75 ")),
        "{summary}"
    );
    std::fs::write(dir.join("config.yaml"), &written).unwrap();
    let out = validate(&dir, &dir.join("config.yaml"));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // MIGRATE-ON-BOOT 1t forbids computing a new rate from a template slot. The old
    // normalizer's successful partial output is intentionally replaced by a no-write refusal.
    let raw = std::fs::read_to_string(fixture("rate_card.yaml"))
        .unwrap()
        .replace(
            "  test-model: { input_utok: 3.0, output_utok: 15.0 }",
            "  test-model:\n    input_utok: ${RATE}\n    output_utok: 15.0",
        );
    assert!(raw.contains("${RATE}"), "{raw}");
    std::fs::write(dir.join("placeholder.yaml"), &raw).unwrap();
    let path = dir.join("placeholder.yaml");
    let facts = busbar_migrate::Facts::of_process(
        WRITE_TIER_UNITS
            .iter()
            .map(|unit| (*unit).to_owned())
            .collect(),
        Vec::new(),
    );
    let never = |_: &str, _: Option<&str>| -> Result<(), String> {
        panic!("the template refusal precedes the strict parse")
    };
    let refused = busbar_migrate::plan(&busbar_migrate::Inputs::new(&path, &facts, &never))
        .expect_err("a computed template value is refused");
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused
            .to_string()
            .contains("rate_card.test-model.input_utok"),
        "{refused}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        raw,
        "no source edit"
    );
    assert!(!dir.join("placeholder.yaml.1.5.5").exists());
    let _ = std::fs::remove_dir_all(&dir);

    // The migrated card boots and bills a partitioned Chat write (8 at 30m + 12 at 12h of 100
    // prompt tokens) at the write rate 3: 80 x 3 + 20 x 3 + 9 x 15 micro-units, never 0.
    let dir = workdir("ttl-boot");
    let mut gateway = boot_chat(
        &dir,
        yaml(&migrated),
        chat_usage(100, 20, Some((8, 12)), 9),
        &[],
    );
    gateway
        .ready()
        .unwrap_or_else(|log| panic!("the migrated card boots; log:\n{log}"));
    assert_eq!(
        gateway.one_chat_spend_micros(),
        435,
        "log:\n{}",
        gateway.log()
    );
    drop(gateway);
    let _ = std::fs::remove_dir_all(&dir);
}
