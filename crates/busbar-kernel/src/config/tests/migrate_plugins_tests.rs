// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's half of a plugin's own migration: it hands each selected plugin its section, writes the
//! answer back, applies only the needs raised against core's keys, prints the report lines under
//! the plugin's name, and rewrites `plugins.fetch` through the release lookup. It knows no plugin's
//! keys: the stub host below does the renaming, as a plugin's `migrate` would.

use busbar_contract::abi::sdk::migrate::{MigrateNeed, Migrated};

use super::{MigrateHost, NoPlugins};
use crate::config::migrate::{migrate_config, migrate_config_with};

/// A stub host: the `stub` store and auth plugins rename `signing-secret` to `signing_secret` and
/// ask for the host their `url` names; `broken` refuses; the index answers `v1.6.0` for the stub's
/// repository, and a pin for the unserved `elsewhere` module.
struct Stub;

impl MigrateHost for Stub {
    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, Migrated)>, String> {
        match module {
            "broken" => Err("its migrate refused: no".into()),
            "stub" => {
                let mut settings = settings.clone();
                let mut report = Vec::new();
                let mut needs = Vec::new();
                if let Some(m) = settings.as_object_mut() {
                    if let Some(v) = m.remove("signing-secret") {
                        m.insert("signing_secret".into(), v);
                        report.push(format!("{kind}: signing-secret -> signing_secret ({from})"));
                    }
                    if let Some(h) = m.get("url").and_then(|u| u.as_str()) {
                        needs.push(MigrateNeed::AllowDestination(h.to_string()));
                    }
                }
                Ok(Some((
                    "busbar-stub".into(),
                    Migrated {
                        settings,
                        report,
                        needs,
                    },
                )))
            }
            _ => Ok(None),
        }
    }

    fn repin(&self, github: &str) -> Result<Option<String>, String> {
        Ok(github
            .starts_with("Acme/busbar-stub@")
            .then(|| "Acme/busbar-stub@v1.6.0".to_string()))
    }

    fn release_for(&self, _: &str, module: &str) -> Result<Option<String>, String> {
        Ok((module == "elsewhere").then(|| "Acme/busbar-elsewhere@v1.6.0".to_string()))
    }
}

const CONFIG: &str = "\
store:
  module: stub
  settings: { signing-secret: { env: S }, url: 10.0.0.7 }
identity-providers:
  corp: { module: stub, settings: { url: 10.0.0.7 } }
  other: { module: elsewhere, settings: { keep: me } }
  sick: { module: broken, settings: { keep: me } }
plugins:
  enabled: true
  fetch:
    - { github: Acme/busbar-stub@v1.0.0, sha256: aaaa }
";

fn doc(yaml: &str) -> serde_yaml::Value {
    let body: String = yaml
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    serde_yaml::from_str(&body).expect("the migrated document parses")
}

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).expect("YAML")
}

#[test]
fn core_writes_back_the_plugins_own_migration_and_applies_only_its_needs() {
    let out = migrate_config_with(CONFIG, &Stub).expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["store"]["settings"],
        yaml("{ signing_secret: { env: S }, url: 10.0.0.7 }"),
        "the plugin's answer replaces its section:\n{}",
        out.yaml
    );
    assert_eq!(
        d["advanced"]["allow_destinations"],
        yaml("['10.0.0.7']"),
        "the raised destination, once, and nothing else:\n{}",
        out.yaml
    );
    assert!(
        d["advanced"]["block_private_addresses"].is_null(),
        "core never turns the guard off"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c == "busbar-stub: store: signing-secret -> signing_secret (1.5.5)"),
        "the report line is printed under the plugin's name: {:?}",
        out.changes
    );
    assert_eq!(
        out.changes
            .iter()
            .filter(|c| c.starts_with("advanced.allow_destinations: added '10.0.0.7'"))
            .count(),
        1,
        "{:?}",
        out.changes
    );
    // A plugin with no migrate passes through; one that refuses is left as written, with a TODO.
    assert_eq!(
        d["identity-providers"]["other"]["settings"],
        yaml("{ keep: me }")
    );
    assert_eq!(
        d["identity-providers"]["sick"]["settings"],
        yaml("{ keep: me }")
    );
    assert!(
        out.todos.iter().any(|t| t.starts_with(
            "identity-providers.sick.settings: the auth plugin 'broken' could not migrate"
        ) && t.contains("its migrate refused: no")),
        "{:?}",
        out.todos
    );
}

#[test]
fn fetch_pins_are_rewritten_through_the_release_lookup_and_unserved_plugins_gain_one() {
    let out = migrate_config_with(CONFIG, &Stub).expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["plugins"]["fetch"],
        yaml(
            "[{ github: Acme/busbar-stub@v1.6.0 }, \
             { github: Acme/busbar-elsewhere@v1.6.0 }]"
        ),
        "the old pin is rewritten without its sha256, and the unserved plugin is pinned:\n{}",
        out.yaml
    );
    assert!(out.changes.iter().any(|c| c
        .starts_with("plugins.fetch: 'Acme/busbar-stub@v1.0.0' -> 'Acme/busbar-stub@v1.6.0'")
        && c.contains("its sha256 pinned the old build, so it was removed")));
    assert!(out
        .changes
        .iter()
        .any(|c| c.starts_with("plugins.fetch: added 'Acme/busbar-elsewhere@v1.6.0'")));
    // Idempotent: the migrated document migrates to itself.
    let again = migrate_config_with(&out.yaml, &Stub).expect("migrates again");
    assert!(
        !again.changes.iter().any(|c| c.starts_with("plugins.fetch")
            || c.starts_with("advanced.allow_destinations")),
        "{:?}",
        again.changes
    );
}

#[test]
fn with_no_plugins_at_hand_every_section_passes_through_unchanged() {
    let plain = migrate_config(CONFIG).expect("migrates");
    let hosted = migrate_config_with(CONFIG, &NoPlugins).expect("migrates");
    assert_eq!(plain.yaml, hosted.yaml);
    let d = doc(&plain.yaml);
    assert_eq!(
        d["store"]["settings"],
        yaml("{ signing-secret: { env: S }, url: 10.0.0.7 }"),
        "core never renames a plugin's key"
    );
    assert!(d["advanced"].is_null());
}

// ── A plane's consumed sections, the merged providers view, and a host allowed only if private ──
//
// A plane's migration is handed the sections it CONSUMES beside the ones it owns, read-only: an
// answer that rewrites one is refused, whole, with the reason. A plane that consumes the transport
// kind's root (`providers`) is handed the catalog merged under the deployment's entries, as boot
// merges them. A plane that cannot tell whether a host it dials is private raises
// `AllowDestinationIfPrivate`: core resolves it at migrate time with the destination guard's own
// predicates and adds exactly that host only when every answer is private or loopback and none is
// cloud metadata, with a report line for every decision.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;

use busbar_contract::plugin::Kind;
use busbar_contract::section::{RESERVED_MODELS_KEY, RESERVED_POOLS_KEY};

use super::{migrate_over, Ledger, PlaneFacts};

/// The section a witness plane reads beside its own that no catalog backs.
const SHARED: &str = "witness_shared";

/// The witness plane: it declares the pools section, owns `witness_own`, and consumes the
/// providers, the models and [`SHARED`].
fn witness() -> PlaneFacts {
    PlaneFacts {
        key: "witness",
        owns: vec![RESERVED_POOLS_KEY, "witness_own"],
        consumes: &[Kind::Transport.root(), RESERVED_MODELS_KEY, SHARED],
    }
}

/// What the witness plane does with what it is handed.
#[derive(Clone, Copy)]
enum Plane {
    /// Rename `old` to `new` in `witness_own`, and raise `AllowDestinationIfPrivate` for every
    /// `base_url` and `token_url` host of the providers it is handed (as a plane does that cannot
    /// resolve a name itself).
    Migrates,
    /// Answer the providers it was handed rewritten (a key added to each entry).
    RewritesProviders,
    /// Answer [`SHARED`] rewritten, and its own section too.
    RewritesShared,
}

/// A host whose witness plane does what [`Plane`] says, whose catalog is `catalog` and whose
/// resolver answers from `dns` (never the network), recording what the plane was handed and every
/// name resolved.
struct Witness {
    plane: Plane,
    catalog: Option<&'static str>,
    dns: BTreeMap<&'static str, Vec<IpAddr>>,
    handed: RefCell<Option<serde_json::Value>>,
    resolved: RefCell<Vec<String>>,
}

impl Witness {
    fn new(plane: Plane) -> Self {
        Self {
            plane,
            catalog: None,
            dns: BTreeMap::new(),
            handed: RefCell::new(None),
            resolved: RefCell::new(Vec::new()),
        }
    }

    fn answers(mut self, name: &'static str, addrs: &[&str]) -> Self {
        self.dns
            .insert(name, addrs.iter().map(|a| a.parse().unwrap()).collect());
        self
    }

    fn handed(&self) -> serde_json::Value {
        self.handed.borrow().clone().expect("the plane was called")
    }
}

impl MigrateHost for Witness {
    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        _: &str,
    ) -> Result<Option<(String, Migrated)>, String> {
        assert_eq!((kind, module), ("plane", "witness"));
        *self.handed.borrow_mut() = Some(settings.clone());
        let mut out = settings.clone();
        let mut needs = Vec::new();
        match self.plane {
            Plane::Migrates => {
                if let Some(own) = out.get_mut("witness_own").and_then(|o| o.as_object_mut()) {
                    if let Some(v) = own.remove("old") {
                        own.insert("new".into(), v);
                    }
                }
                let providers = settings.get(Kind::Transport.root()).and_then(|p| p.as_object());
                for entry in providers.into_iter().flat_map(|p| p.values()) {
                    for key in ["base_url", "token_url"] {
                        let host = entry
                            .get(key)
                            .and_then(|u| u.as_str())
                            .and_then(busbar_contract::net::url_host);
                        if let Some(host) = host {
                            needs.push(MigrateNeed::AllowDestinationIfPrivate(host));
                        }
                    }
                }
            }
            Plane::RewritesProviders => {
                for entry in out[Kind::Transport.root()]
                    .as_object_mut()
                    .expect("handed the providers")
                    .values_mut()
                {
                    entry["added"] = serde_json::json!(true);
                }
            }
            Plane::RewritesShared => {
                out[SHARED] = serde_json::json!({"rewritten": true});
                out["witness_own"] = serde_json::json!({"new": 1});
            }
        }
        Ok(Some((
            "busbar-witness".into(),
            Migrated {
                settings: out,
                report: Vec::new(),
                needs,
            },
        )))
    }

    fn repin(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn providers_catalog(
        &self,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
        let Some(text) = self.catalog else {
            return Ok(None);
        };
        let doc: serde_json::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        Ok(doc.as_object().cloned())
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, String> {
        self.resolved.borrow_mut().push(name.to_string());
        self.dns
            .get(name)
            .cloned()
            .ok_or_else(|| "no such name".to_string())
    }
}

/// Run only the plugin step over `yaml`, with the witness plane registered.
fn run(yaml: &str, host: &Witness) -> (serde_yaml::Value, Vec<String>, Vec<String>) {
    let serde_yaml::Value::Mapping(mut root) = serde_yaml::from_str(yaml).expect("YAML") else {
        panic!("a mapping");
    };
    let (mut changes, mut todos) = (Vec::new(), Vec::new());
    migrate_over(
        &mut root,
        host,
        &mut Ledger {
            changes: &mut changes,
            todos: &mut todos,
        },
        &[witness()],
    );
    (serde_yaml::Value::Mapping(root), changes, todos)
}

const PLANE_DOC: &str = "\
pools:
  p: { members: [{ model: m }] }
witness_own: { old: 1 }
witness_shared: { keep: me }
models:
  m: { provider: a }
providers:
  a: { base_url: 'http://10.0.0.5:8000' }
";

#[test]
fn a_plane_is_handed_its_consumed_sections_beside_its_own() {
    let host = Witness::new(Plane::Migrates);
    let (d, changes, todos) = run(PLANE_DOC, &host);
    let handed = host.handed();
    for section in [
        RESERVED_POOLS_KEY,
        "witness_own",
        RESERVED_MODELS_KEY,
        Kind::Transport.root(),
        SHARED,
    ] {
        assert!(
            handed.get(section).is_some(),
            "handed `{section}`: {handed}"
        );
    }
    assert_eq!(handed[SHARED], serde_json::json!({"keep": "me"}));
    // Its own section is written back; the consumed ones it answered unchanged stay as written.
    assert_eq!(d["witness_own"], yaml("{ new: 1 }"));
    assert_eq!(d[SHARED], yaml("{ keep: me }"));
    assert_eq!(d["models"], yaml("{ m: { provider: a } }"));
    assert!(todos.is_empty(), "{todos:?}");
    assert!(
        changes
            .iter()
            .any(|c| c.starts_with("advanced.allow_destinations: added '10.0.0.5'")),
        "{changes:?}"
    );
}

#[test]
fn a_plane_with_none_of_its_own_sections_is_not_handed_the_ones_it_consumes() {
    let host = Witness::new(Plane::Migrates);
    let (d, changes, todos) = run(
        "models:\n  m: { provider: a }\nproviders:\n  a: { base_url: 'http://10.0.0.5' }\n",
        &host,
    );
    assert!(host.handed.borrow().is_none(), "the plane was not called");
    assert!(d["advanced"].is_null());
    assert!(changes.is_empty() && todos.is_empty());
}

#[test]
fn a_consumed_section_is_read_only_and_a_rewrite_of_it_is_refused_with_the_reason() {
    for plane in [Plane::RewritesShared, Plane::RewritesProviders] {
        let host = Witness::new(plane);
        let (d, _, todos) = run(PLANE_DOC, &host);
        let section = match plane {
            Plane::RewritesShared => SHARED,
            _ => Kind::Transport.root(),
        };
        assert_eq!(
            todos.len(),
            1,
            "one refusal, naming the section: {todos:?}"
        );
        let todo = &todos[0];
        assert!(
            todo.contains("the plugin 'busbar-witness' answered a migration that cannot be written")
                && todo.contains(&format!(
                    "`{section}` is a section it reads but does not own: it was handed it \
                     read-only, and a plugin's migration rewrites only the sections it owns"
                ))
                && todo.ends_with("the settings were left as written"),
            "{todo}"
        );
        // Nothing of the answer is written, its own section included.
        assert_eq!(d, yaml(PLANE_DOC), "the document is left as written");
    }
}

#[test]
fn a_plane_consuming_the_providers_is_handed_the_catalog_merged_under_the_deployment() {
    let mut host = Witness::new(Plane::Migrates);
    host.catalog = Some(
        "\
a: { protocol: one, base_url: 'https://a.example', error_map: { x: rate_limit, y: billing } }
only: { protocol: one, base_url: 'http://192.168.1.9' }
",
    );
    let doc = "\
pools:
  p: { members: [{ model: m }] }
providers:
  a: { base_url: 'http://10.0.0.5', error_map: { y: overloaded } }
  mine: { protocol: two, base_url: 'http://10.0.0.6' }
";
    let (d, _, todos) = run(doc, &host);
    assert!(todos.is_empty(), "{todos:?}");
    assert_eq!(
        host.handed()[Kind::Transport.root()],
        serde_json::json!({
            "a": {
                "protocol": "one",
                "base_url": "http://10.0.0.5",
                "error_map": {"x": "rate_limit", "y": "overloaded"},
            },
            "only": {"protocol": "one", "base_url": "http://192.168.1.9"},
            "mine": {"protocol": "two", "base_url": "http://10.0.0.6"},
        }),
        "the deployment's keys win, a string map merges member by member, and a catalog-only \
         entry is there"
    );
    // The view is the plane's to read: the document's own `providers:` is left as written.
    assert_eq!(
        d[Kind::Transport.root()],
        yaml(
            "{ a: { base_url: 'http://10.0.0.5', error_map: { y: overloaded } }, \
             mine: { protocol: two, base_url: 'http://10.0.0.6' } }"
        )
    );
    assert_eq!(
        d["advanced"]["allow_destinations"],
        yaml("['10.0.0.5', '192.168.1.9', '10.0.0.6']")
    );
}

/// The allow-if-private decision over one host, through a plane that raises it.
fn decide(host: &Witness, url: &str) -> (serde_yaml::Value, Vec<String>, Vec<String>) {
    let doc = format!(
        "pools:\n  p: {{ members: [{{ model: m }}] }}\nproviders:\n  a: {{ base_url: '{url}' }}\n"
    );
    let (d, changes, todos) = run(&doc, host);
    (d["advanced"]["allow_destinations"].clone(), changes, todos)
}

#[test]
fn a_private_host_is_added_exactly_with_a_line_naming_what_it_resolved_to() {
    // An address literal: judged as its own answer, nothing resolved.
    let host = Witness::new(Plane::Migrates);
    let (list, changes, _) = decide(&host, "http://10.0.0.5:8000");
    assert_eq!(list, yaml("['10.0.0.5']"));
    assert!(host.resolved.borrow().is_empty(), "a literal is not resolved");
    assert_eq!(
        changes,
        ["advanced.allow_destinations: added '10.0.0.5' for the plugin 'busbar-witness': resolved \
          at migrate time to 10.0.0.5 (an address literal), every answer private or loopback and \
          none cloud metadata (1.6.0 refuses a private or loopback destination unless it is \
          allowed; only this host is allowed, not every private address)"]
    );

    // An IPv6 unique-local literal, unbracketed in the entry.
    let (list, _, _) = decide(&Witness::new(Plane::Migrates), "http://[fd00::5]:8000");
    assert_eq!(list, yaml("['fd00::5']"));

    // The `localhost` family: loopback by definition, nothing resolved.
    let host = Witness::new(Plane::Migrates);
    let (list, changes, _) = decide(&host, "http://LocalHost:11434");
    assert_eq!(list, yaml("['localhost']"));
    assert!(host.resolved.borrow().is_empty());
    assert!(
        changes[0].contains(
            "resolved at migrate time to loopback (a `localhost` name is loopback by definition)"
        ),
        "{changes:?}"
    );

    // A name: every answer the resolver gives is judged.
    let host = Witness::new(Plane::Migrates).answers("ollama.internal", &["10.1.2.3", "fd00::7"]);
    let (list, changes, todos) = decide(&host, "http://ollama.internal:11434");
    assert_eq!(list, yaml("['ollama.internal']"));
    assert_eq!(*host.resolved.borrow(), ["ollama.internal"]);
    assert!(todos.is_empty(), "{todos:?}");
    assert_eq!(
        changes,
        ["advanced.allow_destinations: added 'ollama.internal' for the plugin 'busbar-witness': \
          resolved at migrate time to 10.1.2.3, fd00::7 (this machine's DNS; where busbar runs it \
          may answer differently, so check this entry there), every answer private or loopback and \
          none cloud metadata (1.6.0 refuses a private or loopback destination unless it is \
          allowed; only this host is allowed, not every private address)"]
    );
}

#[test]
fn a_public_host_is_not_added_and_says_so() {
    let host = Witness::new(Plane::Migrates).answers("api.example.com", &["93.184.216.34"]);
    let (list, changes, todos) = decide(&host, "https://api.example.com/v1");
    assert!(list.is_null(), "nothing added: {list:?}");
    assert!(todos.is_empty(), "{todos:?}");
    assert_eq!(
        changes,
        ["advanced.allow_destinations: not added 'api.example.com' for the plugin \
          'busbar-witness': resolved at migrate time to 93.184.216.34 (this machine's DNS; where \
          busbar runs it may answer differently, so check this entry there), and 93.184.216.34 is \
          public, so it needs no entry"]
    );
}

#[test]
fn cloud_metadata_is_never_added_by_literal_by_name_or_by_answer() {
    for (url, dns) in [
        ("http://169.254.169.254/latest", None),
        ("http://[fd00:ec2::254]/", None),
        ("http://metadata.google.internal/", None),
        ("http://rebinds.internal/", Some("169.254.169.254")),
        ("http://mixed.internal/", Some("10.0.0.9")),
    ] {
        let mut host = Witness::new(Plane::Migrates);
        if let Some(addr) = dns {
            host = host.answers("rebinds.internal", &[addr]);
            host = host.answers("mixed.internal", &["10.0.0.9", "fd00:ec2::23"]);
        }
        let (list, changes, todos) = decide(&host, url);
        assert!(list.is_null(), "{url}: nothing added: {list:?}");
        assert!(todos.is_empty(), "{url}: {todos:?}");
        assert_eq!(changes.len(), 1, "{url}: one line: {changes:?}");
        assert!(
            changes[0].starts_with("advanced.allow_destinations: not added '")
                && changes[0].contains("cloud metadata")
                && changes[0].ends_with(
                    "a migration never allows it (the 1.5.5 `allow_metadata_hosts` carve-outs \
                     keep working as they did)"
                ),
            "{url}: {changes:?}"
        );
    }
}

#[test]
fn a_host_that_cannot_be_decided_is_left_to_the_operator_with_a_todo() {
    // No answer at migrate time.
    let (list, changes, todos) = decide(&Witness::new(Plane::Migrates), "http://gone.internal/");
    assert!(list.is_null() && changes.is_empty());
    assert_eq!(
        todos,
        ["advanced.allow_destinations: 'gone.internal', which the plugin 'busbar-witness' dials, \
          did not resolve at migrate time (no such name), so it was not added; if it is a private \
          or loopback host where busbar runs, add it to advanced.allow_destinations by hand"]
    );
    // A mixed answer: the guard refuses it unless the host is allowed, and core adds it only when
    // every answer is private.
    let host = Witness::new(Plane::Migrates).answers("split.example", &["10.0.0.9", "8.8.8.8"]);
    let (list, changes, todos) = decide(&host, "http://split.example/");
    assert!(list.is_null() && changes.is_empty());
    assert!(
        todos.len() == 1
            && todos[0].starts_with(
                "advanced.allow_destinations: 'split.example', which the plugin 'busbar-witness' \
                 dials, resolved at migrate time to 10.0.0.9, 8.8.8.8"
            )
            && todos[0].contains("some answers private and some public, so it was not added"),
        "{todos:?}"
    );
    // An alternate IPv4 spelling: the guard refuses it whatever the allowlist says.
    let (list, _, todos) = decide(&Witness::new(Plane::Migrates), "http://0x7f.1/");
    assert!(list.is_null());
    assert!(
        todos.len() == 1 && todos[0].contains("is an alternate IPv4 spelling"),
        "{todos:?}"
    );
}

#[test]
fn a_host_already_allowed_is_reported_and_not_resolved_again() {
    let host = Witness::new(Plane::Migrates);
    let doc = "\
pools:
  p: { members: [{ model: m }] }
providers:
  a: { base_url: 'http://ollama.internal' }
  b: { base_url: 'http://ollama.internal:8080' }
advanced:
  allow_destinations: [ollama.internal]
";
    let (d, changes, todos) = run(doc, &host);
    assert_eq!(d["advanced"]["allow_destinations"], yaml("[ollama.internal]"));
    assert!(host.resolved.borrow().is_empty());
    assert!(todos.is_empty());
    assert_eq!(
        changes,
        ["advanced.allow_destinations: 'ollama.internal' for the plugin 'busbar-witness' is \
          already listed, so it was left as it is (not resolved)"],
        "one line for the host, however many times it is raised"
    );
}

/// THE PRIVATE-DESTINATIONS CORPUS FIXTURE (`tests/migration-corpus/private-destinations/`): a
/// 1.5.5 deployment whose providers reach a private literal, `localhost`, a private NAME, a
/// catalog-only private entry and a private `token_url`. Migrated through a plane that raises
/// `AllowDestinationIfPrivate` for each host it dials, every private one is allowed exactly, the
/// public and metadata ones are not, and each decision has its line.
#[test]
fn the_private_destinations_fixture_allows_exactly_its_private_upstreams() {
    let mut host = Witness::new(Plane::Migrates)
        .answers("ollama.internal", &["10.20.0.5"])
        .answers("api.openai.com", &["104.18.6.192"])
        .answers("gateway.example.com", &["93.184.216.34"]);
    host.catalog = Some(include_str!(
        "../../../../../tests/migration-corpus/private-destinations/providers.yaml"
    ));
    let (d, changes, todos) = run(
        include_str!("../../../../../tests/migration-corpus/private-destinations/config.yaml"),
        &host,
    );
    assert!(todos.is_empty(), "{todos:?}");
    let mut allowed: Vec<String> = d["advanced"]["allow_destinations"]
        .as_sequence()
        .expect("a list")
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    allowed.sort();
    assert_eq!(
        allowed,
        [
            "10.0.0.5",
            "10.9.8.7",
            "127.0.0.1",
            "192.168.40.12",
            "localhost",
            "ollama.internal"
        ],
        "the literal, loopback, the private name, the catalog-only entry and the token_url"
    );
    let line = |prefix: &str| {
        changes
            .iter()
            .filter(|c| c.starts_with(prefix))
            .count()
    };
    for added in &allowed {
        assert_eq!(
            line(&format!("advanced.allow_destinations: added '{added}' ")),
            1,
            "{added}: {changes:?}"
        );
    }
    for not in ["api.openai.com", "gateway.example.com", "169.254.169.254"] {
        assert_eq!(
            line(&format!("advanced.allow_destinations: not added '{not}' ")),
            1,
            "{not}: {changes:?}"
        );
    }
    // The deployment overrode the catalog's public `lab-vllm` URL: the catalog's is never dialled.
    assert!(!changes.iter().any(|c| c.contains("vllm.example.com")));
    assert!(d["advanced"]["block_private_addresses"].is_null());
}
