// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::plugin_rows::{NeedLevel, PluginRows, Row, Skipped, Trust};
use busbar_contract::store_calls::StoreDoor;

use crate::preflight::{BuildNote, LinkedRow, RegistryIn};

pub const LINKED_FILE: &str = "(linked)";

pub const LINKED_PUBLISHER: &str = "busbar";

/// One row, with the former names it also answers to and, for a linked row, its door.
#[derive(Clone)]
struct Entry {
    row: Row,
    former: Vec<String>,
    door: Option<DoorFn>,
    /// For a linked auth row stated by [`Rows::with_linked_style`]: the carrier lines its door's
    /// Statement states as the default inbound style (`FACT_DEFAULT_INBOUND_STYLE`), in order.
    inbound_style: Vec<String>,
    /// For a linked auth row stated by [`Rows::with_linked_secret_slots`]: the secret reference
    /// keys its door's Statement names in `secret_refs`.
    secret_slots: Vec<String>,
    /// For a row stated by [`Rows::with_dropped_reference_slots`]: the reference-capable, not-secret
    /// paths its Statement's extensions name (`reference_fields`).
    reference_slots: Vec<String>,
}

impl Entry {
    fn answers_by_alias(&self, word: &str) -> bool {
        self.row.alias == word || self.former.iter().any(|f| f == word)
    }
}

/// THE DOUBLE: a build's rows, linked first.
#[derive(Clone, Default)]
pub struct Rows {
    linked: Vec<Entry>,
    dropped: Vec<Entry>,
    skipped: Vec<Skipped>,
    archives: std::collections::BTreeMap<String, String>,
}

#[must_use]
pub fn row(name: &str, alias: &str, kind: &str) -> Row {
    Row {
        file: format!("{name}.tar.gz"),

        key: name.to_string(),
        name: name.to_string(),
        alias: if alias.is_empty() { name } else { alias }.to_string(),
        kind: kind.to_string(),
        version: "1.5.0".to_string(),
        abi_version: 1,
        trust: Trust::Allowed {
            reason: "unsigned (allowed)".to_string(),
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    }
}

#[must_use]
pub fn skipped(name: &str, alias: &str, reason: &str) -> Skipped {
    Skipped {
        file: format!("{name}.tar.gz"),
        name: name.to_string(),
        alias: alias.to_string(),
        reason: reason.to_string(),
        code: "unsigned",
    }
}

fn linked_entry(name: &str, alias: &str, kind: &str, door: DoorFn, ephemeral: bool) -> Entry {
    let mut row = row(name, alias, kind);
    row.file = LINKED_FILE.to_string();
    row.version = env!("CARGO_PKG_VERSION").to_string();
    row.trust = Trust::Trusted {
        publisher: LINKED_PUBLISHER.to_string(),
        first_party: false,
    };
    row.ephemeral = ephemeral;
    row.in_process = kind == busbar_contract::abi::mechanism::kind::STORE;
    row.linked = true;

    if !alias.is_empty() && alias != name {
        row.key = alias.to_string();
    }
    let former = crate::config::migration_table::former_names(&row.alias)
        .into_iter()
        .filter(|f| *f != row.name && *f != row.alias)
        .collect();
    Entry {
        row,
        former,
        door: Some(door),
        inbound_style: Vec::new(),
        secret_slots: Vec::new(),
        reference_slots: Vec::new(),
    }
}

impl Rows {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_linked(mut self, row: LinkedRow) -> Self {
        self.linked.push(match row {
            LinkedRow::Store((key, ephemeral, door, canonical)) => linked_entry(
                canonical,
                key,
                busbar_contract::abi::mechanism::kind::STORE,
                door,
                ephemeral,
            ),
            LinkedRow::Auth((key, canonical, door)) => linked_entry(
                canonical,
                key,
                busbar_contract::abi::mechanism::kind::AUTH,
                door,
                false,
            ),
        });
        self
    }

    #[must_use]
    pub fn with_linked_style(mut self, row: LinkedRow, lines: &[&str]) -> Self {
        self = self.with_linked(row);
        if let Some(e) = self.linked.last_mut() {
            e.inbound_style = lines.iter().map(|l| (*l).to_string()).collect();
        }
        self
    }

    #[must_use]
    pub fn with_linked_secret_slots(mut self, row: LinkedRow, slots: &[&str]) -> Self {
        self = self.with_linked(row);
        if let Some(e) = self.linked.last_mut() {
            e.secret_slots = slots.iter().map(|s| (*s).to_string()).collect();
        }
        self
    }

    pub(crate) fn inbound_styles(&self) -> Vec<(String, Vec<String>)> {
        self.linked
            .iter()
            .filter(|e| !e.inbound_style.is_empty())
            .map(|e| (e.row.key.clone(), e.inbound_style.clone()))
            .collect()
    }

    #[must_use]
    pub fn with_dropped_secret_slots(mut self, row: Row, slots: &[&str]) -> Self {
        self = self.with_dropped(row);
        if let Some(e) = self.dropped.last_mut() {
            e.secret_slots = slots.iter().map(|s| (*s).to_string()).collect();
        }
        self
    }

    #[must_use]
    pub fn with_dropped_reference_slots(mut self, row: Row, slots: &[&str]) -> Self {
        self = self.with_dropped(row);
        if let Some(e) = self.dropped.last_mut() {
            e.reference_slots = slots.iter().map(|s| (*s).to_string()).collect();
        }
        self
    }

    #[must_use]
    pub fn with_dropped(mut self, row: Row) -> Self {
        self.dropped.push(Entry {
            row,
            former: Vec::new(),
            door: None,
            inbound_style: Vec::new(),
            secret_slots: Vec::new(),
            reference_slots: Vec::new(),
        });
        self
    }

    #[must_use]
    pub fn with_skipped(mut self, skipped: Skipped) -> Self {
        self.skipped.push(skipped);
        self
    }

    #[must_use]
    pub fn with_archive_sha256(mut self, canonical_name: &str, digest: &str) -> Self {
        self.archives.insert(canonical_name.into(), digest.into());
        self
    }

    #[must_use]
    pub fn into_rows(self) -> Arc<dyn PluginRows> {
        Arc::new(self)
    }

    pub(crate) fn linked_doors(&self) -> Vec<(Row, Vec<String>, DoorFn)> {
        self.linked
            .iter()
            .filter_map(|e| {
                let words = [e.row.name.clone(), e.row.alias.clone()]
                    .into_iter()
                    .chain(e.former.iter().cloned())
                    .collect();
                e.door.map(|door| (e.row.clone(), words, door))
            })
            .collect()
    }

    fn all(&self) -> impl Iterator<Item = &Entry> {
        self.linked.iter().chain(self.dropped.iter())
    }

    fn entry(&self, word: &str) -> Option<&Entry> {
        self.all()
            .find(|e| e.row.name == word)
            .or_else(|| self.all().find(|e| e.answers_by_alias(word)))
    }

    fn resolve_kind(&self, word: &str, kind: &str, role: &str) -> Result<&Entry, String> {
        let Some(e) = self.entry(word) else {
            return Err(match self.unresolved_reason(word) {
                Some(s) => format!(
                    "plugin '{word}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{word}' is available (loadable plugins: [{}])",
                    self.dropped
                        .iter()
                        .map(|e| e.row.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if e.row.kind != kind {
            return Err(format!(
                "plugin '{}' has kind '{}', not '{kind}' - it cannot {role}",
                e.row.key, e.row.kind
            ));
        }
        Ok(e)
    }
}

impl std::fmt::Debug for Rows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |entries: &[Entry]| -> Vec<String> {
            entries.iter().map(|e| e.row.name.clone()).collect()
        };
        f.debug_struct("Rows")
            .field("linked", &names(&self.linked))
            .field("dropped", &names(&self.dropped))
            .field("skipped", &self.skipped)
            .finish()
    }
}

impl PluginRows for Rows {
    fn resolve(&self, name_or_alias: &str) -> Option<Row> {
        self.entry(name_or_alias).map(|e| e.row.clone())
    }

    fn archive_sha256(&self, name_or_alias: &str) -> Option<String> {
        let row = self.resolve(name_or_alias)?;
        self.archives.get(&row.name).cloned()
    }

    fn unresolved_reason(&self, name_or_alias: &str) -> Option<Skipped> {
        self.skipped
            .iter()
            .find(|s| s.name == name_or_alias || s.alias == name_or_alias)
            .cloned()
    }

    fn loadable(&self) -> Vec<Row> {
        self.dropped.iter().map(|e| e.row.clone()).collect()
    }

    fn linked(&self) -> Vec<Row> {
        self.linked.iter().map(|e| e.row.clone()).collect()
    }

    fn skipped(&self) -> Vec<Skipped> {
        self.skipped.clone()
    }

    fn store_door(&self, name_or_alias: &str) -> Result<StoreDoor, String> {
        let e = self.resolve_kind(
            name_or_alias,
            busbar_contract::abi::mechanism::kind::STORE,
            "back the governance store",
        )?;
        match (e.row.in_process, e.door) {
            (true, Some(door)) => Ok(StoreDoor::Linked(door)),
            _ => Err(format!(
                "plugin '{}' states no store door: rebuild the plugin against the 1.6.0 SDK",
                e.row.key
            )),
        }
    }

    fn secret_refusal(&self, name_or_alias: &str) -> String {
        self.kind_refusal(
            busbar_contract::abi::mechanism::kind::SECRET,
            "resolve config secrets",
            name_or_alias,
        )
    }

    fn kind_refusal(&self, kind: &str, purpose: &str, name_or_alias: &str) -> String {
        match self.resolve_kind(name_or_alias, kind, purpose) {
            Err(e) => e,
            Ok(e) => format!(
                "plugin '{}': it speaks the 1.5.5 JSON {kind} contract, which this host does not \
                 load — rebuild the plugin against the 1.6.0 SDK",
                e.row.name
            ),
        }
    }

    fn secret_slots(&self, name_or_alias: &str) -> Vec<String> {
        self.entry(name_or_alias)
            .map(|e| e.secret_slots.clone())
            .unwrap_or_default()
    }

    fn reference_slots(&self, name_or_alias: &str) -> Vec<String> {
        self.entry(name_or_alias)
            .map(|e| e.reference_slots.clone())
            .unwrap_or_default()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

#[must_use]
pub fn empty() -> Arc<dyn PluginRows> {
    Rows::new().into_rows()
}

#[must_use]
pub fn linked_only() -> Rows {
    crate::preflight::linked_rows()
        .into_iter()
        .fold(Rows::new(), Rows::with_linked)
}

type DroppedIn = Vec<(PathBuf, Vec<Row>, Vec<Skipped>)>;

fn dropped_in() -> &'static Mutex<DroppedIn> {
    static ONE: OnceLock<Mutex<DroppedIn>> = OnceLock::new();
    ONE.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn drop_in(dir: &Path, rows: Vec<Row>, skipped: Vec<Skipped>) {
    let mut all = dropped_in().lock().unwrap_or_else(|p| p.into_inner());
    all.retain(|(d, _, _)| d != dir);
    all.push((dir.to_path_buf(), rows, skipped));
}

pub fn registry_stand_in(
    i: RegistryIn<'_>,
    note: &mut dyn FnMut(BuildNote<'_>),
) -> Result<Arc<dyn PluginRows>, String> {
    use crate::test_support::store_double::{NAME as DOUBLE, SECRET_REF_PATHS};
    let mut rows = i
        .linked
        .into_iter()
        .fold(Rows::new(), |rows, row| match row {
            LinkedRow::Store(store) if store.3 == DOUBLE => {
                rows.with_linked_secret_slots(row, SECRET_REF_PATHS)
            }
            row => rows.with_linked(row),
        });
    let Some(plugins) = i.plugins else {
        return Ok(rows.into_rows());
    };
    if !plugins.enabled {
        note(BuildNote::Off);
        return Ok(rows.into_rows());
    }
    let dir = Path::new(&plugins.dir);
    if let Some((_, dropped, skipped)) = dropped_in()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(d, _, _)| d == dir)
        .cloned()
    {
        rows = dropped.into_iter().fold(rows, Rows::with_dropped);
        rows = skipped.into_iter().fold(rows, Rows::with_skipped);
    }
    let built = rows.into_rows();
    note(BuildNote::Scanned {
        rows: built.as_ref(),
        copies: &[],
    });
    Ok(built)
}
