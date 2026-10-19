// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET DOUBLE: the kernel's own secret port — the contract's [`SecretAxis`] /
//! [`SecretCalls`], the seam the composition root installs and the kernel names nothing behind —
//! answered in process, so the kernel's tests resolve `{ env: VAR }` / `{ file: PATH }` references
//! with no secret plugin linked (ARCHITECT R-FIX3, 2026-09-26: a behaviour double the kernel's own
//! tests need lives in-crate, linked only). It is not a plugin and not a door, and it names neither
//! plugin crate.
//!
//! FAITHFUL TEXT (coordinator ruling on #565, 2026-10-07): every refusal the double produces is the
//! shipped source's, byte for byte, and its error kind is the source's; each string cites the line
//! of the pinned source it reproduces (`env src/lib.rs` is the env source's at rev 495318c,
//! `file src/lib.rs` the file source's at rev 479c833 — the revs the workspace root pins). Its
//! sugars are what each source's Statement states, declared through the one path the root's loaded
//! Statements take (`Sugars::declare`): the kernel reads them off this axis and names none. A rev
//! bump that changes a
//! refusal changes it here too; the root's suite
//! (`crates/busbar/src/root/tests/linked_secret_sources.rs`, `root/tests/linked.rs`) pins the real
//! sources' words through the linked axis, so the two cannot drift silently apart.
//!
//! It produces a subset of the sources' refusals, the ones the kernel's tests need: a missing /
//! blank `key` / `path`, an unset or non-UTF-8 variable, an unreadable file, an empty value. The sources' own guards beyond those (the blank
//! value / blank file rule, the regular-file check, the size cap) are theirs alone and are proven at
//! the root. A value it returns is the source's bytes, untouched.

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::{
    REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
    SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
};
use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND, ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::{SecretRef, Sugars};

/// The stand-in secret axis a test build installs in place of the root's (`preflight::STAND_IN`).
pub struct SecretsStandIn;

/// The variable source's word: its module alias and its reference sugar, as its Statement states
/// them (the shipped source's, so a kernel test reads the operator's 1.5.5 spelling).
const VAR_SOURCE: &str = "env";
/// The variable source's settings key.
const ENV_KEY: &str = "key";
/// The file source's word.
const PATH_SOURCE: &str = "file";
/// The file source's settings key.
const FILE_KEY: &str = "path";
/// THE THIRD SOURCE's word (a test-only source no shipped plugin is): admitted only inside
/// [`with_third_source`], so the default axis is the shipped two.
pub const THIRD: &str = "stash";
/// The third source's settings key.
const THIRD_KEY: &str = "entry";
/// The one entry the third source holds, and its value.
pub const THIRD_ENTRY: (&str, &str) = ("stash-entry", "stash-material");

std::thread_local! {
    /// Whether this thread's axis admits the third source ([`with_third_source`]).
    static THIRD_ADMITTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with the third secret source admitted on this thread's stand-in axis: its Statement
/// declares its own sugar (`{ stash: <entry> }`), and every reading and resolution on this thread
/// sees it, through the one path the shipped two take.
pub fn with_third_source<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            THIRD_ADMITTED.with(|t| t.set(self.0));
        }
    }
    let _restore = Restore(THIRD_ADMITTED.with(|t| t.replace(true)));
    f()
}

fn third_admitted() -> bool {
    THIRD_ADMITTED.with(std::cell::Cell::get)
}

fn rw(class: u32, from: &str, to: &str) -> (u32, String, String) {
    (class, from.to_string(), to.to_string())
}

/// Each admitted source's Statement rewrites, as its rendering reads back: the shipped two state
/// their 1.5.5 words, the third its own.
fn statements() -> Vec<(&'static str, Vec<(u32, String, String)>)> {
    let mut rows = vec![
        (
            "env-double",
            vec![
                rw(REWRITE_ALIAS, VAR_SOURCE, ""),
                rw(REWRITE_SUGAR, VAR_SOURCE, ENV_KEY),
                rw(REWRITE_SUGAR_SHOWN, VAR_SOURCE, "VAR"),
                rw(
                    REWRITE_SUGAR_NAMES,
                    VAR_SOURCE,
                    "the environment variable name",
                ),
                rw(REWRITE_SUGAR_ROLE, VAR_SOURCE, SUGAR_ROLE_FILL),
            ],
        ),
        (
            "file-double",
            vec![
                rw(REWRITE_ALIAS, PATH_SOURCE, ""),
                rw(REWRITE_SUGAR, PATH_SOURCE, FILE_KEY),
                rw(REWRITE_SUGAR_NAMES, PATH_SOURCE, "the file to read"),
                rw(REWRITE_SUGAR_ROLE, PATH_SOURCE, SUGAR_ROLE_PATH),
            ],
        ),
    ];
    if third_admitted() {
        rows.push(("stash-double", vec![rw(REWRITE_SUGAR, THIRD, THIRD_KEY)]));
    }
    rows
}

/// Which of the sources a reference names.
#[derive(Clone, Copy)]
enum Double {
    Env,
    File,
    Third,
}

fn double(module: &str) -> Option<Double> {
    match module {
        VAR_SOURCE => Some(Double::Env),
        PATH_SOURCE => Some(Double::File),
        THIRD if third_admitted() => Some(Double::Third),
        _ => None,
    }
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

/// The env source's refusal of a missing / blank `key` (env src/lib.rs:42-45 @ 495318c).
const ENV_NEEDS_KEY: &str = "secret module 'env' requires settings.key naming the environment \
     variable (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)";

/// The file source's refusal of a missing / blank `path` (file src/lib.rs:83-86 @ 479c833).
const FILE_NEEDS_PATH: &str = "secret module 'file' requires settings.path naming the file \
     (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)";

/// The non-blank string setting `field` of a settings document; `missing` is the source's refusal
/// when it is absent or blank.
fn setting(settings: &[u8], field: &str, missing: &str) -> Result<String, SecretRefused> {
    // The kernel's resolver hands every call the reference's settings as a JSON object
    // (`config::secret::SecretResolver::resolve`), so a document that is not one is a broken
    // caller, not an operator's refusal: the double does not produce the sources' "secret settings
    // are not a JSON object" refusal (env src/lib.rs:95 @ 495318c, file src/lib.rs:141 @ 479c833),
    // and a test that reaches this fails loudly.
    let doc: serde_json::Map<String, serde_json::Value> = if settings.is_empty() {
        serde_json::Map::new()
    } else {
        // Panics by design (coordinator ruling on #565): the kernel always passes an object, and the plugins' faithful "secret settings are not a JSON object" text trips secret-hygiene check3.
        serde_json::from_slice(settings)
            .expect("the kernel hands a secret module its settings as a JSON object")
    };
    match doc.get(field).and_then(|v| v.as_str()) {
        Some(v) if !v.trim().is_empty() => Ok(v.to_string()),
        _ => Err(refused(ERROR_KIND_INVALID, missing.to_string())),
    }
}

fn resolve_env(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let var = setting(settings, ENV_KEY, ENV_NEEDS_KEY)?;
    let Some(raw) = std::env::var_os(&var) else {
        // env src/lib.rs:55-57 @ 495318c (NotFound).
        return Err(refused(
            ERROR_KIND_NOT_FOUND,
            format!(
                "secret {VAR_SOURCE}:{var} cannot resolve: environment variable '{var}' is \
                 unset"
            ),
        ));
    };
    let value = raw.into_string().map_err(|_| {
        // env src/lib.rs:62-67 @ 495318c (Invalid).
        refused(
            ERROR_KIND_INVALID,
            format!(
                "secret {VAR_SOURCE}:{var} cannot resolve: environment variable '{var}' IS \
                 SET but its \
                 value is not valid UTF-8, so it cannot be read as a secret — this is an \
                 ENCODING problem, not a missing variable; re-export it as UTF-8 (setting it \
                 again will not help)"
            ),
        )
    })?;
    if value.is_empty() {
        // env src/lib.rs:68-71 @ 495318c (Invalid).
        return Err(refused(
            ERROR_KIND_INVALID,
            format!(
                "secret {VAR_SOURCE}:{var} resolved to an EMPTY value; a secret must be \
                 non-empty (fail-closed)"
            ),
        ));
    }
    Ok(value.into_bytes())
}

fn resolve_file(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let path = setting(settings, FILE_KEY, FILE_NEEDS_PATH)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        // The kind is the source's io mapping (file src/lib.rs:62-67 @ 479c833), the text its io
        // refusal (file src/lib.rs:68 @ 479c833).
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
            std::io::ErrorKind::PermissionDenied => ERROR_KIND_DENIED,
            std::io::ErrorKind::Other => ERROR_KIND_INVALID,
            _ => ERROR_KIND_UNAVAILABLE,
        };
        refused(
            kind,
            format!("secret {PATH_SOURCE}:{path} cannot resolve: {e}"),
        )
    })?;
    if bytes.is_empty() {
        // file src/lib.rs:112-115 @ 479c833 (Invalid).
        return Err(refused(
            ERROR_KIND_INVALID,
            format!(
                "secret {PATH_SOURCE}:{path} resolved to an EMPTY file; a secret must be \
                 non-empty (fail-closed)"
            ),
        ));
    }
    Ok(bytes)
}

/// The third source: its one entry's value; any other entry is not found.
fn resolve_third(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let entry = setting(
        settings,
        THIRD_KEY,
        "the third source requires settings.entry",
    )?;
    if entry == THIRD_ENTRY.0 {
        return Ok(THIRD_ENTRY.1.as_bytes().to_vec());
    }
    Err(refused(
        ERROR_KIND_NOT_FOUND,
        format!("secret {THIRD}:{entry} cannot resolve: no such entry"),
    ))
}

impl SecretCalls for Double {
    fn resolve(&self, settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        match self {
            Double::Env => resolve_env(settings),
            Double::File => resolve_file(settings),
            Double::Third => resolve_third(settings),
        }
        .map(Secret::new)
    }
}

impl SecretAxis for SecretsStandIn {
    fn sugars(&self) -> Sugars {
        let mut sugars = Sugars::default();
        for (name, rewrites) in statements() {
            sugars
                .declare(name, &rewrites)
                .expect("the stand-in sources declare distinct sugars");
        }
        sugars
    }

    fn answers(&self, module: &str) -> bool {
        double(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        double(module).is_some()
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        double(module)
            .map(|d| Arc::new(d) as Arc<dyn SecretCalls>)
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))
    }

    fn open(
        &self,
        module: &str,
        _: &serde_json::Value,
        _: &busbar_contract::secret::ResolveRef<'_, Vec<u8>>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        self.shared(module)
    }
}

// ── THE TESTS' REFERENCES, by declared role (no source named) ──────────────────────────────────

/// The installed axis's sugar whose declared role is `role`.
fn by_role(role: &str) -> busbar_contract::secret_ref::Sugar {
    crate::config::secret::sugars()
        .with_role(role)
        .cloned()
        .unwrap_or_else(|| panic!("the installed axis declares a `{role}` sugar"))
}

/// The reference a config `${VAR}` names: the fill sugar's `{ <fill>: var }`, canonical.
pub fn fill_ref(var: impl Into<String>) -> SecretRef {
    by_role(SUGAR_ROLE_FILL).reference(var)
}

/// A key file's reference: the path sugar's `{ <path>: file }`, canonical.
pub fn path_ref(file: impl Into<String>) -> SecretRef {
    by_role(SUGAR_ROLE_PATH).reference(file)
}

/// The fill sugar's word (what the operator spells `{ <fill>: VAR }` with).
pub fn fill_word() -> String {
    by_role(SUGAR_ROLE_FILL).word
}

/// The path sugar's word.
pub fn path_word() -> String {
    by_role(SUGAR_ROLE_PATH).word
}

/// The variable a fill reference names, either way it is spelled.
pub fn fill_var(r: &SecretRef) -> Option<&str> {
    role_value(r, SUGAR_ROLE_FILL)
}

/// The file a path reference names, either way it is spelled.
pub fn path_of(r: &SecretRef) -> Option<&str> {
    role_value(r, SUGAR_ROLE_PATH)
}

fn role_value<'a>(r: &'a SecretRef, role: &str) -> Option<&'a str> {
    let sugar = crate::config::secret::sugars().with_role(role).cloned()?;
    if r.module != sugar.word {
        return None;
    }
    r.settings
        .get(&sugar.setting)
        .or_else(|| r.settings.get(&sugar.word))
        .and_then(|v| v.as_str())
}

/// A reference read as the kernel reads its configuration's: against the installed axis's declared
/// sugars ([`crate::config::secret::declared`]).
///
/// # Errors
///
/// The library's refusal, with its path and position.
pub fn read_ref(yaml: &str) -> Result<SecretRef, serde_yaml::Error> {
    crate::config::secret::declared(serde_yaml::Deserializer::from_str(yaml))
}
