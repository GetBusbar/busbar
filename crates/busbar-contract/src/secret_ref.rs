// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `SecretRef` — the SECRET REFERENCE type, extracted out of `busbar`'s crate-private
//! `crates/busbar-core/src/config/secret.rs` into its own tiny crate, and since merged into the
//! contract (DECISIONS #83: contract = shapes). It is the ONE `SecretRef`: the placeholder
//! `kinds::SecretRef(String)` the secret kind's trait used to take is gone, and a secret plugin
//! resolves this type.
//!
//! Every secret/external value in busbar config is `{ module: <secret-module>, settings: {…} }` — a
//! reference to a SECRET MODULE (`kind: secret` plugin), never the secret itself. The core grammar
//! is that canonical form and the bare scalar `none`. Everything else is a SUGAR a secret plugin
//! DECLARES in its Statement (OWNER LAW 2026-09-27: the kernel knows zero plugin names; the sugar is
//! a shorthand the plugins declare and the kernel resolves generically): a one-key map
//! `{ <word>: <value> }`, where the plugin's `REWRITE_SUGAR` rewrite names the word and the settings
//! key the value lands under, so `{ <word>: X }` is `{ module: <word>, settings: { <key>: X } }`.
//! This crate names no plugin and no sugar word.
//!
//! TWO READINGS, one visitor:
//!
//! * [`SecretRef::deserialize_declared`]: against the sugars the host's loaded Statements declare
//!   ([`Sugars`]). A word no Statement declares is refused where it stands, and every refusal that
//!   lists the sugars renders them from those Statements, so the text, its path and its line and
//!   column are what they were when the sugars were core grammar. The host reads its own
//!   configuration this way.
//! * The plain `Deserialize`: CONTEXT-FREE (this crate holds no state, and a plugin image holds no
//!   host table), for a plugin reading its own settings. It takes the sugar's SHAPE — a one-key
//!   `{ <word>: <non-blank string> }` whose word is not core grammar — as a reference to `<word>`,
//!   its value under that same word ([`SecretRef::sugar`]); the host binds the word to the plugin
//!   that declares it, and refuses one no Statement declares, when the reference reaches it
//!   ([`Sugars::canonical`]).
//!
//! **Why this left the binary.** `SecretRef` used to live `pub(crate)` inside the `busbar` binary
//! crate — unreachable from `busbar-plugin-pack` or any future schema-generation tooling. The
//! `x-busbar-secret` schema vocabulary entry's `oneOf` (the reference shape busbar-ui composes for a
//! secret field) must be generated FROM this real type, not hand-written as a parallel copy that can
//! drift from the actual deserializer. [`Sugars::oneof_schema`] is that derivation, over the same
//! declared sugars `busbar`'s engine parses a live config with. The two are written by hand against
//! each other, not generated one from the other, so what actually keeps them in step is the
//! round-trip test that runs the same table of shapes through both and demands the same verdict —
//! the drift it caught first was a whitespace-only value the schema accepted and the visitor did not.
//!
//! `{ literal: <value> }` (the escape hatch for a plugin whose own legitimately-shaped config field
//! collides with a reference shape) is **not** part of `SecretRef` and never was — it is handled one
//! layer above `SecretRef` parsing, inside busbar's `resolve_settings()`, as a wrapper around the
//! field. Its word is core grammar, so no Statement may declare it as a sugar.
//!
//! `SecretRef` holds no secret material — only the module name and its opaque settings — so it is
//! safe to derive `Debug`/`Clone`/`PartialEq` on it and on every struct embedding it.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;

use crate::abi::mechanism::door::{
    REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN, SUGAR_ROLE_FILL,
    SUGAR_ROLE_PATH,
};
use crate::secret::Resolved;

/// The DECLARED-KEYLESS module name: `api_key: none` (a plain scalar — the only spelling) says
/// "this upstream takes NO credential".
///
/// It exists because a secret reference that fails to resolve now REFUSES BOOT instead of degrading
/// to an empty credential, and a keyless upstream (one that legitimately requires no credential at
/// all) needs a way to say so on purpose rather than by pointing at a variable it knows is unset. It
/// names no source and carries
/// no settings, so it resolves to NOTHING: a resolver asked for its bytes is a hard error, and only
/// a call site that genuinely permits an absent credential may accept it.
pub const SECRET_MODULE_NONE: &str = "none";
/// The TEMPLATE reference's module name: a credential value `${VAR}` filled only in part
/// (`"Bearer ${TOKEN}"`). Its settings' `text` is the value as written, each `${VAR}` a reference
/// to the sugar whose role is the fill ([`SUGAR_ROLE_FILL`]), which the host resolves where it reads
/// the value ([`SecretRef::resolve_template`]); the text itself holds no secret byte. It names no
/// secret module: only a host reader that resolves templates accepts it, and every other resolver
/// refuses it as an unknown module (fail-closed). Not the bare word `template`: the config grammar
/// already spells that word (a prompt's `template`), and a module name is one no other config word
/// shares.
pub const SECRET_MODULE_TEMPLATE: &str = "fill-template";
/// The template module's settings key holding the value as written.
pub const SECRET_TEMPLATE_SETTING_TEXT: &str = "text";

/// The canonical form's two keys and the escape hatch: core grammar, never a sugar word.
const CORE_WORDS: [&str; 4] = ["module", "settings", SECRET_MODULE_NONE, "literal"];

/// "At least one non-whitespace character", as [`Sugars::oneof_schema`] states the non-empty rule.
/// The visitor's own check is `value.trim().is_empty()`, and `minLength: 1` is NOT that: a string of
/// three spaces has length three, so the schema accepted a blank sugar value while the engine
/// refused it — a form that validates in busbar-ui and then fails at boot. This pattern says what
/// the deserializer means.
const NON_BLANK: &str = r"\S";

/// A reference to a secret, resolved through a secret MODULE. See the module docs for the accepted
/// YAML/JSON spellings. `settings` is the module's own (opaque) config — busbar passes it through
/// verbatim and never interprets it beyond the sugar its plugin declares.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SecretRef {
    /// The secret module resolving this reference (a `kind: secret` plugin's name, alias or
    /// declared sugar word).
    pub module: String,
    /// The module's own settings (opaque to busbar; a sugar's value sits under its declared key).
    // settings-leak-lint: allow — DECLARATION, not a projection. This bag is the REFERENCE itself
    // — which environment variable, which path, which plugin-module key names the secret — and
    // holding it is the entire reason this type exists: a config that carried the credential
    // inline would not need a `SecretRef` at all. The resolved bytes never land here. The one
    // admin read that serializes a tree containing one, `GET /config/settings`, runs
    // `admin::v1::service::redact_settings_bags` structurally over the whole body, which rewrites
    // every `settings` member at any depth — this one included — into `settings_keys`.
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl SecretRef {
    /// The CONTEXT-FREE reading of the sugar `{ word: value }`: a reference to `word`, its value
    /// under that same word. The host binds it to the declaring plugin's settings key
    /// ([`Sugars::canonical`]).
    pub fn sugar(word: impl Into<String>, value: impl Into<String>) -> Self {
        let word = word.into();
        let mut settings = serde_json::Map::new();
        settings.insert(word.clone(), serde_json::Value::String(value.into()));
        Self {
            module: word,
            settings,
        }
    }

    /// The sugar this reference was read as without a table ([`SecretRef::sugar`]): `(word, value)`
    /// when its settings are exactly its own word's string.
    pub fn sugar_parts(&self) -> Option<(&str, &str)> {
        match (self.settings.len(), self.settings.get(&self.module)) {
            (1, Some(serde_json::Value::String(v))) => Some((self.module.as_str(), v.as_str())),
            _ => None,
        }
    }

    /// A TEMPLATE reference over `text`, a value as written whose every `${VAR}` names a value of
    /// the fill sugar ([`SECRET_MODULE_TEMPLATE`]).
    pub fn template(text: impl Into<String>) -> Self {
        let mut settings = serde_json::Map::new();
        settings.insert(
            SECRET_TEMPLATE_SETTING_TEXT.to_string(),
            serde_json::Value::String(text.into()),
        );
        Self {
            module: SECRET_MODULE_TEMPLATE.to_string(),
            settings,
        }
    }

    /// The template's text, when this is a [`SECRET_MODULE_TEMPLATE`] reference.
    pub fn template_text(&self) -> Option<&str> {
        if self.module == SECRET_MODULE_TEMPLATE {
            self.settings
                .get(SECRET_TEMPLATE_SETTING_TEXT)
                .and_then(|v| v.as_str())
        } else {
            None
        }
    }

    /// THE VALUE THIS REFERENCE NAMES, resolved through `resolve`: a template's text with each
    /// `${VAR}` replaced by what `resolve` answers for `{ <fill>: VAR }` (`fill`: the word of the
    /// sugar whose role is the fill, [`Sugars::with_role`]), any other reference handed to `resolve`
    /// whole. `${VAR}` is read as the config interpolation reads it (every byte up to the first
    /// `}`); a `$` that opens no `${VAR}` is kept as written.
    ///
    /// # Errors
    ///
    /// `resolve`'s error for the first reference that does not resolve, a template with no text, or
    /// a template whose `${VAR}` no declared sugar fills.
    pub fn resolve_template(
        &self,
        fill: Option<&str>,
        resolve: &crate::secret::ResolveRef<'_, String>,
    ) -> Result<Resolved<String>, String> {
        if self.module != SECRET_MODULE_TEMPLATE {
            return resolve(self);
        }
        let text = self
            .template_text()
            .ok_or_else(|| "a template reference carries no text".to_string())?;
        // The value is built inside the answer it is handed back in: every resolved piece moves
        // into it and is zeroized where it was, so no piece is held bare.
        let mut out = Resolved::new(String::with_capacity(text.len()));
        let mut rest = text;
        while let Some(at) = rest.find("${") {
            out.0.push_str(&rest[..at]);
            let after = &rest[at + 2..];
            match after.find('}') {
                Some(end) if end > 0 => {
                    let word = fill.ok_or_else(|| {
                        "no loaded secret plugin declares the sugar a `${…}` fill names, so the \
                         template does not resolve (fail-closed)"
                            .to_string()
                    })?;
                    let piece = resolve(&SecretRef::sugar(word, &after[..end]))?;
                    out.0.push_str(&piece.0);
                    rest = &after[end + 1..];
                }
                _ => {
                    out.0.push_str("${");
                    rest = after;
                }
            }
        }
        out.0.push_str(rest);
        Ok(out)
    }

    /// The `none` reference: an EXPLICIT declaration that there is no credential. See
    /// [`SECRET_MODULE_NONE`].
    pub fn none() -> Self {
        Self {
            module: SECRET_MODULE_NONE.to_string(),
            settings: serde_json::Map::new(),
        }
    }

    /// True when this reference is the explicit keyless declaration (`api_key: none`).
    pub fn is_none(&self) -> bool {
        self.module == SECRET_MODULE_NONE
    }

    /// A short display form for error messages, with no table: `none`, `<word>:<value>` for a
    /// sugar read without one ([`SecretRef::sugar_parts`]), or `secret module '<name>'`. The host
    /// renders a declared sugar's canonical form the same way through [`Sugars::describe`].
    pub fn describe(&self) -> String {
        if self.is_none() {
            SECRET_MODULE_NONE.to_string()
        } else if let Some((word, value)) = self.sugar_parts() {
            format!("{word}:{value}")
        } else {
            format!("secret module '{}'", self.module)
        }
    }

    /// Read a reference against the sugars the host's loaded Statements declare: a word none of
    /// them declares is refused at its key, as an unknown field, and every refusal that lists the
    /// sugars lists these.
    ///
    /// # Errors
    ///
    /// The shape is not a secret reference.
    pub fn deserialize_declared<'de, D>(deserializer: D, sugars: &Sugars) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RefVisitor {
            sugars: Some(sugars),
        })
    }

    /// [`SecretRef::deserialize_declared`] over a JSON value.
    ///
    /// # Errors
    ///
    /// The value is not a secret reference.
    pub fn from_value_declared(
        value: serde_json::Value,
        sugars: &Sugars,
    ) -> Result<Self, serde_json::Error> {
        Self::deserialize_declared(value, sugars)
    }
}

// ── THE DECLARED SUGARS ────────────────────────────────────────────────────────────────────────

/// ONE DECLARED SUGAR, as a secret plugin's Statement states it (its `REWRITE_SUGAR*` rewrites).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sugar {
    /// The reference key: the `k` in `{ k: X }`. It also names the plugin as a module.
    pub word: String,
    /// The plugin whose Statement declares it.
    pub plugin: String,
    /// The settings key the value lands under (`REWRITE_SUGAR`'s `to`).
    pub setting: String,
    /// The placeholder its refusals show for the value (`REWRITE_SUGAR_SHOWN`; the settings key
    /// when unstated).
    pub shown: String,
    /// What the value names, in the refusal of a reference that does not set it
    /// (`REWRITE_SUGAR_NAMES`; `the <key>` when unstated).
    pub names: String,
}

impl Sugar {
    /// The canonical reference `{ word: value }` reads as: `{ module: word, settings: { setting:
    /// value } }`.
    pub fn reference(&self, value: impl Into<String>) -> SecretRef {
        let mut settings = serde_json::Map::new();
        settings.insert(
            self.setting.clone(),
            serde_json::Value::String(value.into()),
        );
        SecretRef {
            module: self.word.clone(),
            settings,
        }
    }
}

/// THE SUGARS THE LOADED STATEMENTS DECLARE, in word order: what the host reads secret references
/// against. Built only from Statements ([`Sugars::declare`]); empty, nothing but core grammar reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sugars {
    sugars: Vec<Sugar>,
    /// `(role, word)`: each role at most once.
    roles: Vec<(String, String)>,
}

impl Sugars {
    /// Declare every sugar `plugin`'s Statement rewrites state (`(class, from, to)`, as a Statement
    /// rendering reads back): each `REWRITE_SUGAR` a sugar, each `REWRITE_SUGAR_SHOWN`,
    /// `REWRITE_SUGAR_NAMES` and `REWRITE_SUGAR_ROLE` a fact about one of them. Every other class is
    /// not a sugar's and is passed over.
    ///
    /// # Errors
    ///
    /// A word another plugin already declares, a word that is core grammar, a sugar with no
    /// settings key, a fact about a word this Statement does not declare, an unknown role, or a role
    /// another plugin already claims. Each refusal names the word and both plugins.
    pub fn declare(
        &mut self,
        plugin: &str,
        rewrites: &[(u32, String, String)],
    ) -> Result<(), String> {
        let mut mine: Vec<Sugar> = Vec::new();
        for (class, from, to) in rewrites {
            if *class != REWRITE_SUGAR {
                continue;
            }
            if CORE_WORDS.contains(&from.as_str()) {
                return Err(format!(
                    "plugin '{plugin}' declares the sugar `{from}:`, but `{from}` is core \
                     reference grammar and no plugin may claim it"
                ));
            }
            if to.trim().is_empty() {
                return Err(format!(
                    "plugin '{plugin}' declares the sugar `{from}:` with no settings key \
                     for its value"
                ));
            }
            if let Some(other) = self
                .sugars
                .iter()
                .chain(mine.iter())
                .find(|s| s.word == *from)
            {
                return Err(format!(
                    "plugin claim conflict: the sugar `{from}:` is declared by both '{}' and \
                     '{plugin}' - a reference key must name one plugin; remove one",
                    other.plugin
                ));
            }
            mine.push(Sugar {
                word: from.clone(),
                plugin: plugin.to_string(),
                setting: to.clone(),
                shown: to.clone(),
                names: format!("the {to}"),
            });
        }
        let mut roles: Vec<(String, String)> = Vec::new();
        for (class, from, to) in rewrites {
            if ![REWRITE_SUGAR_SHOWN, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE].contains(class) {
                continue;
            }
            let Some(sugar) = mine.iter_mut().find(|s| s.word == *from) else {
                return Err(format!(
                    "plugin '{plugin}' states a fact about the sugar `{from}:`, which its \
                     Statement does not declare"
                ));
            };
            match *class {
                REWRITE_SUGAR_SHOWN => sugar.shown = to.clone(),
                REWRITE_SUGAR_NAMES => sugar.names = to.clone(),
                _ => {
                    if ![SUGAR_ROLE_FILL, SUGAR_ROLE_PATH].contains(&to.as_str()) {
                        return Err(format!(
                            "plugin '{plugin}' gives the sugar `{from}:` the role '{to}', \
                             which the core grammar does not name"
                        ));
                    }
                    if let Some((_, word)) = self
                        .roles
                        .iter()
                        .chain(roles.iter())
                        .find(|(role, _)| role == to)
                    {
                        let other = self
                            .sugars
                            .iter()
                            .chain(mine.iter())
                            .find(|s| s.word == *word)
                            .map_or(plugin, |s| s.plugin.as_str());
                        return Err(format!(
                            "plugin claim conflict: the sugar role '{to}' is claimed by \
                             both '{other}' (`{word}:`) and '{plugin}' (`{from}:`) - a role names \
                             one sugar; remove one"
                        ));
                    }
                    roles.push((to.clone(), from.clone()));
                }
            }
        }
        self.sugars.extend(mine);
        self.sugars.sort_by(|a, b| a.word.cmp(&b.word));
        self.roles.extend(roles);
        Ok(())
    }

    /// Whether no sugar is declared.
    pub fn is_empty(&self) -> bool {
        self.sugars.is_empty()
    }

    /// The declared sugars, in word order.
    pub fn iter(&self) -> impl Iterator<Item = &Sugar> {
        self.sugars.iter()
    }

    /// The sugar `word` declares.
    pub fn get(&self, word: &str) -> Option<&Sugar> {
        self.sugars.iter().find(|s| s.word == word)
    }

    /// The sugar the core grammar's `role` names ([`SUGAR_ROLE_FILL`], [`SUGAR_ROLE_PATH`]).
    pub fn with_role(&self, role: &str) -> Option<&Sugar> {
        self.roles
            .iter()
            .find(|(r, _)| r == role)
            .and_then(|(_, word)| self.get(word))
    }

    /// `secret` in its CANONICAL form: a sugar read without a table ([`SecretRef::sugar`]) bound to
    /// the declaring plugin's settings key. Any other reference is itself.
    pub fn canonical(&self, secret: &SecretRef) -> SecretRef {
        match secret
            .sugar_parts()
            .and_then(|(word, value)| self.get(word).map(|s| s.reference(value)))
        {
            Some(canonical) => canonical,
            None => secret.clone(),
        }
    }

    /// The value of a declared sugar's reference, read off its canonical (or table-free) form:
    /// `(sugar, value)` when `secret` names a declared word and sets its value as a string.
    pub fn value_of<'a>(&'a self, secret: &'a SecretRef) -> Option<(&'a Sugar, &'a str)> {
        let sugar = self.get(&secret.module)?;
        secret
            .settings
            .get(&sugar.setting)
            .or_else(|| secret.settings.get(&sugar.word))
            .and_then(|v| v.as_str())
            .map(|v| (sugar, v))
    }

    /// A short display form for error messages: `none`, `<word>:<value>` for a declared sugar's
    /// reference (whichever way it was spelled), or `secret module '<name>'`.
    pub fn describe(&self, secret: &SecretRef) -> String {
        match self.value_of(secret) {
            Some((sugar, value)) => format!("{}:{value}", sugar.word),
            None => secret.describe(),
        }
    }

    /// The refusal of a key no Statement declares in a reference: serde's own unknown-field text,
    /// listing the canonical keys and then every declared sugar.
    pub fn unknown(&self, word: &str) -> String {
        let mut names = vec!["module", "settings"];
        names.extend(self.sugars.iter().map(|s| s.word.as_str()));
        format!("unknown field `{word}`, {}", one_of(&names))
    }

    /// `{ w: <shown> }` for each sugar.
    fn forms(&self) -> Vec<String> {
        self.sugars
            .iter()
            .map(|s| format!("{{ {}: <{}> }}", s.word, s.shown))
            .collect()
    }

    /// `` `{ w: … }` `` for each sugar, joined `" / "`.
    fn elided(&self) -> String {
        self.sugars
            .iter()
            .map(|s| format!("`{{ {}: … }}`", s.word))
            .collect::<Vec<_>>()
            .join(" / ")
    }

    /// Derive the `x-busbar-secret` field's `oneOf` JSON Schema (2020-12) fragment from the shapes
    /// [`SecretRef::deserialize_declared`] accepts against these sugars — the canonical
    /// `{ module, settings }` form, the bare scalar `none`, and one `{ <word> }` object per declared
    /// sugar. This is the schema busbar-ui composes a secret reference against — never a bare
    /// string.
    ///
    /// This fragment is WRITTEN OUT here rather than mechanically generated from the deserializer —
    /// serde exposes no schema to generate one from — so "it cannot drift" is not something the code
    /// makes true on its own. What pins it is the round-trip test in this module's own suite: one
    /// table of shapes, each fed to BOTH the validator built from this fragment and the declared
    /// reading, with the two verdicts asserted equal.
    ///
    /// `{ "literal": <value> }` is excluded, and needs no special-casing to be: `literal` is core
    /// grammar, never a sugar, and is handled one layer above `SecretRef` parsing.
    pub fn oneof_schema(&self) -> serde_json::Value {
        let mut one_of = vec![
            // The explicit keyless declaration — the ONE scalar spelling a secret field accepts.
            // Every other bare scalar is rejected as an inline literal, so this is a `const`, not a
            // loosening of the "never a bare string" rule.
            serde_json::json!({"const": SECRET_MODULE_NONE}),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "module": {"type": "string", "pattern": NON_BLANK},
                    "settings": {"type": "object"},
                },
                "required": ["module"],
                "additionalProperties": false,
            }),
        ];
        for s in &self.sugars {
            let mut properties = serde_json::Map::new();
            properties.insert(
                s.word.clone(),
                serde_json::json!({"type": "string", "pattern": NON_BLANK}),
            );
            one_of.push(serde_json::json!({
                "type": "object",
                "properties": properties,
                "required": [s.word],
                "additionalProperties": false,
            }));
        }
        serde_json::json!({ "oneOf": one_of })
    }
}

/// serde's own `expected …` clause over `names` (its `OneOf`), byte for byte.
fn one_of(names: &[&str]) -> String {
    match names {
        [] => "there are no fields".to_string(),
        [one] => format!("expected `{one}`"),
        [a, b] => format!("expected `{a}` or `{b}`"),
        _ => format!(
            "expected one of {}",
            names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

// ── THE ONE VISITOR ────────────────────────────────────────────────────────────────────────────

/// The reference visitor: against the declared sugars when the host hands them in, context-free
/// otherwise (see the module docs).
struct RefVisitor<'s> {
    sugars: Option<&'s Sugars>,
}

/// Why a sugar is refused, rendered against the declared sugars ([`RefVisitor::refuse`]).
enum Refusal<'a> {
    /// A second sugar key after `first`.
    Two { first: &'a str, second: &'a str },
    /// A sugar beside `module:`.
    Both { word: &'a str },
    /// A sugar beside `settings:`.
    WithSettings { word: &'a str },
    /// A blank sugar value.
    Blank { word: &'a str },
    /// A sugar value that is not a string (the value may be the secret itself).
    NotText { word: &'a str },
}

impl RefVisitor<'_> {
    /// The one refusal message every inline-scalar spelling shares. Names the accepted shapes and
    /// NEVER echoes what it was handed — the value it was handed is the secret.
    fn inline_literal<E: de::Error>(&self) -> E {
        let mut forms = match self.sugars {
            Some(sugars) => sugars.forms(),
            None => vec!["{ <sugar>: <value> }".to_string()],
        };
        forms.push("{ module: <secret-module>, settings: {…} }".to_string());
        E::custom(format!(
            "a secret value must be a REFERENCE, never an inline literal (the value is not \
             echoed): use {}, or the bare scalar `none` to declare an upstream that takes NO \
             credential",
            forms.join(", ")
        ))
    }

    /// Whether `word` reads as a sugar: a declared one, or (with no table) any word that is not
    /// core grammar.
    fn is_sugar(&self, word: &str) -> bool {
        match self.sugars {
            Some(sugars) => sugars.get(word).is_some(),
            None => !CORE_WORDS.contains(&word),
        }
    }

    /// `refusal`, or the unknown-field refusal of the first word in it no Statement declares (the
    /// key that refusal stood on before the sugars were declared).
    fn refuse<E: de::Error>(&self, refusal: Refusal<'_>) -> E {
        let words: Vec<&str> = match &refusal {
            Refusal::Two { first, second } => vec![*first, *second],
            Refusal::Both { word }
            | Refusal::WithSettings { word }
            | Refusal::Blank { word }
            | Refusal::NotText { word } => vec![*word],
        };
        if let Some(unknown) = words.into_iter().find(|w| !self.is_sugar(w)) {
            return E::custom(self.unknown(unknown));
        }
        let elided = match self.sugars {
            Some(sugars) => sugars.elided(),
            None => "`{ <sugar>: … }`".to_string(),
        };
        match refusal {
            Refusal::Two { .. } => E::custom(match self.sugars {
                Some(sugars) => format!(
                    "a secret reference takes exactly one of {}",
                    sugars
                        .iter()
                        .map(|s| format!("`{}:`", s.word))
                        .collect::<Vec<_>>()
                        .join(" / ")
                ),
                None => "a secret reference takes exactly one sugar key".to_string(),
            }),
            Refusal::Both { .. } => E::custom(format!(
                "a secret reference is either `{{ module: …, settings: … }}` or the {elided} \
                 sugar, not both"
            )),
            Refusal::WithSettings { .. } => E::custom(format!(
                "the {elided} sugar takes no `settings:` (use the canonical `{{ module: …, \
                 settings: … }}` form instead)"
            )),
            Refusal::Blank { word } => E::custom(format!(
                "a `{{ {word}: … }}` secret reference must name a non-empty value"
            )),
            Refusal::NotText { .. } => self.inline_literal(),
        }
    }

    /// The unknown-field refusal of `word`.
    fn unknown(&self, word: &str) -> String {
        match self.sugars {
            Some(sugars) => sugars.unknown(word),
            None => Sugars::default().unknown(word),
        }
    }

    /// The refusal of a map that is neither form.
    fn needs<E: de::Error>(&self) -> E {
        let shown = match self.sugars {
            Some(sugars) if !sugars.is_empty() => sugars
                .iter()
                .map(|s| format!("`{{ {}: <{}> }}`", s.word, s.shown))
                .collect::<Vec<_>>()
                .join(" / "),
            Some(_) => {
                return E::custom(
                    "a secret reference needs `module:` (with optional `settings:`)".to_string(),
                )
            }
            None => "`{ <sugar>: <value> }`".to_string(),
        };
        E::custom(format!(
            "a secret reference needs `module:` (with optional `settings:`) or the {shown} sugar"
        ))
    }
}

/// THE ONE VISITOR: the declared reading ([`SecretRef::deserialize_declared`]) and the
/// context-free one ([`SecretRef`]'s `Deserialize`) both drive it.
impl<'de> Visitor<'de> for RefVisitor<'_> {
    type Value = SecretRef;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut forms = vec!["{ module: <secret-module>, settings: {…} }".to_string()];
        match self.sugars {
            Some(sugars) => forms.extend(sugars.forms()),
            None => forms.push("{ <sugar>: <value> }".to_string()),
        }
        write!(
            f,
            "a secret reference map: {}, or the bare scalar `none`",
            forms.join(", ")
        )
    }

    // A bare scalar here is almost always a LITERAL SECRET pasted inline (the exact mistake this
    // type exists to prevent). Reject it with a message that NEVER echoes the value — serde's
    // default invalid-type error would print the value verbatim into boot logs.
    //
    // The ONE exception is the reserved word `none`: the explicit "this upstream takes no
    // credential" declaration (see [`SECRET_MODULE_NONE`]). It is a SCALAR and only a scalar — it
    // names no source, so a `{ none: … }` map form would invite settings that mean nothing. A real
    // secret that happened to be the literal string `none` would fail CLOSED here (no credential
    // presented), never leak.
    fn visit_str<E>(self, v: &str) -> Result<SecretRef, E>
    where
        E: de::Error,
    {
        if v == SECRET_MODULE_NONE {
            return Ok(SecretRef::none());
        }
        Err(self.inline_literal())
    }

    // Every OTHER scalar form, for the same reason and with the same non-echoing message. A secret
    // is not always quoted: `api_key: 483920175534` and `api_key: true` are perfectly ordinary
    // YAML, and each one landed on serde's default `invalid type` error — which prints the value it
    // received. The one path this type exists to keep a secret off (the boot log) is exactly where
    // it went, and unquoted is the spelling nobody thinks to check.
    fn visit_u64<E>(self, _v: u64) -> Result<SecretRef, E>
    where
        E: de::Error,
    {
        Err(self.inline_literal())
    }

    fn visit_i64<E>(self, _v: i64) -> Result<SecretRef, E>
    where
        E: de::Error,
    {
        Err(self.inline_literal())
    }

    fn visit_f64<E>(self, _v: f64) -> Result<SecretRef, E>
    where
        E: de::Error,
    {
        Err(self.inline_literal())
    }

    fn visit_bool<E>(self, _v: bool) -> Result<SecretRef, E>
    where
        E: de::Error,
    {
        Err(self.inline_literal())
    }

    fn visit_bytes<E>(self, _v: &[u8]) -> Result<SecretRef, E>
    where
        E: de::Error,
    {
        Err(self.inline_literal())
    }

    fn visit_map<A>(self, mut map: A) -> Result<SecretRef, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut module: Option<String> = None;
        let mut settings: Option<serde_json::Map<String, serde_json::Value>> = None;
        let mut sugar: Option<(String, String)> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "module" => {
                    if module.is_some() {
                        return Err(de::Error::duplicate_field("module"));
                    }
                    // Read as an untyped value and check the shape ourselves: a typed
                    // `next_value::<String>()` on a mismatched scalar makes serde echo the scalar
                    // verbatim into the boot log, and this deserializer NEVER echoes what it was
                    // handed. A non-string `module:` names no module — refuse without printing the
                    // value.
                    match map.next_value::<serde_json::Value>()? {
                        serde_json::Value::String(s) => module = Some(s),
                        _ => {
                            return Err(de::Error::custom(
                                "a secret reference `module:` must be a string naming a secret \
                                 module (the value is not echoed)",
                            ))
                        }
                    }
                }
                "settings" => {
                    if settings.is_some() {
                        return Err(de::Error::duplicate_field("settings"));
                    }
                    // Untyped-then-shape-check: `settings:` given as a scalar is a pasted
                    // credential in the wrong slot; a typed `next_value::<Map>()` would echo it.
                    // Refuse with the shared non-echoing message.
                    match map.next_value::<serde_json::Value>()? {
                        serde_json::Value::Object(m) => settings = Some(m),
                        _ => return Err(self.inline_literal()),
                    }
                }
                word if self.is_sugar(word) => {
                    if let Some((first, _)) = &sugar {
                        return Err(self.refuse(Refusal::Two {
                            first,
                            second: word,
                        }));
                    }
                    // Untyped-then-shape-check: a non-string sugar value (e.g. an unquoted YAML
                    // number/bool, or a nested map holding a literal) must not be echoed.
                    match map.next_value::<serde_json::Value>()? {
                        serde_json::Value::String(s) => sugar = Some((word.to_string(), s)),
                        _ => return Err(self.refuse(Refusal::NotText { word })),
                    }
                }
                other => return Err(de::Error::custom(self.unknown(other))),
            }
        }

        match (module, sugar) {
            (Some(_), Some((word, _))) => Err(self.refuse(Refusal::Both { word: &word })),
            (Some(module), None) => {
                if module.trim().is_empty() {
                    return Err(de::Error::custom(
                        "a secret reference `module:` must be non-empty",
                    ));
                }
                Ok(SecretRef {
                    module,
                    settings: settings.unwrap_or_default(),
                })
            }
            (None, Some((word, value))) => {
                if settings.is_some() {
                    return Err(self.refuse(Refusal::WithSettings { word: &word }));
                }
                if value.trim().is_empty() {
                    return Err(self.refuse(Refusal::Blank { word: &word }));
                }
                Ok(match self.sugars.and_then(|s| s.get(&word)) {
                    Some(declared) => declared.reference(value),
                    None => SecretRef::sugar(word, value),
                })
            }
            (None, None) => Err(self.needs()),
        }
    }
}

/// The CONTEXT-FREE reading (see the module docs): what a plugin reads its own settings with.
impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // The one visitor with no table, its scalar refusals stated here, where this impl's own
        // reading of each form is read: every scalar but the bare `none` is an inline literal,
        // refused without echoing it; a map is the one visitor's.
        struct Free;

        impl<'de> Visitor<'de> for Free {
            type Value = SecretRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                RefVisitor { sugars: None }.expecting(f)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretRef, E> {
                if v == SECRET_MODULE_NONE {
                    return Ok(SecretRef::none());
                }
                Err(RefVisitor { sugars: None }.inline_literal())
            }

            fn visit_u64<E: de::Error>(self, _v: u64) -> Result<SecretRef, E> {
                Err(RefVisitor { sugars: None }.inline_literal())
            }

            fn visit_i64<E: de::Error>(self, _v: i64) -> Result<SecretRef, E> {
                Err(RefVisitor { sugars: None }.inline_literal())
            }

            fn visit_f64<E: de::Error>(self, _v: f64) -> Result<SecretRef, E> {
                Err(RefVisitor { sugars: None }.inline_literal())
            }

            fn visit_bool<E: de::Error>(self, _v: bool) -> Result<SecretRef, E> {
                Err(RefVisitor { sugars: None }.inline_literal())
            }

            fn visit_bytes<E: de::Error>(self, _v: &[u8]) -> Result<SecretRef, E> {
                Err(RefVisitor { sugars: None }.inline_literal())
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<SecretRef, A::Error> {
                RefVisitor { sugars: None }.visit_map(map)
            }
        }

        deserializer.deserialize_any(Free)
    }
}

#[cfg(test)]
#[path = "tests/secret_ref_tests.rs"]
mod tests;
