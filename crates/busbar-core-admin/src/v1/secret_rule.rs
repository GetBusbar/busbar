// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET RULE (ADMIN-API-1.6 §14.2) over a document an admin read serves.
//!
//! A configured secret position serializes as `{"set": bool, "secret_ref": string|null}`: the
//! reference text when the value is configured as one (`env:VAR`, `file:/path`, a secret module),
//! `null` for an inline value. Never a value, never a hash of a value. Public key material (a PEM
//! certificate or public key) is shown as `{"fingerprint": "sha256:<hex>"}` of its public bytes.
//!
//! A position is secret when its field name names secret material, when it sits in a plugin
//! settings bag and the plugin did not declare the key public (core reads no plugin setting for
//! meaning, so every undeclared key is treated the same), or when the value is a PEM private key.
//! The rule is a projection over the tree the read is about to serve; it never consults the
//! resolved secret and so cannot carry one.

use std::collections::BTreeSet;

use busbar_contract::json::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Map, Value};
use busbar_contract::secret_ref::Sugars;

/// Field names that are secret material wherever they appear: exactly, or as an `_`-delimited
/// tail (`api_key`, `aws_secret_access_key`, `client_secret`).
const STRONG: &[&str] = &[
    "api_key",
    "client_secret",
    "private_key",
    "signing_key",
    "access_token",
    "refresh_token",
    "id_token",
    "subject_token",
    "api_secret",
    "secret_access_key",
    "password",
    "passphrase",
    "bearer",
    "credential_secret",
];

/// Field names that are secret material only when they are the whole name: a TLS `key`, an
/// identity provider's `token`, an at-rest `previous` key, a request header carrying a credential.
const EXACT: &[&str] = &[
    "key",
    "token",
    "secret",
    "previous",
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
];

/// `_`-delimited tails that name secret material (`foo_secret`, `bar_token`, `baz_key`).
const TAILS: &[&str] = &["secret", "token", "password", "key"];

/// Names that end like a secret but are public material, shown as written.
const PUBLIC: &[&str] = &["public_key"];

/// The kernel readback is still built on the previous JSON library (DEP-3 migration pending). Its
/// exact-number values reach sonic's writer as a one-member token struct under this name; the
/// projection restores each one to the number it carries.
const FOREIGN_NUMBER: &str = "$serde_json::private::Number";

/// What the rule reads: the shorthand the running generation admits (what a `{word: value}`
/// reference means) and which plugin settings each module declares public.
pub(crate) struct Rule<'a> {
    pub(crate) sugars: &'a Sugars,
    pub(crate) public: &'a (dyn Fn(&str) -> BTreeSet<String> + Sync),
}

impl Rule<'_> {
    /// Apply the rule to every position of `value`, in place.
    pub(crate) fn project(&self, value: &mut Value) {
        self.walk(value);
    }

    fn walk(&self, value: &mut Value) {
        if let Some(text) = value.as_str() {
            if let Some(shown) = pem(text) {
                *value = shown;
            }
            return;
        }
        if let Some(items) = value.as_array_mut() {
            for item in items.iter_mut() {
                self.walk(item);
            }
            return;
        }
        if let Some(number) = foreign_number(value) {
            *value = number;
            return;
        }
        let Some(members) = value.as_object_mut() else {
            return;
        };
        let module = members
            .get(&"module")
            .and_then(|m| m.as_str())
            .map(str::to_owned);
        for (key, member) in members.iter_mut() {
            let name = field_name(key);
            if secret_named(name) {
                *member = position(member, self.sugars);
            } else if name == "settings" && member.is_object() {
                self.bag(member, module.as_deref());
            } else {
                self.walk(member);
            }
        }
    }

    /// A plugin settings bag: a key the module declared public is shown as written (still under
    /// the rule), every other key as a secret position.
    fn bag(&self, bag: &mut Value, module: Option<&str>) {
        let public = module.map(|m| (self.public)(m)).unwrap_or_default();
        let Some(members) = bag.as_object_mut() else {
            return;
        };
        for (key, member) in members.iter_mut() {
            if public.contains(key) && !secret_named(key) {
                self.walk(member);
            } else {
                *member = position(member, self.sugars);
            }
        }
    }
}

/// The last segment of a JSON pointer key (a document patch names its target this way), else
/// the key itself.
fn field_name(key: &str) -> &str {
    if key.starts_with('/') {
        key.rsplit('/').next().unwrap_or(key)
    } else {
        key
    }
}

/// Whether a field of this name holds secret material.
pub(crate) fn secret_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let name = lower.replace("~1", "/").replace("~0", "~");
    if PUBLIC.iter().any(|p| tail(&name, p)) {
        return false;
    }
    EXACT.contains(&name.as_str())
        || STRONG.iter().any(|n| tail(&name, n))
        || TAILS.iter().any(|n| qualified(&name, n))
}

fn tail(name: &str, needle: &str) -> bool {
    name == needle || qualified(name, needle)
}

/// `name` carries `needle` as an `_`- or `-`-delimited tail behind at least one character.
fn qualified(name: &str, needle: &str) -> bool {
    name.len() > needle.len() + 1
        && name.ends_with(needle)
        && matches!(
            name.as_bytes().get(name.len() - needle.len() - 1),
            Some(b'_' | b'-')
        )
}

/// The projection of one secret position: `{"set", "secret_ref"}`.
fn position(value: &Value, sugars: &Sugars) -> Value {
    let (set, reference) = classify(value, sugars);
    let mut shown = Map::new();
    shown.insert("set", Value::from(set));
    shown.insert(
        "secret_ref",
        reference
            .as_deref()
            .map_or_else(Value::new_null, Value::from),
    );
    Value::from(shown)
}

/// Whether the position is set, and the reference text when it is configured as a reference.
fn classify(value: &Value, sugars: &Sugars) -> (bool, Option<String>) {
    if value.is_null() {
        return (false, None);
    }
    if let Some(text) = value.as_str() {
        let none = text == busbar_contract::secret_ref::SECRET_MODULE_NONE;
        return (!text.is_empty() && !none, None);
    }
    let Some(members) = value.as_object() else {
        // A number, a boolean or a list at a secret position is an inline value.
        return (true, None);
    };
    // Already projected (a nested read, or the kernel's own presence marker).
    if let Some(set) = members.get(&"set").and_then(|s| s.as_bool()) {
        if members.len() == 2 && members.get(&"secret_ref").is_some() {
            let reference = members
                .get(&"secret_ref")
                .and_then(|r| r.as_str())
                .map(str::to_owned);
            return (set, reference);
        }
    }
    if let Some(present) = members.get(&"present").and_then(|p| p.as_bool()) {
        if members.get(&"value").and_then(|v| v.as_str()) == Some("hidden") {
            return (present, None);
        }
    }
    if members.len() == 1 && members.get(&"literal").is_some() {
        return (true, None);
    }
    if let Some(module) = members.get(&"module").and_then(|m| m.as_str()) {
        return (
            true,
            Some(canonical(module, members.get(&"settings"), sugars)),
        );
    }
    if let Some(template) = members.get(&"template") {
        let module = template
            .get("source")
            .and_then(|s| s.get("module"))
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        return (
            true,
            Some(format!("template using secret module '{module}'")),
        );
    }
    if members.len() == 1 {
        if let Some((word, target)) = members.iter().next() {
            if let (Some(sugar), Some(target)) = (sugars.get(word), target.as_str()) {
                return (true, Some(format!("{}:{target}", sugar.word)));
            }
        }
    }
    // Any other shape is not a reference the running grammar reads: shown as set, never echoed.
    (true, None)
}

/// A canonical `{module, settings}` reference: the declared shorthand when it is exactly one
/// declared sugar's single setting (`env:VAR`), else the module alone, as
/// [`Sugars::describe`] names it.
fn canonical(module: &str, settings: Option<&Value>, sugars: &Sugars) -> String {
    let only = settings.and_then(|s| s.as_object()).and_then(|members| {
        let mut entries = members.iter();
        match (entries.next(), entries.next()) {
            (Some((key, value)), None) => value.as_str().map(|v| (key, v)),
            _ => None,
        }
    });
    if let Some((key, value)) = only {
        if let Some(sugar) = sugars
            .iter()
            .find(|s| s.answers(module) && s.setting == key)
        {
            return format!("{}:{value}", sugar.word);
        }
    }
    format!("secret module '{module}'")
}

/// A PEM block: a private key is a secret position; a certificate or public key is shown as the
/// fingerprint of its public bytes.
fn pem(text: &str) -> Option<Value> {
    let begin = text.find("-----BEGIN ")?;
    let label_end = text[begin + 11..].find("-----")? + begin + 11;
    let label = &text[begin + 11..label_end];
    if label.contains("PRIVATE") || label.contains("ENCRYPTED") {
        let mut shown = Map::new();
        shown.insert("set", Value::from(true));
        shown.insert("secret_ref", Value::new_null());
        return Some(Value::from(shown));
    }
    let body_start = label_end + 5;
    let body_end = text[body_start..]
        .find("-----END ")
        .map_or(text.len(), |end| body_start + end);
    let encoded: String = text[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .unwrap_or_else(|_| text.as_bytes().to_vec());
    let mut shown = Map::new();
    shown.insert(
        "fingerprint",
        Value::from(format!("sha256:{}", busbar_contract::redacted::sha256_hex(&bytes)).as_str()),
    );
    Some(Value::from(shown))
}

/// One foreign exact-number token, restored to its number.
fn foreign_number(value: &Value) -> Option<Value> {
    let members = value.as_object()?;
    if members.len() != 1 {
        return None;
    }
    let lexeme = members.get(&FOREIGN_NUMBER)?.as_str()?;
    busbar_contract::json::parse_value(lexeme.as_bytes())
        .ok()
        .filter(|n| n.is_number())
}
