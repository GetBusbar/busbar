//! Pure ownership split for an admitted plane's declared registration maps.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::json::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Map, Value};

use super::{ConfiguredUpstreams, UpstreamDef, Upstreams};
use crate::auth_bindings::{bind_upstreams_for, ImplicitInstance, OperatorAuth, UpstreamView};
use crate::config::min3::{parse_upstream_entry, UpstreamAuthForm, UpstreamCfg};
use crate::plugin_config::TrustAnchor;

const CORE_KEYS: &[&str] = &[
    "url",
    "command",
    "tls",
    "auth",
    "upstream_credentials",
    "allow_private",
];
const MAX_PATHS: usize = 4;

/// A plane-visible bag and its separately owned core definitions. The authored input is never mutated.
pub struct Declared {
    pub visible_bag: Value,
    pub definitions: ConfiguredUpstreams,
    pub origins: BTreeMap<Box<str>, String>,
    pub parsed: BTreeMap<Box<str>, UpstreamCfg>,
    retained: BTreeMap<String, Map>,
    pointers: Vec<String>,
    instance: String,
}

/// An implicit outbound auth instance to open, scoped to one declared registration.
/// Credentials remain source references, never resolved values in plane-visible config.
pub struct DeclaredAuth {
    pub upstream: Box<str>,
    pub spec: ImplicitInstance,
    pub credential: Option<busbar_contract::secret_ref::SecretRef>,
}

impl Declared {
    /// Resolve binding owners and mode flags against admitted descriptions before this generation opens.
    pub fn resolve_bindings(
        &mut self,
        styles: &[(&str, Vec<&str>)],
        operator: &[OperatorAuth<'_>],
        flags: &dyn Fn(&str, &str) -> u64,
    ) -> Result<Vec<DeclaredAuth>, Vec<String>> {
        let views: Vec<_> = self
            .parsed
            .iter()
            .map(|(name, cfg)| UpstreamView {
                name,
                auth: cfg.auth.as_ref(),
                upstream_credentials: cfg.upstream_credentials,
                stdio: self
                    .definitions
                    .get(name)
                    .is_some_and(|d| d.command.is_some()),
            })
            .collect();
        let bindings = bind_upstreams_for(&self.instance, &views, styles, operator, flags)?;
        let mut definitions = BTreeMap::new();
        let mut implicit = Vec::new();
        for binding in bindings {
            let Some(current) = self.definitions.get(&binding.name) else {
                return Err(vec![
                    "an outbound binding has no declared registration".into()
                ]);
            };
            let mut definition = (*current).clone();
            definition.auth = binding.auth;
            if let Some(spec) = binding.implicit {
                let credential = self
                    .parsed
                    .get(&binding.name)
                    .and_then(|cfg| cfg.auth.as_ref())
                    .and_then(|auth| match &auth.form {
                        UpstreamAuthForm::Bearer(value) => Some(value.clone()),
                        UpstreamAuthForm::ApiKey { secret, .. } => Some(secret.clone()),
                        UpstreamAuthForm::TokenExchange { subject_token, .. } => {
                            Some(subject_token.clone())
                        }
                        _ => None,
                    });
                implicit.push(DeclaredAuth {
                    upstream: binding.name.clone(),
                    spec,
                    credential,
                });
            }
            definitions.insert(binding.name, Arc::new(definition));
        }
        self.definitions = ConfiguredUpstreams::from_definitions(definitions);
        Ok(implicit)
    }

    /// Only this instance's caller-mode registrations, after resolve_bindings.
    pub fn caller_upstreams(&self) -> Vec<Box<str>> {
        self.definitions
            .names()
            .filter(|name| {
                self.definitions
                    .get(name)
                    .is_some_and(|d| d.auth.as_ref().is_some_and(|a| a.caller))
            })
            .map(Box::from)
            .collect()
    }

    /// Reattach core fields after a plane normalizes its visible bag. A plane may not change core policy.
    pub fn reattach(&self, normalized_visible: &Value) -> Result<Value, Vec<String>> {
        let pointers: Vec<_> = self.pointers.iter().map(String::as_str).collect();
        let members = registrations(normalized_visible, &pointers)?;
        let mut refused = Vec::new();
        for (_, path, value) in members {
            for key in CORE_KEYS {
                if value.get(*key).is_some() {
                    refused.push(format!(
                        "{path}/{key}: a plane cannot return a core-owned field"
                    ));
                }
            }
        }
        let mut result = normalized_visible.clone();
        for (path, core) in &self.retained {
            let tokens = decode(path).map_err(|e| vec![e])?;
            let Some(member) = node_mut(&mut result, &tokens).and_then(Value::as_object_mut) else {
                refused.push(format!(
                    "{path}: a plane cannot remove or rename a registration's retained core fields"
                ));
                continue;
            };
            for (key, value) in core {
                member.insert(key, value.clone());
            }
        }
        if refused.is_empty() {
            Ok(result)
        } else {
            Err(refused)
        }
    }
}

/// Split this instance's admitted registration objects from the plane's opaque settings.
pub fn declared(
    instance: &str,
    authored: &Value,
    pointers: &[&str],
    anchor: &dyn Fn(&str) -> Result<Arc<TrustAnchor>, String>,
) -> Result<Declared, Vec<String>> {
    let members = registrations(authored, pointers)?;
    let mut visible_bag = authored.clone();
    let mut definitions = BTreeMap::new();
    let mut origins = BTreeMap::new();
    let mut parsed = BTreeMap::new();
    let mut retained = BTreeMap::new();
    let mut refused = Vec::new();
    for (name, path, value) in members {
        let at = format!("{instance}{path}");
        let mut core = Map::new();
        for key in CORE_KEYS {
            if let Some(value) = value.get(*key) {
                core.insert(*key, value.clone());
            }
        }
        let entry = Value::from(core.clone());
        let cfg = match parse_upstream_entry(&at, &entry) {
            Ok(cfg) => cfg,
            Err(mut errors) => {
                refused.append(&mut errors);
                continue;
            }
        };
        match UpstreamDef::from_config_at(&name, &at, &entry, &cfg, anchor) {
            Ok(mut def) => {
                if let (Some(auth), Some(config)) = (def.auth.as_mut(), cfg.auth.as_ref()) {
                    if !matches!(config.form, UpstreamAuthForm::Instance(_)) {
                        auth.instance = implicit_identity(instance, &name);
                    }
                }
                definitions.insert(name.clone().into_boxed_str(), Arc::new(def));
                parsed.insert(name.clone().into_boxed_str(), cfg);
                origins.insert(name.into_boxed_str(), path.clone());
            }
            Err(mut errors) => {
                refused.append(&mut errors);
                continue;
            }
        }
        let tokens = decode(&path).map_err(|e| vec![e])?;
        if let Some(member) = node_mut(&mut visible_bag, &tokens).and_then(Value::as_object_mut) {
            for key in CORE_KEYS {
                member.remove(key);
            }
        }
        retained.insert(path, core);
    }
    if !refused.is_empty() {
        return Err(refused);
    }
    Ok(Declared {
        visible_bag,
        definitions: ConfiguredUpstreams::from_definitions(definitions),
        origins,
        parsed,
        retained,
        pointers: pointers.iter().map(|p| (*p).to_owned()).collect(),
        instance: instance.to_owned(),
    })
}

/// Reserved, unambiguous host identity; operator names cannot contain the NUL namespace marker.
pub(crate) fn implicit_identity(instance: &str, name: &str) -> Box<str> {
    format!(
        "\0upstream:{}:{instance}{}:{name}",
        instance.len(),
        name.len()
    )
    .into_boxed_str()
}

fn escaped(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn decode(pointer: &str) -> Result<Vec<String>, String> {
    let Some(body) = pointer.strip_prefix('/') else {
        return Err("upstream path must be an absolute JSON pointer".into());
    };
    body.split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c != '~' {
                    decoded.push(c);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err("upstream path contains an invalid JSON pointer escape".into()),
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn node<'a>(mut value: &'a Value, tokens: &[String]) -> Result<Option<&'a Value>, String> {
    for token in tokens {
        let Some(map) = value.as_object() else {
            return Err("a declared registration parent must be an object".into());
        };
        let Some(child) = map.get(&token.as_str()) else {
            return Ok(None);
        };
        value = child;
    }
    Ok(Some(value))
}

fn node_mut<'a>(mut value: &'a mut Value, tokens: &[String]) -> Option<&'a mut Value> {
    for token in tokens {
        value = value.as_object_mut()?.get_mut(&token.as_str())?;
    }
    Some(value)
}

fn registrations<'a>(
    authored: &'a Value,
    pointers: &[&str],
) -> Result<Vec<(String, String, &'a Value)>, Vec<String>> {
    if pointers.len() > MAX_PATHS {
        return Err(vec![
            "at most four upstream registration paths are allowed".into()
        ]);
    }
    let mut parents: Vec<Vec<String>> = Vec::new();
    let mut names = BTreeSet::new();
    let mut members = Vec::new();
    for pointer in pointers {
        let mut tokens = decode(pointer).map_err(|e| vec![e])?;
        if tokens.pop().as_deref() != Some("*") || tokens.iter().any(|p| p == "*") {
            return Err(vec![
                "an upstream path must end with its only wildcard".into()
            ]);
        }
        if parents
            .iter()
            .any(|p| tokens.starts_with(p) || p.starts_with(&tokens))
        {
            return Err(vec!["upstream registration declarations overlap".into()]);
        }
        parents.push(tokens.clone());
        let Some(parent) = node(authored, &tokens).map_err(|e| vec![format!("{pointer}: {e}")])?
        else {
            continue;
        };
        let Some(map) = parent.as_object() else {
            return Err(vec![format!(
                "{pointer}: a registration map must be an object"
            )]);
        };
        for (name, value) in map {
            if name.is_empty()
                || name.len() > super::MAX_NAME
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
            {
                return Err(vec![format!("{pointer}: a registration name must use 1..={} lowercase letters, digits, _, . or -", super::MAX_NAME)]);
            }
            if !names.insert(name.to_string()) {
                return Err(vec![format!(
                    "registration '{name}' is declared more than once in this instance"
                )]);
            }
            if !value.is_object() {
                return Err(vec![format!(
                    "{pointer}: registration '{name}' must be an object"
                )]);
            }
            let mut path = String::new();
            for token in &tokens {
                path.push('/');
                path.push_str(&escaped(token));
            }
            path.push('/');
            path.push_str(&escaped(name));
            members.push((name.to_string(), path, value));
        }
    }
    Ok(members)
}

/// Exact core-owned secret positions admitted for migration LIFT, before literals become references.
/// This only authorizes positions; it does not move, resolve or expose any credential value.
pub fn core_secret_paths(
    authored: &Value,
    pointers: &[&str],
) -> Result<BTreeSet<String>, Vec<String>> {
    let mut paths = BTreeSet::new();
    for (_, path, value) in registrations(authored, pointers)? {
        if let Some(command) = value.get("command").filter(|v| !v.is_null()) {
            if !command.is_object() {
                return Err(vec![format!("{path}/command must be an object")]);
            }
            if let Some(env) = command.get("env").filter(|v| !v.is_null()) {
                let Some(env) = env.as_object() else {
                    return Err(vec![format!("{path}/command/env must be an object")]);
                };
                for (key, _) in env {
                    paths.insert(format!("{path}/command/env/{}", escaped(key)));
                }
            }
        }
        if let Some(tls) = value.get("tls").filter(|v| !v.is_null()) {
            if !tls.is_object() {
                return Err(vec![format!("{path}/tls must be an object")]);
            }
            if tls.get("client_identity").is_some() {
                paths.insert(format!("{path}/tls/client_identity"));
            }
        }
        let Some(auth) = value.get("auth").filter(|v| !v.is_null()) else {
            continue;
        };
        if auth.is_string() {
            continue;
        }
        let Some(auth) = auth.as_object() else {
            return Err(vec![format!(
                "{path}/auth must be an instance name or an auth form"
            )]);
        };
        let mut forms = 0;
        for (form, value) in auth {
            let suffix = match form {
                "cache_max_s" => continue,
                "bearer" => Some(""),
                "api_key" => Some("secret"),
                "token_exchange" => Some("subject_token"),
                "connection" => None,
                _ => return Err(vec![format!("{path}/auth has an unknown auth form")]),
            };
            forms += 1;
            if form == "bearer" {
                paths.insert(format!("{path}/auth/bearer"));
            } else {
                if !value.is_object() {
                    return Err(vec![format!("{path}/auth/{form} must be an object")]);
                }
                if let Some(key) = suffix {
                    if value.get(key).is_some() {
                        paths.insert(format!("{path}/auth/{form}/{key}"));
                    }
                }
            }
        }
        if forms != 1 {
            return Err(vec![format!("{path}/auth must name exactly one form")]);
        }
    }
    Ok(paths)
}
