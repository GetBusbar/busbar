// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Auth outbound bindings: one auth instance per binding, implicit dialect and upstream bindings, credential mode
//! (IF §12.18). Run at every config load (`--validate` too), after describe and before 2c opens the auth
//! instances. Everything here is pure over what the registry decoded and what K7 parsed; the binder opens the
//! instances it answers. The style words and settings keys are core vocabulary
//! (`busbar_contract::config::dialect_styles`); no plugin name is compared here.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::config::dialect_styles::{self as styles, Row, Settings};
use busbar_contract::config::outbound_owner;
use busbar_plugin_loader::encode::plane::{DialectAuthOwned, PresentationOwned};

mod outbound;
mod upstream;

pub use outbound::{upstream_credential, OwnedUpstreamIn};
pub use upstream::{bind_upstreams, check_upstream_credentials, UpstreamBinding, UpstreamView};

/// Where an implicit instance's `credential` reference comes from. The binder reads that reference from the
/// config it already walked (no second copy of a secret reference is held here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialFrom {
    /// `providers.<p>.api_key`.
    ProviderApiKey(Box<str>),
    /// The secret of `upstreams.<name>.auth`'s form (`bearer`, `api_key.secret`, `token_exchange.subject_token`).
    UpstreamForm(Box<str>),
    /// No credential (`connection`: the caller's grant is presented).
    None,
}

/// One in-memory auth instance core opens in 2c with the operator's instances. Never written to config.yaml.
/// `name` is the configured name under `auth:` (texts show it as `auth.<name>`). No `Debug`: the settings may
/// carry URLs.
#[derive(Clone, PartialEq, Eq)]
pub struct ImplicitInstance {
    pub name: Box<str>,
    /// The owner: the unique admitted auth plugin declaring `style` as a D_OUTBOUND_STYLE item.
    pub module: Box<str>,
    pub style: Box<str>,
    pub credential: CredentialFrom,
    pub settings: Settings,
}

impl ImplicitInstance {
    /// The instance config `{style, credential, settings}` with the credential at `credential` as the JSON text
    /// the binder already holds for that reference (e.g. `{"$secret": n}`).
    pub fn config_json(&self, credential: Option<&str>) -> String {
        let style = busbar_contract::json::to_string(&*self.style).unwrap_or_default();
        match credential {
            Some(c) => format!(
                "{{\"style\":{style},\"credential\":{c},\"settings\":{}}}",
                self.settings.to_json()
            ),
            None => format!(
                "{{\"style\":{style},\"settings\":{}}}",
                self.settings.to_json()
            ),
        }
    }
}

/// An operator-configured auth instance, as far as bindings read it.
pub struct OperatorAuth<'a> {
    pub name: &'a str,
    pub module: &'a str,
    /// The binding's configured `style`, if it is an outbound binding.
    pub style: Option<&'a str>,
    /// The keys its `settings` already hold (the binding's own keys win over core's fill).
    pub settings_keys: Vec<&'a str>,
}

/// `providers.<p>.auth` as resolved (deployment first, else catalog).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderAuth<'a> {
    /// A deployment auth instance name.
    Instance(&'a str),
    /// A catalog style word and no deployment instance name.
    Style(&'a str),
    /// No `auth` anywhere: the dialect-native presentation.
    None,
}

/// One resolved provider entry, as far as bindings read it. No `Debug`: it carries URLs.
pub struct ProviderView<'a> {
    pub name: &'a str,
    /// The resolved `protocol`.
    pub protocol: &'a str,
    pub base_url: Option<&'a str>,
    pub auth: ProviderAuth<'a>,
    pub has_api_key: bool,
    /// The forwarded keys (§8.6 item 2), for a catalog-styled binding.
    pub token_url: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub subject: Option<&'a str>,
}

/// One pool member as the serving plane reaches it.
#[derive(Clone, Copy, Debug)]
pub struct MemberView<'a> {
    /// The member's model name (refusal texts).
    pub member: &'a str,
    /// `v`: the configured name of the plane instance serving the member's pool.
    pub plane: &'a str,
    /// The identity of `v`'s image (selects its D_DIALECT_AUTH rows).
    pub image: &'a str,
    pub provider: &'a str,
}

/// Everything one load's provider bindings read.
pub struct ProviderPlan<'a> {
    pub members: &'a [MemberView<'a>],
    pub providers: &'a [ProviderView<'a>],
    /// `Registry::dialect_auth()`.
    pub rows: &'a [(&'a str, Vec<DialectAuthOwned>)],
    /// `Registry::outbound_styles()`.
    pub styles: &'a [(&'a str, Vec<&'a str>)],
    pub operator: &'a [OperatorAuth<'a>],
}

/// `(serving plane instance, provider, dialect)`: the key of one attempt's auth binding.
pub type AttemptKey = (Box<str>, Box<str>, Box<str>);

/// Core-vocabulary `settings` keys an explicit binding lacked, with the values to add in memory.
pub type Fills = Vec<(&'static str, String)>;

/// What a load's provider bindings answer.
#[derive(Default)]
pub struct ProviderBindings {
    pub implicit: Vec<ImplicitInstance>,
    /// `(serving plane instance, provider, dialect)` → the auth instance its attempts use (implicit or explicit).
    pub by_attempt: BTreeMap<AttemptKey, Box<str>>,
    /// Explicit bindings' core-vocabulary keys their `settings` lacked, to add in memory before bind.
    pub fills: BTreeMap<Box<str>, Fills>,
}

fn row_of<'r>(
    rows: &'r [(&str, Vec<DialectAuthOwned>)],
    image: &str,
    dialect: &str,
    protocol: &str,
) -> Option<Row<'r>> {
    let (_, image_rows) = rows.iter().find(|(id, _)| *id == image)?;
    let pick = |d: &str| image_rows.iter().find(|r| &*r.dialect == d);
    let row = pick(dialect).or_else(|| pick(protocol))?;
    Some(match &row.present {
        PresentationOwned::Header {
            key_header,
            own_header,
            passthrough_header,
            families,
        } => Row::Header {
            key_header: key_header.as_deref(),
            own_header: own_header.as_deref(),
            passthrough_header: passthrough_header.as_deref(),
            families,
        },
        PresentationOwned::Sign {
            service,
            region_after,
            region_default,
        } => Row::Sign {
            service,
            region_after,
            region_default,
        },
    })
}

fn no_row_text(member: &str, provider: &str, dialect: &str) -> String {
    format!(
        "member '{member}': provider '{provider}' states no `auth:` and its plane declares no default style for \
         the dialect '{dialect}'"
    )
}

fn squat_text(name: &str, owner_path: &str) -> String {
    format!(
        "`auth.{name}` is the name core gives an implicit outbound binding; name it in `{owner_path}.auth`"
    )
}

fn fill_text(instance: &str) -> String {
    format!(
        "`auth.{instance}`: its core settings differ between the providers, dialects or serving planes that reach \
         it; write `settings` explicitly"
    )
}

fn style_text(instance: &str, style: &str) -> String {
    format!("`auth.{instance}`: its module declares no outbound style `{style}`")
}

/// An operator binding's `style` must be one of its module's D_OUTBOUND_STYLE items.
fn check_style(op: &OperatorAuth<'_>, styles: &[(&str, Vec<&str>)]) -> Option<String> {
    let style = op.style?;
    let declared = styles
        .iter()
        .any(|(id, words)| *id == op.module && words.contains(&style));
    (!declared).then(|| style_text(op.name, style))
}

/// The provider half of §12.18: implicit dialect bindings (rows per serving plane, dedup by value, the
/// `<p>-<d>[-<v>]-outbound` names), catalog-styled bindings (`<p>-outbound` with the forwarded keys), the
/// explicit-binding fill, the owner and squat refusals and the operator style check. Err = every refusal text.
pub fn bind_providers(plan: &ProviderPlan<'_>) -> Result<ProviderBindings, Vec<String>> {
    let mut refused = Vec::new();
    let mut out = ProviderBindings::default();
    let operator = |name: &str| plan.operator.iter().find(|o| o.name == name);

    // (p, d, style, settings) -> serving planes.
    let mut implicit: BTreeMap<(&str, &str, &'static str, Settings), BTreeSet<&str>> =
        BTreeMap::new();
    // explicit instance -> (provider, fill) per (v, p, d).
    let mut explicit: BTreeMap<&str, Vec<(&str, Fills)>> = BTreeMap::new();
    let mut styled: BTreeSet<&str> = BTreeSet::new();

    for m in plan.members {
        let Some(p) = plan.providers.iter().find(|p| p.name == m.provider) else {
            continue;
        };
        let d = p.protocol;
        let attempt = (Box::from(m.plane), Box::from(p.name), Box::from(d));
        match p.auth {
            ProviderAuth::None => {
                if !p.has_api_key {
                    continue;
                }
                let Some(row) = row_of(plan.rows, m.image, d, p.protocol) else {
                    refused.push(no_row_text(m.member, p.name, d));
                    continue;
                };
                let (style, settings) = styles::dialect_binding(&row, d, p.base_url);
                implicit
                    .entry((p.name, d, style, settings))
                    .or_default()
                    .insert(m.plane);
            }
            ProviderAuth::Style(_) => {
                styled.insert(p.name);
                out.by_attempt
                    .insert(attempt, format!("{}-outbound", p.name).into());
            }
            ProviderAuth::Instance(name) => {
                out.by_attempt.insert(attempt, name.into());
                let (Some(op), Some(row)) =
                    (operator(name), row_of(plan.rows, m.image, d, p.protocol))
                else {
                    continue;
                };
                let (style, settings) = styles::dialect_binding(&row, d, p.base_url);
                if op.style != Some(style) {
                    continue;
                }
                let fill: Vec<_> = settings
                    .entries()
                    .into_iter()
                    .filter(|(k, _)| !op.settings_keys.contains(k))
                    .collect();
                explicit.entry(name).or_default().push((p.name, fill));
            }
        }
    }

    // Names: `<p>-<d>-outbound` when (p, d) has one distinct binding, else `<p>-<d>-<v>-outbound` with `v` the
    // lexicographically first serving plane of that binding.
    let mut per_pd: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (p, d, _, _) in implicit.keys() {
        *per_pd.entry((p, d)).or_default() += 1;
    }
    for ((p, d, style, settings), planes) in implicit {
        let first = planes.iter().next().copied().unwrap_or_default();
        let name: Box<str> = if per_pd.get(&(p, d)).copied() == Some(1) {
            format!("{p}-{d}-outbound").into()
        } else {
            format!("{p}-{d}-{first}-outbound").into()
        };
        if operator(&name).is_some() {
            refused.push(squat_text(&name, &format!("providers.{p}")));
            continue;
        }
        let module = match outbound_owner(plan.styles, style) {
            Ok(owner) => owner,
            Err(why) => {
                refused.push(why.text(&format!("auth.{name}"), style));
                continue;
            }
        };
        for v in planes {
            out.by_attempt
                .insert((v.into(), p.into(), d.into()), name.clone());
        }
        out.implicit.push(ImplicitInstance {
            name,
            module: module.into(),
            style: style.into(),
            credential: CredentialFrom::ProviderApiKey(p.into()),
            settings,
        });
    }

    for p in styled {
        let Some(view) = plan.providers.iter().find(|v| v.name == p) else {
            continue;
        };
        let ProviderAuth::Style(word) = view.auth else {
            continue;
        };
        let name: Box<str> = format!("{p}-outbound").into();
        if operator(&name).is_some() {
            refused.push(squat_text(&name, &format!("providers.{p}")));
            continue;
        }
        match outbound_owner(plan.styles, word) {
            Ok(module) => out.implicit.push(ImplicitInstance {
                name,
                module: module.into(),
                style: word.into(),
                credential: if view.has_api_key {
                    CredentialFrom::ProviderApiKey(p.into())
                } else {
                    CredentialFrom::None
                },
                settings: Settings::Forwarded {
                    token_url: view.token_url.map(Box::from),
                    scope: view.scope.map(Box::from),
                    subject: view.subject.map(Box::from),
                },
            }),
            Err(why) => refused.push(why.text(&format!("auth.{name}"), word)),
        }
    }

    // One fill per explicit binding: one provider, one value.
    for (instance, reached) in explicit {
        let providers: BTreeSet<&str> = reached.iter().map(|(p, _)| *p).collect();
        let fills: BTreeSet<&Vec<(&'static str, String)>> =
            reached.iter().map(|(_, f)| f).collect();
        let any_fill = fills.iter().any(|f| !f.is_empty());
        if any_fill && (providers.len() > 1 || fills.len() > 1) {
            refused.push(fill_text(instance));
            continue;
        }
        if let Some(fill) = fills.into_iter().next().filter(|f| !f.is_empty()) {
            out.fills.insert(instance.into(), fill.clone());
        }
    }

    refused.extend(
        plan.operator
            .iter()
            .filter_map(|op| check_style(op, plan.styles)),
    );
    if refused.is_empty() {
        Ok(out)
    } else {
        Err(refused)
    }
}

#[cfg(test)]
mod tests;
