// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Secret grammar from immutable admitted describe facts, before any typed secret reference is read.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::secret_ref::Sugars;
use busbar_kernel::config::grammar::{Item, Owner, SecretSource};
use busbar_kernel::config::Grammar;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::Images;
use busbar_ports::secret::SugarDecl;

pub(crate) fn of_images(
    images: &Images,
    owners: BTreeMap<String, Owner>,
    items: Vec<Item>,
    report: Vec<String>,
) -> Result<Grammar, String> {
    let sugars = sugars(images.sugars())?;
    let mut sources = BTreeMap::new();
    for identity in images.identities() {
        let described = images
            .described(identity)
            .ok_or_else(|| format!("{identity}: admitted description missing"))?;
        if described.kind != KindCode::Secret {
            continue;
        }
        let schemas: Vec<_> = described
            .items
            .iter()
            .filter(|(tag, _)| *tag == busbar_plugin_abi::secret::tag::D_REF_SCHEMA)
            .collect();
        let [(_, body)] = schemas.as_slice() else {
            return Err(format!(
                "{identity}: describe must contain exactly one secret reference schema"
            ));
        };
        let schema = std::str::from_utf8(body)
            .map_err(|_| format!("{identity}: reference schema is not UTF-8"))?;
        busbar_contract::json::SchemaCheck::new(schema.as_bytes())
            .map_err(|_| format!("{identity}: invalid secret reference schema"))?;
        if images
            .sugars()
            .iter()
            .any(|sugar| &*sugar.identity == identity)
        {
            let settings = described.schema.as_deref().ok_or_else(|| {
                format!("{identity}: secret shorthand requires a settings schema")
            })?;
            let check = busbar_contract::json::SchemaCheck::new(settings.as_bytes())
                .map_err(|_| format!("{identity}: invalid secret settings schema"))?;
            if !check.is_valid(b"{}") {
                return Err(format!(
                    "{identity}: secret shorthand settings schema must accept an empty object"
                ));
            }
        }
        let source = SecretSource {
            identity: identity.to_owned(),
            ref_schema: schema.to_owned(),
        };
        for name in images.names(identity) {
            if sources.insert(name.to_owned(), source.clone()).is_some() {
                return Err(format!(
                    "{name}: secret image name is claimed more than once"
                ));
            }
        }
    }
    Ok(Grammar::new(sugars, owners, report)
        .with_items(items)
        .with_secret_sources(sources))
}

fn sugars(decls: &[SugarDecl]) -> Result<Sugars, String> {
    use busbar_contract::plugin_settings::sugar_words::{
        REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
        SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
    };
    let mut owners: Vec<Arc<str>> = Vec::new();
    for decl in decls {
        if !owners.iter().any(|owner| **owner == *decl.identity) {
            owners.push(Arc::clone(&decl.identity));
        }
    }
    let mut sugars = Sugars::default();
    for owner in owners {
        let mut rewrites = Vec::new();
        for decl in decls.iter().filter(|decl| *decl.identity == *owner) {
            let word = decl.word.to_string();
            if decl.alias {
                rewrites.push((REWRITE_ALIAS, word.clone(), owner.to_string()));
            }
            rewrites.push((REWRITE_SUGAR, word.clone(), decl.key.to_string()));
            rewrites.push((REWRITE_SUGAR_SHOWN, word.clone(), decl.shown.to_string()));
            rewrites.push((REWRITE_SUGAR_NAMES, word.clone(), decl.names.to_string()));
            let role = match decl.role {
                busbar_plugin_abi::secret::SUGAR_ROLE_FILL => Some(SUGAR_ROLE_FILL),
                busbar_plugin_abi::secret::SUGAR_ROLE_PATH => Some(SUGAR_ROLE_PATH),
                _ => None,
            };
            if let Some(role) = role {
                rewrites.push((REWRITE_SUGAR_ROLE, word, role.to_owned()));
            }
        }
        sugars.declare(&owner, &rewrites)?;
    }
    Ok(sugars)
}
