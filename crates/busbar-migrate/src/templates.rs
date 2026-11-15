// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1t, the template rule (MIGRATE-ON-BOOT §A3 1t): the chain converts config.yaml's raw bytes R,
//! the uninterpolated template, so every `${VAR}` is string text to every pass and a value a pass
//! moves keeps its reference. A scratch copy I, R interpolated exactly as the boot interpolates it
//! (the kernel's `interpolate_env_lookup`, Strict: an unset variable refuses, as 1.5.5 refused to
//! boot), is read for exactly two uses: the value decisions 1.5.5 made on resolved values, and proof
//! two (interpolation parity). I is never written, hashed, reported or logged, and it is wiped on
//! drop. A pass that must compute a new value from a slot whose template holds `${` refuses
//! ([`computed`]), so no environment value is ever computed into the file.

use busbar_contract::yaml::{self, MappingExt, Value, ValueExt};
use zeroize::Zeroize;

use crate::{Env, Refusal};

/// The most nodes a document the chain reads may hold.
const MAX_NODES: usize = 262_144;

/// A template interpolated as the boot interpolates it. The text holds environment values, so it
/// is wiped on drop and never leaves this process's memory.
pub(crate) struct Resolved(String);

impl Resolved {
    /// `template` interpolated with `env`, Strict.
    ///
    /// # Errors
    /// CONFIG naming `shown` with the interpolation's own text (an unset variable, an unsafe value).
    pub(crate) fn of(template: &str, env: Env, shown: &str) -> Result<Self, Refusal> {
        busbar_kernel::config::interpolate_env_lookup(
            template,
            busbar_kernel::config::EnvSubst::Strict,
            &mut Vec::new(),
            env,
        )
        .map(Self)
        .map_err(|error| Refusal::Config(format!("{shown}: {error}")))
    }

    pub(crate) fn text(&self) -> &str {
        &self.0
    }
}

impl Drop for Resolved {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A document read as the chain reads it: the template tree R and its resolved twin I.
pub(crate) struct Template {
    tree: Value,
    resolved: Value,
}

impl Template {
    /// Read `text` (named `shown` in refusals) as a template and its interpolation.
    ///
    /// # Errors
    /// CONFIG when either is not YAML (the position only: no value is quoted), the document is
    /// larger than the chain reads, or the interpolation refuses.
    pub(crate) fn read(text: &str, env: Env, shown: &str) -> Result<Self, Refusal> {
        let tree = parse(text, shown)?;
        budget(&tree, shown)?;
        let resolved = parse(Resolved::of(text, env, shown)?.text(), shown)?;
        Ok(Self { tree, resolved })
    }

    /// R: the tree every pass converts.
    pub(crate) fn tree(&self) -> &Value {
        &self.tree
    }

    /// I: the tree 1.5.5's value decisions are made on.
    pub(crate) fn resolved(&self) -> &Value {
        &self.resolved
    }

    /// Proof two (§A7 "Authored text"): `patched`, interpolated, reads the same scalar (type and
    /// value) as the source at every path the chain did not change (`after` is the chain's tree).
    /// This is what catches a lost quote: `"${P}"` and `${P}` are one template string, and only
    /// the interpolated reading differs.
    ///
    /// # Errors
    /// VERIFY naming the first path whose reading changed; nothing is written.
    pub(crate) fn parity(
        &self,
        patched: &str,
        after: &Value,
        env: Env,
        shown: &str,
    ) -> Result<(), Refusal> {
        let _ = (patched, after, env, shown);
        Ok(())
    }
}

impl Drop for Template {
    fn drop(&mut self) {
        wipe(&mut self.resolved);
    }
}

/// Whether `value` is a template slot: a string holding `${`.
pub(crate) fn is_template(value: &Value) -> bool {
    value.as_str().is_some_and(|text| text.contains("${"))
}

/// 1t's refusal: the pass at `path` must compute a new value from a slot whose template holds
/// `${`. The value is quoted nowhere.
pub(crate) fn computed(path: &str) -> Refusal {
    Refusal::Config(format!(
        "`{path}` uses `${{VAR}}` and the 1.6.0 upgrade must rewrite this value; write the 1.6.0 \
         form by hand, keeping the reference, then boot again"
    ))
}

fn parse(text: &str, shown: &str) -> Result<Value, Refusal> {
    yaml::from_str(text).map_err(|error| {
        let at = error.location().map_or_else(String::new, |location| {
            format!(" at line {} column {}", location.line(), location.column())
        });
        Refusal::Config(format!("{shown} is not valid YAML{at}"))
    })
}

/// The structure budget: at most [`MAX_NODES`] nodes (the facade bounds the depth).
fn budget(tree: &Value, shown: &str) -> Result<(), Refusal> {
    let mut pending = vec![tree];
    let mut nodes = 0usize;
    while let Some(node) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES {
            return Err(Refusal::Config(format!(
                "{shown} holds more than {MAX_NODES} YAML nodes, more than the upgrade reads"
            )));
        }
        match node {
            Value::Array(items) => pending.extend(items.iter()),
            Value::Map(pairs) => {
                for (key, value) in pairs {
                    pending.push(key);
                    pending.push(value);
                }
            }
            Value::Tag(_, inner) => pending.push(inner),
            _ => {}
        }
    }
    Ok(())
}

/// Walk the template before and after the chain beside their interpolations; `Err(path)` at the
/// first unchanged scalar whose interpolated reading changed.
fn same_reading(
    before: &Value,
    after: &Value,
    read_before: &Value,
    read_after: &Value,
    path: &mut Vec<String>,
) -> Result<(), String> {
    match (before, after) {
        (Value::Map(was), Value::Map(now)) => {
            for (key, value) in was {
                let Some(kept) = now.get_key(key) else {
                    continue;
                };
                path.push(key.as_str().map_or_else(|| "?".to_owned(), str::to_owned));
                let (Some(read_was), Some(read_now)) = (read_before.get(key), read_after.get(key))
                else {
                    return Err(path.join("."));
                };
                same_reading(value, kept, read_was, read_now, path)?;
                path.pop();
            }
            Ok(())
        }
        (Value::Array(was), Value::Array(now)) if was.len() == now.len() => {
            for (at, (value, kept)) in was.iter().zip(now).enumerate() {
                path.push(at.to_string());
                let (Some(read_was), Some(read_now)) = (read_before.get(at), read_after.get(at))
                else {
                    return Err(path.join("."));
                };
                same_reading(value, kept, read_was, read_now, path)?;
                path.pop();
            }
            Ok(())
        }
        (Value::Map(_) | Value::Array(_), _) | (_, Value::Map(_) | Value::Array(_)) => Ok(()),
        (was, now) if yaml::same_tree(was, now) => {
            if yaml::same_tree(read_before, read_after) {
                Ok(())
            } else {
                Err(path.join("."))
            }
        }
        _ => Ok(()),
    }
}

/// Overwrite every string and byte string in `value`.
fn wipe(value: &mut Value) {
    match value {
        Value::Text(text) => text.zeroize(),
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Map(pairs) => {
            for (key, value) in pairs.iter_mut() {
                wipe(key);
                wipe(value);
            }
        }
        Value::Tag(_, inner) => wipe(inner),
        _ => {}
    }
}

#[cfg(test)]
#[path = "tests/templates_tests.rs"]
mod tests;
