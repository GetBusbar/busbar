// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::file_core_cfg` and the settled write-back (IF §7.2, §12.10; MIGRATE-ON-BOOT r42 §4): what
//! an instance's `open` settled, its canonical settings bag and the core config its older bag held
//! (CORE_CFG), is written back by core without interpretation, keyed by core's own instance path and
//! index (never the plugin's identity). On an unstamped boot this is step 5; on a stamped boot or a
//! reload it is the seam's patch-writer edit of the same answer.
//!
//! UPSTREAM fragments are retired by UPSTREAMS-DECLARED r3. LIMITS (empty name, once) is validated and filed nowhere (the plugin's answer is applied in
//! memory at its open); TRUST_APPROVAL and ROUTE_MEDIA are filed nowhere either (no key in the grammar). LIFT (empty name, one JSON pointer, once per
//! pointer) moves a literal secret out of the settings bag into a planned 0600 secret file under the
//! config directory and leaves a `{file: <path>}` reference; the value never enters a report. Any
//! other section, and any fragment at all on a stamped boot (a current config moves nothing), refuses
//! CONFIG naming the instance index. Each fragment's own schema is the boot's strict parse of the
//! result (`Check`), which runs on the planned document before anything is written.

use std::fmt;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use busbar_contract::secure::SecureString;
use busbar_contract::yaml::{self, MappingExt, Pairs, Value, ValueExt};
use zeroize::Zeroize;

use crate::patch::{rewrite, schema_insert};
use crate::templates::Template;
use crate::{Env, Refusal};

/// `abi::core_cfg::*` (IF §8.8): the sections a plugin's `open` may hand back. 1, 5 and 6 are retired
/// and never reused.
pub mod section {
    // Section 1 (host-global upstream) is retired by UPSTREAMS-DECLARED r3.
    pub const TRUST_APPROVAL: u32 = 2;
    pub const ROUTE_MEDIA: u32 = 3;
    pub const LIMITS: u32 = 4;
    pub const LIFT: u32 = 7;
}

/// One CORE_CFG fragment: the section, its name and its value in that section's grammar.
#[derive(Debug, Clone)]
pub struct CoreCfg {
    pub section: u32,
    pub name: String,
    pub value: Value,
}

/// What instance `index`'s `open` settled. `path` is core's path of the instance's block in the
/// document (`["store"]`, `["auth", "<name>"]`); `settings` is the text of the value that replaces its `settings` bag (`None`: the
/// bag as written; guarded text, never a readable tree), secret references already restored to the operator's form.
#[derive(Debug, Clone)]
pub struct Settled {
    pub index: u32,
    pub path: Vec<String>,
    pub settings: Option<SecureString>,
    pub core_cfg: Vec<CoreCfg>,
    /// Exact pointers authorized by core from admitted describe paths and typed core leaves.
    /// Never infer this set from CONFIG strings or from requested LIFT fragments.
    pub allowed_lifts: std::collections::BTreeSet<String>,
    pub placement: BagPlacement,
}

/// Core's authored location of the config bag, never chosen by the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BagPlacement {
    Settings,
    Block,
}

/// A planned 0600 secret file: a lifted literal. The bytes are wiped on drop and never printed.
pub struct SecretFile {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl SecretFile {
    /// Where the file is written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The slot's exact UTF-8 bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SecretFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFile")
            .field("path", &self.path)
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// The settled answers applied to a document: its new text, one report line per change, and the
/// secret files to write first.
#[derive(Debug)]
pub struct Applied {
    text: String,
    report: Vec<String>,
    secrets: Vec<SecretFile>,
}

impl Applied {
    /// The document after the settled answers.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// One line per change (never a secret value).
    #[must_use]
    pub fn report(&self) -> &[String] {
        &self.report
    }

    /// The secret files a lift planned.
    #[must_use]
    pub fn secrets(&self) -> &[SecretFile] {
        &self.secrets
    }
}

fn refuse(index: u32, text: &str) -> Refusal {
    Refusal::Config(format!("instance {index}: {text}"))
}

/// The instance's block: the mapping at `path` of the document.
fn block_mut<'v>(root: &'v mut Pairs, path: &[String]) -> Option<&'v mut Pairs> {
    let (first, rest) = path.split_first()?;
    let Some(Value::Map(head)) = root.get_key_mut(first.as_str()) else {
        return None;
    };
    let mut at: &mut Pairs = head;
    for key in rest {
        let Some(Value::Map(inner)) = at.get_key_mut(key.as_str()) else {
            return None;
        };
        at = inner;
    }
    Some(at)
}

/// RFC 6901 over a settings bag.
fn pointer_mut<'v>(root: &'v mut Value, pointer: &str) -> Option<&'v mut Value> {
    if pointer.is_empty() {
        return Some(root);
    }
    let mut at = root;
    for raw in pointer.strip_prefix('/')?.split('/') {
        let mut step = String::new();
        let mut chars = raw.chars();
        while let Some(ch) = chars.next() {
            step.push(match ch {
                '~' => match chars.next()? {
                    '0' => '~',
                    '1' => '/',
                    _ => return None,
                },
                other => other,
            });
        }
        at = match at {
            Value::Map(entries) => {
                let found = entries
                    .iter()
                    .position(|(key, _)| key.as_text() == Some(step.as_str()))?;
                &mut entries[found].1
            }
            Value::Array(items) => {
                if step.is_empty()
                    || !step.bytes().all(|b| b.is_ascii_digit())
                    || (step.len() > 1 && step.starts_with('0'))
                {
                    return None;
                }
                items.get_mut(step.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(at)
}

/// The directory beside config.yaml that lifted secrets are written in.
fn secret_path(dir: &Path, instance: &[String], pointer: &str) -> Result<PathBuf, Refusal> {
    let digest = busbar_contract::crypto::sha256(pointer.as_bytes());
    let tag: String = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let slug: String = instance
        .join("-")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let file = dir.join(format!("{slug}.{tag}.secret"));
    if file.to_str().is_none() {
        return Err(Refusal::Config(format!(
            "{} is not UTF-8, so a lifted secret cannot be referenced there; nothing was written",
            file.display()
        )));
    }
    Ok(file)
}

/// What one instance's settled answer changes inside its own block: its bag, its `limits`, its lifts.
fn settle_block(
    block: &mut Pairs,
    answer: &Settled,
    dir: &Path,
    report: &mut Vec<String>,
    secrets: &mut Vec<SecretFile>,
) -> Result<(), Refusal> {
    if answer.placement == BagPlacement::Block {
        let mut wrapped = vec![(Value::from("settings"), Value::Map(block.clone()))];
        let mut nested = answer.clone();
        nested.placement = BagPlacement::Settings;
        settle_block(&mut wrapped, &nested, dir, report, secrets)?;
        let Some(Value::Map(bag)) = wrapped.get_key("settings") else {
            return Err(refuse(
                answer.index,
                "a whole-block CONFIG must be an object",
            ));
        };
        *block = bag.clone();
        if let Some(limits) = wrapped.get_key("limits") {
            block.insert_key("limits", limits.clone());
        }
        return Ok(());
    }
    let index = answer.index;
    let shown = answer.path.join(".");
    if let Some(settings) = &answer.settings {
        let bag: Value = yaml::from_str(settings.as_str()).map_err(|_| {
            refuse(
                index,
                "the settled settings are not a YAML value; nothing was written",
            )
        })?;
        block.insert_key("settings", bag);
    }
    let mut limits_seen = false;
    let mut lifted: Vec<&str> = Vec::new();
    for frag in &answer.core_cfg {
        match frag.section {
            section::LIMITS => {
                if !frag.name.is_empty() || limits_seen {
                    return Err(refuse(
                        index,
                        "`limits` carries an empty name and appears once",
                    ));
                }
                limits_seen = true;
                if !matches!(&frag.value, Value::Map(_)) {
                    return Err(refuse(index, "`limits` is not a mapping"));
                }
                report.push(format!(
                    "{shown}: instance {index}'s old limits are not filed: the instance runs at its \
                     kind's defaults, with the plugin's own answer applied in memory at its open"
                ));
            }
            section::LIFT => {
                let (Some(pointer), true) = (frag.value.as_text(), frag.name.is_empty()) else {
                    return Err(refuse(
                        index,
                        "a lift carries an empty name and one JSON pointer string",
                    ));
                };
                if !answer.allowed_lifts.contains(pointer) {
                    return Err(refuse(
                        index,
                        "a lift names a slot not authorized by its admitted secret grammar",
                    ));
                }
                if lifted.contains(&pointer) {
                    return Err(refuse(
                        index,
                        &format!("the lift of `{pointer}` appears more than once"),
                    ));
                }
                lifted.push(pointer);
                let bag = block.get_key_mut("settings").ok_or_else(|| {
                    refuse(
                        index,
                        "a lift names a slot, but the instance has no settings",
                    )
                })?;
                let slot = pointer_mut(bag, pointer)
                    .filter(|slot| slot.as_text().is_some())
                    .ok_or_else(|| {
                        refuse(
                            index,
                            &format!("the lift of `{pointer}` names no string in its settings"),
                        )
                    })?;
                let file = secret_path(dir, &answer.path, pointer)?;
                let reference = Value::Map(vec![(
                    Value::from("file"),
                    Value::from(file.to_str().unwrap_or_default()),
                )]);
                let Value::Text(literal) = std::mem::replace(slot, reference) else {
                    return Err(refuse(index, "a lifted slot was not text"));
                };
                report.push(format!(
                    "{shown}: the literal secret at `{pointer}` moved to the 0600 file {}",
                    file.display()
                ));
                secrets.push(SecretFile {
                    path: file,
                    bytes: literal.into_bytes(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Apply `settled` to `text` (config.yaml, after the chain): each instance's bag replaced, its
/// CORE_CFG filed, its LIFT pointers lifted. `stamped` is a stamped boot or a reload: no fragment is
/// then accepted. Nothing is written; the secret files are the caller's to write ([`write_secrets`]).
///
/// # Errors
/// CONFIG naming the instance index for any rule above, or when the patch writer cannot keep the
/// operator's text (VERIFY).
#[cold]
#[inline(never)]
pub fn apply_settled(
    text: &str,
    config: &Path,
    settled: &[Settled],
    stamped: bool,
    env: Env,
) -> Result<Applied, Refusal> {
    let mut report = Vec::new();
    let mut secrets = Vec::new();
    if settled.is_empty() {
        return Ok(Applied {
            text: text.to_owned(),
            report,
            secrets,
        });
    }
    let template = Template::read(text, env, "config.yaml")?;
    let mut after = template.tree().clone();
    let dir = match config.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            std::path::absolute(parent).unwrap_or_else(|_| parent.to_path_buf())
        }
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let Value::Map(root) = &mut after else {
        return Ok(Applied {
            text: text.to_owned(),
            report,
            secrets,
        });
    };
    for answer in settled {
        let index = answer.index;
        if stamped && !answer.core_cfg.is_empty() {
            return Err(refuse(
                index,
                "answered core config for a current config, which moves nothing; the instance \
                 must not hand back CORE_CFG when its settings are already canonical",
            ));
        }
        let shown = answer.path.join(".");
        if answer.placement == BagPlacement::Block
            && answer.path.len() == 1
            && root.get_key(answer.path[0].as_str()).is_none()
        {
            schema_insert(root, &answer.path[0], Value::Map(Vec::new()));
        }
        let block = block_mut(root, &answer.path).ok_or_else(|| {
            refuse(
                index,
                &format!("`{shown}` is not an instance block of this document"),
            )
        })?;
        settle_block(block, answer, &dir, &mut report, &mut secrets)?;
        for frag in &answer.core_cfg {
            match frag.section {
                section::LIMITS | section::LIFT => {}
                section::TRUST_APPROVAL | section::ROUTE_MEDIA => {
                    report.push(format!(
                        "{shown}: instance {index}'s core config section {} is not filed: \
                         the grammar has no key for it",
                        frag.section
                    ));
                }
                other => {
                    return Err(refuse(
                        index,
                        &format!("core config section {other} is not one this release reads"),
                    ));
                }
            }
        }
    }
    let patched = rewrite(text, template.tree(), &after, "config.yaml")?;
    if patched != text {
        template.parity(&patched, &after, env, "config.yaml")?;
    }
    Ok(Applied {
        text: patched,
        report,
        secrets,
    })
}

/// 5a: write each planned secret file (`O_EXCL`, 0600, fsynced). A file already there with the same
/// bytes (an interrupted upgrade's) is kept; one with other bytes is refused, nothing overwritten.
///
/// # Errors
/// CONFIG naming the file.
#[cold]
#[inline(never)]
pub fn write_secrets(secrets: &[SecretFile]) -> Result<(), Refusal> {
    for secret in secrets {
        let shown = secret.path.display();
        match std::fs::read(&secret.path) {
            Ok(mut held) => {
                let same = held == secret.bytes;
                held.zeroize();
                if same {
                    continue;
                }
                return Err(Refusal::Config(format!(
                    "{shown} exists and holds other bytes than the secret this upgrade lifts; move \
                     it aside, then boot again; nothing was written"
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Refusal::Config(format!(
                    "cannot read {shown}: {error}; nothing was written"
                )))
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret.path)
            .map_err(|error| {
                Refusal::Config(format!(
                    "cannot create {shown}: {error}; nothing was renamed"
                ))
            })?;
        file.write_all(&secret.bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| Refusal::Config(format!("cannot write {shown}: {error}")))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/settle_tests.rs"]
mod tests;
