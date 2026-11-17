// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cold code of `crate::dispatch::{load, plugin, migrate, log_file}`.

use busbar_contract::abi::mechanism::call::{AbiStr, Op};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::rendering::{RenderError, Unreadable};
use busbar_contract::abi::mechanism::route::Route;

use crate::dispatch::load::LoadError;

// ---------------------------------------------------------------------------------------------
// dispatch::load: load-time Statement and library refusals, and the tables built once at admission.

/// A Statement rendering that does not read back.
#[cold]
pub(crate) fn unreadable(e: &Unreadable) -> LoadError {
    LoadError::Rendering(format!("byte {} is not {}", e.at, e.what))
}

/// A Statement rendering naming a kind the host does not have.
#[cold]
pub(crate) fn unknown_kind(kind: u32) -> LoadError {
    LoadError::Rendering(format!("it names kind {kind}"))
}

/// A Statement that does not render.
#[cold]
pub(crate) fn unrendered(e: RenderError) -> LoadError {
    LoadError::Rendering(e.to_string())
}

/// A library that exports no door.
#[cold]
pub(crate) fn no_door(e: &libloading::Error) -> LoadError {
    LoadError::NoDoor(crate::stage::loader_error(e))
}

/// A hook's routes, read once at admission.
#[cold]
pub(crate) fn routes(routes: &[Route]) -> Vec<Route> {
    routes.to_vec()
}

/// A measurement class the legacy plane billing tail also declares.
#[cold]
pub(crate) fn billed_twice(class: &str) -> LoadError {
    LoadError::BadStatement(format!(
        "measurement class '{class}' is also declared by the legacy plane billing tail"
    ))
}

/// A Statement that breaks a bound `check_statement` checks.
#[cold]
pub(crate) fn statement_fault(f: Fault) -> LoadError {
    LoadError::BadStatement(format!("{} breaks {:?}", f.field, f.rule))
}

/// A metric family of an unknown kind.
#[cold]
pub(crate) fn family_kind(i: usize, kind: u8) -> LoadError {
    LoadError::BadStatement(format!("family {i} has kind {kind}"))
}

/// A metric family whose label keys are NULL with a count.
#[cold]
pub(crate) fn family_label_keys(i: usize) -> LoadError {
    LoadError::BadStatement(format!("family {i}'s label keys are NULL"))
}

/// A metric family with no name.
#[cold]
pub(crate) fn family_name(i: usize) -> LoadError {
    LoadError::BadStatement(format!("family {i} has no name"))
}

/// The secret-ref keys of a Statement, read once at admission.
#[cold]
pub(crate) fn secret_keys<'a>(keys: impl Iterator<Item = &'a [u8]>) -> Vec<String> {
    keys.map(|k| String::from_utf8_lossy(k).into_owned())
        .collect()
}

/// A settings field named both secret and reference-capable.
#[cold]
pub(crate) fn secret_and_reference(path: &str) -> LoadError {
    LoadError::BadStatement(format!(
        "extensions.reference_fields names '{path}', which secret_refs also names: a \
         settings field is secret or reference-capable, never both"
    ))
}

/// A refused plugin's name, for its refusal.
#[cold]
pub(crate) fn plugin_name(name: AbiStr) -> String {
    crate::dispatch::plugin::str_bytes(name)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

/// A kind tail whose head states less than the head itself.
#[cold]
pub(crate) fn short_tail_head(size: u32) -> LoadError {
    LoadError::KindTail(format!(
        "its head states {size} bytes, less than the head itself"
    ))
}

/// A transport tail that does not reach its claim rows.
#[cold]
pub(crate) fn short_transport_tail(size: u32) -> LoadError {
    LoadError::KindTail(format!(
        "a transport tail states {size} bytes, less than its claim rows"
    ))
}

/// A transport tail's claim rows that break a bound.
#[cold]
pub(crate) fn claim_rows_fault(f: Fault) -> LoadError {
    LoadError::KindTail(format!("{} breaks {:?}", f.field, f.rule))
}

/// A door's op table: each slot's op, and whether the plugin filled it.
pub(crate) type OpTable = (Box<[Op]>, Box<[bool]>);

/// A door's op table, read once at admission: each slot's op and whether the plugin filled it.
#[cold]
pub(crate) fn op_table(
    slots: u32,
    slot: impl FnMut(u32) -> Result<(Op, bool), LoadError>,
) -> Result<OpTable, LoadError> {
    let entries = (0..slots).map(slot).collect::<Result<Vec<_>, _>>()?;
    let (ops, operations): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
    Ok((ops.into_boxed_slice(), operations.into_boxed_slice()))
}

// ---------------------------------------------------------------------------------------------
// Shared: owned copies taken once at bind, admission or config apply.

/// An owned copy of `s`.
#[cold]
pub(crate) fn text(s: &str) -> String {
    s.to_owned()
}

/// `bytes` as text, invalid UTF-8 replaced.
#[cold]
pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The text a refusal's error displays.
#[cold]
pub(crate) fn text_of(e: &dyn std::fmt::Display) -> String {
    e.to_string()
}

/// A list built once, at bind: `len` entries, each from its index.
#[cold]
pub(crate) fn boxed_table<T>(len: usize, entry: impl FnMut(usize) -> T) -> Box<[T]> {
    (0..len).map(entry).collect()
}

/// [`boxed_table`] whose entries may refuse.
#[cold]
pub(crate) fn try_boxed_table<T, E>(
    len: usize,
    entry: impl FnMut(usize) -> Result<T, E>,
) -> Result<Box<[T]>, E> {
    (0..len).map(entry).collect()
}

/// A list kept, shrunk to fit, once at bind.
#[cold]
pub(crate) fn boxed<T>(list: Vec<T>) -> Box<[T]> {
    list.into_boxed_slice()
}

// ---------------------------------------------------------------------------------------------
// dispatch::plugin: refusal text, first-sight copies, and the out-of-line spill of a long label list.

/// A plugin's refused open.
#[cold]
pub(crate) fn open_failure(display: &str, reason: &dyn std::fmt::Display) -> String {
    format!("plugin '{display}' open failed: {reason}")
}

/// The text of a call the host refused before the plugin answered it.
#[cold]
pub(crate) fn host_refused(why: &str) -> Vec<u8> {
    format!("the host refused this call: {why}").into_bytes()
}

/// A connection admission with no authority to judge it.
#[cold]
pub(crate) fn admission_missing() -> String {
    "connection admission authority missing".to_owned()
}

/// A connection admission its authority refused.
#[cold]
pub(crate) fn admission_refused() -> String {
    "connection admission authority refused".to_owned()
}

/// A CA certificate the host refused.
#[cold]
pub(crate) fn ca_refused(path: &str, need: u32, reason: &str) -> String {
    format!(
        "{path}: the host refused the CA certificate it names for need {need} ({reason}); \
         it must be PEM that parses into a trust anchor"
    )
}

/// A need its connection table refused to declare.
#[cold]
pub(crate) fn declare_refused(error: busbar_contract::conn::ConnError) -> String {
    crate::observe::conn_reason(error).to_owned()
}

/// An operation's policy reply joined with the host's original extension bytes, held for the
/// operation's remaining crossings: built once, at the operation's first crossing.
#[cold]
pub(crate) fn joined_reply(reply: &[u8], prior: &[u8]) -> std::sync::Arc<[u8]> {
    let mut joined = Vec::with_capacity(reply.len() + prior.len());
    joined.extend_from_slice(reply);
    joined.extend_from_slice(prior);
    std::sync::Arc::from(joined)
}

/// A refusal's text as the bytes a crossing answers.
#[cold]
pub(crate) fn text_bytes(error: &str) -> Vec<u8> {
    error.as_bytes().to_vec()
}

/// A Statement with no kind tail.
#[cold]
pub(crate) fn no_kind_tail(who: &str) -> String {
    format!("{who} states no kind tail")
}

/// A kind tail smaller than its kind's frozen size.
#[cold]
pub(crate) fn short_kind_tail(who: &str, size: u32, frozen: usize) -> String {
    format!("{who} states a {size}-byte tail, smaller than its frozen {frozen}")
}

/// A metric's label values when the family has more labels than the stack holds: `len` values,
/// each read by its index; `None` when one is malformed.
#[cold]
pub(crate) fn spilled_labels<'a>(
    len: usize,
    label: impl FnMut(usize) -> Option<&'a [u8]>,
) -> Option<Vec<&'a [u8]>> {
    (0..len).map(label).collect()
}

// ---------------------------------------------------------------------------------------------
// dispatch::log_file: config-apply and bind-time words, file names and refusals.

/// A `plugins.logs.level` that names no level.
#[cold]
pub(crate) fn bad_log_level(word: &str) -> String {
    format!("plugins.logs.level: '{word}' is not a level (off, error, warn, info, debug, trace)")
}

/// A `plugins.logs.levels` entry that names no level.
#[cold]
pub(crate) fn bad_instance_log_level(instance: &str, word: &str) -> String {
    format!(
        "plugins.logs.levels['{instance}']: '{word}' is not a level (off, error, warn, info, debug, trace)"
    )
}

/// An owned path of `s`.
#[cold]
pub(crate) fn path(s: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(s)
}

/// An owned copy of `p`.
#[cold]
pub(crate) fn path_copy(p: &std::path::Path) -> std::path::PathBuf {
    p.to_path_buf()
}

/// An owned copy of `map`.
#[cold]
pub(crate) fn map_copy<K: Clone, V: Clone>(
    map: &std::collections::BTreeMap<K, V>,
) -> std::collections::BTreeMap<K, V> {
    map.clone()
}

/// Re-level every live sink at a config apply, dropping the dead ones.
#[cold]
pub(crate) fn relevel<T>(sinks: &mut Vec<std::sync::Weak<T>>, mut each: impl FnMut(&T)) {
    sinks.retain(|s| {
        s.upgrade().is_some_and(|s| {
            each(&s);
            true
        })
    });
}

/// Drop the dead entries of a list a sink is added to once, at its bind.
#[cold]
pub(crate) fn prune_weak<T>(list: &mut Vec<std::sync::Weak<T>>) {
    list.retain(|s| s.strong_count() > 0);
}

/// Drop the dead entries of a map a writer or file slot is added to once, at its first bind.
#[cold]
pub(crate) fn prune_weak_map<K, V, S>(
    map: &mut std::collections::HashMap<K, std::sync::Weak<V>, S>,
) {
    map.retain(|_, s| s.strong_count() > 0);
}

/// The tag a plugin kind's log lines carry.
#[cold]
pub(crate) fn kind_tag(kind: busbar_contract::abi::mechanism::KindCode) -> String {
    format!("{kind:?}").to_ascii_lowercase()
}

/// A plugin log writer that could not start.
#[cold]
pub(crate) fn writer_refused(instance: &str, e: &std::io::Error) -> String {
    format!("plugins.logs: the log writer of {instance} could not start: {e}")
}

/// An instance's log file name: `<section>.<instance>.log` (the section omitted when the instance
/// already carries it), every byte outside `[A-Za-z0-9._-]` written as `_`.
#[cold]
pub(crate) fn log_file_name(
    instance: &str,
    kind: busbar_contract::abi::mechanism::KindCode,
) -> String {
    let qualified = match crate::boot::kind_of(kind).root_key() {
        Some(section)
            if !instance
                .strip_prefix(section)
                .is_some_and(|rest| rest.starts_with('.')) =>
        {
            format!("{section}.{instance}")
        }
        _ => instance.to_string(),
    };
    let stem: String = qualified
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                b as char
            } else {
                '_'
            }
        })
        .collect();
    if stem.bytes().all(|b| b == b'.') {
        format!("{}.log", stem.replace('.', "_"))
    } else {
        format!("{stem}.log")
    }
}

/// An unusable plugin log directory.
#[cold]
pub(crate) fn dir_refusal(dir: &std::path::Path, e: &std::io::Error) -> String {
    format!("plugins.logs.dir {}: {e}", dir.display())
}

/// A failed log rotation, the line it writes in the file.
#[cold]
pub(crate) fn rotation_failed(failed: &[crate::host::FailedStep], limit: u64) -> String {
    format!(
        "busbar: this log file could not be rotated ({}); it is tried again once it holds another {limit} bytes",
        failed.join(", ")
    )
}
