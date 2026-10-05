// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRAIT-TO-SLOT COVERAGE WITNESS (TRANSPORT-STACK (3): the HOT ABI is a mechanical lowering of
//! the carrier and framer traits, ONE SLOT PER METHOD).
//!
//! The linked traits are the source of truth. This reads `Carrier` and `Framer` out of
//! `src/transport/stack.rs` and their slot tables out of `src/abi/hot/transport.rs`, and requires the
//! two to name exactly the same methods: a trait method with no slot (a lowering that silently drops
//! what a linked transport does) is RED, and so is a slot no method explains (a byte-stream-shaped
//! slot of its own). The RED arm is kept: [`a_method_without_a_slot_is_red`] runs the same check
//! over a trait that grew a method its table did not, and requires it to name the method.

use std::collections::BTreeSet;
use std::path::Path;

/// The `{ ... }` block that opens at `header` in `src`, braces balanced.
fn block<'a>(src: &'a str, header: &str) -> Result<&'a str, String> {
    let start = src
        .find(header)
        .ok_or_else(|| format!("`{header}` is not in the source"))?;
    let open = start
        + src[start..]
            .find('{')
            .ok_or_else(|| format!("`{header}` opens no block"))?;
    let mut depth = 0_usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&src[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    Err(format!("`{header}`'s block never closes"))
}

/// The methods a trait block declares (`fn name`), outside comments.
fn methods(trait_block: &str) -> BTreeSet<String> {
    trait_block
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter_map(|l| l.strip_prefix("fn "))
        .map(|rest| {
            rest.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// The slots a slot-table list declares (`name: Alias = fn(...)`, the one declarative list the
/// table and its fn-pointer types are generated from); the sized header is not a slot.
fn slots(table_block: &str) -> BTreeSet<String> {
    table_block
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter_map(|l| l.split_once(':'))
        .filter(|(name, ty)| {
            !name.contains(' ')
                && ty
                    .split_once('=')
                    .is_some_and(|(_, f)| f.trim().starts_with("fn("))
        })
        .map(|(name, _)| name.trim().to_string())
        .collect()
}

/// Every method of `trait_name` in `traits` has exactly one slot in `table_name` of `abi`, and every
/// slot is a method's.
fn covered(traits: &str, trait_name: &str, abi: &str, table_name: &str) -> Result<usize, String> {
    let methods = methods(block(traits, &format!("pub trait {trait_name}: "))?);
    let slots = slots(block(
        abi,
        &format!("pub struct {table_name} lowers {trait_name} {{"),
    )?);
    let unlowered: Vec<_> = methods.difference(&slots).collect();
    let unexplained: Vec<_> = slots.difference(&methods).collect();
    if methods.is_empty() {
        return Err(format!(
            "`{trait_name}` declares no method the witness can read"
        ));
    }
    if !unlowered.is_empty() || !unexplained.is_empty() {
        return Err(format!(
            "`{trait_name}` -> `{table_name}`: methods with no slot {unlowered:?}, slots no method \
             explains {unexplained:?}"
        ));
    }
    Ok(methods.len())
}

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_carrier_and_framer_method_has_exactly_one_slot() {
    let (traits, abi) = (
        read("src/transport/stack.rs"),
        read("src/abi/hot/transport.rs"),
    );
    assert_eq!(covered(&traits, "Carrier", &abi, "CarrierSlots"), Ok(8));
    assert_eq!(covered(&traits, "Framer", &abi, "FramerSlots"), Ok(10));
}

/// THE RED ARM, kept: a trait that grew a method its slot table did not is refused, and the refusal
/// names the method — the check above is one a real drift fails.
#[test]
fn a_method_without_a_slot_is_red() {
    let (traits, abi) = (
        read("src/transport/stack.rs"),
        read("src/abi/hot/transport.rs"),
    );
    let grown = traits.replacen(
        "pub trait Carrier: Plugin + Send + Sync + 'static {",
        "pub trait Carrier: Plugin + Send + Sync + 'static {\n    fn poll_shutdown(&self);",
        1,
    );
    assert_ne!(grown, traits, "the plant landed");
    let err = covered(&grown, "Carrier", &abi, "CarrierSlots").unwrap_err();
    assert!(
        err.contains("methods with no slot [\"poll_shutdown\"]"),
        "{err}"
    );
    // And the other direction: a slot no method explains.
    let widened = abi.replacen(
        "pub struct CarrierSlots lowers Carrier {",
        "pub struct CarrierSlots lowers Carrier {\n    poll_peek: CarrierPeekFn = fn(state: *mut c_void);",
        1,
    );
    assert_ne!(widened, abi, "the plant landed");
    let err = covered(&traits, "Carrier", &widened, "CarrierSlots").unwrap_err();
    assert!(
        err.contains("slots no method explains [\"poll_peek\"]"),
        "{err}"
    );
}

/// The host hands a transport ONE service: `wake`. No slot returns key or certificate material to a
/// plugin, and none takes a signing request from one — connection security is core's own (#40(b),
/// #36; TRANSPORT-STACK (1)).
#[test]
fn the_host_hands_a_transport_nothing_but_its_waker() {
    let abi = read("src/abi/hot/transport.rs");
    let host = block(&abi, "pub struct WireWaker").unwrap();
    let fns: Vec<_> = host
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("pub "))
        .filter(|l| l.contains("Option<"))
        .collect();
    assert_eq!(fns, ["wake: Option<WireWakeFn>,"]);
}

/// The fields a struct block declares (`pub name: ...`), outside comments; `_reserved` padding and
/// the sized header are not fields a claim states.
fn fields(struct_block: &str) -> BTreeSet<String> {
    struct_block
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("pub "))
        .filter_map(|rest| rest.split_once(':'))
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.starts_with('_') && name != "size")
        .collect()
}

/// Every field of the linked `Claim` has exactly one field in `DeclClaim`, and every `DeclClaim`
/// field is a claim's (TRANSPORT-STACK (A): the claims table is lowered as mechanically as the
/// slots are).
fn claims_covered(traits: &str, abi: &str) -> Result<usize, String> {
    let linked = fields(block(traits, "pub struct Claim {")?);
    let lowered = fields(block(abi, "pub struct DeclClaim {")?);
    let unlowered: Vec<_> = linked.difference(&lowered).collect();
    let unexplained: Vec<_> = lowered.difference(&linked).collect();
    if linked.is_empty() {
        return Err("`Claim` declares no field the witness can read".to_string());
    }
    if !unlowered.is_empty() || !unexplained.is_empty() {
        return Err(format!(
            "`Claim` -> `DeclClaim`: fields with no lowering {unlowered:?}, lowered fields no claim \
             explains {unexplained:?}"
        ));
    }
    Ok(linked.len())
}

#[test]
fn every_claim_field_is_lowered_exactly_once() {
    let (traits, abi) = (
        read("src/transport/stack.rs"),
        read("src/abi/hot/transport.rs"),
    );
    assert_eq!(claims_covered(&traits, &abi), Ok(8));
}

/// THE RED ARM, kept: a claim that grew a field the lowering did not is refused, by name.
#[test]
fn a_claim_field_without_a_lowering_is_red() {
    let (traits, abi) = (
        read("src/transport/stack.rs"),
        read("src/abi/hot/transport.rs"),
    );
    let grown = traits.replacen(
        "pub struct Claim {",
        "pub struct Claim {\n    pub framing: Framing,",
        1,
    );
    assert_ne!(grown, traits, "the plant landed");
    let err = claims_covered(&grown, &abi).unwrap_err();
    assert!(
        err.contains("fields with no lowering [\"framing\"]"),
        "{err}"
    );
}

// ── the memory ABI's kind ops (`abi/transport`): the table the host drives every carrier through ──

/// THE LOWERING of each trait method to its kind op in `abi/transport`'s `slot` module: the one
/// place a method's slot is named. A method missing here, or a kind op of the role no method
/// lowers to, is RED.
const CARRIER_SLOTS: &[(&str, &str)] = &[
    ("listen", "LISTEN"),
    ("poll_accept", "ACCEPT"),
    ("dial", "DIAL"),
    ("poll_read", "READ"),
    ("poll_write", "WRITE"),
    ("poll_flush", "FLUSH"),
    ("poll_close", "SHUT"),
    ("arrival", "ARRIVAL"),
];
const FRAMER_SLOTS: &[(&str, &str)] = &[
    ("locate", "LOCATE"),
    ("open", "BEGIN"),
    ("ingest", "INGEST"),
    ("emit", "EMIT"),
    ("encode_envelope", "ENCODE"),
    ("refusal", "REFUSE"),
    ("close", "FINISH"),
    ("detach", "DETACH"),
    ("adopt", "ADOPT"),
    ("tick", "TIMER"),
];

/// The kind ops of `role` (`Carrier` | `Framer`) the `slot` module declares: each `pub const`
/// whose doc line names the role.
fn kind_ops(abi: &str, role: &str) -> Result<BTreeSet<String>, String> {
    let slot = block(abi, "pub mod slot")?;
    let mut ops = BTreeSet::new();
    let mut doc = String::new();
    for line in slot.lines().map(str::trim) {
        if let Some(d) = line.strip_prefix("///") {
            doc = d.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("pub const ") {
            let name = rest.split(':').next().unwrap_or_default().trim().to_string();
            if doc.starts_with(&format!("{role}:")) {
                ops.insert(name);
            }
            doc.clear();
        }
    }
    Ok(ops)
}

/// Every method of `trait_name` lowers to exactly one kind op of `role`, and every kind op of the
/// role is a method's.
fn kind_covered(
    traits: &str,
    trait_name: &str,
    abi: &str,
    role: &str,
    lowering: &[(&str, &str)],
) -> Result<usize, String> {
    let methods = methods(block(traits, &format!("pub trait {trait_name}: "))?);
    let ops = kind_ops(abi, role)?;
    let unlowered: Vec<_> = methods
        .iter()
        .filter(|m| !lowering.iter().any(|(l, op)| l == m && ops.contains(*op)))
        .collect();
    let unexplained: Vec<_> = ops
        .iter()
        .filter(|op| !lowering.iter().any(|(m, o)| o == op && methods.contains(*m)))
        .collect();
    if methods.is_empty() || ops.is_empty() {
        return Err(format!("`{trait_name}` or its `{role}` kind ops read as empty"));
    }
    if !unlowered.is_empty() || !unexplained.is_empty() {
        return Err(format!(
            "`{trait_name}` -> `abi::transport::slot`: methods with no kind op {unlowered:?}, \
             kind ops no method explains {unexplained:?}"
        ));
    }
    Ok(methods.len())
}

/// THE CARRIER AND FRAMER TRAITS ARE LOWERED ONE KIND OP PER METHOD on the memory ABI the host
/// drives (TRANSPORT-STACK (3)): the carrier's eight, the framer's ten.
#[test]
fn every_carrier_and_framer_method_has_exactly_one_kind_op() {
    let (traits, abi) = (
        read("src/transport/stack.rs"),
        read("src/abi/transport/mod.rs"),
    );
    assert_eq!(
        kind_covered(&traits, "Carrier", &abi, "Carrier", CARRIER_SLOTS),
        Ok(8)
    );
    assert_eq!(
        kind_covered(&traits, "Framer", &abi, "Framer", FRAMER_SLOTS),
        Ok(10)
    );
}

/// THE RED ARM, kept: a carrier method with no kind op is refused by name, and so is a carrier kind
/// op no method explains.
#[test]
fn a_carrier_method_without_a_kind_op_is_red() {
    let (traits, abi) = (
        read("src/transport/stack.rs"),
        read("src/abi/transport/mod.rs"),
    );
    let grown = traits.replacen(
        "pub trait Carrier: Plugin + Send + Sync + 'static {",
        "pub trait Carrier: Plugin + Send + Sync + 'static {\n    fn poll_shutdown(&self);",
        1,
    );
    assert_ne!(grown, traits, "the plant landed");
    let err = kind_covered(&grown, "Carrier", &abi, "Carrier", CARRIER_SLOTS).unwrap_err();
    assert!(err.contains("methods with no kind op [\"poll_shutdown\"]"), "{err}");
    let widened = abi.replacen(
        "pub mod slot {",
        "pub mod slot {\n    /// Carrier: peek.\n    pub const PEEK: u32 = 99;",
        1,
    );
    assert_ne!(widened, abi, "the plant landed");
    let err = kind_covered(&traits, "Carrier", &widened, "Carrier", CARRIER_SLOTS).unwrap_err();
    assert!(err.contains("kind ops no method explains [\"PEEK\"]"), "{err}");
}
