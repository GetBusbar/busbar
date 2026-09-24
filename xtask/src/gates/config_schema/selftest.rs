//! THE GATE'S OWN RED PROOFS — the shell's `--selftest`, driven through [`Gate::run`].
//!
//! ## HOW A CASE IS PLANTED
//!
//! The shell fed its classifier hand-written `base.json`/`fresh.json` pairs. That proved the
//! classifier judged a delta correctly and NOTHING about the generator: every one of those cases
//! stayed green while the generator rendered no delta at all for a breaking source change, which is
//! exactly the failure that let a retyped secret reference through.
//!
//! So the cases here move the half a real run can move. The FRESH side is always the real render of
//! the real tracked source set — the thing that ships — and the BASELINE is planted through
//! [`crate::ctx::Ctx::git_show`], which is where a real run reads it from. Planting the baseline and
//! reading the fresh side from the tree is the same shape as a real commit: it is the working tree
//! that changed, and the delta is measured against history.
//!
//! A mutation is therefore expressed BACKWARDS from how the shell wrote it. "A new optional field
//! is additive" is planted by REMOVING that field from the baseline, so the real render supplies it;
//! "a field was removed" is planted by ADDING one to the baseline that the real render does not
//! have. This is not a trick of the harness — it is what a commit that adds or deletes a field
//! actually looks like to the gate.
//!
//! ## WHAT IS PROVEN HERE AND WHAT IS PROVEN IN `xtask/tests/config_schema.rs`
//!
//! The five ROWS are proven here, because a row is a property of the gate. The GENERATOR SURFACE —
//! that a hand-written `Deserialize`'s wire keys, member types and refused input forms move the
//! fingerprint at all, that `rename_all` reaches struct fields, that a `cfg(test)` fixture is not
//! grammar, that a duplicate bare name is refused — is proven against [`super::schema::extract`]
//! over throwaway sources in `xtask/tests/config_schema.rs`, because those are properties of the
//! fingerprint and driving them through a five-row gate would say less about them, not more.
//!
//! ## THE ONE ARM NO PLANT HERE CAN REACH
//!
//! The classifier's unrecognised-kind break fires only when the baseline AND the fresh render agree
//! on a kind the classifier does not know, and the fresh render is produced by a generator that
//! emits exactly four. It is red-proved directly against [`super::classify::classify`] in
//! `xtask/tests/config_schema.rs`, and it is named here so that its absence from this file reads as
//! a decision rather than as an oversight.

use serde_json::{json, Value};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_rows_green, prove_rows_red, Gate, Report};

use super::schema;
use super::{
    ROW_ADDITIVE_ONLY, ROW_BASELINE, ROW_SNAPSHOT_DRIFT, ROW_TRACKED_SOURCES, ROW_WAIVERS,
};

/// The floor under this suite's own case count. A suite that runs zero cases reports zero failures,
/// which is the false green the shell gate was burned by; the shell pinned its floor at 68 across
/// its classifier, generator and coverage arms, and the floor only ever rises. The generator and
/// coverage arms live in `xtask/tests/config_schema.rs` and carry their own floor.
pub const CASE_FLOOR: usize = 46;

// ── THE ANCHORS ──────────────────────────────────────────────────────────────────────────────────
// Real types from the real frozen surface, chosen because the shell's own coverage assertions
// already pinned them: mutating a type nobody ships would prove the classifier moves and leave the
// question of whether it is pointed at anything.

/// The top-level document. `deny_unknown_fields` is ON, which is what makes it the right subject
/// for the flag cases.
const T_STRUCT: &str = "DeployCfg";
/// One of the 1.6.0-additive LIFTED carriers — optional, and typed.
const F_OPTIONAL: &str = "tools";
/// A field an operator MUST write. The requiredness cases need one that is genuinely required.
const F_REQUIRED: &str = "providers";
const T_ENUM: &str = "HookStage";
const V_ENUM: &str = "routing";
const T_ALIAS: &str = "type HookDefs";
const T_MANUAL: &str = "manual-de SecretRef";
/// A container whose `deny_unknown_fields` is OFF in the real render.
const T_DENY_OFF: &str = "BindingMode";

// ── PLANTING ─────────────────────────────────────────────────────────────────────────────────────

/// The committed snapshot, parsed. It is byte-equal to the fresh render on a clean tree, which is
/// what makes it the honest starting point for a baseline: a mutation of it is a delta of exactly
/// the size the case describes and of no other size.
fn snapshot(cx: &Ctx) -> Value {
    serde_json::from_str(&cx.read(schema::SNAPSHOT).unwrap_or_default())
        .unwrap_or_else(|_| json!({ "types": {} }))
}

/// An overlay whose BASELINE REF carries `doc` as the baseline snapshot.
///
/// The ref is planted as WELL as the file. A synthetic ref is answered entirely from the overlay
/// (see [`crate::ctx::Ctx::git_show`]), so this cannot fall through to the real repository and
/// silently judge against a real ref.
///
/// IT PLANTS [`super::DEFAULT_BASELINE_REF`] AND NEVER A LITERAL. Every plant in this file used to
/// name `HEAD`, because that is what the default was; the moment the default moved to the freeze
/// point those plants would have addressed a ref the gate no longer asks about, the overlay would
/// have gone unread, and every case would have judged the real tree against the real tag while
/// believing it was judging its own mutation. The cases would not have failed — several would have
/// stayed green — so the constant is the only safe spelling.
fn baseline_doc(doc: &Value) -> Overlay {
    let mut ov = Overlay::new();
    ov.set_command(format!("git-ref:{}", super::DEFAULT_BASELINE_REF), "1");
    ov.set_command(
        format!(
            "git-show:{}:{}",
            super::DEFAULT_BASELINE_REF,
            schema::SNAPSHOT
        ),
        schema::canonical(doc),
    );
    ov
}

/// The committed snapshot as the baseline, with one mutation applied.
fn baseline(cx: &Ctx, f: impl Fn(&mut Value)) -> Overlay {
    let mut doc = snapshot(cx);
    f(&mut doc);
    baseline_doc(&doc)
}

/// The same, plus a waiver register. Every waiver case needs both halves: the break, and the line
/// that does or does not excuse it.
fn baseline_with_waivers(cx: &Ctx, waivers: &str, f: impl Fn(&mut Value)) -> Overlay {
    let mut ov = baseline(cx, f);
    ov.set(schema::WAIVERS, waivers.to_string());
    ov
}

/// Drop `key` from the baseline's type map — "the working tree ADDED this".
fn drop_type(doc: &mut Value, key: &str) {
    if let Some(t) = doc["types"].as_object_mut() {
        t.remove(key);
    }
}

/// THE FIXTURE BASE: the committed snapshot as the baseline, and an EMPTY waiver register — the
/// unplanted state every `ROW_ADDITIVE_ONLY` red proof is measured from.
///
/// WHY A FIXTURE AND NOT THE REAL BASELINE. [`crate::gates::prove_red`] demands a GREEN -> RED
/// transition, and it reads the GREEN half off the context it is handed. Handed the real tree, that
/// half is the real render against the real freeze-point ref — which is RED today on real debt (the
/// seven `PoolMember` removals; see the second control in [`run`]). Every additive red proof
/// measured from there was PROOF IMPOSSIBLE: a planted break over a row that was already red proves
/// nothing about whether the rule can fire.
///
/// Measured from THIS base instead, the unplanted additive row is honestly green — the committed
/// snapshot is byte-equal to the fresh render, which the first control proves — and each case's
/// plant is that same base with exactly one mutation, so the RED it produces is the plant's and
/// no one else's. The real-tree red is not hidden by this: it stays RED on `cargo xtask gate
/// config-schema` and on the second control below. This fixes the PROOF, not the tree.
///
/// The register is emptied for the same reason [`additive_green`] empties it: a verdict about
/// waivers must not decide a case that is not about waivers.
fn fixture_base(cx: &Ctx) -> Overlay {
    baseline_with_waivers(cx, "# no waivers\n", |_| {})
}

/// The context whose UNPLANTED state is [`fixture_base`]. A plant handed to a proof run on this
/// context must itself carry the whole base (every `baseline*` helper here builds a complete
/// overlay), because [`Ctx::with_overlay`] replaces the overlay rather than layering on it.
fn on_fixture(cx: &Ctx) -> Ctx {
    cx.with_overlay(fixture_base(cx))
}

/// A green case for the additive rule.
///
/// THE REGISTER IS EMPTIED IN EVERY ONE OF THESE. The committed register's single line is stale
/// against this branch's own `HEAD`, so leaving it in place would let a verdict about waivers decide
/// a case that is not about waivers. The waiver cases plant their own register explicitly.
fn additive_green<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    f: impl Fn(&mut Value),
) -> crate::gates::CasePlan<'a> {
    prove_rows_green(
        cx,
        gate,
        name,
        &[ROW_ADDITIVE_ONLY],
        baseline_with_waivers(cx, "# no waivers\n", f),
    )
}

/// A red case for the additive rule, naming the path and the reason the report must carry.
///
/// MEASURED FROM [`fixture_base`], never from the real tree: the transition proven is "the committed
/// snapshot as baseline is additive-green; the same baseline with this one mutation is RED".
fn additive_red<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    naming: &[&str],
    f: impl Fn(&mut Value),
) -> crate::gates::CasePlan<'a> {
    prove_rows_red(
        &on_fixture(cx),
        gate,
        name,
        &[ROW_ADDITIVE_ONLY],
        baseline_with_waivers(cx, "# no waivers\n", f),
        naming,
    )
}

/// The tracked file carrying `SecretRef`'s hand-written `Deserialize`, at its path today and at the
/// freeze point alike (it has not moved since `v1.5.3`).
const SECRETREF_SRC: &str = "crates/secret-ref/src/lib.rs";

/// A baseline `SecretRef` impl that REFUSES every bare scalar — the `v1.5.3` shape, whose
/// `visit_str` could only fail and whose other scalar forms fell to serde's default error.
const BASE_SECRETREF_REFUSES_ALL: &str = "impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(d: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct RefVisitor;
        impl<'de> Visitor<'de> for RefVisitor {
            type Value = SecretRef;
            fn visit_str<E>(self, _v: &str) -> Result<SecretRef, E> where E: de::Error {
                Err(E::custom(\"a secret must be a reference\"))
            }
            fn visit_map<A>(self, map: A) -> Result<SecretRef, A::Error> where A: MapAccess<'de> {
                Ok(from_map(map))
            }
        }
        d.deserialize_any(RefVisitor)
    }
}
";

/// A baseline `SecretRef` impl that ACCEPTS every bare scalar — so each one the tree refuses today
/// is a form that parsed and no longer does.
const BASE_SECRETREF_ACCEPTS_ALL: &str = "impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(d: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        struct RefVisitor;
        impl<'de> Visitor<'de> for RefVisitor {
            type Value = SecretRef;
            fn visit_str<E>(self, v: &str) -> Result<SecretRef, E> { Ok(lit(v)) }
            fn visit_u64<E>(self, v: u64) -> Result<SecretRef, E> { Ok(lit(v)) }
            fn visit_i64<E>(self, v: i64) -> Result<SecretRef, E> { Ok(lit(v)) }
            fn visit_f64<E>(self, v: f64) -> Result<SecretRef, E> { Ok(lit(v)) }
            fn visit_bool<E>(self, v: bool) -> Result<SecretRef, E> { Ok(lit(v)) }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<SecretRef, E> { Ok(lit(v)) }
        }
        d.deserialize_any(RefVisitor)
    }
}
";

/// The fixture base with `SecretRef`'s hand-written detail removed from the baseline SNAPSHOT — as
/// `v1.5.3` has it — and `src` planted as the `SecretRef` source the baseline REF carries. The ref
/// is synthetic, so every other source read at it answers "no such file" rather than falling
/// through to the real repository.
fn predating_baseline(cx: &Ctx, src: &str) -> Overlay {
    let mut ov = baseline_with_waivers(cx, "# no waivers\n", |d| drop_type(d, T_MANUAL));
    ov.set_command(
        format!("git-show:{}:{SECRETREF_SRC}", super::DEFAULT_BASELINE_REF),
        src.to_string(),
    );
    ov
}

/// Record `PoolMember` in the baseline the way the freeze point does: a DERIVED struct carrying the
/// fields its map grammar accepts, read from the forwarded `RichMember` node of the real render —
/// plus, when `extra` is named, one field the forwarded grammar does not carry.
fn derived_pool_member(d: &mut Value, extra: Option<&str>) {
    let mut fields = d["types"]["RichMember"]["fields"].clone();
    if let (Some(x), Some(m)) = (extra, fields.as_object_mut()) {
        m.insert(x.to_string(), json!({ "optional": true, "type": "u32" }));
    }
    d["types"]["PoolMember"] = json!({ "kind": "struct", "fields": fields });
}

pub fn run<'a>(gate: &'a dyn Gate, cx: &'a Ctx) -> Report<'a> {
    let mut report = Report::new();

    // ── THE CONTROLS. Every RED below is worth nothing unless the unplanted tree is green in the
    //    rows the case is about, so the controls come first and are narrowed to those rows.
    //
    //    ROW_WAIVERS is deliberately NOT in this control. The committed register's one line is
    //    stale against this branch's own `HEAD` — the widened `SecretRef` refusal it excuses is
    //    already in the baseline — so the real tree is RED there, in the legacy script exactly as
    //    here. Asserting it green would be asserting a tree we do not have; it gets its own green
    //    below, over a baseline where the waiver is doing work.
    report.push(prove_rows_green(
        cx,
        gate,
        "control: the real tracked source set renders the committed snapshot with no drift",
        &[ROW_TRACKED_SOURCES, ROW_SNAPSHOT_DRIFT, ROW_BASELINE],
        Overlay::new(),
    ));
    // THIS CONTROL IS RED ON THIS TREE, AND THE RED IS TRUE. Leave it.
    //
    // It was vacuous until the baseline was repaired: with `DEFAULT_BASELINE_REF = "HEAD"` it
    // compared the tree against itself, so "the real render against the real baseline is additive"
    // was a sentence that could not be false. Against the freeze point it is a real assertion.
    //
    // It first went red on seven `PoolMember` "removals" (`attempt_timeout_ms`, `context_max`,
    // `model`, `reasoning`, `tags`, `tier`, `weight`) — FALSE ones: `PoolMember` became a
    // hand-written impl that forwards a map to a derived `RichMember`, the wire still parses all
    // seven, and only the renderer's sentinel had lost them. The classifier now sees through the
    // forward ([`super::classify::SeeThrough`]; the see-through cases below), with the snapshot's
    // bytes unchanged. What keeps it red now is a TRUE finding the refusal arm could not make
    // before it read the baseline's source (item 163): `manual-de SecretRef::visit_str` — at
    // `v1.5.3` a bare string was refused outright, and today the bare string `none` parses (the
    // keyless reference). Whether that widening is waived is the owner's call; see
    // `docs/design/1.6.0-denominator.md` §8.1 for the history.
    //
    // This standing red USED to make every `ROW_ADDITIVE_ONLY` red-proof below report
    // `Impossible`, because each was measured from the real tree and `prove_red` demands a
    // GREEN -> RED transition. Those proofs are now measured from [`fixture_base`] — whose
    // additive row is green, which the fixture control below proves — so each is a real
    // transition again, and none of them depends on this row. That is a repair to the PROOFS, not
    // to this row: it is NOT a reason to waive the path, to re-record the snapshot, or to narrow
    // this control to rows it can pass — each of those restores the green and nothing else.
    report.push(prove_rows_green(
        cx,
        gate,
        "control: the real render against the real baseline is additive",
        &[ROW_ADDITIVE_ONLY],
        Overlay::new(),
    ));
    // THE FIXTURE CONTROL. Every `ROW_ADDITIVE_ONLY` red proof below starts from this base, so it
    // must be green on that row — or each of those proofs is measured from a red, and the harness
    // will say so (`Impossible`) rather than pass it.
    report.push(prove_rows_green(
        cx,
        gate,
        "control: the fixture base (committed snapshot as baseline, empty register) is additive",
        &[ROW_ADDITIVE_ONLY, ROW_BASELINE],
        fixture_base(cx),
    ));

    // ══ :tracked-sources ═════════════════════════════════════════════════════════════════════════
    // A source that silently drops out of the set silently un-freezes its grammar. Each of these is
    // a way that could happen, and each must stop the gate rather than narrow the scan.

    let mut ov = Overlay::new();
    ov.remove("crates/secret-ref/src/lib.rs");
    report.push(prove_rows_red(
        cx,
        gate,
        "a tracked source that VANISHED is a hard error, never a skip",
        &[ROW_TRACKED_SOURCES],
        ov,
        &["does not exist"],
    ));

    let mut ov = Overlay::new();
    ov.remove("crates/api/src/auth.rs");
    report.push(prove_rows_red(
        cx,
        gate,
        "the upstream-credential grammar leaving the tree is a hard error",
        &[ROW_TRACKED_SOURCES],
        ov,
        &["does not exist"],
    ));

    // TWO HOMES FOR ONE PLANE'S GRAMMAR. Resolving this by preference order would freeze one home's
    // shapes and quietly un-freeze the other's — a coverage hole that reads green.
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-a2a-fork/src/a2a/config.rs",
        "// a second home for the agents: grammar\n",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "TWO grammar homes for one plane is REFUSED, never silently picked",
        &[ROW_TRACKED_SOURCES],
        ov,
        &["config-grammar directories"],
    ));

    // A DUPLICATE BARE NAME. The fingerprint is a flat map, so the second one read would replace
    // the first and the classifier would report the swap as a break nobody made.
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel/src/config/zz_collision_fixture.rs",
        "#[derive(serde::Deserialize)]\npub struct DeployCfg {\n    pub other: String,\n}\n",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a DUPLICATE bare type name across two tracked files is REFUSED",
        &[ROW_TRACKED_SOURCES],
        ov,
        &["declared in BOTH"],
    ));

    // A LIFTED KEY WITH NO CARRIER. The lift list must not be usable to hold a deleted field open.
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel/src/config/zz_lift_fixture.rs",
        "pub(crate) const LIFTED_EXTRA_KEYS: &[&str] = &[\"zz_no_such_key\"];\n",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a lifted key that NO struct carries is REFUSED",
        &[ROW_TRACKED_SOURCES],
        ov,
        &["no struct in the tracked"],
    ));

    // AN UNSUPPORTED `rename_all` would fingerprint wire keys the parser does not accept.
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel/src/config/zz_rename_fixture.rs",
        "#[derive(serde::Deserialize)]\n#[serde(rename_all = \"Klingon\")]\npub struct ZzRenameFx {\n    pub max_tokens: u32,\n}\n",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "an unsupported #[serde(rename_all)] is REFUSED, not silently ignored",
        &[ROW_TRACKED_SOURCES],
        ov,
        &["unsupported"],
    ));

    // ── THE CORE-KIND ROOT CENSUS ────────────────────────────────────────────────────────────────
    // The tracked set used to name ONE core crate by a hardcoded path. The config layer is being
    // carved out of the engine (`busbar-kernel`, which absorbed `busbar-core`) into `busbar-core-*`
    // surfaces, and under a hardcoded root every file that leaves takes its grammar out of the
    // fingerprint with it: the fresh render loses the types, and the additive rule reads the loss as
    // a BREAK. That is a MOVE being reported as a deletion, which is the one thing this gate must not
    // say — the operator-visible grammar did not change by a byte.
    //
    // These two cases are a matched pair, and neither is worth anything without the other: the
    // first says a type that MOVED between two core-kind roots is not a break, the second says a
    // type that VANISHED from every core-kind root still is. A census that only knew how to say
    // "fine" would pass both halves of that pair and gate nothing.
    //
    // THE MOVE TARGET IS READ FROM THE CENSUS, NEVER NAMED. This case used to plant into
    // `crates/busbar-core-config`, which the drain has since dissolved: no manifest names it and
    // no directory holds it, so the "move" re-homed the file where nothing reads it — a deletion
    // asserted green (item 231). The target is now the grammar directory of a core-kind root the
    // census ACTUALLY returns, other than the one the file leaves; a census that stops counting
    // that root turns this move back into a deletion and this case red. Both halves are measured
    // over [`fixture_base`], so the standing real-tree red on the additive row cannot decide them.
    let moved = "crates/busbar-kernel/src/config/overlay.rs";
    let target = schema::core_roots(cx)
        .unwrap_or_default()
        .into_iter()
        .map(|r| schema::grammar_dir(cx, &r))
        .find(|d| !moved.starts_with(&format!("{d}/")))
        .unwrap_or_else(|| "crates/<no second core-kind root in the census>/src".to_string());

    let mut ov = fixture_base(cx);
    ov.set(
        format!("{target}/overlay.rs"),
        cx.read(moved).unwrap_or_default(),
    );
    ov.remove(moved);
    report.push(prove_rows_green(
        cx,
        gate,
        "a grammar type that MOVED between two core-kind roots is NOT a break",
        &[ROW_TRACKED_SOURCES, ROW_SNAPSHOT_DRIFT, ROW_ADDITIVE_ONLY],
        ov,
    ));

    // THE SAME DELETION WITHOUT THE ARRIVAL. No second core crate, no re-home: the types are gone
    // from the tracked set entirely. The census must not have turned a removal into a shrug.
    let mut ov = baseline_with_waivers(cx, "# no waivers\n", |_| {});
    ov.remove(moved);
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "a grammar type that VANISHED from every core-kind root is still a BREAK",
        &[ROW_ADDITIVE_ONLY],
        ov,
        &["OverlayDoc"],
    ));

    // ══ :snapshot-drift ══════════════════════════════════════════════════════════════════════════

    let mut ov = Overlay::new();
    ov.set(
        schema::SNAPSHOT,
        cx.read(schema::SNAPSHOT).unwrap_or_default() + "\n",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a committed snapshot that is not the fresh render is STALE",
        &[ROW_SNAPSHOT_DRIFT],
        ov,
        &["is STALE"],
    ));

    let mut ov = Overlay::new();
    ov.set(
        schema::SNAPSHOT,
        cx.read(schema::SNAPSHOT)
            .unwrap_or_default()
            .replace("\"frozen_at\": \"1.5.3\"", "\"frozen_at\": \"9.9.9\""),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "drift in the _meta block is drift too — the whole file is frozen, not just the types",
        &[ROW_SNAPSHOT_DRIFT],
        ov,
        &["is STALE"],
    ));

    let mut ov = Overlay::new();
    ov.remove(schema::SNAPSHOT);
    report.push(prove_rows_red(
        cx,
        gate,
        "a MISSING committed snapshot is RED — there is nothing to compare against",
        &[ROW_SNAPSHOT_DRIFT],
        ov,
        &["MISSING"],
    ));

    // A SOURCE CHANGE THE SNAPSHOT DOES NOT CARRY. This is the drift the guard exists for, and it
    // is planted in the SOURCE rather than in the artefact, so it also proves the generator sees a
    // real edit to a real tracked file.
    match cx.read("crates/busbar-voice/src/config.rs") {
        Ok(src) => {
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-voice/src/config.rs",
                src + "\n#[derive(serde::Deserialize)]\npub struct ZzDriftFx {\n    pub added: String,\n}\n",
            );
            report.push(prove_rows_red(
                cx,
                gate,
                "a new config type in a tracked source makes the committed snapshot STALE",
                &[ROW_SNAPSHOT_DRIFT],
                ov,
                &["is STALE"],
            ));
        }
        Err(e) => report.note_infra_failure(format!(
            "the voice plane's config grammar could not be read: {e}"
        )),
    }

    // ══ :baseline ════════════════════════════════════════════════════════════════════════════════
    // Three bypasses, each of which made every breaking change green.

    let mut ov = Overlay::new();
    ov.set_command(format!("git-ref:{}", super::DEFAULT_BASELINE_REF), "0");
    report.push(prove_rows_red(
        cx,
        gate,
        "a baseline ref that does NOT RESOLVE is refused (the shallow-checkout bypass)",
        &[ROW_BASELINE],
        ov,
        &["does not resolve"],
    ));

    // Planted ref, no planted file: resolves, carries no snapshot.
    let mut ov = Overlay::new();
    ov.set_command(format!("git-ref:{}", super::DEFAULT_BASELINE_REF), "1");
    report.push(prove_rows_red(
        cx,
        gate,
        "a baseline ref that RESOLVES but carries NO snapshot is RED, not a friendly note",
        &[ROW_BASELINE],
        ov,
        &["carries NO"],
    ));

    // THE HOLE: an empty baseline passes. Against an empty type map every type in the fresh render
    // is `new type/section added`, which is ADDITIVE, which is GREEN — a total, silent bypass that
    // looks exactly like a clean run.
    report.push(prove_rows_red(
        cx,
        gate,
        "HOLE: a baseline whose type map is EMPTY is refused (every delta would read as additive)",
        &[ROW_BASELINE],
        baseline(cx, |d| {
            d["types"] = json!({});
        }),
        &["EMPTY type map"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "HOLE: a baseline with NO types key at all is refused on the same terms",
        &[ROW_BASELINE],
        baseline(cx, |d| {
            if let Some(o) = d.as_object_mut() {
                o.remove("types");
            }
        }),
        &["EMPTY type map"],
    ));

    // And the empty baseline must not merely be refused — the additive check must NOT report green
    // beside it. This is the case that distinguishes "the hole is closed" from "the hole is
    // labelled": the row that would have lied is SKIP, never PASS.
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "HOLE: an empty baseline leaves the additive check UNPROVEN rather than passing",
        &[ROW_ADDITIVE_ONLY],
        baseline(cx, |d| {
            d["types"] = json!({});
        }),
        &["unproven"],
    ));

    let mut ov = baseline_doc(&json!({ "types": { "X": { "kind": "struct" } } }));
    ov.set_command(
        format!(
            "git-show:{}:{}",
            super::DEFAULT_BASELINE_REF,
            schema::SNAPSHOT
        ),
        "{ not json",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a baseline snapshot that is not readable JSON is refused",
        &[ROW_BASELINE],
        ov,
        &["does not parse"],
    ));

    // ══ :additive-only — the GREEN arm ═══════════════════════════════════════════════════════════

    report.push(additive_green(
        cx,
        gate,
        "additive: a new OPTIONAL field is GREEN",
        |d| {
            if let Some(f) = d["types"][T_STRUCT]["fields"].as_object_mut() {
                f.remove(F_OPTIONAL);
            }
        },
    ));

    report.push(additive_green(
        cx,
        gate,
        "additive: a whole new section is GREEN",
        |d| drop_type(d, T_ENUM),
    ));

    report.push(additive_green(
        cx,
        gate,
        "additive: an enum-variant append is GREEN",
        |d| {
            if let Some(v) = d["types"][T_ENUM]["variants"].as_array_mut() {
                v.retain(|x| x.as_str() != Some(V_ENUM));
            }
        },
    ));

    report.push(additive_green(
        cx,
        gate,
        "additive: a required -> optional relaxation is GREEN",
        |d| {
            d["types"][T_STRUCT]["fields"][F_OPTIONAL]["optional"] = json!(false);
        },
    ));

    report.push(additive_green(
        cx,
        gate,
        "additive: a NEW definition-map alias is GREEN",
        |d| drop_type(d, T_ALIAS),
    ));

    report.push(additive_green(
        cx,
        gate,
        "additive: a new accepted wire key on a hand-written Deserialize is GREEN",
        |d| {
            if let Some(v) = d["types"][T_MANUAL]["wire_keys"].as_array_mut() {
                v.retain(|x| x.as_str() != Some("env"));
            }
        },
    ));

    report.push(additive_green(
        cx,
        gate,
        "additive: deny_unknown_fields turned OFF widens the accepted set and is GREEN",
        |d| {
            d["types"][T_DENY_OFF]["deny_unknown_fields"] = json!(true);
        },
    ));

    // A NO-OP MUST BE A NO-OP. Key order and formatting are not grammar; the canonical renderer
    // sorts, so a reordered baseline is the same baseline.
    report.push(additive_green(
        cx,
        gate,
        "no-op: a reordered / reformatted baseline is GREEN",
        |d| {
            let reversed: serde_json::Map<String, Value> = d["types"]
                .as_object()
                .map(|t| {
                    t.iter()
                        .rev()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default();
            d["types"] = Value::Object(reversed);
        },
    ));

    // A BASELINE THAT PREDATES A FIELD OF THE FINGERPRINT compares against nothing rather than
    // against the empty set — otherwise the commit that ADDS a check reds the gate. For the
    // refusal arm that is only true when the baseline ref's SOURCE cannot answer either: the
    // fixture's ref is synthetic and plants no source, so there is nothing to measure. The cases
    // after the stricter arm below plant that source, and there the arm DOES fire (item 163).
    report.push(additive_green(
        cx,
        gate,
        "a baseline with no `refused` key AND no source for the impl has nothing to compare",
        |d| {
            if let Some(m) = d["types"][T_MANUAL].as_object_mut() {
                m.remove("refused");
            }
        },
    ));

    report.push(additive_green(
        cx,
        gate,
        "a baseline with no container-flag keys predates them and does not fire them",
        |d| {
            if let Some(m) = d["types"][T_ENUM].as_object_mut() {
                m.remove("deny_unknown_fields");
                m.remove("transparent");
            }
        },
    ));

    // A RELOCATION IS A THIRD VERDICT: the same type, a new module path, no grammar change. A gate
    // that reds on this teaches reviewers to wave it through, which is how a stability gate dies.
    report.push(additive_green(
        cx,
        gate,
        "relocation: a field type that only MOVED module is not a break",
        |d| {
            d["types"][T_STRUCT]["fields"][F_OPTIONAL]["type"] =
                json!("busbar_someplace::config::ToolsSection");
        },
    ));

    report.push(additive_green(
        cx,
        gate,
        "relocation: an alias target that only MOVED module is not a break",
        |d| {
            d["types"][T_ALIAS]["target"] =
                json!("indexmap::IndexMap<String, crate::hooks::HookDefCfg>");
        },
    ));

    // ══ :additive-only — the RED arm ═════════════════════════════════════════════════════════════

    report.push(additive_red(
        cx,
        gate,
        "breaking: a field REMOVAL is RED",
        &["field REMOVED"],
        |d| {
            d["types"][T_STRUCT]["fields"]["zz_removed_key"] =
                json!({ "type": "String", "optional": false });
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: a field RETYPE is RED",
        &["field RETYPED"],
        |d| {
            d["types"][T_STRUCT]["fields"][F_OPTIONAL]["type"] = json!("u32");
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: a field made newly REQUIRED is RED",
        &["made REQUIRED"],
        |d| {
            d["types"][T_STRUCT]["fields"][F_REQUIRED]["optional"] = json!(true);
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: a new REQUIRED field is RED (it breaks a config that omits it)",
        &["new REQUIRED field added"],
        |d| {
            if let Some(f) = d["types"][T_STRUCT]["fields"].as_object_mut() {
                f.remove(F_REQUIRED);
            }
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: an enum-variant DROP is RED",
        &["enum variant REMOVED/RENAMED"],
        |d| {
            if let Some(v) = d["types"][T_ENUM]["variants"].as_array_mut() {
                v.push(json!("zz_dropped"));
            }
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: an enum-variant RENAME is RED (it is a drop and an append)",
        &["enum variant REMOVED/RENAMED"],
        |d| {
            if let Some(v) = d["types"][T_ENUM]["variants"].as_array_mut() {
                for x in v.iter_mut() {
                    if x.as_str() == Some(V_ENUM) {
                        *x = json!("routed");
                    }
                }
            }
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: a whole-section REMOVAL is RED",
        &["type/section REMOVED"],
        |d| {
            d["types"]["ZzGhostCfg"] = json!({
                "kind": "struct",
                "fields": {},
                "deny_unknown_fields": false,
                "transparent": false
            });
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: a kind change (struct -> enum) is RED",
        &["kind changed"],
        |d| {
            d["types"][T_STRUCT] = json!({
                "kind": "enum",
                "variants": ["a"],
                "deny_unknown_fields": true,
                "transparent": false
            });
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: retargeting a definition-map alias to a list is RED",
        &["alias RETARGETED"],
        |d| {
            d["types"][T_ALIAS]["target"] = json!("Vec<HookDefCfg>");
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: dropping an accepted wire key from a hand-written Deserialize is RED",
        &["accepted wire key REMOVED/RENAMED"],
        |d| {
            if let Some(v) = d["types"][T_MANUAL]["wire_keys"].as_array_mut() {
                v.push(json!("zz_sugar"));
            }
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: retyping a hand-written Deserialize's member is RED",
        &["field RETYPED"],
        |d| {
            d["types"][T_MANUAL]["fields"]["module"]["type"] = json!("Vec<String>");
        },
    ));

    // THE STRICTER ARM, BOTH WAYS. Everywhere else a widened grammar is green; here it is not, and
    // the asymmetry is the point — for a secret reference the widened form is an inline literal,
    // the exact shape the type exists to reject and the one that ends up in a boot log.
    report.push(additive_red(
        cx,
        gate,
        "breaking: a REFUSED input form that is no longer refused is RED (the widening arm)",
        &["no longer refused"],
        |d| {
            if let Some(v) = d["types"][T_MANUAL]["refused"].as_array_mut() {
                v.push(json!("seq"));
            }
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: an input form that PARSED and is now refused is RED (the narrowing arm)",
        &["now refused"],
        |d| {
            if let Some(v) = d["types"][T_MANUAL]["refused"].as_array_mut() {
                v.retain(|x| x.as_str() != Some("bool"));
            }
        },
    ));

    // ── THE STRICTER ARM AGAINST A BASELINE SNAPSHOT THAT PREDATES IT (item 163) ─────────────────
    // The pinned freeze point `v1.5.3` carries NO `refused` key and NO `manual-de` node at all, so
    // the two cases above — both planted into a baseline that already records refusals — proved an
    // arm that could never run against the baseline a real run reads. Each case here plants the
    // baseline the way `v1.5.3` looks (no `manual-de SecretRef` node) and the SOURCE that baseline
    // ref carried, and the arm must answer from that source.
    //
    // The widening case leans on the tree as it is: `SecretRef` accepts the bare string `none`
    // (the keyless reference), where a baseline whose `visit_str` can only fail refused every bare
    // string. If the tree stops accepting `none`, this case goes RED loudly — it cannot pass
    // silently, because a plant that proves nothing is refused by the harness.
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "breaking: a refusal DROPPED since a baseline that predates the arm is RED (read from its source)",
        &[ROW_ADDITIVE_ONLY],
        predating_baseline(cx, BASE_SECRETREF_REFUSES_ALL),
        &["manual-de SecretRef::visit_str", "no longer refused"],
    ));
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "breaking: a form that PARSED at a baseline that predates the arm and is now refused is RED",
        &[ROW_ADDITIVE_ONLY],
        predating_baseline(cx, BASE_SECRETREF_ACCEPTS_ALL),
        &["manual-de SecretRef::visit_u64", "now refused"],
    ));
    // ...and it does not cry wolf: the SAME source at the baseline as in the tree is no delta,
    // which is what proves the two sides are measured by one rule.
    report.push(prove_rows_green(
        cx,
        gate,
        "a baseline that predates the arm, carrying the tree's own impl, has no refusal delta",
        &[ROW_ADDITIVE_ONLY],
        predating_baseline(cx, &cx.read(SECRETREF_SRC).unwrap_or_default()),
    ));

    // ── SEEING THROUGH A HAND-WRITTEN IMPL (the seven `PoolMember` "removals") ──────────────────
    // `PoolMember` was a DERIVED struct at the freeze point; today a hand-written impl forwards a
    // map to a derived `RichMember`, and the render records `PoolMember` as a field-less sentinel.
    // Planted the way `v1.5.3` records it, the forwarded grammar must read as unchanged...
    report.push(additive_green(
        cx,
        gate,
        "see-through: a derived struct that became a forwarding hand-written impl is not a removal",
        |d| derived_pool_member(d, None),
    ));
    // ...and a field the forwarded grammar really lost must still read as REMOVED.
    report.push(additive_red(
        cx,
        gate,
        "see-through: a field the forwarded grammar really LOST is still a removal",
        &["PoolMember.zz_gone", "field REMOVED"],
        |d| derived_pool_member(d, Some("zz_gone")),
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: deny_unknown_fields turned ON is RED (a config with an extra key parsed before)",
        &["turned ON"],
        |d| {
            d["types"][T_STRUCT]["deny_unknown_fields"] = json!(false);
        },
    ));

    report.push(additive_red(
        cx,
        gate,
        "breaking: a serde(transparent) flip is RED in EITHER direction",
        &["transparent"],
        |d| {
            d["types"][T_ENUM]["transparent"] = json!(true);
        },
    ));

    // ANTI-LAUNDER. The committed snapshot on disk is exactly what the source renders — which is
    // what a laundered break looks like — and the gate is STILL red, because the baseline it
    // classifies against comes from the ref and not from the file the same commit is free to
    // rewrite. This is the single property the whole design rests on.
    report.push(additive_red(
        cx,
        gate,
        "anti-launder: a snapshot refreshed to match the source does NOT launder a break",
        &["field REMOVED"],
        |d| {
            d["types"][T_STRUCT]["fields"]["zz_laundered_key"] =
                json!({ "type": "String", "optional": false });
        },
    ));

    // ══ :waivers ═════════════════════════════════════════════════════════════════════════════════

    let waiver_line = "DeployCfg.zz_waived_key = reviewed break (self-test)\n";
    fn plant_break(d: &mut Value) {
        d["types"][T_STRUCT]["fields"]["zz_waived_key"] =
            json!({ "type": "String", "optional": false });
    }

    // The register's green: a waiver that names an exact path excuses THAT break, and the gate is
    // green in both the additive row and the waiver row.
    report.push(prove_rows_green(
        cx,
        gate,
        "waiver: an exact-path waiver excuses ITS break, and the register is doing work",
        &[ROW_ADDITIVE_ONLY, ROW_WAIVERS],
        baseline_with_waivers(cx, waiver_line, plant_break),
    ));

    // THE DECISIVE ONE: a waiver for path A must not suppress an unrelated break at path B.
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "waiver: a waiver for one path does NOT excuse an unwaived break at another",
        &[ROW_ADDITIVE_ONLY],
        baseline_with_waivers(cx, waiver_line, |d| {
            plant_break(d);
            d["types"][T_STRUCT]["fields"]["zz_second_key"] =
                json!({ "type": "String", "optional": false });
        }),
        &["zz_second_key"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "waiver: a STALE waiver is itself an error — it is standing permission to break later",
        &[ROW_WAIVERS],
        baseline_with_waivers(cx, "SomeType.gone = the break it excused is gone\n", |d| {
            drop_type(d, T_ENUM);
        }),
        &["STALE"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "waiver: a WILDCARD waiver is refused outright — the hatch must stay narrow",
        &[ROW_WAIVERS],
        baseline_with_waivers(cx, "DeployCfg.* = wildcards must be refused\n", plant_break),
        &["wildcard"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "waiver: a waiver with a path and NO reason is refused",
        &[ROW_WAIVERS],
        baseline_with_waivers(cx, "DeployCfg.zz_waived_key =\n", plant_break),
        &["BOTH an exact path AND a reason"],
    ));

    report.push(prove_rows_red(
        cx,
        gate,
        "waiver: a malformed line with no `=` is refused",
        &[ROW_WAIVERS],
        baseline_with_waivers(cx, "this is not a waiver\n", plant_break),
        &["malformed waiver"],
    ));

    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "waiver: an EMPTY register weakens nothing — the break stays RED",
        &[ROW_ADDITIVE_ONLY],
        baseline_with_waivers(cx, "# no waivers\n", plant_break),
        &["field REMOVED"],
    ));

    // A COMMENT IS NOT A WAIVER. The register's format ignores `#`, and a break "waived" in a
    // comment is not waived at all.
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "waiver: a waiver commented out is not a waiver",
        &[ROW_ADDITIVE_ONLY],
        baseline_with_waivers(cx, &format!("# {waiver_line}"), plant_break),
        &["field REMOVED"],
    ));

    // A MALFORMED REGISTER MUST NOT LET THE ADDITIVE CHECK CLAIM A PASS: it is the register the
    // breaks are judged against, so nothing can be judged without it.
    report.push(prove_rows_red(
        &on_fixture(cx),
        gate,
        "waiver: a malformed register leaves the additive check UNPROVEN rather than passing",
        &[ROW_ADDITIVE_ONLY],
        baseline_with_waivers(cx, "no equals sign here\n", plant_break),
        &["unproven"],
    ));

    // ── THE SUITE'S OWN HONESTY CHECK. A suite that runs zero cases reports zero failures, which is
    //    the false green this gate exists to be immune to.
    if report.cases().len() < CASE_FLOOR {
        report.note_infra_failure(format!(
            "the config-schema self-test executed only {} case(s), under its floor of {CASE_FLOOR}. \
             Coverage was deleted, or the suite exited early — either way this is NOT a pass.",
            report.cases().len()
        ));
    }

    report
}
