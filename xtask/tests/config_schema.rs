//! THE CONFIG-SCHEMA GENERATOR AND CLASSIFIER, PROVEN AGAINST THROWAWAY SOURCES.
//!
//! The gate's five rows are proven in its own `selftest` (55 cases, planted through the overlay).
//! What is proven HERE is the layer underneath: that the FINGERPRINT MOVES when the grammar moves,
//! and that the CLASSIFIER judges the movement correctly.
//!
//! That split is not tidiness. The shell gate's classifier cases were hand-written JSON pairs, and
//! every one of them stayed green while the generator emitted a BYTE-IDENTICAL fingerprint for four
//! separate breaking source changes — a retyped secret reference, a dropped upstream-credential
//! value, a flipped `deny_unknown_fields` and a `rename_all` added to a config struct. A classifier
//! that judges deltas perfectly proves nothing about a generator that renders no delta to judge. So
//! these cases drive [`extract`] over real Rust text and assert the fingerprint it produces.
//!
//! [`extract`]: xtask::gates::config_schema::schema::extract

use serde_json::Value;

use xtask::gates::config_schema::classify::{self, Severity};
use xtask::gates::config_schema::schema;

/// The floor under this suite. The shell pinned 68 cases across its classifier, generator and
/// coverage arms; this file carries the generator and classifier halves and the gate's own
/// `selftest` carries the rest. A suite that runs zero cases reports zero failures.
const CASE_FLOOR: usize = 40;

// ── HARNESS ──────────────────────────────────────────────────────────────────────────────────────

/// Fingerprint one throwaway source file.
fn fp1(src: &str) -> Value {
    fp(&[("fixture.rs", src)])
}

/// Fingerprint a throwaway source TREE, and refuse to hide a refusal behind a panic message that
/// does not say what was refused.
fn fp(files: &[(&str, &str)]) -> Value {
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
        .collect();
    schema::extract(&owned).unwrap_or_else(|e| panic!("extract refused: {e}"))
}

/// The refusal a source tree produces, or a panic naming the fingerprint it produced instead.
fn refusal(files: &[(&str, &str)]) -> String {
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
        .collect();
    match schema::extract(&owned) {
        Err(e) => e,
        Ok(v) => panic!("expected a refusal; got a fingerprint with {} type(s)", {
            v["types"].as_object().map(|o| o.len()).unwrap_or(0)
        }),
    }
}

fn types(doc: &Value) -> &serde_json::Map<String, Value> {
    doc["types"].as_object().expect("types map")
}

/// Classify one source change and report the severities it produced, by path.
fn verdicts(before: &str, after: &str) -> Vec<(Severity, String, String)> {
    classify::classify(&fp1(before), &fp1(after))
        .into_iter()
        .map(|f| (f.severity, f.path, f.reason))
        .collect()
}

fn is_breaking(before: &str, after: &str) -> bool {
    verdicts(before, after)
        .iter()
        .any(|(s, _, _)| *s == Severity::Breaking)
}

fn severities_at(before: &str, after: &str, path: &str) -> Vec<Severity> {
    verdicts(before, after)
        .into_iter()
        .filter(|(_, p, _)| p == path)
        .map(|(s, _, _)| s)
        .collect()
}

// ── THE FIXTURES ─────────────────────────────────────────────────────────────────────────────────
// The secret-reference grammar: a hand-written `Deserialize` accepting a canonical form plus two
// sugar spellings, and REFUSING a bare scalar. This shape is `SecretRef`, whose whole reason for
// existing is to make `api_key: "sk-live-…"` impossible.

const SECRETREF: &str = r#"
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SecretRefFx {
    pub module: String,
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for SecretRefFx {
    fn visit_str<E>(self, _v: &str) -> Result<SecretRefFx, E> {
        Err(Self::inline_literal())
    }

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "module" => module = Some(map.next_value()?),
                "settings" => settings = Some(map.next_value()?),
                "env" => sugar = Some(map.next_value()?),
                "file" => sugar = Some(map.next_value()?),
                other => return Err(de::Error::unknown_field(other, FIELDS)),
            }
        }
    }
}
"#;

const CREDS: &str = r#"
#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpstreamCredsFx {
    #[default]
    Own,
    Passthrough,
}
"#;

const DENY_OFF: &str = r#"
#[derive(serde::Deserialize)]
pub(crate) struct DenyFx {
    pub(crate) protocol: String,
}
"#;

const DENY_ON: &str = r#"
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenyFx {
    pub(crate) protocol: String,
}
"#;

const RENAME_NONE: &str = r#"
#[derive(serde::Deserialize)]
pub(crate) struct RenameFx {
    pub(crate) max_tokens: u32,
    pub(crate) on_error: String,
}
"#;

const RENAME_KEBAB: &str = r#"
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RenameFx {
    pub(crate) max_tokens: u32,
    pub(crate) on_error: String,
}
"#;

const LIFT_NONE: &str = r#"
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiftFx {
    pub(crate) frozen_key: String,
    #[serde(skip)]
    pub(crate) carried_key: CarriedCfg,
    #[serde(skip)]
    pub(crate) private_state: u64,
}
"#;

const LIFT_LISTED: &str = r#"
pub(crate) const LIFTED_TOP_LEVEL_KEYS: &[&str] = &["carried_key"];

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiftFx {
    pub(crate) frozen_key: String,
    #[serde(skip)]
    pub(crate) carried_key: CarriedCfg,
    #[serde(skip)]
    pub(crate) private_state: u64,
}
"#;

// ══ THE SECRET-REFERENCE GRAMMAR ═════════════════════════════════════════════════════════════════

#[test]
fn control_an_unchanged_source_renders_an_identical_fingerprint() {
    // The control comes first: without it, a RED below could be the fixture rather than the change.
    assert_eq!(
        schema::canonical(&fp1(SECRETREF)),
        schema::canonical(&fp1(SECRETREF))
    );
    assert!(classify::classify(&fp1(SECRETREF), &fp1(SECRETREF)).is_empty());
    assert!(classify::classify(&fp1(CREDS), &fp1(CREDS)).is_empty());
}

#[test]
fn a_hand_written_deserialize_has_its_wire_keys_fingerprinted() {
    let t = fp1(SECRETREF);
    let keys = types(&t)["manual-de SecretRefFx"]["wire_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(keys, vec!["env", "file", "module", "settings"]);
}

#[test]
fn a_hand_written_deserialize_has_its_member_types_fingerprinted() {
    // The type carries no derive — that is what a hand-written impl means — so the derive-gated
    // walk skipped it entirely and `module: String` could be retyped freely.
    let t = fp1(SECRETREF);
    assert_eq!(
        types(&t)["manual-de SecretRefFx"]["fields"]["module"]["type"],
        Value::String("String".into())
    );
}

#[test]
fn a_hand_written_deserialize_has_its_refused_input_forms_fingerprinted() {
    // The wire keys say what a MAP may contain. They say nothing about whether a bare scalar is
    // accepted at all, and for a secret reference that rejection is the whole point of the type.
    let t = fp1(SECRETREF);
    let refused = types(&t)["manual-de SecretRefFx"]["refused"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(refused, vec!["str"]);
}

#[test]
fn only_wire_visible_members_are_recorded() {
    // A hand-impl'd type's declaration is also its PARSED RESULT, and the two are not the same set.
    // Freezing the whole declaration would fire RED on an internal rename no config can observe.
    let src = SECRETREF.replace(
        "pub settings: serde_json::Map<String, serde_json::Value>,",
        "pub settings: serde_json::Map<String, serde_json::Value>,\n    pub internal_cache: u64,",
    );
    let t = fp1(&src);
    let fields = types(&t)["manual-de SecretRefFx"]["fields"]
        .as_object()
        .unwrap();
    assert!(
        !fields.contains_key("internal_cache"),
        "a member no document can write must not be frozen: {fields:?}"
    );
}

#[test]
fn retyping_the_secret_reference_canonical_form_is_breaking() {
    let retyped = SECRETREF.replace("pub module: String,", "pub module: Vec<String>,");
    assert!(is_breaking(SECRETREF, &retyped));
}

#[test]
fn renaming_a_secret_reference_sugar_spelling_is_breaking() {
    let renamed = SECRETREF.replace("\"env\" =>", "\"environment\" =>");
    assert!(is_breaking(SECRETREF, &renamed));
}

#[test]
fn dropping_a_refusal_is_breaking_because_it_widens_the_grammar() {
    // THE STRICTER ARM. Everywhere else a widened grammar is additive and green. Here it is red,
    // and the asymmetry is the entire point: the widened form is an inline secret literal, the
    // exact shape the type exists to reject and the one that ends up in a boot log. Before
    // `refused` was recorded this rendered a BYTE-IDENTICAL fingerprint.
    let ok = SECRETREF.replace(
        "        Err(Self::inline_literal())",
        "        Ok(SecretRefFx::from_env(_v))",
    );
    assert_ne!(
        schema::canonical(&fp1(SECRETREF)),
        schema::canonical(&fp1(&ok)),
        "dropping a refusal must MOVE the fingerprint, or the classifier has nothing to judge"
    );
    let sev = severities_at(SECRETREF, &ok, "manual-de SecretRefFx::visit_str");
    assert_eq!(sev, vec![Severity::Breaking], "{sev:?}");
}

#[test]
fn adding_a_refusal_is_breaking_because_a_document_that_parsed_now_fails() {
    let ok = SECRETREF.replace(
        "        Err(Self::inline_literal())",
        "        Ok(SecretRefFx::from_env(_v))",
    );
    let sev = severities_at(&ok, SECRETREF, "manual-de SecretRefFx::visit_str");
    assert_eq!(sev, vec![Severity::Breaking], "{sev:?}");
}

#[test]
fn a_visitor_that_can_succeed_is_not_recorded_as_a_refusal() {
    // Deliberately CONSERVATIVE: a form counts as refused only when its body can ONLY fail. This
    // never claims a refusal it cannot prove by reading the body.
    let t = fp1(SECRETREF);
    let refused = types(&t)["manual-de SecretRefFx"]["refused"].to_string();
    assert!(
        !refused.contains("map"),
        "the real parser must not be a refusal: {refused}"
    );
}

// ══ THE UPSTREAM-CREDENTIAL GRAMMAR ══════════════════════════════════════════════════════════════

#[test]
fn dropping_an_upstream_credential_value_is_breaking() {
    let dropped = CREDS.replace("    Passthrough,\n", "");
    assert!(is_breaking(CREDS, &dropped));
}

#[test]
fn variant_rename_all_is_applied_to_the_variant_ident() {
    // `rename_all` on a VARIANT and on a FIELD are different transforms of the same rule name, and
    // getting it wrong produces a fingerprint that quietly disagrees with the parser.
    let t = fp1(CREDS);
    let v = types(&t)["UpstreamCredsFx"]["variants"].to_string();
    assert!(v.contains("own") && v.contains("passthrough"), "{v}");
}

// ══ THE CONTAINER KNOBS ══════════════════════════════════════════════════════════════════════════

#[test]
fn deny_unknown_fields_is_recorded_and_not_discarded() {
    assert_eq!(
        types(&fp1(DENY_ON))["DenyFx"]["deny_unknown_fields"],
        Value::Bool(true)
    );
    assert_eq!(
        types(&fp1(DENY_OFF))["DenyFx"]["deny_unknown_fields"],
        Value::Bool(false)
    );
}

#[test]
fn turning_deny_unknown_fields_on_is_breaking_and_off_is_additive() {
    // On is breaking in the plainest possible sense: a config carrying an extra key parsed
    // yesterday and is a hard boot error today. Off only widens what is accepted.
    assert_eq!(
        severities_at(DENY_OFF, DENY_ON, "DenyFx[deny_unknown_fields]"),
        vec![Severity::Breaking]
    );
    assert_eq!(
        severities_at(DENY_ON, DENY_OFF, "DenyFx[deny_unknown_fields]"),
        vec![Severity::Additive]
    );
}

#[test]
fn every_derived_container_records_both_serde_flags() {
    // The flags were once parsed and thrown away, so either could be flipped with ZERO delta. The
    // tolerant "absent means never recorded" branch in the classifier is self-extinguishing only
    // because the generator writes both on every node — which is what this asserts.
    let t = fp1(DENY_OFF);
    for (name, node) in types(&t) {
        if node.get("deserialize").and_then(Value::as_str) == Some("manual") {
            continue;
        }
        if matches!(
            node.get("kind").and_then(Value::as_str),
            Some("struct" | "enum")
        ) {
            assert!(
                node.get("deny_unknown_fields").is_some(),
                "{name} has no deny flag"
            );
            assert!(
                node.get("transparent").is_some(),
                "{name} has no transparent flag"
            );
        }
    }
}

// ══ `rename_all` ON A STRUCT ═════════════════════════════════════════════════════════════════════

#[test]
fn container_rename_all_is_applied_to_struct_field_keys() {
    // This reached enum variants but never struct fields, so adding `rename_all` to a config struct
    // renamed every one of its wire keys with zero snapshot delta.
    let t = fp1(RENAME_KEBAB);
    let mut keys: Vec<&str> = types(&t)["RenameFx"]["fields"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["max-tokens", "on-error"]);
}

#[test]
fn adding_or_removing_a_struct_rename_all_is_breaking_either_way() {
    assert!(is_breaking(RENAME_NONE, RENAME_KEBAB));
    assert!(is_breaking(RENAME_KEBAB, RENAME_NONE));
}

// ══ THE LIFTED CARRIERS ══════════════════════════════════════════════════════════════════════════

#[test]
fn an_unlisted_skipped_field_stays_out_of_the_grammar() {
    let t = fp1(LIFT_NONE);
    let keys: Vec<&str> = types(&t)["LiftFx"]["fields"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["frozen_key"]);
}

#[test]
fn a_listed_carrier_is_recorded_typed_and_optional() {
    // It is OPTIONAL because a carrier is: `skip` requires `Default`, so an absent key leaves the
    // default in place.
    let t = fp1(LIFT_LISTED);
    let f = types(&t)["LiftFx"]["fields"].as_object().unwrap();
    let mut keys: Vec<&str> = f.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["carried_key", "frozen_key"]);
    assert_eq!(f["carried_key"]["type"], Value::String("CarriedCfg".into()));
    assert_eq!(f["carried_key"]["optional"], Value::Bool(true));
}

#[test]
fn listing_one_carrier_does_not_readmit_the_other_skipped_fields() {
    let t = fp1(LIFT_LISTED);
    assert!(!types(&t)["LiftFx"]["fields"]
        .as_object()
        .unwrap()
        .contains_key("private_state"));
}

#[test]
fn naming_a_carrier_is_additive_and_dropping_one_is_breaking() {
    assert!(!is_breaking(LIFT_NONE, LIFT_LISTED));
    assert!(is_breaking(LIFT_LISTED, LIFT_NONE));
}

#[test]
fn a_lifted_key_with_no_carrier_field_is_refused() {
    // Without this the lift list would be a way to keep a field in the fingerprint after deleting
    // it — or to smuggle an unrelated skipped field back in by naming it.
    let orphan = r#"
pub(crate) const LIFTED_TOP_LEVEL_KEYS: &[&str] = &["carried_key", "no_such_key"];

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiftFx {
    pub(crate) frozen_key: String,
    #[serde(skip)]
    pub(crate) carried_key: CarriedCfg,
}
"#;
    let why = refusal(&[("fixture.rs", orphan)]);
    assert!(why.contains("no_such_key"), "{why}");
    assert!(why.contains("no struct in the tracked"), "{why}");
}

// ══ TEST-ONLY TYPES ══════════════════════════════════════════════════════════════════════════════

#[test]
fn cfg_test_types_are_excluded_and_cannot_displace_a_real_one() {
    // The extractor is last-definition-wins for declarations, so a fixture sharing a real type's
    // name would REPLACE the real grammar in the fingerprint.
    let src = r#"
#[derive(serde::Deserialize)]
pub(crate) struct RealFx {
    pub(crate) real_key: String,
}

#[cfg(test)]
mod tests {
    #[derive(serde::Deserialize)]
    struct TestOnlyFx {
        fixture_key: String,
    }

    #[derive(serde::Deserialize)]
    struct RealFx {
        displaced: String,
    }
}
"#;
    let t = fp1(src);
    assert!(!types(&t).contains_key("TestOnlyFx"));
    let keys: Vec<&str> = types(&t)["RealFx"]["fields"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["real_key"]);
}

// ══ THE COLLISION RULE, IN ALL THREE NAMESPACES ══════════════════════════════════════════════════

const PLANE_A: &str = r#"
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PinMechanismFx {
    JwsIssuerKey,
    Unpinned,
}
"#;

const PLANE_B: &str = r#"
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PinMechanismFx {
    PinnedPubkey,
    Unpinned,
}
"#;

#[test]
fn control_each_plane_fingerprints_fine_alone() {
    assert!(types(&fp(&[("plane_a.rs", PLANE_A)])).contains_key("PinMechanismFx"));
    assert!(types(&fp(&[("plane_b.rs", PLANE_B)])).contains_key("PinMechanismFx"));
}

#[test]
fn a_duplicate_bare_name_across_files_is_refused_and_names_both() {
    // Not hypothetical: `a2a/config.rs` and `mcp/config.rs` each declared a `PinMechanism` with
    // DIFFERENT variants, so the second read replaced the first and the classifier reported
    // `PinMechanism::jws_issuer_key: enum variant REMOVED` out of a commit that touched neither.
    // The refusal must NAME both files or an operator cannot act on it.
    let why = refusal(&[("plane_a.rs", PLANE_A), ("plane_b.rs", PLANE_B)]);
    assert!(why.contains("plane_a.rs"), "{why}");
    assert!(why.contains("plane_b.rs"), "{why}");
    assert!(why.contains("PinMechanismFx"), "{why}");
}

#[test]
fn hole_a_duplicate_definition_map_alias_is_refused() {
    // THE HOLE: `collide()` guarded the DERIVED namespace only. The alias keys were written
    // straight into the same flat map, so two files declaring `type HookDefs` silently froze one
    // shape and un-froze the other — and a definition-map alias IS the shape of its whole section.
    let a = "pub type HookDefs = indexmap::IndexMap<String, HookDefCfg>;\n";
    let b = "pub type HookDefs = Vec<HookDefCfg>;\n";
    let why = refusal(&[("a.rs", a), ("b.rs", b)]);
    assert!(why.contains("type HookDefs"), "{why}");
    assert!(why.contains("a.rs") && why.contains("b.rs"), "{why}");
}

#[test]
fn hole_a_duplicate_hand_written_deserialize_is_refused() {
    // The same hole in the namespace where the REFUSALS live: a second `impl Deserialize for X`
    // overwrote the first, and the replaced impl's accepted wire keys and refused input forms
    // stopped being covered at all.
    let a = SECRETREF;
    let b = SECRETREF.replace("\"env\" =>", "\"other\" =>");
    let why = refusal(&[("a.rs", a), ("b.rs", &b)]);
    assert!(why.contains("manual-de SecretRefFx"), "{why}");
    assert!(why.contains("a.rs") && why.contains("b.rs"), "{why}");
}

// ══ THE `rename = "default"` HOLE ════════════════════════════════════════════════════════════════

#[test]
fn hole_a_field_renamed_to_default_is_still_required() {
    // THE HOLE: the knob readers were substring searches over the whole `#[serde(…)]` span, so
    // `\bdefault\b` matched the six letters inside `rename = "default"`. The field was recorded
    // `optional: true` while serde still REQUIRES it — the fingerprint claimed a document omitting
    // that key parses when it does not, and it was silent in both directions: adding such a field
    // rendered no delta the classifier could call breaking, and making it genuinely optional later
    // rendered none either.
    let src = r#"
#[derive(serde::Deserialize)]
pub struct RenameDefaultFx {
    #[serde(rename = "default")]
    pub fallback: String,
}
"#;
    let t = fp1(src);
    let f = types(&t)["RenameDefaultFx"]["fields"].as_object().unwrap();
    assert!(
        f.contains_key("default"),
        "the wire key is `default`: {f:?}"
    );
    assert_eq!(
        f["default"]["optional"],
        Value::Bool(false),
        "a field renamed to the wire key `default` carries no #[serde(default)] and is REQUIRED"
    );
}

#[test]
fn a_real_serde_default_still_records_the_field_as_optional() {
    // The mask must not have made the reader blind: the knob itself is outside the literal.
    let src = r#"
#[derive(serde::Deserialize)]
pub struct RealDefaultFx {
    #[serde(default)]
    pub fallback: String,
}
"#;
    let t = fp1(src);
    assert_eq!(
        types(&t)["RealDefaultFx"]["fields"]["fallback"]["optional"],
        Value::Bool(true)
    );
}

#[test]
fn a_field_renamed_to_flatten_or_skip_is_not_flattened_or_skipped() {
    // The same reading applied to every knob spelled as a bare word.
    let src = r#"
#[derive(serde::Deserialize)]
pub struct KnobWordFx {
    #[serde(rename = "flatten")]
    pub a: String,
    #[serde(rename = "skip")]
    pub b: String,
}
"#;
    let t = fp1(src);
    let f = types(&t)["KnobWordFx"]["fields"].as_object().unwrap();
    let mut keys: Vec<&str> = f.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["flatten", "skip"], "neither knob fired: {f:?}");
    assert_eq!(f["flatten"]["type"], Value::String("String".into()));
}

// ══ TYPE NORMALISATION AND THE ALIASES ═══════════════════════════════════════════════════════════

#[test]
fn option_unwraps_to_an_optional_field_and_formatting_is_not_a_retype() {
    let a = "#[derive(serde::Deserialize)]\npub struct OptFx {\n    pub x: Option<String>,\n}\n";
    // Whitespace only. A TRAILING COMMA inside the generic is deliberately not used here: the
    // Python's `^Option\s*<\s*(.+)\s*>$` captures it into the inner type just as this port does, so
    // `Option<String,>` normalises to `String,` in BOTH implementations. That is a shared quirk of
    // the frozen format, not a difference, and a test asserting otherwise would be asserting a
    // behaviour neither generator has.
    let b =
        "#[derive(serde::Deserialize)]\npub struct OptFx {\n    pub x:   Option< String >,\n}\n";
    let t = fp1(a);
    assert_eq!(
        types(&t)["OptFx"]["fields"]["x"]["optional"],
        Value::Bool(true)
    );
    assert_eq!(
        types(&t)["OptFx"]["fields"]["x"]["type"],
        Value::String("String".into())
    );
    assert!(
        classify::classify(&fp1(a), &fp1(b)).is_empty(),
        "reformatting a type expression is not a grammar change"
    );
}

#[test]
fn a_callback_alias_is_plumbing_and_never_config_grammar() {
    let src = "pub type Handler = Box<dyn Fn(u32) -> u32>;\npub type Defs = indexmap::IndexMap<String, DefCfg>;\n";
    let t = fp1(src);
    assert!(!types(&t).contains_key("type Handler"));
    assert!(types(&t).contains_key("type Defs"));
}

#[test]
fn an_indented_type_alias_is_a_local_detail_and_is_not_tracked() {
    // Anchored at column 0 on purpose: an indented `type Value = …;` is a local alias inside a fn
    // or an impl, not config grammar, and must not be able to trip the gate.
    let src = "impl Foo {\n    type Value = u32;\n}\n";
    let t = fp1(src);
    assert!(
        !types(&t).contains_key("type Value"),
        "{:?}",
        types(&t).keys().collect::<Vec<_>>()
    );
}

#[test]
fn retargeting_a_definition_map_alias_to_a_list_is_breaking() {
    let a = "pub type Defs = indexmap::IndexMap<String, DefCfg>;\n";
    let b = "pub type Defs = Vec<DefCfg>;\n";
    assert_eq!(severities_at(a, b, "type Defs"), vec![Severity::Breaking]);
}

// ══ THE CANONICAL BYTES ══════════════════════════════════════════════════════════════════════════

#[test]
fn the_canonical_render_is_sorted_two_space_and_newline_terminated() {
    // The freeze is worth nothing unless the two generators agree BYTE FOR BYTE, and that agreement
    // rests on `json.dumps(indent=2, sort_keys=True, ensure_ascii=False) + "\n"`.
    let text = schema::canonical(&fp1(DENY_ON));
    assert!(text.ends_with("}\n"), "must end with exactly one newline");
    assert!(
        text.contains("\n  \"_meta\": {"),
        "two-space indent: {text:.80}"
    );
    let meta = text.find("\"_meta\"").unwrap();
    let types_at = text.find("\"types\"").unwrap();
    assert!(meta < types_at, "keys are sorted, so _meta precedes types");
}

#[test]
fn the_meta_block_still_names_the_generator_the_frozen_bytes_name() {
    // The generator string is part of the frozen bytes. Moving it is a snapshot rewrite and belongs
    // in a commit whose whole diff is that rewrite, never bundled with a port that has to prove
    // byte identity against it. This test is what makes that a decision rather than a leftover.
    let t = fp1(DENY_ON);
    assert_eq!(
        t["_meta"]["generator"],
        Value::String("scripts/config-schema.py gen".into())
    );
    assert_eq!(t["_meta"]["frozen_at"], Value::String("1.5.3".into()));
}

// ══ THE CLASSIFIER'S OWN ARMS ════════════════════════════════════════════════════════════════════

fn node(kind: &str) -> Value {
    serde_json::json!({
        "kind": kind,
        "fields": { "keep": { "type": "String", "optional": false } },
        "deny_unknown_fields": false,
        "transparent": false
    })
}

#[test]
fn hole_an_unrecognised_node_kind_is_a_break_and_not_a_silent_pass() {
    // THE HOLE, AND THE ONE ARM THE GATE'S OWN SELFTEST CANNOT PLANT. The classifier's last arm was
    // a bare `else: # enum`, so ANY node whose kind is not alias/manual/struct — a typo, a missing
    // key, a `"kind": "object"` from a hand-edit or a future generator — was handed to the VARIANT
    // comparison. That reads `variants` on both sides, finds it absent on both, compares the empty
    // set against the empty set and reports NOTHING: the node's fields were never compared, so
    // every field under it was free to be removed, retyped or made required at zero delta.
    //
    // It is unreachable from the gate because it fires only when BOTH sides carry the unknown kind
    // and the fresh side is produced by a generator that emits exactly four — so it is proved here,
    // directly, rather than left unproven.
    let mut before = node("object");
    let mut after = node("object");
    // A field REMOVED under the unrecognised node — the delta the old arm rendered as silence.
    after["fields"] = serde_json::json!({});

    let b = serde_json::json!({ "types": { "Weird": before.take() } });
    let f = serde_json::json!({ "types": { "Weird": after.take() } });
    let found = classify::classify(&b, &f);
    assert!(
        found
            .iter()
            .any(|x| x.severity == Severity::Breaking && x.path == "Weird"),
        "an unrecognised kind must be a break, not silence: {:?}",
        found
            .iter()
            .map(|x| (&x.path, x.severity))
            .collect::<Vec<_>>()
    );
    let why = &found.iter().find(|x| x.path == "Weird").unwrap().reason;
    assert!(why.contains("NOT compared"), "{why}");
}

#[test]
fn a_recognised_kind_is_still_compared_normally() {
    // The guard above must not have swallowed the ordinary arms.
    let b = serde_json::json!({ "types": { "S": node("struct") } });
    let mut after = node("struct");
    after["fields"] = serde_json::json!({});
    let f = serde_json::json!({ "types": { "S": after } });
    let found = classify::classify(&b, &f);
    assert!(found
        .iter()
        .any(|x| x.path == "S.keep" && x.severity == Severity::Breaking));
}

#[test]
fn hole_relocation_is_a_third_verdict_and_a_real_retype_is_still_breaking() {
    // `relocated_only` had no self-test cases at all. It is the rule that stops the gate reding on
    // a plane extraction that alters no operator-visible grammar — and a gate that reds on a
    // no-op change teaches reviewers to wave it through, which is how a stability gate dies.
    assert!(classify::relocated_only(
        "crate::a2a::config::AgentsCfg",
        "busbar_proto_a2a::config::AgentsCfg"
    ));
    assert!(classify::relocated_only(
        "self::AgentsCfg",
        "super::config::AgentsCfg"
    ));

    // NOTHING ELSE IS RELAXED. A different bare name is a retype.
    assert!(!classify::relocated_only(
        "crate::a2a::config::AgentsCfg",
        "crate::a2a::config::OtherCfg"
    ));
    // A FOREIGN path is part of the type's identity, so a container change is still a break.
    assert!(!classify::relocated_only(
        "std::collections::BTreeMap<String, CandidatePoolCfg>",
        "Vec<CandidatePoolCfg>"
    ));
    // Identical expressions are not a relocation.
    assert!(!classify::relocated_only(
        "crate::a2a::AgentsCfg",
        "crate::a2a::AgentsCfg"
    ));
}

#[test]
fn a_relocated_field_type_does_not_red_the_gate_but_is_reported() {
    let mut before = node("struct");
    before["fields"]["keep"]["type"] = Value::String("crate::a2a::config::AgentsCfg".into());
    let mut after = node("struct");
    after["fields"]["keep"]["type"] = Value::String("busbar_proto_a2a::config::AgentsCfg".into());
    let b = serde_json::json!({ "types": { "S": before } });
    let f = serde_json::json!({ "types": { "S": after } });
    let found = classify::classify(&b, &f);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, Severity::Relocated);
    assert!(found[0].reason.contains("MOVED"), "{}", found[0].reason);
}

#[test]
fn hole_an_empty_baseline_classifies_every_type_as_additive() {
    // This is WHY the gate refuses an empty baseline rather than trusting the classifier to catch
    // it: against an empty type map the classifier is behaving correctly and every single type
    // reads as `new type/section added`, which is ADDITIVE, which is GREEN. The refusal has to live
    // above the classifier, and this test pins the reason it does.
    let b = serde_json::json!({ "types": {} });
    let f = serde_json::json!({ "types": { "A": node("struct"), "B": node("struct") } });
    let found = classify::classify(&b, &f);
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|x| x.severity == Severity::Additive));
}

// ══ THE WAIVER REGISTER ══════════════════════════════════════════════════════════════════════════

#[test]
fn the_committed_waiver_register_parses_exactly_as_the_gate_reads_it() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(schema::WAIVERS),
    )
    .expect("the committed waiver register");
    let w = classify::load_waivers(schema::WAIVERS, &text).expect("it must parse");
    // The register is EMPTY today: the one waiver it carried excused a widening the committed
    // baseline now carries, and a dead waiver is what `:waivers` refuses. What this test pins is
    // that the committed file parses under the gate's own reader and that every key it does carry
    // is an exact path with a reason -- not that any particular line is present.
    for (path, reason) in &w {
        assert!(
            !path.trim().is_empty() && !reason.trim().is_empty(),
            "{path:?} = {reason:?}"
        );
    }
}

#[test]
fn a_waiver_must_name_an_exact_path_and_a_reason() {
    assert!(classify::load_waivers("w", "A.b = why\n").is_ok());
    assert!(classify::load_waivers("w", "A.b =\n").is_err());
    assert!(classify::load_waivers("w", " = why\n").is_err());
    assert!(classify::load_waivers("w", "no equals\n").is_err());
    assert!(classify::load_waivers("w", "A.* = globs\n").is_err());
    assert!(classify::load_waivers("w", "A.? = globs\n").is_err());
    // Comments and blank lines are ignored, and an empty register is the documented default.
    assert!(classify::load_waivers("w", "# just a comment\n\n")
        .unwrap()
        .is_empty());
}

#[test]
fn a_waiver_excuses_one_path_and_an_unused_waiver_is_stale() {
    let findings = classify::classify(
        &serde_json::json!({ "types": { "S": node("struct") } }),
        &serde_json::json!({ "types": {} }),
    );
    let mut waivers = std::collections::BTreeMap::new();
    waivers.insert("S".to_string(), "reviewed".to_string());
    let out = classify::judge(findings.clone(), &waivers);
    assert_eq!(out.breaking.len(), 0);
    assert_eq!(out.waived.len(), 1);
    assert!(out.stale.is_empty());
    assert_eq!(out.code(), 0);

    let mut other = std::collections::BTreeMap::new();
    other.insert("SomethingElse".to_string(), "reviewed".to_string());
    let out = classify::judge(findings, &other);
    assert_eq!(out.breaking.len(), 1, "an unrelated waiver excuses nothing");
    assert_eq!(out.stale, vec!["SomethingElse".to_string()]);
    assert_eq!(out.code(), 4);
}

// ══ THE SUITE'S OWN HONESTY CHECK ════════════════════════════════════════════════════════════════

#[test]
fn this_suite_still_carries_the_coverage_it_claims() {
    // A suite that runs zero cases reports zero failures. The count is read from this file's own
    // source so deleting a case is itself RED, exactly as the shell asserted its executed case
    // count rather than trusting the suite to have run.
    let src = include_str!("config_schema.rs");
    let cases = src.matches("\n#[test]").count();
    assert!(
        cases >= CASE_FLOOR,
        "this suite declares {cases} case(s), under its floor of {CASE_FLOOR}; coverage was deleted"
    );
}
