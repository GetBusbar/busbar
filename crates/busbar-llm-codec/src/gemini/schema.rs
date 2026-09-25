//! Gemini structured output (`responseMimeType` / `responseSchema` / `responseJsonSchema`) and
//! the JSON-Schema sanitizing and `$ref` inlining Gemini's schema subset needs.

use super::*;

/// Read Gemini's structured-output directive out of `generationConfig` into the protocol-agnostic
/// [`crate::ir::IrResponseFormat`]. The ONLY code that knows Gemini's structured-output wire shape:
/// `generationConfig.responseMimeType` (e.g. `"application/json"`) plus an optional `responseSchema`
/// — Gemini has no single `response_format` key. Returns `None` when NEITHER sub-field is present, so
/// a plain request never gains a spurious directive.
pub(super) fn read_gemini_response_format(
    gen_config: Option<&serde_json::Value>,
) -> Option<crate::ir::IrResponseFormat> {
    let gc = gen_config?;
    let mime = gc.get(FIELD_RESPONSE_MIME_TYPE).and_then(|m| m.as_str());
    // Two schema slots: the OpenAPI-subset `responseSchema` (normalized to JSON Schema, GEM-11) and
    // the JSON-Schema `responseJsonSchema` (read as-is, GEM-04 — it used to be ignored, so JSON mode
    // reached a foreign target with no schema). The API accepts one or the other.
    let schema = gc
        .get("responseSchema")
        .map(gemini_openapi_schema_to_json_schema)
        .or_else(|| gc.get("responseJsonSchema").cloned());
    if mime.is_none() && schema.is_none() {
        return None;
    }
    Some(crate::ir::IrResponseFormat {
        json: schema.is_some() || mime == Some(MIME_APPLICATION_JSON),
        schema,
        name: None,
        strict: None,
        description: None,
    })
}

/// Project the agnostic [`crate::ir::IrResponseFormat`] into a Gemini `generationConfig` map. The ONLY
/// code that builds Gemini's structured-output wire shape: a JSON directive emits
/// `responseMimeType:"application/json"` plus the sanitized `responseSchema` (schema keywords Gemini
/// rejects are stripped). A non-JSON directive emits nothing — Gemini's default is plain text.
pub(super) fn write_gemini_response_format(
    gen_config: &mut serde_json::Map<String, serde_json::Value>,
    rf: &crate::ir::IrResponseFormat,
) {
    if !rf.json {
        return;
    }
    gen_config.insert(
        FIELD_RESPONSE_MIME_TYPE.to_string(),
        serde_json::json!(MIME_APPLICATION_JSON),
    );
    if let Some(schema) = &rf.schema {
        gen_config.insert(
            "responseSchema".to_string(),
            sanitize_gemini_schema(&resolve_gemini_schema_refs(schema)),
        );
    }
}

/// JSON-Schema keywords Gemini's `OpenAPI`-subset schema validator REJECTS with a 400 when present in
/// a `responseSchema` or a tool's `parameters`. Gemini accepts a strict OpenAPI 3.0 `Schema` subset,
/// NOT full JSON Schema, so draft keywords a foreign protocol (OpenAI/Anthropic) routinely emits on a
/// tool/structured-output schema hard-fail the request. Stripping them (recursively) lets a
/// cross-protocol tool/structured-output definition survive instead of 400-ing. Kept as one
/// list so both `responseSchema` and tool `parameters` sanitize identically.
///
/// RESEARCHED AGAINST THE LIVE API (2026-07-30), not just Google's docs, because the docs and the
/// backend disagree on `$ref`/`$defs`:
///
/// - Google's structured-output docs (<https://ai.google.dev/gemini-api/docs/structured-output>) and
///   announcement (<https://blog.google/innovation-and-ai/technology/developers-tools/gemini-api-structured-outputs/>)
///   both say `$ref`/`$defs`/`additionalProperties` are now supported keywords. Taken at face value
///   that would mean just deleting them from this list. It is NOT that simple:
/// - `$ref` into a NAMED `$defs`/`definitions` entry — exactly what every Pydantic/Zod-generated
///   nested-model tool schema produces — still 400s on the live backend today:
///   google-gemini/gemini-cli#13326 ("can't resolve reference #/$defs/Issue from id #", closed by
///   pointing callers at `google.genai._transformers.process_schema`, which INLINES refs before
///   sending rather than relying on the backend to resolve them) and vercel/ai#14369 ("The referenced
///   name #/$defs/__schema0 ... does not match to a display_name", fixed the same way: inline `$ref`
///   against `$defs` client-side). The docs' own `$ref` example is `"$ref": "#"` — self-reference to
///   the schema ROOT for recursive types — not the named-`$defs`-entry pattern SDKs actually emit.
///   So `$ref`/`$defs`/`definitions` STAY on this list: [`resolve_gemini_schema_refs`] runs BEFORE
///   this filter and inlines every named `$ref` against its `$defs`/`definitions` entry, so by the
///   time this filter sees a schema, no resolvable `$ref`/`$defs`/`definitions` remain — this filter
///   catches only the leftover, defensive case (an unresolvable/dangling ref, or a cyclic one this
///   crate deliberately declines to inline; see [`inline_gemini_schema_refs`]).
/// - `additionalProperties` genuinely IS accepted by the live backend, but ONLY as a boolean.
///   google-gemini/gemini-cli#13694 (closed not-planned) shows the backend 400ing with "Expected
///   boolean, received object" the moment it carries a schema — the shape Pydantic's
///   `dict[str, Model]` / Zod's record types emit (`{"additionalProperties": {"$ref": ...}}`).
///   So `additionalProperties` is handled specially in [`sanitize_gemini_schema`] (kept when boolean,
///   stripped when a schema) rather than being an unconditional entry in this list.
/// - The remaining keys (`$schema`, `$id`, `$comment`, `additionalItems`, `patternProperties`,
///   `unevaluatedProperties`, `const`, `examples`) are NOT listed as supported anywhere in the current
///   docs' explicit keyword table (`type`, `title`, `description`, `properties`, `required`,
///   `additionalProperties`, `enum`, `format`, `minimum`, `maximum`, `items`, `prefixItems`,
///   `minItems`, `maxItems`, `anyOf`, `$ref`) and the docs still warn "Not all JSON Schema features are
///   supported" — no independent evidence surfaced that any of them are now accepted, so they stay.
pub(super) const GEMINI_SCHEMA_REJECTED_KEYS: &[&str] = &[
    "$schema",
    "$id",
    "$ref",
    "$defs",
    "definitions",
    "additionalItems",
    "patternProperties",
    "unevaluatedProperties",
    "const",
    "examples",
    "$comment",
];

/// The JSON-Schema keywords whose VALUE is a map from a USER-CHOSEN NAME to a subschema, rather than
/// a subschema itself. Inside these maps the keys are field names the caller invented, not keywords,
/// so [`GEMINI_SCHEMA_REJECTED_KEYS`] must not be applied to them — see [`sanitize_gemini_schema`].
/// (`$defs`, `definitions` and `patternProperties` are name-keyed too, but they are stripped whole,
/// so they never reach the descent.)
pub(super) const GEMINI_SCHEMA_NAME_KEYED_MAPS: &[&str] = &["properties", "dependentSchemas"];

/// Recursively strip the JSON-Schema keywords Gemini rejects (`GEMINI_SCHEMA_REJECTED_KEYS`) from a
/// schema value so a cross-protocol tool / `responseSchema` definition does not hard-fail with a
/// 400. Returns a cleaned clone — the source IR value is left intact (only the egress wire copy is
/// sanitized), so the stripped keys still round-trip same-protocol via the preserved raw object in
/// `extra` where applicable.
///
/// THE FILTER IS POSITIONAL, and has to be. It used to match on the key at EVERY object level with
/// no notion of where in the schema it was, so it also fired inside a `properties` map — where the
/// keys are FIELD NAMES THE CALLER CHOSE, not keywords. A perfectly ordinary tool schema with a
/// property named `examples`, `const`, `definitions` or `$ref` had that property silently deleted
/// from `properties` while `required` — an array of strings the walker never inspects — went on
/// naming it. Gemini then 400s the request for a `required` entry with no property (a hard failure
/// the translation layer exists to prevent); if the field was optional it merely became invisible to
/// the model, so the tool call came back without it. Descending into the name-keyed maps through
/// [`sanitize_gemini_schema_names`] keeps the keyword filter where keywords actually live.
pub(super) fn sanitize_gemini_schema(schema: &serde_json::Value) -> serde_json::Value {
    match schema {
        serde_json::Value::Object(map) => {
            let mut cleaned = serde_json::Map::new();
            for (k, v) in map {
                // `additionalProperties` is value-dependent, not a blanket reject: the live API
                // accepts the boolean form but 400s on the schema form (see the research note on
                // GEMINI_SCHEMA_REJECTED_KEYS), so it is handled here rather than in that list.
                if k == "additionalProperties" {
                    if matches!(v, serde_json::Value::Bool(_)) {
                        cleaned.insert(k.clone(), v.clone());
                    }
                    continue;
                }
                if GEMINI_SCHEMA_REJECTED_KEYS.contains(&k.as_str()) {
                    continue;
                }
                let sanitized = if GEMINI_SCHEMA_NAME_KEYED_MAPS.contains(&k.as_str()) {
                    sanitize_gemini_schema_names(v)
                } else {
                    sanitize_gemini_schema(v)
                };
                cleaned.insert(k.clone(), sanitized);
            }
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_gemini_schema).collect())
        }
        other => other.clone(),
    }
}

/// The NAME-KEYED half of [`sanitize_gemini_schema`]: every key is kept verbatim (it is a caller's
/// field name, not a keyword) and every VALUE is sanitized as a schema object. A non-object here is
/// malformed schema, so it falls back to the keyword walker rather than being invented into one.
pub(super) fn sanitize_gemini_schema_names(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), sanitize_gemini_schema(v)))
                .collect(),
        ),
        other => sanitize_gemini_schema(other),
    }
}

/// Collect every `$defs`/`definitions` map found anywhere in a schema, keyed by definition name, so
/// [`inline_gemini_schema_refs`] can resolve a `$ref` against it. POSITIONAL, exactly like
/// [`sanitize_gemini_schema`]: does not descend into [`GEMINI_SCHEMA_NAME_KEYED_MAPS`] (`properties`,
/// `dependentSchemas`) as if their keys were `$defs`/`definitions` keywords, because those keys are
/// CALLER-CHOSEN FIELD NAMES — a tool with a property literally named `definitions` must not have its
/// contents mistaken for a definitions map (the same bug class [`sanitize_gemini_schema`]'s doc
/// comment describes for the keyword filter). An earlier-collected name wins on collision, matching
/// nearest-scope-wins JSON Schema semantics closely enough for the generated (never hand-authored)
/// schemas this sanitizer exists to handle.
pub(super) fn collect_gemini_schema_defs(
    schema: &serde_json::Value,
    out: &mut serde_json::Map<String, serde_json::Value>,
) {
    match schema {
        serde_json::Value::Object(map) => {
            for defs_key in ["$defs", "definitions"] {
                if let Some(serde_json::Value::Object(defs)) = map.get(defs_key) {
                    for (k, v) in defs {
                        out.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
            for (k, v) in map {
                if k == "$defs" || k == "definitions" {
                    continue;
                }
                if GEMINI_SCHEMA_NAME_KEYED_MAPS.contains(&k.as_str()) {
                    if let serde_json::Value::Object(names) = v {
                        for nv in names.values() {
                            collect_gemini_schema_defs(nv, out);
                        }
                    }
                } else {
                    collect_gemini_schema_defs(v, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_gemini_schema_defs(v, out);
            }
        }
        _ => {}
    }
}

/// Ceiling on the nodes one `$ref` resolution may emit. The `active` stack stops a schema that
/// refers back to itself, but says nothing about a cycle-FREE schema whose expansion is merely
/// enormous: N chained definitions that each reference the next twice form a diamond that inlines
/// to 2^N nodes without ever repeating a name on the current path. Client-supplied schemas reach
/// this walk (tool `input_schema` and `response_format`), so the expansion needs its own ceiling.
pub(super) const GEMINI_SCHEMA_INLINE_MAX_NODES: usize = 100_000;

/// Ceiling on how deep the inlined result may nest, matching the substrate JSON parser's input
/// depth guard. That guard measures the depth of the schema as it ARRIVES; inlining can multiply
/// it, so a few thousand shallow definitions chained singly pass the parser and still build a
/// `Value` deep enough to overflow the stack on the recursive walk — and again on its drop.
pub(super) const GEMINI_SCHEMA_INLINE_MAX_DEPTH: usize = 128;

/// One inlining allowance, owned by [`resolve_gemini_schema_refs`] and threaded through the walk so
/// every branch draws on the SAME pool rather than each getting a fresh one.
pub(super) struct GeminiInlineBudget {
    remaining_nodes: usize,
    depth: usize,
}

/// Recursively inline every `$ref` that points at a NAMED `#/$defs/X` or `#/definitions/X` entry in
/// `defs`, replacing the reference with the (recursively resolved) target subschema. `active` is the
/// stack of definition names currently being expanded on the current path — a genuinely recursive
/// model (a def that refs itself, directly or through a cycle) has no finite inlining, and the live
/// Gemini backend does not reliably resolve `$ref` into named `$defs` entries anyway (see the research
/// note on [`GEMINI_SCHEMA_REJECTED_KEYS`]), so a cycle falls back to an untyped `{}` for that branch
/// rather than looping forever or re-emitting a reference Gemini will 400 on. A `$ref` that does not
/// resolve (dangling name, external URI, or a bare root self-reference like `"$ref":"#"`) is left
/// alone here and caught defensively by [`sanitize_gemini_schema`]'s keyword filter downstream.
/// POSITIONAL in the same way [`collect_gemini_schema_defs`] is: [`GEMINI_SCHEMA_NAME_KEYED_MAPS`]
/// values are walked as name→subschema maps, not schema objects themselves.
///
/// `budget` bounds the expansion itself. A schema that exhausts the node pool or hits the depth
/// ceiling degrades to the same untyped `{}` a cycle does, so an over-budget schema is handled
/// exactly like a recursive one instead of hanging or overflowing the stack.
pub(super) fn inline_gemini_schema_refs(
    schema: &serde_json::Value,
    defs: &serde_json::Map<String, serde_json::Value>,
    active: &mut Vec<String>,
    budget: &mut GeminiInlineBudget,
) -> serde_json::Value {
    // Spending the budget in the one place every recursive edge passes through means a branch that
    // runs out degrades to exactly the untyped `{}` the cycle arm below already returns.
    if budget.remaining_nodes == 0 || budget.depth >= GEMINI_SCHEMA_INLINE_MAX_DEPTH {
        return serde_json::json!({});
    }
    budget.remaining_nodes -= 1;
    budget.depth += 1;
    let out = inline_gemini_schema_refs_within_budget(schema, defs, active, budget);
    budget.depth -= 1;
    out
}

/// The inlining walk proper. Only ever reached through [`inline_gemini_schema_refs`], which charges
/// the node/depth budget for this node first.
pub(super) fn inline_gemini_schema_refs_within_budget(
    schema: &serde_json::Value,
    defs: &serde_json::Map<String, serde_json::Value>,
    active: &mut Vec<String>,
    budget: &mut GeminiInlineBudget,
) -> serde_json::Value {
    match schema {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(r)) = map.get("$ref") {
                let target_name = r
                    .strip_prefix("#/$defs/")
                    .or_else(|| r.strip_prefix("#/definitions/"));
                if let Some(name) = target_name {
                    if let Some(target) = defs.get(name) {
                        if active.contains(&name.to_string()) {
                            return serde_json::json!({});
                        }
                        active.push(name.to_string());
                        let inlined = inline_gemini_schema_refs(target, defs, active, budget);
                        active.pop();
                        // Sibling keywords beside `$ref` (e.g. a caller-added `description`)
                        // override/extend the inlined target rather than being discarded.
                        if map.len() > 1 {
                            if let serde_json::Value::Object(mut inlined_map) = inlined {
                                for (k, v) in map {
                                    if k != "$ref" {
                                        inlined_map.insert(
                                            k.clone(),
                                            inline_gemini_schema_refs(v, defs, active, budget),
                                        );
                                    }
                                }
                                return serde_json::Value::Object(inlined_map);
                            }
                        }
                        return inlined;
                    }
                }
            }
            let cleaned: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "$defs" && k.as_str() != "definitions")
                .map(|(k, v)| {
                    let resolved = if GEMINI_SCHEMA_NAME_KEYED_MAPS.contains(&k.as_str()) {
                        match v {
                            serde_json::Value::Object(names) => serde_json::Value::Object(
                                names
                                    .iter()
                                    .map(|(nk, nv)| {
                                        (
                                            nk.clone(),
                                            inline_gemini_schema_refs(nv, defs, active, budget),
                                        )
                                    })
                                    .collect(),
                            ),
                            other => inline_gemini_schema_refs(other, defs, active, budget),
                        }
                    } else {
                        inline_gemini_schema_refs(v, defs, active, budget)
                    };
                    (k.clone(), resolved)
                })
                .collect();
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| inline_gemini_schema_refs(v, defs, active, budget))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Entry point: resolve every `$ref` in a schema against its own `$defs`/`definitions` maps and drop
/// those maps, so a Pydantic/Zod-generated nested-model tool/structured-output schema arrives at
/// [`sanitize_gemini_schema`] already flattened into real, typed structure instead of a reference the
/// live Gemini backend does not reliably resolve. Called BEFORE [`sanitize_gemini_schema`] at both
/// call sites (`responseSchema` and tool `parameters`). A schema with no `$defs`/`definitions`
/// anywhere is returned unchanged (the common case — most tool schemas are not nested).
pub(super) fn resolve_gemini_schema_refs(schema: &serde_json::Value) -> serde_json::Value {
    let mut defs = serde_json::Map::new();
    collect_gemini_schema_defs(schema, &mut defs);
    if defs.is_empty() {
        return schema.clone();
    }
    let mut active = Vec::new();
    let mut budget = GeminiInlineBudget {
        remaining_nodes: GEMINI_SCHEMA_INLINE_MAX_NODES,
        depth: 0,
    };
    inline_gemini_schema_refs(schema, &defs, &mut active, &mut budget)
}
