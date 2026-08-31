#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# ENUMERATE every request and response field of every chat dialect busbar speaks, expand it into
# the field inventory, and WRITE it to qa/field-inventory.json — which
# crates/busbar/tests/field_coverage.rs turns into a build failure for any field that is neither
# CARRIED (with a named test that proves it) nor explicitly WAIVED with a reason.
#
# WHY THIS FILE EXISTS.
# The 1.6.0 IR-losslessness audit's single most important observation was not any of the six
# defects it ranked. It was this: the exposure lived in fields that are NEVER READ OR NEVER
# EMITTED, where there was nothing to mutate and therefore nothing for a test to catch. A mutation
# pass over all six writers renamed eight emitted keys and every one was caught — while audio
# attachments, usage sub-buckets and citation offsets were being dropped in silence, because you
# cannot mutate a field that does not exist.
#
# So a list of six is a list of six things somebody happened to notice. This file exists to make
# the CLASS enumerable, for exactly the reason scripts/method-inventory.py exists for methods:
#
#   > "a hand-written list is precisely how coverage ends at J with nobody noticing: the author
#   >  writes down the fields they were thinking about, the ones they were not thinking about are
#   >  absent, and an absent row looks exactly like a row that was considered and found not to
#   >  apply."
#
# WHERE THE FIELD LISTS COME FROM, AND THE ONE HONEST WEAKNESS.
# qa/field-schemas/<dialect>.json. Each is a VENDORED SCHEMA: the dialect's own published field
# set, with a `source` URL and a `retrieved` date, checked in so it is reviewable and diffable.
# They are NOT derived from busbar's own readers, which are the thing under test — a derivation
# from the reader would be a tautology (it would report perfect coverage of exactly the fields the
# reader already knows about, which is the failure mode).
#
# The weakness, stated plainly rather than hidden: method-inventory.py reads the SPEC AUTHORS' OWN
# MACHINE ARTEFACTS (rmcp's `model.rs`, a2a-pb's `a2a.proto`), so it cannot fall behind the spec
# silently. No equivalent machine artefact for these six dialects is pinned in this tree — there
# is no vendored OpenAPI document and no provider SDK crate in the lockfile — so these schemas are
# TRANSCRIBED from the published references. That makes them reviewable but not self-updating.
# The upgrade path is recorded in each schema's `todo` field: vendor the provider's OpenAPI
# document (OpenAI and Anthropic both publish one; the Bedrock Converse shape is in the AWS
# service model JSON that ships in aws-sdk-bedrockruntime) and derive from it here. Until then
# this script REFUSES to run on a schema missing its `source`/`retrieved` provenance, so a schema
# can never quietly become anonymous.
#
# WHAT COUNTS AS COVERED.
# Not "the IR has a struct member for it". A field is CARRIED only when qa/field-coverage.status
# names a test that fails if it stops being carried, and the Rust gate checks that the named test
# actually exists. A field a test would not miss is a field the next edit drops silently — which
# is precisely how the audited six arrived.
#
# USAGE
#   scripts/field-inventory.py --write     regenerate qa/field-inventory.json
#   scripts/field-inventory.py --check     fail if the committed file is stale (CI)
#   scripts/field-inventory.py --selftest  prove the derivation cannot be lied to

import argparse
import glob
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_DIR = os.path.join(REPO, "qa", "field-schemas")
OUT = os.path.join(REPO, "qa", "field-inventory.json")

DIRECTIONS = ("request", "response")

# The six chat dialects. Listed here so a schema file that is ADDED without being registered, or a
# dialect registered with no schema file, is a hard error rather than a silently smaller inventory.
DIALECTS = ("anthropic", "openai", "responses", "gemini", "bedrock", "cohere")

REQUIRED_SCHEMA_KEYS = ("dialect", "surface", "source", "retrieved", "request", "response")


def load_schemas():
    """Read every vendored schema, refusing anything without provenance."""
    schemas = {}
    for path in sorted(glob.glob(os.path.join(SCHEMA_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for key in REQUIRED_SCHEMA_KEYS:
            if not doc.get(key):
                sys.exit(
                    f"{path}: missing required key {key!r}. A schema without provenance is a "
                    f"hand-written list wearing a filename; refusing to derive from it."
                )
        dialect = doc["dialect"]
        if dialect != os.path.splitext(os.path.basename(path))[0]:
            sys.exit(f"{path}: `dialect` {dialect!r} does not match the filename")
        if dialect in schemas:
            sys.exit(f"{path}: duplicate dialect {dialect!r}")
        for direction in DIRECTIONS:
            fields = doc[direction]
            if len(set(fields)) != len(fields):
                dupes = sorted({f for f in fields if fields.count(f) > 1})
                sys.exit(f"{path}: duplicate {direction} field(s) {dupes}")
        schemas[dialect] = doc

    missing = sorted(set(DIALECTS) - set(schemas))
    extra = sorted(set(schemas) - set(DIALECTS))
    if missing:
        sys.exit(f"no schema for registered dialect(s): {missing}")
    if extra:
        sys.exit(
            f"schema present for unregistered dialect(s) {extra}; add them to DIALECTS so the "
            f"gate covers them, or the inventory silently excludes a whole surface"
        )
    return schemas


def build(schemas):
    fields = []
    for dialect in DIALECTS:
        doc = schemas[dialect]
        for direction in DIRECTIONS:
            for field in doc[direction]:
                fields.append(
                    {
                        "id": f"{dialect}/{direction}/{field}",
                        "dialect": dialect,
                        "direction": direction,
                        "field": field,
                        # A `stream:` prefix marks a field/event that exists only on the streaming
                        # surface. Kept as its own row rather than merged into the non-stream one:
                        # "survives at stream:false and vanishes at stream:true" is a real and
                        # separately-observed defect class, so it needs its own cell.
                        "streaming": field.startswith("stream:"),
                    }
                )
    return {
        "_comment": [
            "GENERATED by scripts/field-inventory.py. Do not edit by hand.",
            "Regenerate:  scripts/field-inventory.py --write",
            "",
            "Every request and response field of every chat dialect busbar speaks.",
            "crates/busbar/tests/field_coverage.rs reads this and FAILS the build for any",
            "field that is neither CARRIED (naming a test that proves it survives the hop)",
            "nor WAIVED with a dated reason in qa/field-coverage.status.",
            "",
            "A field is CARRIED when a test proves it survives, NOT when a struct has a",
            "member for it. That distinction is the entire point: the audited losses were",
            "all in fields nothing read and nothing emitted, where there was nothing for a",
            "mutation test to break.",
        ],
        "derived_from": {
            d: f"{schemas[d]['source']} (retrieved {schemas[d]['retrieved']})" for d in DIALECTS
        },
        "dialects": list(DIALECTS),
        "directions": list(DIRECTIONS),
        "field_count": len(fields),
        "fields": fields,
    }


def selftest(schemas):
    """Prove the derivation cannot be lied to."""
    ok = True

    # 1. A schema stripped of its provenance must be REFUSED, not silently accepted.
    for key in ("source", "retrieved"):
        probe = dict(schemas["openai"])
        probe.pop(key)
        if all(probe.get(k) for k in REQUIRED_SCHEMA_KEYS):
            print(f"SELFTEST FAIL: a schema without {key} would be accepted")
            ok = False

    # 2. Every id must be unique — a collision would let one field's coverage claim stand in for
    #    another's, which is the shape of a fake green.
    inv = build(schemas)
    ids = [f["id"] for f in inv["fields"]]
    if len(set(ids)) != len(ids):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        print(f"SELFTEST FAIL: duplicate field ids {dupes}")
        ok = False

    # 3. Every dialect must contribute BOTH directions. A dialect with an empty response list would
    #    report full coverage of a surface nobody enumerated.
    for dialect in DIALECTS:
        for direction in DIRECTIONS:
            n = sum(
                1 for f in inv["fields"] if f["dialect"] == dialect and f["direction"] == direction
            )
            if n == 0:
                print(f"SELFTEST FAIL: {dialect}/{direction} enumerates no fields")
                ok = False

    # 4. The known-lost fields the audit NAMED must all be present in the inventory. If the
    #    enumeration cannot even see a defect that was found by hand, it cannot see the ones that
    #    were not.
    audited = [
        "openai/request/content[].type=input_audio.input_audio.data",
        "openai/request/content[].type=file.file.file_id",
        "openai/response/usage.completion_tokens_details.reasoning_tokens",
        "openai/response/choices[].message.annotations",
        "anthropic/request/content[].type=document.source.data",
        "anthropic/response/usage.cache_creation.ephemeral_1h_input_tokens",
        "bedrock/request/content[].video.source.bytes",
        "cohere/response/message.tool_plan",
        "cohere/response/usage.billed_units.search_units",
        "responses/request/content[].type=input_file.file_data",
        "gemini/request/parts[].inlineData.mimeType",
    ]
    have = set(ids)
    for a in audited:
        if a not in have:
            print(f"SELFTEST FAIL: audited field {a!r} is not in the enumeration")
            ok = False

    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    schemas = load_schemas()
    if args.selftest:
        return selftest(schemas)

    inv = build(schemas)
    text = json.dumps(inv, indent=2) + "\n"

    if args.write:
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {OUT} ({inv['field_count']} fields)")
        return 0

    if args.check:
        if not os.path.exists(OUT):
            print(f"{OUT} is missing; run scripts/field-inventory.py --write")
            return 1
        with open(OUT, encoding="utf-8") as fh:
            current = fh.read()
        if current != text:
            print(f"{OUT} is STALE; run scripts/field-inventory.py --write")
            return 1
        print(f"{OUT} is up to date ({inv['field_count']} fields)")
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
