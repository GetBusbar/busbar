#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Validate a shadow-oracle recording of busbar's LLM plane against the providers' PUBLISHED specs.

For every LLM cell in a recording (testing/shadow-oracle/record.sh layout) this checks two things
against the ingress dialect's specification, and writes ONE ledger row per cell x direction:

  <cell-id>#request    the client request the oracle sent busbar (raw/<cell>/request.body, or the
                       same bytes rebuilt by the pinned oracle tool's build-request.py) against the
                       dialect's REQUEST schema. This proves the harness speaks the spec, so a busbar
                       refusal in the response row is busbar's, not the harness's.
  <cell-id>#response   what busbar answered: a JSON body against the RESPONSE schema (2xx) or the
                       dialect's ERROR schema for that status; an SSE body event-by-event against the
                       STREAM-EVENT union; a Bedrock binary event stream frame-by-frame (CRCs checked)
                       against the ConverseStreamOutput event union.

Row status: PASS (valid) | FAIL (schema violation: JSON pointer + rule) | SKIP (a NAMED GAP: no
fetchable schema for that check, the recording has nothing to check, or every violation on the row
is one named-gaps.json names as a place the VENDOR'S schema is the incomplete side). A SKIP is never
a pass; the run script keeps SKIP ids out of the owed set and reports them by name. Zero rows is red
(run.sh). Naming a gap never relaxes a check: the violation is still computed, an unnamed violation
on the same row still fails it, and an entry that forgives nothing is itself red.

Schema sources, all resolved through the digest-pinned cache vendor.sh fills:
  openai/responses  OpenAPI 3.1 (openai-openapi)          $ref within the document
  anthropic         OpenAPI 3.1 (Stainless-published)      $ref within the document
  cohere            OpenAPI 3.1 (cohere-developer-experience)
  gemini            Google discovery document -> converted to closed JSON-schema-ish objects
  bedrock           botocore service-2.json -> shapes converted (structures are closed; unions
                    exactly-one-member; members that live in the URI/headers are not body fields)
  gemini ERRORS     schemas/google-rpc-status.json, hand-transcribed (the discovery document does
                    not describe error bodies). Rows checked with it say "schema source: transcribed".

The checker is a deliberately small JSON-schema subset (type, const, enum, required, properties,
additionalProperties, patternProperties, items, min/max*, pattern, allOf/anyOf/oneOf/not, nullable,
discriminator) written on the stdlib so nothing here depends on a validator package whose own
version could change a verdict. The two YAML specs need PyYAML (>= 6.0) to parse; the parsed
document is cached as JSON beside the spec so later runs need only the stdlib.

Usage:
  validate.py --recording <dir> --out <dir> [--cells testing/shadow-oracle/cells.json]
              [--digests spec-digests.tsv] [--spec-cache ~/.cache/busbar-llm-specs]
  validate.py --owed [--cells ...]        print every id the gate OWES (cell x direction), no I/O on
                                          the recording; run.sh diffs the ledger against this list.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import zlib

sys.setrecursionlimit(20000)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
ORACLE = os.path.join(REPO, "testing", "shadow-oracle")

# Which published document each ingress dialect is judged by. `openai` and `responses` are two
# doors in one OpenAPI file.
DIALECT_SPEC = {"openai": "openai", "responses": "openai", "anthropic": "anthropic",
                "gemini": "gemini", "bedrock": "bedrock", "cohere": "cohere"}

# Per-dialect schema addresses. Error schemas for a given status are derived from the OpenAPI path
# item where the spec declares them (see error_schema_for); `error` here is the fallback envelope.
DIALECTS = {
    "openai": dict(path="/chat/completions", request="#/components/schemas/CreateChatCompletionRequest",
                   response="#/components/schemas/CreateChatCompletionResponse",
                   stream="#/components/schemas/CreateChatCompletionStreamResponse", stream_kind="sse",
                   sentinel="[DONE]", error="#/components/schemas/ErrorResponse"),
    "responses": dict(path="/responses", request="#/components/schemas/CreateResponse",
                      response="#/components/schemas/Response",
                      stream="#/components/schemas/ResponseStreamEvent", stream_kind="sse",
                      error="#/components/schemas/ErrorResponse"),
    "anthropic": dict(path="/v1/messages", request="#/components/schemas/CreateMessageParams",
                      response="#/components/schemas/Message",
                      stream="#/components/schemas/MessageStreamEvent", stream_kind="sse",
                      error="#/components/schemas/ErrorResponse"),
    "cohere": dict(path="/v2/chat", request="#/paths/~1v2~1chat/post/requestBody/content/application~1json/schema",
                   response="#/components/schemas/ChatResponseV2",
                   stream="#/components/schemas/StreamedChatResponseV2", stream_kind="sse",
                   error="#/components/schemas/Error"),
    "gemini": dict(request="#/schemas/GenerateContentRequest", response="#/schemas/GenerateContentResponse",
                   stream="#/schemas/GenerateContentResponse", stream_kind="sse",
                   error="transcribed:google-rpc-status"),
    "bedrock": dict(request="#/shapes/ConverseRequest", request_stream="#/shapes/ConverseStreamRequest",
                    response="#/shapes/ConverseResponse", stream="#/shapes/ConverseStreamOutput",
                    stream_kind="eventstream", error="exception"),
}
STREAM_CT = {"sse": "text/event-stream", "eventstream": "application/vnd.amazon.eventstream"}

# WHICH SIDE OF 2xx EACH OUTCOME MUST LAND ON. A cell's outcome is the thing it exists to prove, and
# the schema cannot see it: an `unauthenticated` cell answered HTTP 200 with the happy path's own
# body is a perfectly valid response body, and a check that only asks "does this parse against the
# schema for the status that was sent" calls it conformant. So does the mirror — an `ok` cell
# answered with a well-formed refusal envelope. Both were green. The status CLASS the outcome
# implies is asserted here; the body is then still judged against the schema for the status that was
# actually sent, so a run says both what was wrong and what the bytes were.
#
# The line is 2xx / not-2xx and nothing finer, because it has to hold across six dialects that
# disagree about the code (Gemini answers an absent key with 400 where OpenAI answers 401). Which
# code within the class is the shadow oracle's diff against the golden, not this gate's.
OUTCOME_REFUSES = {"malformed", "unauthenticated", "out_of_scope", "over_budget", "over_budget_total",
                   "upstream_down"}
# `stream_upstream_error` is exempt in both directions: the upstream fails PART WAY THROUGH, so the
# response legitimately opens 2xx and carries the failure as an in-band event.
OUTCOME_STATUS_EXEMPT = {"stream_upstream_error"}


# ── ledger (same TSV contract as testing/fleet-fixtures/lib.sh `record`) ─────────────────────────
class Ledger:
    def __init__(self, path):
        self.path = path
        self.rows = []
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        open(path, "w").close()

    def record(self, rid, status, title, detail=""):
        clean = lambda s: str(s).replace("\t", " ").replace("\n", " ")
        title, detail = clean(title), clean(detail)
        with open(self.path, "a") as f:
            f.write(f"{rid}\t{status}\t{title}\t{detail}\n")
        self.rows.append((rid, status, title, detail))
        if status == "PASS":
            print(f"PASS  {rid:<52} {title}")
        elif status == "FAIL":
            print(f"FAIL  {rid:<52} {title}\n      {detail}")
            print(f"::error title=llm-spec {rid}::{title} — {detail}")
        else:
            print(f"SKIP  {rid:<52} {title}\n      {detail}")
            print(f"::warning title=llm-spec {rid} DID NOT VERIFY::{title} — {detail}")


# ── spec loading ────────────────────────────────────────────────────────────────────────────────
def read_digests(path):
    out = {}
    with open(path) as f:
        for ln in f:
            if not ln.strip() or ln.startswith("#"):
                continue
            parts = ln.rstrip("\n").split("\t")
            if len(parts) >= 4:
                out[parts[0]] = dict(fmt=parts[1], digest=parts[2], url=parts[3])
    return out


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_spec_doc(spec, pin, cache_root):
    """Locate the pinned document in the cache, RE-MEASURE IT AGAINST THE PIN, and parse it.

    THE DOCUMENT IS RE-MEASURED ON EVERY RUN, AND ONLY THE MEASURED BYTES ARE EVER PARSED. There
    used to be a `spec.parsed.json` beside the spec — the same document pre-parsed, written on the
    first run so later runs would not need PyYAML — and it was returned BEFORE any digest was
    computed. Nothing in the rig ever measured it: vendor.sh calls the directory "cached" by
    comparing its `.digest` sidecar with itself, and this function handed the pre-parsed copy
    straight to the checker. So a `spec.parsed.json` that no longer said what the pinned digest
    names was the document every verdict was decided by, and a response missing a member the
    published spec REQUIRES came back PASS with the whole run GREEN — the gate reporting
    conformance to a spec nobody published. A pinned digest that is not re-computed pins nothing.

    Re-measuring costs about half a second across all five documents (2 ms to sha256 the largest,
    280 ms to parse it with PyYAML's C loader), which is why the pre-parsed copy is simply gone
    rather than made verifiable: it never bought enough to be worth an unmeasured schema.
    """
    d = os.path.join(cache_root, spec, pin["digest"])
    cands = [os.path.join(d, "spec.json"), os.path.join(d, "spec.yaml")]
    path = next((c for c in cands if os.path.isfile(c)), None)
    if not path:
        raise SystemExit(f"spec '{spec}' is not in the cache ({d}); run testing/llm-conformance/vendor.sh")
    if pin["fmt"] == "raw":
        got = sha256_file(path)
        if got != pin["digest"]:
            raise SystemExit(f"spec '{spec}' digest mismatch in cache: {got} != pinned {pin['digest']} "
                             f"({path} is not the document that digest names; re-run vendor.sh, or "
                             f"--repin it on purpose)")
def parse_spec_bytes(spec, path):
    """Parse the on-disk spec document (JSON, else YAML)."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except ValueError:
        try:
            import yaml  # PyYAML >= 6.0, on every run: a YAML spec is parsed from its measured bytes
        except ImportError:
            raise SystemExit(f"spec '{spec}' is YAML and PyYAML is not installed (pip install 'pyyaml>=6.0')")
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        return yaml.load(raw, Loader=loader)


def load_spec_doc(spec, pin, cache_root):
    """Locate the pinned document in the cache, re-verify its digest, parse it (cached as JSON)."""
    d = os.path.join(cache_root, spec, pin["digest"])
    cands = [os.path.join(d, "spec.json"), os.path.join(d, "spec.yaml")]
    path = next((c for c in cands if os.path.isfile(c)), None)
    if not path:
        raise SystemExit(f"spec '{spec}' is not in the cache ({d}); run testing/llm-conformance/vendor.sh")

    # THE PIN IS VERIFIED BEFORE THE PARSED CACHE IS TRUSTED, NOT AFTER IT.
    #
    # `spec.parsed.json` used to short-circuit here, ABOVE both digest checks -- so whenever that
    # sidecar existed the pinned bytes were never read at all. CI restores the whole spec cache
    # directory, sidecar included, from a build artifact, which means that on every run after the
    # first, no digest in spec-digests.tsv was compared to anything. Overwriting spec.yaml with
    # arbitrary content while leaving the sidecar alone left this gate GREEN while judging busbar
    # against a document nobody pinned -- the exact substitution the pin exists to prevent.
    #
    # The sidecar is still worth having: for a `raw`-format YAML spec it saves the YAML parse, which
    # is the expensive part. It is now allowed to save the PARSE only, never the VERIFICATION.
    doc = None
    if pin["fmt"] == "raw":
        got = sha256_file(path)
    elif pin["fmt"] == "json-canonical":
        doc = parse_spec_bytes(spec, path)
        got = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    else:
        # An unrecognised format used to mean NO check ran at all: neither branch matched and the
        # document was accepted unverified. A pin nobody knows how to check is not a pin.
        raise SystemExit(f"spec '{spec}': unknown digest format {pin['fmt']!r} in spec-digests.tsv "
                         "(expected 'raw' or 'json-canonical') -- refusing to use an unverifiable spec")
    if got != pin["digest"]:
        raise SystemExit(f"spec '{spec}' digest mismatch in cache ({pin['fmt']}): {got} != pinned {pin['digest']} "
                         f"-- the cached document at {path} is not the pinned one; "
                         "re-run testing/llm-conformance/vendor.sh")

    parsed = os.path.join(d, "spec.parsed.json")
    if os.path.isfile(parsed):
        with open(parsed) as f:
            return json.load(f)
    if doc is None:
        doc = parse_spec_bytes(spec, path)
    # YAML can carry dates/timestamps inside `example:` blocks; they are documentation, not schema,
    # so stringifying them loses nothing the checker reads.
    return json.loads(json.dumps(doc, separators=(",", ":"), default=str))


# ── botocore service model -> schema document ───────────────────────────────────────────────────
BODY_EXCLUDED_LOCATIONS = {"uri", "header", "headers", "querystring"}


def botocore_to_schema(model):
    shapes = model["shapes"]
    out = {}
    for name, sh in shapes.items():
        t = sh.get("type")
        if sh.get("document"):
            out[name] = {}
            continue
        if t == "structure":
            props, req = {}, []
            for m, md in (sh.get("members") or {}).items():
                if md.get("location") in BODY_EXCLUDED_LOCATIONS:
                    continue  # lives in the URI/headers, so it is not a body field
                props[m] = {"$ref": "#/shapes/" + md["shape"]}
            for r in sh.get("required") or []:
                if r in props:
                    req.append(r)
            s = {"type": "object", "properties": props, "additionalProperties": False}
            if req:
                s["required"] = req
            if sh.get("union"):
                s["minProperties"], s["maxProperties"] = 1, 1
            if sh.get("exception"):
                # rest-json error envelope: the type rides in x-amzn-errortype or in __type/code
                props.setdefault("__type", {"type": "string"})
                props.setdefault("code", {"type": "string"})
                props.setdefault("Message", {"type": "string"})
            if sh.get("eventstream"):
                s["x-eventstream"] = True
            out[name] = s
        elif t == "list":
            s = {"type": "array", "items": {"$ref": "#/shapes/" + sh["member"]["shape"]}}
            if "min" in sh: s["minItems"] = sh["min"]
            if "max" in sh: s["maxItems"] = sh["max"]
            out[name] = s
        elif t == "map":
            out[name] = {"type": "object", "additionalProperties": {"$ref": "#/shapes/" + sh["value"]["shape"]}}
        elif t == "string":
            s = {"type": "string"}
            if "enum" in sh: s["enum"] = sh["enum"]
            if "min" in sh: s["minLength"] = sh["min"]
            if "max" in sh: s["maxLength"] = sh["max"]
            if "pattern" in sh: s["pattern"] = sh["pattern"]
            out[name] = s
        elif t in ("integer", "long"):
            s = {"type": "integer"}
            if "min" in sh: s["minimum"] = sh["min"]
            if "max" in sh: s["maximum"] = sh["max"]
            out[name] = s
        elif t in ("float", "double"):
            s = {"type": "number"}
            if "min" in sh: s["minimum"] = sh["min"]
            if "max" in sh: s["maximum"] = sh["max"]
            out[name] = s
        elif t == "boolean":
            out[name] = {"type": "boolean"}
        elif t == "blob":
            out[name] = {"type": "string"}
        elif t == "timestamp":
            out[name] = {"type": ["number", "string"]}
        else:
            out[name] = {}
    return {"shapes": out, "operations": model["operations"], "x-botocore-shapes": shapes}


# ── Google discovery document -> schema document ────────────────────────────────────────────────
def discovery_to_schema(doc):
    def conv(s):
        if not isinstance(s, dict):
            return s
        if "$ref" in s:
            return {"$ref": "#/schemas/" + s["$ref"]}
        o = {}
        t = s.get("type")
        if t and t != "any":
            o["type"] = t
        if "enum" in s:
            o["enum"] = s["enum"]
        if "properties" in s:
            props, req = {}, []
            for k, v in s["properties"].items():
                props[k] = conv(v)
                if isinstance(v, dict) and v.get("required") is True:
                    req.append(k)
            o["properties"] = props
            if req:
                o["required"] = req
            # a proto message is closed: a field the discovery document does not name is one the
            # provider would reject (unknown field)
            o["additionalProperties"] = conv(s["additionalProperties"]) if "additionalProperties" in s else False
        elif "additionalProperties" in s:
            o["additionalProperties"] = conv(s["additionalProperties"])
        if "items" in s:
            o["items"] = conv(s["items"])
        return o
    return {"schemas": {k: conv(v) for k, v in doc["schemas"].items()}, "resources": doc.get("resources", {})}


# ── the checker ─────────────────────────────────────────────────────────────────────────────────
class Violation:
    __slots__ = ("pointer", "rule", "detail")

    def __init__(self, pointer, rule, detail):
        self.pointer, self.rule, self.detail = pointer, rule, detail

    def as_dict(self):
        return {"pointer": self.pointer, "rule": self.rule, "detail": self.detail}

    def __str__(self):
        return f"{self.pointer} {self.rule}: {self.detail}"


# ── named conformance gaps ──────────────────────────────────────────────────────────────────────
# A gap is a violation the owner has READ and ruled the vendor's schema wrong about — the bytes
# stay, the finding is named, and the row leaves the owed set as the rig's existing named-gap status
# rather than as a pass. THE VALIDATOR IS NOT WEAKENED BY THIS: it still computes every violation,
# a violation this file does not name still fails its row, and a row is only downgraded when EVERY
# violation on it is named.
#
# The refusals below are the whole design. Each is a way a "gap" could quietly become a bypass:
# an entry with no owner or no reason forgives anonymously; an entry with no `cells` list, or a
# wildcard in one, forgives a rule across every cell that ever produces it; a short or empty
# `detail_contains` matches violations nobody has looked at. All are load-time errors, not warnings.
class NamedGaps:
    def __init__(self, entries):
        self.entries = entries
        self.hits = {g["id"]: set() for g in entries}      # gap id -> rows it actually forgave
        self.judged = set()                                 # every row the validator judged

    @staticmethod
    def load(path):
        """-> (NamedGaps, [refusal, ...]). A refusal list that is non-empty means: do not run."""
        if not path or not os.path.exists(path):
            return NamedGaps([]), []
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            return NamedGaps([]), [f"{path}: not readable as JSON ({e})"]
        if not isinstance(doc, dict) or not isinstance(doc.get("gaps"), list):
            return NamedGaps([]), [f"{path}: must be an object with a `gaps` list"]
        bad, seen, ok = [], set(), []
        for i, g in enumerate(doc["gaps"]):
            where = f"{path}: gaps[{i}]"
            if not isinstance(g, dict):
                bad.append(f"{where}: not an object")
                continue
            gid = g.get("id")
            where = f"{path}: gap {gid!r}" if isinstance(gid, str) and gid else where
            if not isinstance(gid, str) or not gid.strip():
                bad.append(f"{where}: no `id`")
                continue
            if gid in seen:
                bad.append(f"{where}: duplicate `id` — two entries answering for the same name")
                continue
            seen.add(gid)
            errs = []
            if not isinstance(g.get("owner"), str) or not g["owner"].strip():
                errs.append("no `owner` — a gap nobody owns is a bypass")
            if not isinstance(g.get("why"), str) or len(g.get("why", "").strip()) < 40:
                errs.append("`why` must say why the vendor's schema is the incomplete side, in a sentence")
            if not isinstance(g.get("rule"), str) or not g["rule"].strip():
                errs.append("no `rule` — the gap must name the check it forgives")
            dc = g.get("detail_contains")
            if not isinstance(dc, str) or len(dc.strip()) < 8:
                errs.append("`detail_contains` must be a substring of the violation's own detail, long enough to name it")
            elif any(ch in dc for ch in "*?"):
                errs.append("`detail_contains` is matched literally; `*`/`?` would read as a wildcard that is not one")
            cells = g.get("cells")
            if not isinstance(cells, list) or not cells:
                errs.append("no `cells` — a gap must name the rows it covers, one by one")
            else:
                for c in cells:
                    if not isinstance(c, str) or "#" not in c:
                        errs.append(f"cell {c!r} is not a `<cell id>#<direction>` row")
                    elif any(ch in c for ch in "*?"):
                        errs.append(f"cell {c!r} carries a wildcard — a gap that matches a pattern of rows is a bypass")
            if errs:
                bad += [f"{where}: {e}" for e in errs]
            else:
                ok.append(g)
        return NamedGaps(ok), bad

    def partition(self, rid, viols):
        """-> (unnamed violations, [gap, ...] that covered the rest). Records what was judged."""
        self.judged.add(rid)
        unnamed, covered = [], []
        for v in viols:
            g = next((g for g in self.entries
                      if rid in g["cells"] and v.rule == g["rule"] and g["detail_contains"] in v.detail), None)
            if g is None:
                unnamed.append(v)
            else:
                self.hits[g["id"]].add(rid)
                if g not in covered:
                    covered.append(g)
        return unnamed, covered

    def stale(self):
        """Rows a gap names, that this run JUDGED, and that did NOT produce the named violation.

        A row the run never judged is not stale — the recorder may simply not have made that cell on
        this pass, and that absence is already a named gap row of its own. A row that WAS judged and
        came back clean is the real case: the gap is forgiving nothing and must come out of the file.
        """
        out = []
        for g in self.entries:
            for c in g["cells"]:
                if c in self.judged and c not in self.hits[g["id"]]:
                    out.append((g["id"], c))
        return out


def gap_detail(covered):
    """The ledger detail for a row whose every violation is named. It carries the owner and the
    reason, so the gap is readable in the run's own output and not only in the file."""
    return "named gap — " + " | ".join(f"{g['id']} ({g['owner']}): {g['why']}" for g in covered)


def esc(tok):
    return str(tok).replace("~", "~0").replace("/", "~1")


def short(v, n=60):
    s = json.dumps(v, separators=(",", ":"), ensure_ascii=False) if not isinstance(v, str) else repr(v)
    return s if len(s) <= n else s[:n - 1] + "…"


class Checker:
    def __init__(self, root):
        self.root = root

    def resolve(self, ref):
        if not ref.startswith("#/"):
            raise KeyError(f"external $ref not supported: {ref}")
        node = self.root
        for tok in ref[2:].split("/"):
            tok = tok.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                node = node[int(tok)]
            else:
                node = node[tok]
        return node

    def deref(self, schema, chain=()):
        seen = 0
        while isinstance(schema, dict) and "$ref" in schema and seen < 32:
            target = self.resolve(schema["$ref"])
            extra = {k: v for k, v in schema.items() if k != "$ref"}
            schema = dict(target, **extra) if extra else target
            seen += 1
        return schema

    @staticmethod
    def at(ptr):
        """The pointer to report for the value at `ptr`: a bare prefix like `sse[3]:` is the root of
        that event, shown as `sse[3]:/`; an empty prefix is the body root `/`."""
        return ptr if ptr and not ptr.endswith(":") else ptr + "/"

    @staticmethod
    def type_ok(inst, t):
        if t == "null": return inst is None
        if t == "boolean": return isinstance(inst, bool)
        if t == "integer": return (isinstance(inst, int) and not isinstance(inst, bool)) or (isinstance(inst, float) and inst.is_integer())
        if t == "number": return isinstance(inst, (int, float)) and not isinstance(inst, bool)
        if t == "string": return isinstance(inst, str)
        if t == "object": return isinstance(inst, dict)
        if t == "array": return isinstance(inst, list)
        return True

    def check(self, inst, schema, ptr, out):
        if schema is True or schema == {}:
            return
        if schema is False:
            out.append(Violation(self.at(ptr), "schema", "no value is allowed here")); return
        schema = self.deref(schema)
        types = schema.get("type")
        if isinstance(types, str):
            types = [types]
        nullable = schema.get("nullable") is True or (types and "null" in types)
        if inst is None and nullable:
            return
        if "const" in schema and inst != schema["const"]:
            out.append(Violation(self.at(ptr), "const", f"expected {short(schema['const'])}, got {short(inst)}"))
        if "enum" in schema and inst not in schema["enum"] and not (inst is None and nullable):
            allowed = [e for e in schema["enum"] if e is not None]
            out.append(Violation(self.at(ptr), "enum", f"{short(inst)} not in {short(allowed, 120)}"))
        if types and not any(self.type_ok(inst, t) for t in types):
            got = "null" if inst is None else type(inst).__name__.replace("dict", "object").replace("list", "array").replace("str", "string").replace("float", "number").replace("int", "integer").replace("bool", "boolean")
            out.append(Violation(self.at(ptr), "type", f"expected {'/'.join(types)}, got {got} {short(inst)}"))
            return  # nothing below applies to the wrong type
        if isinstance(inst, dict):
            self.check_object(inst, schema, ptr, out)
        elif isinstance(inst, list):
            self.check_array(inst, schema, ptr, out)
        elif isinstance(inst, str):
            if "minLength" in schema and len(inst) < schema["minLength"]:
                out.append(Violation(self.at(ptr), "minLength", f"length {len(inst)} < {schema['minLength']}"))
            if "maxLength" in schema and len(inst) > schema["maxLength"]:
                out.append(Violation(self.at(ptr), "maxLength", f"length {len(inst)} > {schema['maxLength']}"))
            if "pattern" in schema:
                try:
                    if not re.search(schema["pattern"], inst):
                        out.append(Violation(self.at(ptr), "pattern", f"{short(inst)} does not match /{schema['pattern']}/"))
                except re.error:
                    pass
        elif isinstance(inst, (int, float)) and not isinstance(inst, bool):
            if "minimum" in schema and inst < schema["minimum"]:
                out.append(Violation(self.at(ptr), "minimum", f"{inst} < {schema['minimum']}"))
            if "maximum" in schema and inst > schema["maximum"]:
                out.append(Violation(self.at(ptr), "maximum", f"{inst} > {schema['maximum']}"))
            if "exclusiveMinimum" in schema and isinstance(schema["exclusiveMinimum"], (int, float)) and inst <= schema["exclusiveMinimum"]:
                out.append(Violation(self.at(ptr), "exclusiveMinimum", f"{inst} <= {schema['exclusiveMinimum']}"))
        for sub in schema.get("allOf") or []:
            self.check(inst, sub, ptr, out)
        if "not" in schema:
            tmp = []
            self.check(inst, schema["not"], ptr, tmp)
            if not tmp:
                out.append(Violation(self.at(ptr), "not", "value matches a forbidden schema"))
        if "anyOf" in schema or "oneOf" in schema:
            self.check_union(inst, schema, ptr, out)

    def check_object(self, inst, schema, ptr, out):
        props = schema.get("properties") or {}
        for r in schema.get("required") or []:
            if r not in inst:
                out.append(Violation(self.at(ptr), "required", f"missing property '{r}'"))
        if "minProperties" in schema and len(inst) < schema["minProperties"]:
            out.append(Violation(self.at(ptr), "minProperties", f"{len(inst)} members < {schema['minProperties']} (a union needs exactly one)"))
        if "maxProperties" in schema and len(inst) > schema["maxProperties"]:
            out.append(Violation(self.at(ptr), "maxProperties", f"{len(inst)} members > {schema['maxProperties']} (a union allows exactly one): {sorted(inst)}"))
        pats = schema.get("patternProperties") or {}
        addl = schema.get("additionalProperties", True)
        for k, v in inst.items():
            p = f"{ptr}/{esc(k)}"
            if k in props:
                self.check(v, props[k], p, out)
                continue
            matched = False
            for pat, sub in pats.items():
                try:
                    if re.search(pat, k):
                        matched = True
                        self.check(v, sub, p, out)
                except re.error:
                    pass
            if matched:
                continue
            if addl is False:
                out.append(Violation(p, "additionalProperties", f"property '{k}' is not declared by the spec"))
            elif isinstance(addl, dict):
                self.check(v, addl, p, out)

    def check_array(self, inst, schema, ptr, out):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            out.append(Violation(self.at(ptr), "minItems", f"{len(inst)} items < {schema['minItems']}"))
        if "maxItems" in schema and len(inst) > schema["maxItems"]:
            out.append(Violation(self.at(ptr), "maxItems", f"{len(inst)} items > {schema['maxItems']}"))
        items = schema.get("items")
        if isinstance(items, dict):
            for i, v in enumerate(inst):
                self.check(v, items, f"{ptr}/{i}", out)
        elif isinstance(items, list):
            for i, (v, s) in enumerate(zip(inst, items)):
                self.check(v, s, f"{ptr}/{i}", out)

    def branch_name(self, sub):
        if isinstance(sub, dict) and "$ref" in sub:
            return sub["$ref"].rsplit("/", 1)[-1]
        d = self.deref(sub) if isinstance(sub, dict) else {}
        if isinstance(d, dict):
            if "const" in d: return f"const {d['const']!r}"
            if d.get("title"): return d["title"]
            if d.get("type"): return str(d["type"])
        return "inline"

    def admits(self, sub, pn, val):
        """Does alternative `sub` pin property `pn` (via const/enum, possibly through allOf) to `val`?"""
        d = self.deref(sub) if isinstance(sub, dict) else {}
        if not isinstance(d, dict):
            return False
        prop = (d.get("properties") or {}).get(pn)
        if prop is not None:
            p = self.deref(prop)
            if isinstance(p, dict):
                if "const" in p: return p["const"] == val
                if "enum" in p: return val in p["enum"]
        return any(self.admits(s, pn, val) for s in d.get("allOf") or [])

    def check_union(self, inst, schema, ptr, out):
        kind = "oneOf" if "oneOf" in schema else "anyOf"
        branches = schema[kind]
        disc = schema.get("discriminator")
        if disc and isinstance(inst, dict):
            pn = disc.get("propertyName")
            mapping = disc.get("mapping") or {}
            val = inst.get(pn)
            if val is None:
                out.append(Violation(self.at(ptr), "discriminator", f"missing discriminator property '{pn}'"))
                return
            if mapping:
                if val in mapping:
                    self.check(inst, {"$ref": mapping[val]}, ptr, out)
                else:
                    out.append(Violation(self.at(ptr), "discriminator", f"'{pn}': {val!r} is not one of {sorted(mapping)}"))
                return
            # no explicit mapping: the branches whose own `pn` const/enum admits the value decide
            picked = [s for s in branches if self.admits(s, pn, val)]
            if not picked:
                out.append(Violation(self.at(ptr), "discriminator", f"'{pn}': {val!r} is not admitted by any of the {len(branches)} alternatives"))
                return
            branches = picked
        if len(branches) == 1:
            # one admissible alternative: its violations ARE the finding, no union wrapper
            self.check(inst, branches[0], ptr, out)
            return
        results = []
        for sub in branches:
            errs = []
            self.check(inst, sub, ptr, errs)
            results.append((errs, sub))
        matches = [r for r in results if not r[0]]
        if kind == "oneOf" and len(matches) > 1:
            names = [self.branch_name(s) for _, s in matches]
            out.append(Violation(self.at(ptr), "oneOf", f"matches {len(matches)} alternatives, exactly one allowed: {names}"))
            return
        if matches:
            return
        best = min(results, key=lambda r: len(r[0]))
        # a branch that failed only on its discriminating const/enum is not the closest match
        named = [(e, s) for e, s in results if not all(v.rule in ("const", "enum") for v in e)]
        if named:
            best = min(named, key=lambda r: len(r[0]))
        summary = "; ".join(str(v) for v in best[0][:3])
        out.append(Violation(self.at(ptr), kind, f"matches none of {len(branches)} alternatives; closest ({self.branch_name(best[1])}): {summary}"))


# ── wire decoders ───────────────────────────────────────────────────────────────────────────────
def parse_sse(text):
    """-> list of (index, event_name, data_str). Per the SSE spec: blocks split on a blank line,
    multiple `data:` lines joined with \\n, one leading space after the colon stripped, `:` comments
    ignored, unknown fields ignored."""
    events = []
    for i, block in enumerate(re.split(r"\r?\n\r?\n", text)):
        if not block.strip():
            continue
        ev, data = None, []
        for ln in block.split("\n"):
            ln = ln.rstrip("\r")
            if not ln or ln.startswith(":"):
                continue
            field, _, value = ln.partition(":")
            if value.startswith(" "):
                value = value[1:]
            if field == "data":
                data.append(value)
            elif field == "event":
                ev = value
        if data or ev is not None:
            events.append((len(events), ev, "\n".join(data)))
    return events


def parse_eventstream(b):
    """AWS event-stream framing -> list of dicts {index, headers, payload, crc_ok, error}."""
    frames, off = [], 0
    while off < len(b):
        if len(b) - off < 16:
            frames.append({"index": len(frames), "error": f"truncated frame: {len(b) - off} trailing bytes"}); break
        total, hlen, pcrc = struct.unpack(">IIi", b[off:off + 12])
        fr = {"index": len(frames), "headers": {}, "payload": b"", "crc_ok": True, "error": None}
        if total < 16 or off + total > len(b):
            fr["error"] = f"frame length {total} exceeds remaining {len(b) - off} bytes"; frames.append(fr); break
        if (zlib.crc32(b[off:off + 8]) & 0xFFFFFFFF) != (pcrc & 0xFFFFFFFF):
            fr["crc_ok"] = False
        p, end = off + 12, off + 12 + hlen
        while p < end:
            nlen = b[p]; p += 1
            name = b[p:p + nlen].decode("utf-8", "replace"); p += nlen
            ht = b[p]; p += 1
            if ht in (0, 1): val = ht == 0
            elif ht == 2: val = b[p]; p += 1
            elif ht == 3: val = struct.unpack(">h", b[p:p + 2])[0]; p += 2
            elif ht == 4: val = struct.unpack(">i", b[p:p + 4])[0]; p += 4
            elif ht == 5: val = struct.unpack(">q", b[p:p + 8])[0]; p += 8
            elif ht in (6, 7):
                vlen = struct.unpack(">H", b[p:p + 2])[0]; p += 2
                raw = b[p:p + vlen]; p += vlen
                val = raw.decode("utf-8", "replace") if ht == 7 else raw
            elif ht == 8: val = struct.unpack(">q", b[p:p + 8])[0]; p += 8
            elif ht == 9: val = b[p:p + 16].hex(); p += 16
            else: fr["error"] = f"unknown header value type {ht}"; break
            fr["headers"][name] = val
        fr["payload"] = b[end:off + total - 4]
        mcrc = struct.unpack(">i", b[off + total - 4:off + total])[0]
        if (zlib.crc32(b[off:off + total - 4]) & 0xFFFFFFFF) != (mcrc & 0xFFFFFFFF):
            fr["crc_ok"] = False
        frames.append(fr)
        off += total
    return frames


# ── recording access ────────────────────────────────────────────────────────────────────────────
def parse_headers_file(path):
    h = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.rstrip("\r\n")
            if ":" in ln and not ln.startswith("HTTP/"):
                k, v = ln.split(":", 1)
                h[k.strip().lower()] = v.strip()
    return h


class Recording:
    def __init__(self, root):
        self.root = root
        self.cells_dir = os.path.join(root, "cells")
        self.raw_dir = os.path.join(root, "raw")
        self.ledger = {}
        lp = os.path.join(root, "ledger.tsv")
        if os.path.isfile(lp):
            with open(lp) as f:
                for ln in f:
                    parts = ln.rstrip("\n").split("\t")
                    if len(parts) >= 2:
                        self.ledger[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
        self.meta = {}
        mp = os.path.join(root, "meta.json")
        if os.path.isfile(mp):
            try:
                with open(mp) as f:
                    self.meta = json.load(f)
            except ValueError:
                pass

    def llm_cell_files(self):
        if not os.path.isdir(self.cells_dir):
            return []
        return sorted(f for f in os.listdir(self.cells_dir) if f.startswith("llm__") and f.endswith(".json"))

    def cell(self, safe):
        p = os.path.join(self.cells_dir, safe + ".json")
        if not os.path.isfile(p):
            return None
        with open(p) as f:
            return json.load(f)

    def raw(self, safe, name):
        p = os.path.join(self.raw_dir, safe, name)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                return f.read()
        return None

    def response_bytes(self, safe, cell):
        """(bytes, source) — the raw wire body when the recording kept it, else the normalized cell."""
        raw = self.raw(safe, "body")
        if raw is not None:
            return raw, "raw/body"
        body = cell.get("body") or {}
        if "json" in body:
            return json.dumps(body["json"], separators=(",", ":")).encode(), "cell.body.json"
        text = body.get("text", "")
        if text.startswith("base64:"):
            return base64.b64decode(text[7:]), "cell.body.text(base64)"
        return text.encode("utf-8"), "cell.body.text"

    def response_headers(self, safe, cell):
        p = os.path.join(self.raw_dir, safe, "headers")
        if os.path.isfile(p):
            return parse_headers_file(p)
        return {k.lower(): v for k, v in (cell.get("headers") or {}).items()}


def load_cells(path):
    with open(path) as f:
        doc = json.load(f)
    cells = doc["cells"] if isinstance(doc, dict) else doc
    # `plane == "llm"` alone is no longer selective enough: cells.json also carries the "teller"
    # family (billing-pipeline script cells) under the same plane. This rig judges the LLM WIRE
    # dialects against their published specs, so restrict to that family explicitly rather than
    # crashing on a teller cell's missing `ingress_dialect`/`outcome` shape below.
    return [c for c in cells if c.get("plane") == "llm" and c.get("family") == "llm.wire"]


def owed_ids(cells):
    """Every id the gate owes a row for: each LLM cell x {request, response}. The request row is
    not owed for `malformed` cells — that request is non-JSON on purpose, so a schema check of it
    would be a check of the test's intent, not of any wire contract."""
    out = []
    for c in cells:
        if c.get("outcome") != "malformed":
            out.append(c["id"] + "#request")
        out.append(c["id"] + "#response")
    return out


# REBUILDING A REQUEST IS THE FALLBACK, AND IT BELONGS TO THE TOOL, NOT TO THIS TREE.
# build-request.py is part of the pinned shadow-oracle TOOL (it is what the recorder used to make
# the bytes in the first place); only this repository's oracle DATA lives under testing/shadow-oracle.
# So it is resolved the way every cell driver here resolves a tool file -- through the tool directory
# bin/oracle exports, falling back to the data directory for the old in-tree layout.
#
# LOADED ON DEMAND, NEVER AT STARTUP. A recording that carries raw/<cell>/request.body for every
# cell -- which is what the recorder writes and what CI hands this gate -- needs no rebuild at all,
# and eagerly importing the tool made a missing tool kill the validator before it recorded its FIRST
# row. That is the worst possible failure shape for this gate: the run reports VACUOUS ("zero probes
# reported a result") and the real reason sits in a log nobody reads. A rebuild that cannot happen is
# a fact about ONE row, so it is reported as one -- see the request direction below.
def build_request_dir():
    return os.environ.get("BUSBAR_ORACLE_TOOL_DIR") or ORACLE


def load_build_request():
    """Import the tool's build-request module, or return (None, why) if it is not installed."""
    p = os.path.join(build_request_dir(), "build-request.py")
    if not os.path.exists(p):
        return None, (f"the pinned shadow-oracle tool is not installed ({p} does not exist); "
                      "run bin/oracle to install it, or record with raw/<cell>/request.body present")
    try:
        spec = importlib.util.spec_from_file_location("oracle_build_request", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:  # a tool that will not import is a fact about the rebuild, not a crash
        return None, f"the pinned shadow-oracle tool at {p} failed to import: {e}"
    return mod, ""


# ── the per-dialect judgement ───────────────────────────────────────────────────────────────────
class Judge:
    def __init__(self, digests, cache_root, transcribed_dir):
        self.docs, self.checkers = {}, {}
        for spec, pin in digests.items():
            doc = load_spec_doc(spec, pin, cache_root)
            if spec == "bedrock":
                doc = botocore_to_schema(doc)
            elif spec == "gemini":
                doc = discovery_to_schema(doc)
            self.docs[spec] = doc
            self.checkers[spec] = Checker(doc)
        with open(os.path.join(transcribed_dir, "google-rpc-status.json")) as f:
            self.rpc_status = json.load(f)
        self.rpc_checker = Checker(self.rpc_status)

    def checker(self, dialect):
        return self.checkers[DIALECT_SPEC[dialect]]

    # --- error schema selection -------------------------------------------------------------
    def error_schema_for(self, dialect, status):
        """-> (checker, schema-or-None, source-note). Uses the schema the OpenAPI path item declares
        for this status (exact code, then N XX class, then default); otherwise the dialect's error
        envelope. Returns None when no error shape exists for the dialect at all."""
        cfg = DIALECTS[dialect]
        ck = self.checker(dialect)
        path = cfg.get("path")
        if path:
            doc = self.docs[DIALECT_SPEC[dialect]]
            responses = doc.get("paths", {}).get(path, {}).get("post", {}).get("responses", {})
            for key in (str(status), f"{str(status)[0]}XX", "default"):
                if key in responses:
                    r = ck.deref(responses[key])
                    sch = (r.get("content") or {}).get("application/json", {}).get("schema")
                    if sch is not None:
                        return ck, sch, f"declared for {key} at {path}"
        if cfg["error"].startswith("transcribed:"):
            return self.rpc_checker, self.rpc_status, "transcribed google.rpc.Status (not a fetched spec)"
        if cfg["error"] == "exception":
            return ck, None, "exception shape named by x-amzn-errortype / __type"
        return ck, {"$ref": cfg["error"]}, f"fallback envelope {cfg['error'].rsplit('/', 1)[-1]} (spec declares no {status} response at {path})"

    # --- request ---------------------------------------------------------------------------
    def judge_request(self, dialect, outcome, body_bytes):
        cfg = DIALECTS[dialect]
        ck = self.checker(dialect)
        try:
            inst = json.loads(body_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            return [Violation("/", "body.json", f"request body is not JSON: {e}")], "request"
        ref = cfg.get("request_stream") if (outcome == "ok_stream" and cfg.get("request_stream")) else cfg["request"]
        out = []
        ck.check(inst, {"$ref": ref}, "", out)
        return out, ref.rsplit("/", 1)[-1]

    # --- response --------------------------------------------------------------------------
    def judge_response(self, dialect, outcome, status, headers, body_bytes):
        """-> (violations, description, skip_reason_or_None)"""
        cfg = DIALECTS[dialect]
        ck = self.checker(dialect)
        ct = (headers.get("content-type") or "").split(";")[0].strip().lower()
        out = []
        self.judge_outcome_status(outcome, status, out)
        if 200 <= status < 300:
            want_stream = outcome == "ok_stream"
            want_stream_array = outcome == "ok_stream_array"
            stream_ct = STREAM_CT[cfg["stream_kind"]]
            if want_stream and ct != stream_ct:
                out.append(Violation("/", "stream.content-type", f"stream=true request answered with content-type '{ct or '(none)'}'; the spec streams as {stream_ct}"))
            if ct == stream_ct:
                if not want_stream:
                    out.append(Violation("/", "content-type", f"non-stream request answered with a {ct} stream"))
                if cfg["stream_kind"] == "sse":
                    self.judge_sse(dialect, body_bytes, out)
                    return out, f"{status} {ct}: {cfg['stream'].rsplit('/', 1)[-1]} per event", None
                self.judge_eventstream(body_bytes, out)
                return out, f"{status} {ct}: ConverseStreamOutput per frame", None
            if ct != "application/json":
                out.append(Violation("/", "content-type", f"expected application/json, got '{ct or '(none)'}'"))
            inst, err = self.parse_json(body_bytes)
            if err:
                out.append(Violation("/", "body.json", err)); return out, f"{status} {ct}", None
            if want_stream_array and not isinstance(inst, list):
                out.append(Violation("/", "stream-array.shape", "ok_stream_array outcome expects a JSON array of response objects (gemini's non-SSE stream shape), got a single object"))
            # Gemini quirk, not a busbar deviation: a request for a stream WITHOUT `?alt=sse` is
            # served as a JSON ARRAY of GenerateContentResponse objects under application/json (see
            # the Gemini API docs) instead of one object or an SSE stream. So for gemini specifically
            # — and only when the body really is a JSON array under application/json, whatever the
            # outcome label says — judge it element-by-element against the normal response schema
            # instead of the whole-body object schema. Every OTHER dialect keeps the plain
            # whole-body-is-an-object check below, so an array body there still fails as a type
            # violation (array where an object is expected) — that stays a real deviation.
            if dialect == "gemini" and isinstance(inst, list):
                for i, elem in enumerate(inst):
                    ck.check(elem, {"$ref": cfg["response"]}, f"/{i}", out)
                what = f"JSON array of {len(inst)} {cfg['response'].rsplit('/', 1)[-1]} element(s), checked element-by-element (gemini stream without ?alt=sse is a JSON array, not one object or SSE)"
                return out, f"{status} {ct}: {what}", None
            ck.check(inst, {"$ref": cfg["response"]}, "", out)
            return out, f"{status} {ct}: {cfg['response'].rsplit('/', 1)[-1]}", None
        # an error status: the dialect's error contract for that status
        if ct != "application/json":
            out.append(Violation("/", "content-type", f"error responses are application/json in this dialect, got '{ct or '(none)'}'"))
        inst, err = self.parse_json(body_bytes)
        if err:
            out.append(Violation("/", "body.json", err)); return out, f"{status} {ct}", None
        if dialect == "bedrock":
            desc = self.judge_bedrock_error(status, headers, inst, out)
            return out, f"{status} {ct}: {desc}", None
        eck, sch, note = self.error_schema_for(dialect, status)
        if sch is None:
            return out, f"{status} {ct}", f"no error schema for {dialect} {status}"
        eck.check(inst, sch, "", out)
        return out, f"{status} {ct}: {note}", None

    @staticmethod
    def judge_outcome_status(outcome, status, out):
        """The cell's outcome names which side of 2xx the answer had to land on (see OUTCOME_REFUSES).

        An outcome this rig has never been taught is a violation of its own, not a pass: the whole
        point of the check is that a cell cannot be answered with something other than what it was
        asked for, and an unclassified outcome is a cell nothing is asserted about. Adding a cell
        kind therefore has to say, once, which side it belongs on.
        """
        if outcome in OUTCOME_STATUS_EXEMPT:
            return
        ok = 200 <= status < 300
        if outcome.startswith("ok"):
            if not ok:
                out.append(Violation("/", "outcome.status", f"a '{outcome}' cell — an authenticated, in-scope, in-budget request against a healthy upstream — was answered {status}"))
        elif outcome in OUTCOME_REFUSES:
            if ok:
                out.append(Violation("/", "outcome.status", f"a '{outcome}' cell — the request this cell exists to see REFUSED — was answered {status}"))
        else:
            out.append(Violation("/", "outcome.status", f"outcome '{outcome}' is not classified as a success or a refusal, so nothing is asserted about the status it was answered with; classify it in OUTCOME_REFUSES / OUTCOME_STATUS_EXEMPT"))

    @staticmethod
    def parse_json(b):
        try:
            return json.loads(b.decode("utf-8")), None
        except (ValueError, UnicodeDecodeError) as e:
            return None, f"body is not JSON: {e}"

    def judge_sse(self, dialect, body_bytes, out):
        cfg = DIALECTS[dialect]
        ck = self.checker(dialect)
        try:
            text = body_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            out.append(Violation("/", "sse.utf8", str(e))); return
        events = parse_sse(text)
        if not events:
            out.append(Violation("/", "sse.empty", "no events in the stream")); return
        sentinel = cfg.get("sentinel")
        for i, ev, data in events:
            p = f"sse[{i}]"
            if sentinel and data == sentinel:
                if i != len(events) - 1:
                    out.append(Violation(p, "sse.sentinel", f"{sentinel} before the end of the stream"))
                continue
            if data == "":
                out.append(Violation(p, "sse.data", f"event '{ev}' carries no data")); continue
            try:
                inst = json.loads(data)
            except ValueError as e:
                out.append(Violation(p, "sse.data", f"data is not JSON ({e}): {short(data)}")); continue
            ck.check(inst, {"$ref": cfg["stream"]}, p + ":", out)
        if sentinel and events[-1][2] != sentinel:
            out.append(Violation(f"sse[{len(events) - 1}]", "sse.sentinel", f"stream did not end with `data: {sentinel}`"))

    def judge_eventstream(self, body_bytes, out):
        doc = self.docs["bedrock"]
        ck = self.checkers["bedrock"]
        members = doc["x-botocore-shapes"]["ConverseStreamOutput"]["members"]
        frames = parse_eventstream(body_bytes)
        if not frames:
            out.append(Violation("/", "eventstream.empty", "no frames in the stream")); return
        for fr in frames:
            p = f"frame[{fr['index']}]"
            if fr.get("error"):
                out.append(Violation(p, "eventstream.frame", fr["error"])); continue
            if not fr["crc_ok"]:
                out.append(Violation(p, "eventstream.crc", "prelude or message CRC does not match"))
            h = fr["headers"]
            mt = h.get(":message-type")
            if mt == "event":
                et = h.get(":event-type")
                if et == "initial-response":
                    continue
                if et not in members:
                    out.append(Violation(p, "eventstream.event-type", f"':event-type' {et!r} is not a member of ConverseStreamOutput {sorted(members)}")); continue
                if h.get(":content-type") not in ("application/json", None):
                    out.append(Violation(p, "eventstream.content-type", f"':content-type' {h.get(':content-type')!r}, expected application/json"))
                inst, err = self.parse_json(fr["payload"])
                if err:
                    out.append(Violation(p, "eventstream.payload", err)); continue
                ck.check(inst, {"$ref": "#/shapes/" + members[et]["shape"]}, f"{p}({et}):", out)
            elif mt == "exception":
                et = h.get(":exception-type")
                if et not in doc["shapes"]:
                    out.append(Violation(p, "eventstream.exception-type", f"':exception-type' {et!r} is not a shape of the service")); continue
                inst, err = self.parse_json(fr["payload"])
                if err:
                    out.append(Violation(p, "eventstream.payload", err)); continue
                ck.check(inst, {"$ref": "#/shapes/" + et}, f"{p}({et}):", out)
            else:
                out.append(Violation(p, "eventstream.message-type", f"':message-type' {mt!r}, expected event or exception"))

    def judge_bedrock_error(self, status, headers, inst, out):
        doc = self.docs["bedrock"]
        ck = self.checkers["bedrock"]
        raw = doc["x-botocore-shapes"]
        hdr = (headers.get("x-amzn-errortype") or "").split(":")[0].strip()
        body_type = ""
        if isinstance(inst, dict):
            body_type = str(inst.get("__type") or inst.get("code") or "").split("#")[-1]
        et = hdr or body_type
        if not et:
            out.append(Violation("/", "error.type", "neither an x-amzn-errortype header nor a __type/code member names the exception"))
            return "unnamed exception"
        if hdr and body_type and hdr != body_type:
            out.append(Violation("/__type", "error.type", f"body names {body_type!r} but x-amzn-errortype says {hdr!r}"))
        if et not in raw or not raw[et].get("exception"):
            out.append(Violation("/", "error.type", f"{et!r} is not an exception shape of bedrock-runtime"))
            return et
        declared = {e["shape"] for op in ("Converse", "ConverseStream") for e in doc["operations"][op].get("errors", [])}
        if et not in declared:
            out.append(Violation("/", "error.declared", f"{et} is not an error Converse/ConverseStream declare: {sorted(declared)}"))
        want = (raw[et].get("error") or {}).get("httpStatusCode")
        if want and want != status:
            out.append(Violation("/", "error.httpStatusCode", f"{et} is defined with HTTP {want}, sent with {status}"))
        ck.check(inst, {"$ref": "#/shapes/" + et}, "", out)
        return et


# ── driver ──────────────────────────────────────────────────────────────────────────────────────
def generalize(pointer):
    return re.sub(r"\[\d+\]", "[N]", re.sub(r"/\d+(?=/|$|:)", "/N", pointer))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--recording")
    ap.add_argument("--out")
    ap.add_argument("--cells", default=os.path.join(ORACLE, "cells.json"))
    ap.add_argument("--digests", default=os.path.join(HERE, "spec-digests.tsv"))
    ap.add_argument("--named-gaps", default=os.path.join(HERE, "named-gaps.json"),
                    help="violations the owner has ruled the vendor's schema wrong about (see the file's own header)")
    ap.add_argument("--spec-cache", default=os.environ.get("BUSBAR_LLM_SPEC_CACHE") or os.path.expanduser("~/.cache/busbar-llm-specs"))
    ap.add_argument("--ledger", default=None, help="ledger path (default <out>/ledger.tsv, or $LEDGER)")
    ap.add_argument("--owed", action="store_true", help="print the owed ids and exit")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    cells = load_cells(args.cells)
    if args.owed:
        for i in owed_ids(cells):
            print(i)
        return 0
    if not args.recording or not args.out:
        ap.error("--recording and --out are required")

    os.makedirs(args.out, exist_ok=True)
    ledger_path = args.ledger or os.environ.get("LEDGER") or os.path.join(args.out, "ledger.tsv")
    if args.quiet:
        sys.stdout = open(os.devnull, "w")
    ledger = Ledger(ledger_path)
    # The gap list is read BEFORE anything is judged, and a malformed entry stops the run rather
    # than being dropped: a gap file that silently loses an entry turns a named gap back into a FAIL,
    # and one that silently KEEPS a malformed entry is the bypass this loader exists to refuse.
    gaps, gap_refusals = NamedGaps.load(args.named_gaps)
    if gap_refusals:
        for r in gap_refusals:
            sys.stderr.write(f"validate: REFUSED named gap — {r}\n")
        sys.stderr.write("validate: the named-gap list is not loadable; nothing was judged\n")
        return 2
    rec = Recording(args.recording)
    files = rec.llm_cell_files()
    if not files:
        # nothing to judge: write NO rows so the verdict reads this as the vacuous run it is
        sys.stderr.write(f"validate: no llm cells under {rec.cells_dir}; ZERO ROWS IS RED\n")
        write_reports(args.out, rec, [], {}, cells_seen=0)
        return 1

    judge = Judge(read_digests(args.digests), args.spec_cache, os.path.join(HERE, "schemas"))
    build, build_why = load_build_request()

    violations = []  # (id, direction, dialect, Violation)
    per_dialect = {}
    known = {f[:-5] for f in files}
    for c in cells:
        cid, safe = c["id"], c["id"].replace("|", "__")
        dialect, outcome = c["ingress_dialect"], c["outcome"]
        pd = per_dialect.setdefault(dialect, dict(cells=0, request=dict(PASS=0, FAIL=0, SKIP=0), response=dict(PASS=0, FAIL=0, SKIP=0)))
        rec_status = rec.ledger.get(cid)
        cell = rec.cell(safe) if safe in known else None
        if cell is None:
            why = f"recorder: {rec_status[0]} {rec_status[1][:120]}" if rec_status else "cell not in the recording"
            for d in ("request", "response"):
                if d == "request" and outcome == "malformed":
                    continue
                ledger.record(f"{cid}#{d}", "SKIP", f"{dialect} {d}: not recorded", f"named gap — {why}")
                pd[d]["SKIP"] += 1
            continue
        pd["cells"] += 1

        # request direction
        if outcome != "malformed":
            body = rec.raw(safe, "request.body")
            src = "raw/request.body"
            rid = f"{cid}#request"
            if body is None and build is None:
                # The recording did not keep the request bytes AND the tool that could rebuild them
                # is absent, so this ROW cannot be judged. It is a FAIL, not a skip and not a crash:
                # a request the gate never saw is not a request it approved, and the row names which
                # of the two halves is missing.
                ledger.record(rid, "FAIL", f"{dialect} request: not recorded and not rebuildable", build_why)
                pd["request"]["FAIL"] += 1
                violations.append((cid, "request", dialect, build_why))
            else:
                if body is None:
                    body = build.request_for(c)["body"].encode("utf-8")
                    src = "build-request.py"
                viols, schema_name = judge.judge_request(dialect, outcome, body)
                viols, covered = gaps.partition(rid, viols)
                if not viols and covered:
                    ledger.record(rid, "SKIP", f"{dialect} request vs {schema_name} ({src})", gap_detail(covered))
                    pd["request"]["SKIP"] += 1
                elif viols:
                    ledger.record(rid, "FAIL", f"{dialect} request vs {schema_name} ({src})", f"{len(viols)} violation(s): " + " | ".join(str(v) for v in viols[:4]))
                    pd["request"]["FAIL"] += 1
                    violations += [(cid, "request", dialect, v) for v in viols]
                else:
                    ledger.record(rid, "PASS", f"{dialect} request vs {schema_name} ({src})", "")
                    pd["request"]["PASS"] += 1

        # response direction
        status = int(cell.get("status") or 0)
        covered = []
        headers = rec.response_headers(safe, cell)
        body, bsrc = rec.response_bytes(safe, cell)
        rid = f"{cid}#response"
        if bsrc.startswith("cell.body.text") and "�" in body.decode("utf-8", "replace") and (headers.get("content-type") or "").startswith("application/vnd.amazon.eventstream"):
            ledger.record(rid, "SKIP", f"{dialect} response {status}: binary event stream", "named gap — the normalized cell does not preserve the eventstream bytes and raw/<cell>/body is absent")
            pd["response"]["SKIP"] += 1
            continue
        viols, desc, skip = judge.judge_response(dialect, outcome, status, headers, body)
        if not skip:
            viols, covered = gaps.partition(rid, viols)
        if skip:
            ledger.record(rid, "SKIP", f"{dialect} response {desc}", f"named gap — {skip}")
            pd["response"]["SKIP"] += 1
        elif not viols and covered:
            ledger.record(rid, "SKIP", f"{dialect} response {desc} ({bsrc})", gap_detail(covered))
            pd["response"]["SKIP"] += 1
        elif viols:
            ledger.record(rid, "FAIL", f"{dialect} response {desc} ({bsrc})", f"{len(viols)} violation(s): " + " | ".join(str(v) for v in viols[:4]))
            pd["response"]["FAIL"] += 1
            violations += [(cid, "response", dialect, v) for v in viols]
        else:
            ledger.record(rid, "PASS", f"{dialect} response {desc} ({bsrc})", "")
            pd["response"]["PASS"] += 1

    # A GAP THAT FORGIVES NOTHING MUST NOT SIT HERE. The file is written out even when empty, so
    # run.sh can tell "checked, none stale" from "never checked"; run.sh refuses on a non-empty one
    # before the verdict, because a stale entry is the shape a real future FAIL would hide behind.
    stale = gaps.stale()
    with open(os.path.join(args.out, "stale-gaps.txt"), "w", encoding="utf-8") as f:
        for gid, row in stale:
            f.write(f"{gid}\t{row}\n")
            print(f"::error title=llm-spec stale named gap::{gid} names {row}, which this run judged and which did not produce its violation — remove the row from testing/llm-conformance/named-gaps.json")
    write_reports(args.out, rec, violations, per_dialect, cells_seen=len(files))
    return 0


def write_reports(out_dir, rec, violations, per_dialect, cells_seen):
    distinct = {}
    for cid, direction, dialect, v in violations:
        key = (dialect, direction, generalize(v.pointer), v.rule)
        e = distinct.setdefault(key, dict(dialect=dialect, direction=direction, pointer=generalize(v.pointer), rule=v.rule, count=0, cells=[], example=str(v)))
        e["count"] += 1
        if cid not in e["cells"]:
            e["cells"].append(cid)
    top = sorted(distinct.values(), key=lambda e: (-e["count"], e["dialect"], e["pointer"]))
    report = {
        "recording": rec.root,
        "binary": rec.meta.get("binary"),
        "version": rec.meta.get("version"),
        "llm_cells_in_recording": cells_seen,
        "per_dialect": per_dialect,
        "distinct_violations": top,
        "violations": [dict(cell=cid, direction=d, dialect=dl, **v.as_dict()) for cid, d, dl, v in violations],
    }
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=1, sort_keys=True)
    lines = [f"# LLM spec conformance — {rec.meta.get('version') or rec.root}", "",
             f"recording: `{rec.root}`  ", f"llm cells in recording: {cells_seen}", "",
             "| dialect | cells | request PASS/FAIL/SKIP | response PASS/FAIL/SKIP |", "|---|---|---|---|"]
    for d in sorted(per_dialect):
        p = per_dialect[d]
        lines.append(f"| {d} | {p['cells']} | {p['request']['PASS']}/{p['request']['FAIL']}/{p['request']['SKIP']} | {p['response']['PASS']}/{p['response']['FAIL']}/{p['response']['SKIP']} |")
    lines += ["", f"## Distinct violations ({len(top)})", ""]
    if not top:
        lines.append("none")
    for e in top:
        lines.append(f"- **{e['dialect']}** {e['direction']} `{e['pointer']}` {e['rule']} ×{e['count']} in {len(e['cells'])} cell(s) — {e['example']}")
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
