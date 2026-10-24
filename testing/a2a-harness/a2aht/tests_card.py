"""Agent card conformance and discovery. Target acts as an A2A server.

Every test below names the defect it catches. If a test's defect line could be
deleted without loss, the test should be deleted instead.
"""

import copy
import json

from .model import (a2a_test, ROLE_SERVER, EVERY_COMMIT, PULL_REQUEST,
                    PRE_RELEASE, NEEDS_FAKE_PEER, Inapplicable)
from . import spec, transport


@a2a_test(
    id="card.served",
    defect="Agent is undiscoverable: no card at the well-known URI, so no "
           "client can ever learn how to talk to it.",
    clause="SPEC 8.1, 8.2, 14.3",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_card_served(ctx):
    resp = ctx.target.fetch_card_response(force=True)
    ctx.assert_must(
        resp is not None and resp.status == 200,
        "no agent card retrievable from %s (status %s)"
        % (ctx.target.card_candidates(),
           resp.status if resp else "no response"),
        "SPEC 8.1: 'A2A Servers MUST make an Agent Card available.'",
    )
    ctx.assert_must(
        resp.json_or_none() is not None,
        "agent card is not valid JSON",
        "SPEC 14.3: the resource 'MUST return an AgentCard object'.",
    )
    # Which of the two readings of SPEC 8.2 answered. Neither is a failure.
    ctx.observe("card_url", getattr(resp, "card_url", None),
                spec.AMBIGUITIES["CARD_AT_INTERFACE_URL"]["summary"])
    ctx.observe("card_content_type", resp.content_type(),
                "SPEC 14.3 registers application/a2a+json but does not "
                "mandate it for the card endpoint.")


@a2a_test(
    id="card.required_fields",
    defect="Card omits a field the proto marks REQUIRED, so a strict client "
           "rejects the agent outright and delegation silently never starts.",
    clause="PROTO AgentCard REQUIRED annotations; SPEC 5.7",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_card_required_fields(ctx):
    card = ctx.target.card()
    missing = [f for f in spec.AGENT_CARD_REQUIRED if f not in card]
    ctx.assert_must(
        not missing,
        "agent card is missing REQUIRED field(s): %s" % ", ".join(missing),
        "SPEC 5.7: 'Fields marked with [(google.api.field_behavior) = "
        "REQUIRED] indicate that the field MUST be present and set in valid "
        "messages.' PROTO AgentCard marks: %s"
        % ", ".join(spec.AGENT_CARD_REQUIRED),
    )
    present_optional = [f for f in spec.AGENT_CARD_OPTIONAL if f in card]
    ctx.observe("optional_fields_present", sorted(present_optional))


@a2a_test(
    id="card.required_arrays_nonempty",
    defect="Card declares zero skills or zero input modes, so a client that "
           "selects agents by capability can never route work to it.",
    clause="SPEC 5.7 (see AMBIGUITIES.EMPTY_REQUIRED_ARRAYS)",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_required_arrays(ctx):
    card = ctx.target.card()
    # NOT an assertion. SPEC 5.7 says required arrays MUST be non-empty, but
    # SPEC 8.4.1's own canonicalisation worked example emits "skills": [] and
    # calls it a REQUIRED field that must be included. The spec contradicts
    # itself, so failing here would be a bug in the test.
    empties = [f for f in spec.AGENT_CARD_REQUIRED_NONEMPTY_ARRAYS
               if isinstance(card.get(f), list) and not card[f]]
    ctx.observe("empty_required_arrays", sorted(empties),
                "SPEC 5.7 says non-empty; SPEC 8.4.1 example says [] is fine.")


@a2a_test(
    id="card.interfaces_wellformed",
    defect="An interface entry lacks a url, binding or protocol version, so a "
           "client cannot work out where or how to connect.",
    clause="PROTO AgentInterface REQUIRED annotations",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_card_interfaces(ctx):
    card = ctx.target.card()
    ifaces = card.get("supportedInterfaces")
    ctx.assert_must(
        isinstance(ifaces, list) and ifaces,
        "supportedInterfaces is absent or empty; there is no way to reach "
        "this agent",
        "PROTO AgentCard.supported_interfaces is REQUIRED.",
    )
    for i, iface in enumerate(ifaces):
        missing = [f for f in spec.AGENT_INTERFACE_REQUIRED if not iface.get(f)]
        ctx.assert_must(
            not missing,
            "supportedInterfaces[%d] missing REQUIRED %s" % (i, missing),
            "PROTO AgentInterface: url, protocol_binding and "
            "protocol_version are all REQUIRED.",
        )
    ctx.observe("bindings", [i.get("protocolBinding") for i in ifaces])
    ctx.observe("protocol_versions",
                sorted({i.get("protocolVersion") for i in ifaces}))
    # protocol_binding is explicitly "an open form string" in the proto, so an
    # unrecognised value is legal and is observed, not failed.
    unknown = [i.get("protocolBinding") for i in ifaces
               if i.get("protocolBinding") not in spec.CORE_PROTOCOL_BINDINGS]
    ctx.observe("non_core_bindings", unknown,
                "PROTO AgentInterface.protocol_binding: 'This is an open form "
                "string, to be easily extended for other protocol bindings.'")


@a2a_test(
    id="card.every_declared_binding_is_exercised",
    defect="The subject serves a protocol binding this battery cannot drive, "
           "so the suite goes green having never touched the transport that "
           "actually ships. A battery that cannot exercise the shipped "
           "transport is worse than no battery, because it looks like proof.",
    clause="SPEC 5.1 Functional Equivalence Requirements. This test is the "
           "harness refusing to overclaim, not a conformance requirement on "
           "the target.",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_all_bindings_driven(ctx):
    declared = [i.get("protocolBinding") for i in ctx.target.interfaces()]
    drivable = {"JSONRPC", "HTTP+JSON"}
    undrivable = sorted({b for b in declared if b not in drivable})
    ctx.observe("declared_bindings", sorted(set(declared)))
    ctx.observe("bindings_this_harness_can_drive", sorted(drivable))
    ctx.observe("bindings_not_exercised", undrivable)

    allow = str(ctx.config.get("allow_undriven_bindings", "")).strip()
    allowed = {b.strip() for b in allow.split(",") if b.strip()}
    unaccounted = [b for b in undrivable if b not in allowed]

    ctx.assert_must(
        not unaccounted,
        "the target declares binding(s) %s that this battery CANNOT DRIVE, "
        "so those transports are completely untested while the run would "
        "otherwise look green.\n"
        "SPEC 5.1 requires every binding an agent supports to provide "
        "identical functionality and consistent behaviour, so an untested "
        "binding is untested surface, not a duplicate of a tested one.\n"
        "gRPC in particular is not implemented here: driving it needs "
        "generated stubs from a2a.proto and a protobuf runtime.\n"
        "Either build the driver, or stop advertising the binding, or "
        "acknowledge the gap explicitly with "
        "--allow-undriven-bindings %s, which records it as a known hole "
        "rather than hiding it."
        % (unaccounted, ",".join(unaccounted)),
        "Harness honesty rule: the battery must not report success on "
        "surface it never touched.",
    )
    if allowed & set(undrivable):
        ctx.note(
            "ACKNOWLEDGED GAP: binding(s) %s are declared by the target and "
            "are NOT exercised by this battery. Nothing in this run says "
            "anything about them."
            % sorted(allowed & set(undrivable)))


@a2a_test(
    id="card.protocol_version_no_patch",
    defect="Card advertises a patch-level protocol version, which breaks "
           "version negotiation against clients matching on Major.Minor.",
    clause="SPEC 3.6",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_version_shape(ctx):
    for iface in ctx.target.interfaces():
        pv = str(iface.get("protocolVersion", ""))
        ctx.assert_must(
            pv.count(".") <= 1,
            "interface declares protocolVersion %r, which carries a patch "
            "component" % pv,
            "SPEC 3.6: 'Patch version numbers SHOULD NOT be used in requests, "
            "responses and Agent Cards, and MUST not be considered when "
            "clients and servers negotiate protocol versions.'",
        )


@a2a_test(
    id="card.skills_wellformed",
    defect="A declared skill is missing its id, name, description or tags, so "
           "capability-based agent selection picks the wrong agent.",
    clause="PROTO AgentSkill REQUIRED annotations",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_skills(ctx):
    skills = ctx.target.card().get("skills") or []
    if not skills:
        raise Inapplicable("card declares no skills; nothing to validate")
    for i, skill in enumerate(skills):
        missing = [f for f in spec.AGENT_SKILL_REQUIRED
                   if skill.get(f) in (None, "", [])]
        ctx.assert_must(
            not missing,
            "skills[%d] (%r) missing REQUIRED %s"
            % (i, skill.get("id", "?"), missing),
            "PROTO AgentSkill: id, name, description and tags are REQUIRED.",
        )
    ctx.observe("skill_ids", [s.get("id") for s in skills])


@a2a_test(
    id="card.security_schemes_wellformed",
    defect="A declared security scheme uses an unrecognised discriminator, so "
           "a client cannot work out how to authenticate and delegation fails "
           "with an opaque 401.",
    clause="PROTO SecurityScheme oneof; SPEC 4.5",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_security_schemes(ctx):
    card = ctx.target.card()
    schemes = card.get("securitySchemes")
    if not schemes:
        ctx.observe("security_schemes", None)
        ctx.observe("declares_auth", False)
        raise Inapplicable("card declares no securitySchemes (this is legal; "
                           "the field is not REQUIRED in the proto)")
    ctx.assert_must(
        isinstance(schemes, dict),
        "securitySchemes must be a map of name to SecurityScheme",
        "PROTO AgentCard.security_schemes is map<string, SecurityScheme>.",
    )
    for name, value in schemes.items():
        kinds = [k for k in spec.SECURITY_SCHEME_KINDS if k in (value or {})]
        ctx.assert_must(
            len(kinds) == 1,
            "securitySchemes[%r] does not select exactly one scheme kind "
            "(found %s, expected one of %s)"
            % (name, kinds, list(spec.SECURITY_SCHEME_KINDS)),
            "PROTO SecurityScheme is a oneof, so exactly one variant is set.",
        )
        if kinds[0] == "apiKeySecurityScheme":
            loc = (value[kinds[0]] or {}).get("location")
            ctx.assert_must(
                loc in spec.API_KEY_LOCATIONS,
                "apiKeySecurityScheme location %r is not one of %s"
                % (loc, list(spec.API_KEY_LOCATIONS)),
                "PROTO APIKeySecurityScheme.location: 'Valid values are "
                'query, header, or cookie.\'',
            )
    ctx.observe("security_scheme_kinds",
                sorted({k for v in schemes.values()
                        for k in spec.SECURITY_SCHEME_KINDS if k in (v or {})}))
    # See AMBIGUITIES.CARD_SECURITY_FIELD_NAME.
    ctx.observe("security_requirements_field",
                "securityRequirements" if "securityRequirements" in card
                else ("security" if "security" in card else None))


@a2a_test(
    id="card.stable_between_fetches",
    defect="Card changes between two back-to-back fetches with no deployment "
           "in between, which lets an agent be approved on one card and "
           "operated under another. This is the bait-and-switch surface.",
    clause="NO SPEC CLAUSE. See spec.RECOMMENDATIONS. Reported as a finding, "
           "never as a conformance failure.",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_stability(ctx):
    first = ctx.target.fetch_card_response(force=True).json_or_none()
    second = ctx.target.fetch_card_response(force=True).json_or_none()
    same = json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    ctx.observe("card_stable_across_two_fetches", same)
    if not same:
        ctx.note(
            "ADVISORY, not a conformance failure: the agent card differed "
            "between two immediately consecutive fetches. The spec permits "
            "this. It is nonetheless the exact surface a hostile peer uses to "
            "get one card approved and serve another."
        )
    ctx.observe("version_field", (first or {}).get("version"))


@a2a_test(
    id="card.caching_headers",
    defect="Card endpoint ships no ETag or Cache-Control, so every client "
           "refetches on every call and a changed card is indistinguishable "
           "from a cached one.",
    clause="SPEC 8.6.1 (SHOULD, so observed and never failed)",
    role=ROLE_SERVER, tier=PRE_RELEASE,
)
def test_card_caching(ctx):
    resp = ctx.target.fetch_card_response(force=True)
    ctx.observe("has_etag", "etag" in resp.headers)
    ctx.observe("has_cache_control", "cache-control" in resp.headers)
    ctx.observe("has_last_modified", "last-modified" in resp.headers)
    if "etag" in resp.headers:
        again = transport.request(
            "GET", resp.card_url,
            headers=ctx.target.request_headers(
                {"If-None-Match": resp.headers["etag"]}),
            insecure=ctx.target.insecure)
        ctx.observe("conditional_get_status", again.status,
                    "SPEC 8.6.2 expects clients to use If-None-Match; a "
                    "server that ignores it merely wastes bandwidth.")


@a2a_test(
    id="card.signature_shape",
    defect="A signed card carries a malformed JWS, so signature verification "
           "either crashes the client or, worse, is skipped and the card is "
           "trusted unverified.",
    clause="SPEC 8.4.2; PROTO AgentCardSignature",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_signature_shape(ctx):
    import base64
    card = ctx.target.card()
    sigs = card.get("signatures")
    ctx.observe("card_signed", bool(sigs))
    if not sigs:
        # Signing is MAY (SPEC 8.4), so an unsigned card is fully conformant.
        raise Inapplicable("card is unsigned; SPEC 8.4 makes signing a MAY")
    for i, sig in enumerate(sigs):
        missing = [f for f in spec.CARD_SIGNATURE_REQUIRED if not sig.get(f)]
        ctx.assert_must(
            not missing,
            "signatures[%d] missing REQUIRED %s" % (i, missing),
            "PROTO AgentCardSignature: protected and signature are REQUIRED.",
        )
        raw = sig["protected"]
        padded = raw + "=" * (-len(raw) % 4)
        try:
            header = json.loads(base64.urlsafe_b64decode(padded))
        except Exception as exc:
            ctx.assert_must(
                False,
                "signatures[%d].protected is not base64url-encoded JSON: %s"
                % (i, exc),
                "SPEC 8.4.2: protected is a 'Base64url-encoded JSON object "
                "containing the JWS Protected Header'.",
            )
        missing_hdr = [p for p in spec.JWS_PROTECTED_REQUIRED
                       if p not in header]
        ctx.assert_must(
            not missing_hdr,
            "signatures[%d] protected header missing %s" % (i, missing_hdr),
            "SPEC 8.4.2: 'The protected header MUST include: alg ... kid'.",
        )
        ctx.observe("sig_alg_%d" % i, header.get("alg"))
        ctx.observe("sig_has_jku_%d" % i, "jku" in header)
        ctx.observe("sig_typ_%d" % i, header.get("typ"),
                    "SPEC 8.4.2 says typ SHOULD be JOSE, so this is observed.")


@a2a_test(
    id="card.signature_verifies",
    defect="A card's signature does not actually verify over its RFC 8785 "
           "canonical form, meaning the integrity protection is decorative "
           "and a tampered card would be accepted.",
    clause="SPEC 8.4.1, 8.4.3",
    role=ROLE_SERVER, tier=PRE_RELEASE,
)
def test_card_signature_verifies(ctx):
    from .jcs import canonicalize, verify_jws
    card = ctx.target.card()
    sigs = card.get("signatures")
    if not sigs:
        raise Inapplicable("card is unsigned; SPEC 8.4 makes signing a MAY")
    payload_card = {k: v for k, v in card.items() if k != "signatures"}
    canonical = canonicalize(payload_card)
    ctx.observe("canonical_payload_sha256", _sha(canonical))
    results = []
    for sig in sigs:
        results.append(verify_jws(sig, canonical))
    ctx.observe("signature_verification", results)
    verifiable = [r for r in results if r.get("verified") is not None]
    if not verifiable:
        ctx.note(
            "Signature present but not verifiable by this harness: no public "
            "key was reachable (no jku, and no --jwks given). This is "
            "reported, not passed. SPEC 8.4.3 step 2 requires the client to "
            "retrieve the key by kid/jku."
        )
        return
    ctx.assert_must(
        any(r.get("verified") for r in verifiable),
        "no signature on the agent card verified against its RFC 8785 "
        "canonical form: %s" % results,
        "SPEC 8.4.3: clients verify by canonicalising with RFC 8785 after "
        "excluding the signatures field, then verifying the JWS.",
    )


def _sha(text):
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@a2a_test(
    id="card.unreachable_endpoint_is_legible",
    defect="When the card advertises a URL that does not answer, the failure "
           "surfaces as a hang or a stack trace rather than a legible error, "
           "so an operator cannot tell a down peer from a broken one.",
    clause="NO SPEC CLAUSE for the message; SPEC 8.3.1 requires the URL be "
           "accurate. This test characterises the failure mode.",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_url_reachable(ctx):
    import urllib.parse
    reach = {}
    for iface in ctx.target.interfaces():
        url = iface.get("url") or ""
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            reach[url] = "non-http-scheme"
            continue
        port = parts.port or (443 if parts.scheme == "https" else 80)
        reach[url] = transport.port_open(parts.hostname, port, timeout=3.0)
    ctx.observe("interface_url_reachable", reach)
    # SPEC 8.3.1 says each interface "MUST accurately declare its transport
    # protocol and URL". A URL that refuses connections is not accurate, but
    # it may also just be a private address unreachable from the harness, so
    # this is reported rather than failed.
    if any(v is False for v in reach.values()):
        ctx.note(
            "One or more advertised interface URLs refused a TCP connection "
            "from the harness. SPEC 8.3.1 requires the declared URL be "
            "accurate, but the harness may simply not be on the right "
            "network, so this is a finding for a human, not a failure."
        )


@a2a_test(
    id="card.https_in_production",
    defect="Card advertises a plaintext http:// interface, so A2A traffic "
           "including bearer credentials crosses the network in the clear.",
    clause="PROTO AgentInterface.url: 'Must be a valid absolute HTTPS URL in "
           "production.'",
    role=ROLE_SERVER, tier=PRE_RELEASE,
)
def test_card_https(ctx):
    plaintext = [i.get("url") for i in ctx.target.interfaces()
                 if str(i.get("url", "")).startswith("http://")]
    ctx.observe("plaintext_interface_urls", plaintext)
    # Deliberately not an assertion: the proto says "in production", and a
    # test harness cannot know whether the target is production. Loopback in
    # particular is a normal local test configuration.
    if plaintext:
        ctx.note(
            "Interfaces advertised over plaintext http://: %s. PROTO "
            "AgentInterface.url says HTTPS 'in production'. The harness "
            "cannot tell whether this target is production, so this is a "
            "finding, not a failure." % plaintext
        )


@a2a_test(
    id="card.no_embedded_credentials",
    defect="Card leaks a credential. The card is a public document, so any "
           "token in it is compromised the moment the agent is discoverable.",
    clause="NO SPEC CLAUSE. spec.RECOMMENDATIONS.CARD_NO_CREDENTIALS. This is "
           "MY RECOMMENDATION, not a conformance requirement.",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_card_no_credentials(ctx):
    import re
    blob = json.dumps(ctx.target.card())
    patterns = {
        "bearer_token": r"[Bb]earer\s+[A-Za-z0-9\-\._~\+/]{20,}",
        "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "generic_secret_field": r'"(?:password|secret|apiKey|api_key|token|'
                                r'credentials)"\s*:\s*"[^"]{8,}"',
    }
    hits = sorted(name for name, pat in patterns.items()
                  if re.search(pat, blob))
    # The JWS `signature` and `protected` fields are base64 and can trip the
    # jwt pattern legitimately; exclude a card whose only hit is inside them.
    ctx.observe("credential_patterns_in_card", hits)
    if hits:
        ctx.note(
            "ADVISORY (my recommendation, no spec clause): the agent card "
            "matched credential-shaped patterns %s. Verify by hand." % hits
        )


@a2a_test(
    id="card.malformed_is_rejected_by_our_parser",
    defect="Proves the harness's own card validator actually rejects bad "
           "cards. Without this, every card test could be vacuously green.",
    clause="Self-test of the harness. Catches the harness, not the target.",
    role=ROLE_SERVER, tier=EVERY_COMMIT, needs=NEEDS_FAKE_PEER,
)
def test_validator_self_check(ctx):
    from .validate import validate_agent_card
    good = copy.deepcopy(ctx.target.card())
    ok, problems = validate_agent_card(good)
    ctx.observe("real_card_validation_problems", problems)

    # Now mutate it and require that the validator notices.
    caught = {}
    for field in spec.AGENT_CARD_REQUIRED:
        broken = copy.deepcopy(good)
        broken.pop(field, None)
        ok2, probs = validate_agent_card(broken)
        caught[field] = not ok2
    ctx.assert_must(
        all(caught.values()),
        "the harness's own card validator failed to notice a missing "
        "REQUIRED field: %s"
        % [k for k, v in caught.items() if not v],
        "Self-test. A validator that accepts anything makes every card test "
        "meaningless.",
    )
