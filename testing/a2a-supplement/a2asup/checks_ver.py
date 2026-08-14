# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""VER-*: SPEC 3.6 version negotiation, and GRPC-SVC-003.

VER-SERVER-001 is the interesting one and the reason this file exists. "Process requests using the
semantics of the requested version" sounds untestable until you notice the specification gives the
two live versions DIFFERENT METHOD VOCABULARIES -- 1.0 names its JSON-RPC methods with the
PascalCase rpc names of SPEC 9.1, 0.3 with the slash form -- so the version an agent is actually
applying is observable in which names it answers. An agent that ignores the header and serves one
vocabulary regardless is not processing per the requested version, and that is decidable from
outside with four requests.
"""

from __future__ import annotations

import json
import re
import uuid

from a2asup.model import Result, Verdict, short
from a2asup.spec import REQUIREMENTS
from a2asup.target import Target
from a2asup.transport import METHODS_0_3, METHODS_1_0

VERSION_NOT_SUPPORTED = -32009  # SPEC 5.4
METHOD_NOT_FOUND = -32601  # JSON-RPC 2.0
PATCH_VERSION = re.compile(r"^\d+\.\d+\.\d+")


def _probe_message(marker: str) -> dict:
    return {
        "message": {
            "role": "ROLE_USER",
            "parts": [{"text": f"a2a-supplement version probe {marker}"}],
            "messageId": f"a2asup-ver-{marker}-{uuid.uuid4().hex[:12]}",
        }
    }


def check_ver_server_001(target: Target) -> Result:
    """SPEC 3.6.2: 'Agents MUST process requests using the semantics of the requested A2A-Version
    (matching Major.Minor). ... Agents MUST interpret empty value as 0.3 version.'"""
    req = REQUIREMENTS["VER-SERVER-001"]
    evidence: list[str] = []
    bindings = target.bindings()
    binding = bindings.get("jsonrpc")
    if binding is None:
        return Result(
            req.id,
            Verdict.NOT_APPLICABLE,
            "the observable difference between 0.3 and 1.0 semantics used here is the JSON-RPC "
            "method vocabulary (SPEC 9.1 vs the 0.3 slash form), and this card declares no "
            "JSON-RPC interface. Reported rather than asserted.",
            [f"declared bindings = {sorted(bindings)}"],
        )

    declared = target.versions_declared()
    evidence.append(f"card declares interface protocolVersion(s) = {declared}")
    failures: list[str] = []

    # 1. Every version the card DECLARES must be accepted when it is requested. An agent that
    #    advertises a version and then refuses it is not processing per the requested version.
    for version in declared or ["1.0"]:
        vocab = METHODS_1_0 if version.split(".")[0] != "0" else METHODS_0_3
        reply = binding.call(
            "send_message",
            _probe_message("declared"),
            token=target.token,
            version=version,
            method_override=vocab["send_message"],
        )
        evidence.append(f"A2A-Version: {version} + {vocab['send_message']} -> {reply!r}")
        if reply.code == VERSION_NOT_SUPPORTED:
            failures.append(
                f"the card declares protocolVersion {version} but a request carrying "
                f"A2A-Version: {version} was answered VersionNotSupportedError"
            )
        elif reply.code == METHOD_NOT_FOUND:
            failures.append(
                f"A2A-Version: {version} was accepted but the method name that version defines "
                f"({vocab['send_message']!r}) was answered MethodNotFound, so the agent is not "
                f"applying that version's vocabulary"
            )

    # 2. An ABSENT A2A-Version must be answered as 0.3 (SPEC 3.6.2, last sentence), whose name for
    #    Send Message is the slash form.
    absent_0_3 = binding.call(
        "send_message",
        _probe_message("absent03"),
        token=target.token,
        version=None,
        method_override=METHODS_0_3["send_message"],
    )
    evidence.append(f"no A2A-Version + {METHODS_0_3['send_message']!r} -> {absent_0_3!r}")
    if absent_0_3.code in {METHOD_NOT_FOUND, VERSION_NOT_SUPPORTED}:
        failures.append(
            f"with no A2A-Version header the agent must apply 0.3 semantics, but 0.3's own method "
            f"name {METHODS_0_3['send_message']!r} was answered {absent_0_3.code!r}"
        )

    # 3. The EMPTY value, which SPEC 3.6.2 names explicitly and separately from the absent one.
    empty_0_3 = binding.call(
        "send_message",
        _probe_message("empty03"),
        token=target.token,
        version="",
        method_override=METHODS_0_3["send_message"],
    )
    evidence.append(f"A2A-Version: '' + {METHODS_0_3['send_message']!r} -> {empty_0_3!r}")
    if empty_0_3.code in {METHOD_NOT_FOUND, VERSION_NOT_SUPPORTED}:
        failures.append(
            f"an EMPTY A2A-Version must be interpreted as 0.3, but 0.3's own method name was "
            f"answered {empty_0_3.code!r}"
        )

    # 4. THE DISCRIMINATOR. Without this the three probes above are also passed by an agent that
    #    ignores the header entirely and answers every method name it has ever heard of. Requesting
    #    1.0 and then using 0.3's vocabulary must NOT be processed as 0.3.
    crossed = binding.call(
        "send_message",
        _probe_message("crossed"),
        token=target.token,
        version="1.0",
        method_override=METHODS_0_3["send_message"],
    )
    evidence.append(
        f"A2A-Version: 1.0 + 0.3's name {METHODS_0_3['send_message']!r} -> {crossed!r} "
        f"(the discriminator: an agent applying 1.0 semantics does not have this name)"
    )
    ignores_version = crossed.ok

    if failures:
        return Result(req.id, Verdict.FAIL, "; ".join(failures), evidence)
    if ignores_version:
        return Result(
            req.id,
            Verdict.FAIL,
            "every version the card declares is accepted, and an absent or empty header is "
            f"answered as 0.3 -- but a request explicitly declaring A2A-Version: 1.0 was ALSO "
            f"answered on 0.3's method name {METHODS_0_3['send_message']!r}. The agent is "
            "answering both vocabularies regardless of the header, which is not processing "
            "requests using the semantics of the REQUESTED version; it is ignoring the request.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"every declared version {declared} is accepted under its own method vocabulary, an "
        f"absent and an empty A2A-Version are both answered as 0.3, and a request declaring 1.0 "
        f"is NOT answered on 0.3's method name -- so the vocabulary tracks the requested version "
        f"rather than being served unconditionally.",
        evidence,
    )


def check_ver_client_002(target: Target) -> Result:
    """SPEC 3.6: 'Patch version numbers ... MUST not be considered when clients and servers
    negotiate protocol versions.'"""
    req = REQUIREMENTS["VER-CLIENT-002"]
    evidence: list[str] = []
    bindings = target.bindings()
    binding = bindings.get("jsonrpc") or next(iter(bindings.values()), None)
    if binding is None:
        return Result(req.id, Verdict.FAIL, "the card declares no drivable binding.", evidence)

    declared = target.versions_declared() or ["1.0"]
    base = declared[0].split(".")
    major_minor = ".".join(base[:2]) if len(base) >= 2 else "1.0"
    with_patch = f"{major_minor}.7"

    plain = binding.call(
        "send_message", _probe_message("nopatch"), token=target.token, version=major_minor
    )
    patched = binding.call(
        "send_message", _probe_message("patch"), token=target.token, version=with_patch
    )
    evidence.append(f"A2A-Version: {major_minor} -> {plain!r}")
    evidence.append(f"A2A-Version: {with_patch} -> {patched!r}")

    if patched.code == VERSION_NOT_SUPPORTED:
        return Result(
            req.id,
            Verdict.FAIL,
            f"A2A-Version: {with_patch} was answered VersionNotSupportedError while "
            f"A2A-Version: {major_minor} was accepted. The patch component was considered in "
            f"negotiation, which SPEC 3.6 forbids in as many words.",
            evidence,
        )
    if plain.ok != patched.ok:
        return Result(
            req.id,
            Verdict.FAIL,
            f"the same request is answered differently with and without a patch component "
            f"({major_minor} ok={plain.ok}, {with_patch} ok={patched.ok}), so the patch component "
            f"changed the outcome.",
            evidence,
        )

    # The SHOULD half, reported separately and never folded into the MUST verdict.
    patchy = [i.version for i in target.interfaces if PATCH_VERSION.match(i.version or "")]
    if patchy:
        evidence.append(
            f"SHOULD (reported, not part of the MUST verdict): the card publishes patch-numbered "
            f"protocolVersion values {patchy}; SPEC 3.6 says patch numbers SHOULD NOT be used in "
            f"Agent Cards."
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"A2A-Version: {with_patch} is processed exactly as {major_minor} is -- the patch "
        f"component was not considered."
        + (f" (SHOULD note: card publishes patch-numbered versions {patchy}.)" if patchy else ""),
        evidence,
    )


def check_ver_client_001(target: Target) -> Result:
    """SPEC 3.6.1: 'Clients MUST send the A2A-Version header with each request'.

    A requirement on the CLIENT role, decided by observing the requests the subject ORIGINATES.
    """
    req = REQUIREMENTS["VER-CLIENT-001"]
    if not target.upstream_record:
        return Result(
            req.id,
            Verdict.NOT_APPLICABLE,
            "this target was not run with an upstream recorder, so no request that the subject "
            "ORIGINATED was observed. This requirement is about the client role and cannot be "
            "decided from the server-facing side of a connection; reported rather than assumed.",
            [],
        )
    try:
        with open(target.upstream_record, encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        return Result(
            req.id,
            Verdict.FAIL,
            f"an upstream recorder was configured at {target.upstream_record} but wrote no file, "
            f"so the check could not observe the requests it exists to observe. That is a failure "
            f"of the run, reported loudly rather than skipped.",
            [],
        )

    evidence = [f"{len(records)} upstream request(s) recorded at {target.upstream_record}"]
    # The card fetch is EXCLUDED: SPEC 8.2 makes agent card discovery a plain HTTPS GET of a
    # well-known document rather than an A2A protocol operation, and SPEC 3.6.1's sentence is about
    # A2A requests. Including it would fail every implementation for a request the requirement does
    # not reach.
    protocol = [
        r
        for r in records
        if not str(r.get("path", "")).startswith("/.well-known/")
        and str(r.get("method", "")).upper() != "OPTIONS"
    ]
    evidence.append(f"{len(protocol)} of them are A2A protocol requests (card fetches excluded)")
    if not protocol:
        return Result(
            req.id,
            Verdict.FAIL,
            "the recorder saw no A2A protocol request originated by the subject at all, so the "
            "client role was never exercised and this run establishes nothing about it. Reported "
            "as a failure of the run rather than as a pass.",
            evidence
            + [f"paths seen = {short(sorted({r.get('path') for r in records}))}"],
        )

    missing: list[str] = []
    for record in protocol:
        headers = {str(k).lower(): v for k, v in (record.get("headers") or {}).items()}
        query = record.get("query") or {}
        has_header = "a2a-version" in headers
        # SPEC 3.6.1 explicitly permits the version as a request PARAMETER instead of a header.
        has_param = any(str(k).lower() == "a2a-version" for k in query)
        if not (has_header or has_param):
            missing.append(f"{record.get('method')} {record.get('path')}")
    evidence.append(f"sample header set = {short(sorted((protocol[0].get('headers') or {})))}")

    if missing:
        return Result(
            req.id,
            Verdict.FAIL,
            f"{len(missing)} of {len(protocol)} requests the subject originated upstream carried "
            f"neither an A2A-Version header nor an A2A-Version parameter: "
            f"{short(missing[:8])}",
            evidence,
        )
    versions = sorted(
        {
            str(
                {str(k).lower(): v for k, v in (r.get("headers") or {}).items()}.get(
                    "a2a-version", ""
                )
            )
            for r in protocol
        }
    )
    return Result(
        req.id,
        Verdict.PASS,
        f"all {len(protocol)} A2A protocol requests the subject originated upstream carried "
        f"A2A-Version (values seen: {versions}).",
        evidence,
    )


def check_grpc_svc_003(target: Target) -> Result:
    """SPEC 10.1: 'Protocol: gRPC over HTTP/2 with TLS'."""
    req = REQUIREMENTS["GRPC-SVC-003"]
    bindings = target.bindings()
    if "grpc" not in bindings:
        return Result(
            req.id,
            Verdict.NOT_APPLICABLE,
            f"the card declares no gRPC interface ({sorted(bindings)}), so the gRPC binding's "
            f"transport requirement does not apply to this target.",
            [],
        )
    evidence: list[str] = []
    binding = bindings["grpc"]
    # THE HTTP/2 CONJUNCT. gRPC is defined over HTTP/2 and nothing else, so a successful gRPC call
    # IS the observation: the channel completed an HTTP/2 connection preface and framed a
    # request-response exchange. A server answering HTTP/1.1 cannot produce this.
    reply = binding.call("get_task", {"id": f"a2asup-{uuid.uuid4().hex[:8]}"}, token=target.token)
    evidence.append(f"gRPC GetTask over the declared authority -> {reply!r}")
    http2 = reply.ok or reply.code in {
        "NOT_FOUND",
        "UNAUTHENTICATED",
        "PERMISSION_DENIED",
        "INVALID_ARGUMENT",
        "UNIMPLEMENTED",
    }
    if not http2:
        return Result(
            req.id,
            Verdict.FAIL,
            f"no gRPC exchange completed against the authority the card publishes for its gRPC "
            f"interface, so the HTTP/2 conjunct is not met: {reply!r}",
            evidence,
        )
    scheme = target.card_url.split("://", 1)[0]
    evidence.append(f"the endpoint this run was pointed at is {scheme}://")
    return Result(
        req.id,
        Verdict.PARTIAL,
        "HTTP/2 IS established: a gRPC request-response exchange completed against the authority "
        "the card publishes, which is only possible over HTTP/2. TLS is NOT established and "
        "cannot be by this instrument -- it is the same deployment property as AUTH-TLS-001, the "
        f"rig is `{scheme}://` loopback by construction, and the official TCK's own source carries "
        "the comment 'Not tested: TLS is a production deployment concern' against this very "
        "requirement. Reported PARTIAL, never counted as a pass.",
        evidence,
    )
