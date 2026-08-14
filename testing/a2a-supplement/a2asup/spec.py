# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""The requirements this supplement covers, and the SPECIFICATION SENTENCE each one encodes.

EVERY entry here is transcribed from `specification/specification.md` at the commit the official
TCK pins (`5996b79f9cefa6fc390980e383e358a66fb9e49e`). Nothing here was derived by reading busbar.
That is the whole discipline of this directory: a test written from an implementation asserts what
the implementation does, which is a mirror, and a mirror produces a number that means nothing.

WHERE THE SPECIFICATION IS AMBIGUOUS the `reading` field states the interpretation this suite
encodes AND the reason for it, out loud, so a reader who disagrees can see exactly what was decided
rather than having to reverse-engineer it out of an assertion.

`level` is the requirement level the TCK's own registry assigns, restated here so the two
instruments cannot drift about which requirements are MUSTs.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Requirement:
    id: str
    level: str
    section: str
    sentence: str
    """VERBATIM normative text from specification.md. Quoted, not paraphrased."""
    reading: str = ""
    """The interpretation encoded, stated only where the sentence admits more than one."""
    limits: str = ""
    """What this suite's check does NOT establish. An honest boundary beats a silent one."""
    tags: tuple[str, ...] = field(default_factory=tuple)


REQUIREMENTS: dict[str, Requirement] = {
    r.id: r
    for r in [
        # ── Section 7: authentication and authorization ────────────────────────────────────────
        Requirement(
            id="AUTH-TLS-001",
            level="MUST",
            section="7.1",
            sentence=(
                "Production deployments **MUST** use encrypted communication (HTTPS for "
                "HTTP-based bindings, TLS for gRPC)."
            ),
            reading=(
                "The subject of this sentence is a DEPLOYMENT, not a build. It is not a property "
                "any request-response probe can establish about a binary, and a loopback "
                "conformance rig is plaintext by construction -- both this suite's and the "
                "official TCK's. Reported UNTESTABLE with the mechanism rather than asserted."
            ),
            tags=("auth", "tls"),
        ),
        Requirement(
            id="AUTH-SERVER-002",
            level="MUST",
            section="7.4",
            sentence=(
                "The A2A Server: - **MUST** authenticate every incoming request based on the "
                "provided credentials and its declared authentication requirements."
            ),
            reading=(
                "Two readings exist and they diverge on an agent that declares NO security "
                "scheme. Under the weak reading the requirement is vacuous for such an agent -- "
                "it has no declared requirements, so it authenticates nothing and is compliant. "
                "Under the strong reading authentication must actually occur. THIS SUITE ENCODES "
                "THE STRONG READING, because the weak one makes a MUST that no implementation can "
                "fail, and a requirement that cannot be failed is not a requirement. An agent "
                "declaring no scheme is reported FAIL with that reason named. Independently of "
                "the reading, a FORGED or MALFORMED credential must not be admitted where a "
                "scheme IS declared; that half is unambiguous and is asserted separately."
            ),
            tags=("auth", "server"),
        ),
        Requirement(
            id="AUTH-INTASK-001",
            level="MUST",
            section="7.6.1",
            sentence=(
                "To request that a client fulfills an authorization request, the agent: 1. MUST "
                "use a Task to track the operation it is performing"
            ),
            reading=(
                "Observable as: when the agent needs authorization it answers with a Task object "
                "carrying an id, not with a bare Message. Driven by an upstream agent that parks "
                "a task in auth_required, so what is measured is whether the A2A server under "
                "test preserves that fact end to end."
            ),
            tags=("auth", "in-task"),
        ),
        Requirement(
            id="AUTH-INTASK-002",
            level="MUST",
            section="7.6.1",
            sentence=(
                "To request that a client fulfills an authorization request, the agent: 2. MUST "
                "transition the TaskState to `TASK_STATE_AUTH_REQUIRED`"
            ),
            tags=("auth", "in-task"),
        ),
        Requirement(
            id="AUTH-INTASK-003",
            level="MUST",
            section="7.6.1",
            sentence=(
                "To request that a client fulfills an authorization request, the agent: 3. MUST "
                "include a TaskStatus message explaining the required authorization, unless the "
                "details of the authorization have been negotiated out-of-band or via an extension"
            ),
            reading=(
                "The `unless` clause is an escape only for a party that HAS negotiated out of "
                "band. This suite negotiates nothing, so the clause does not apply to it and the "
                "message must be present."
            ),
            tags=("auth", "in-task"),
        ),
        Requirement(
            id="AUTH-INTASK-004",
            level="MUST",
            section="7.6.1",
            sentence=(
                "Agents MUST arrange to receive credentials via an out-of-band means, unless an "
                "in-band mechanism has been negotiated out-of-band or via an extension."
            ),
            reading=(
                "This is a requirement about a channel that is by definition NOT the A2A "
                "connection. An external observer of the A2A wire can see that credentials did "
                "not arrive in band, but 'did not arrive in band' is also what a broken agent "
                "looks like -- absence of evidence on the only channel visible. Reported "
                "UNTESTABLE with the mechanism."
            ),
            tags=("auth", "in-task"),
        ),
        Requirement(
            id="AUTH-SCOPE-001",
            level="MUST",
            section="13.1",
            sentence=(
                "Servers **MUST** implement authorization checks on every [A2A Protocol "
                "Operations](#3-a2a-protocol-operations) request"
            ),
            reading=(
                "'Every' is taken at face value: the check is applied per OPERATION, across every "
                "operation the agent's card says it implements, and an operation that answers a "
                "credential-less or forged-credential call with a success is a failure of this "
                "requirement whatever the other operations do."
            ),
            tags=("auth", "scope"),
        ),
        Requirement(
            id="AUTH-SCOPE-002",
            level="MUST",
            section="13.1",
            sentence=(
                "Implementations **MUST** scope results to the caller's authorized access "
                "boundaries as defined by the agent's authorization model ... Even when "
                "`contextId` or other filter parameters are not specified in requests, "
                "implementations **MUST** scope results to the caller's authorized access "
                "boundaries ... [`List Tasks`](#314-list-tasks): **MUST** only return tasks "
                "visible to the authenticated client according to the agent's authorization model"
            ),
            reading=(
                "The authorization model is agent-defined, so this suite cannot assert WHICH "
                "boundary applies. It asserts the one consequence that holds under every "
                "authorization model in the specification's own list (user, role, project, "
                "tenant): two DISTINCT authenticated principals, neither of which the operator "
                "placed in a shared group, must not see each other's tasks in an unfiltered List "
                "Tasks. If an implementation deliberately puts all principals in one boundary it "
                "may declare that; there is no protocol surface on which to declare it, which is "
                "itself worth reporting."
            ),
            limits=(
                "Does not establish that the boundary is the RIGHT one, only that a boundary "
                "exists and separates two principals."
            ),
            tags=("auth", "scope"),
        ),
        Requirement(
            id="AUTH-SCOPE-003",
            level="MUST",
            section="3.3.2",
            sentence=(
                "Servers **MUST NOT** reveal the existence of resources the client is not "
                "authorized to access"
            ),
            reading=(
                "The observable consequence is INDISTINGUISHABILITY: a Get Task for a task that "
                "exists but belongs to another principal must be answered identically to a Get "
                "Task for an id that does not exist at all. A `403`/PERMISSION_DENIED where a "
                "`404`/TaskNotFoundError is given for the absent id reveals the existence of the "
                "resource and fails, and so does any difference in error code or message shape."
            ),
            tags=("auth", "scope", "security"),
        ),
        # ── Section 5.1: functional equivalence across bindings ────────────────────────────────
        Requirement(
            id="BIND-EQUIV-001",
            level="MUST",
            section="5.1",
            sentence=(
                "When an agent supports multiple protocols, all supported protocols **MUST**: - "
                "**Identical Functionality**: Provide the same set of operations and capabilities"
            ),
            reading=(
                "Operationally: for each of the eleven operations in the section 5.3 method "
                "mapping table, an agent either implements it or answers "
                "UnsupportedOperationError. The SET of implemented operations must be identical "
                "across every binding the card declares. Answering `not implemented` on one "
                "binding and succeeding on another is the failure."
            ),
            tags=("interop", "equivalence"),
        ),
        Requirement(
            id="BIND-EQUIV-002",
            level="MUST",
            section="5.1",
            sentence=(
                "When an agent supports multiple protocols, all supported protocols **MUST**: - "
                "**Consistent Behavior**: Return semantically equivalent results for the same "
                "requests"
            ),
            reading=(
                "'Semantically equivalent', not byte-identical: server-assigned identifiers and "
                "timestamps necessarily differ between two calls and are normalised out. What "
                "must match is the STRUCTURE and the semantic content -- the same shape, the same "
                "task state, the same role, the same part kinds, the same text."
            ),
            tags=("interop", "equivalence"),
        ),
        Requirement(
            id="BIND-EQUIV-003",
            level="MUST",
            section="5.1",
            sentence=(
                "When an agent supports multiple protocols, all supported protocols **MUST**: - "
                "**Same Error Handling**: Map errors consistently using appropriate "
                "protocol-specific codes"
            ),
            reading=(
                "The specification supplies the canonical mapping table itself (section 5.4), so "
                "'consistently' is not left to interpretation: one provoked error condition, "
                "driven on every declared binding, must produce the row of that table -- e.g. "
                "TaskNotFoundError as JSON-RPC `-32001`, gRPC `NOT_FOUND`, HTTP `404`."
            ),
            tags=("interop", "equivalence", "error"),
        ),
        Requirement(
            id="BIND-EQUIV-004",
            level="MUST",
            section="5.1",
            sentence=(
                "When an agent supports multiple protocols, all supported protocols **MUST**: - "
                "**Equivalent Authentication**: Support the same authentication schemes declared "
                "in the AgentCard"
            ),
            reading=(
                "Two observable consequences. (a) The card declares security schemes once, for "
                "the agent, not per interface -- so a per-interface divergence in the declaration "
                "is a failure on its face. (b) The declared scheme must actually be enforced on "
                "every binding: a credential that is refused on one binding and admitted on "
                "another means the bindings do not support the same scheme, whatever the card "
                "says."
            ),
            tags=("interop", "equivalence", "auth"),
        ),
        # ── Section 8.4: agent card signing ────────────────────────────────────────────────────
        Requirement(
            id="CARD-SIGN-001",
            level="MUST",
            section="8.4.1",
            sentence=(
                "Before signing, the Agent Card content **MUST** be canonicalized using the JSON "
                "Canonicalization Scheme (JCS) as defined in [RFC "
                "8785](https://tools.ietf.org/html/rfc8785)."
            ),
            reading=(
                "The TCK marks this NOT_AUTOMATABLE. It is in fact decidable from outside, "
                "because a signature is a proof of which bytes were signed: independently "
                "canonicalise the served card with RFC 8785 and verify the published signature "
                "over exactly those bytes. If it verifies, JCS is what the signer used -- any "
                "other serialisation would produce different bytes and the verification would "
                "fail. The check is only meaningful because the verifier here is an INDEPENDENT "
                "JCS implementation, so this suite ships its own rather than calling the "
                "subject's."
            ),
            limits=(
                "Establishes JCS was used, not that every RFC 8785 corner case (surrogate pairs, "
                "number formatting extremes) is handled -- the served card must contain such a "
                "value for the check to reach it."
            ),
            tags=("card", "signing", "jcs"),
        ),
        Requirement(
            id="CARD-SIGN-002",
            level="MUST",
            section="8.4.1",
            sentence=(
                "**Signature Field Exclusion**: The `signatures` field itself **MUST** be "
                "excluded from the content being signed to avoid circular dependencies."
            ),
            reading=(
                "Decided by a matched pair, not by one verification: the signature MUST verify "
                "over the card with `signatures` removed, and MUST NOT verify over the card with "
                "`signatures` retained. The negative half is what makes the positive half "
                "evidence of exclusion rather than of coincidence."
            ),
            tags=("card", "signing"),
        ),
        Requirement(
            id="CARD-SIGN-003",
            level="MUST",
            section="8.4.2",
            sentence=(
                "The protected header **MUST** include: - `alg`: Algorithm used for signing (e.g. "
                '"ES256", "RS256") - `typ`: **SHOULD** be set to "JOSE" for JWS - `kid`: Key ID '
                "for identifying the signing key"
            ),
            reading=(
                "`alg` and `kid` are MUST; `typ` is SHOULD in the same bullet list and is "
                "reported separately rather than folded into the MUST verdict. `protected` is "
                "base64url of a JSON object per section 4.4.7, so a `protected` that does not "
                "base64url-decode to a JSON object fails before the members are looked at."
            ),
            tags=("card", "signing", "jws"),
        ),
        Requirement(
            id="CARD-SIGN-004",
            level="MUST",
            section="8.4.3",
            sentence="Expired or revoked keys **MUST NOT** be used for verification",
            reading=(
                "This is a requirement on the VERIFYING party, so it is only testable against a "
                "subject that verifies cards -- i.e. an A2A client or a gateway that fetches "
                "upstream cards. The operational meaning of 'revoked' that is reachable over the "
                "wire is: a key the verifier has not been given, or has been told not to trust. "
                "The check presents a card signed by a key OTHER than the one the operator pinned "
                "and requires refusal. True temporal expiry needs an X.509 or JWKS validity "
                "window, which a bare `AgentCardSignature` does not carry."
            ),
            limits="Covers untrusted-key refusal. Does NOT cover notAfter-style temporal expiry.",
            tags=("card", "signing", "security"),
        ),
        # ── Section 3.6: versioning ────────────────────────────────────────────────────────────
        Requirement(
            id="VER-CLIENT-001",
            level="MUST",
            section="3.6.1",
            sentence=(
                "Clients MUST send the `A2A-Version` header with each request to maintain "
                "compatibility after an agent upgrades to a new version of the protocol (except "
                "for 0.3 Clients - 0.3 will be assumed for empty header)."
            ),
            reading=(
                "A requirement on the CLIENT role. A gateway that fronts an upstream agent is an "
                "A2A client on its upstream leg, and that leg is observable: an intermediary "
                "between the subject and its upstream records the headers of every request the "
                "subject originates. The specification also permits the version as a request "
                "PARAMETER instead of a header, so the check accepts either."
            ),
            tags=("versioning", "client"),
        ),
        Requirement(
            id="VER-CLIENT-002",
            level="MUST",
            section="3.6",
            sentence=(
                "Patch version numbers used by the specification, do not affect protocol "
                "compatibility. Patch version numbers SHOULD NOT be used in requests, responses "
                "and Agent Cards, and MUST not be considered when clients and servers negotiate "
                "protocol versions."
            ),
            reading=(
                "The MUST half is 'MUST not be considered ... when negotiating'. Observable as: a "
                "request carrying `A2A-Version: <M>.<m>.<patch>` for a supported `<M>.<m>` must be "
                "processed exactly as `<M>.<m>` would be, and in particular must NOT be answered "
                "with VersionNotSupportedError. The SHOULD half -- no patch numbers in Agent "
                "Cards -- is checked and reported separately, not folded into the MUST verdict."
            ),
            tags=("versioning",),
        ),
        Requirement(
            id="VER-SERVER-001",
            level="MUST",
            section="3.6.2",
            sentence=(
                "Agents MUST process requests using the semantics of the requested `A2A-Version` "
                "(matching `Major.Minor`). ... Agents MUST interpret empty value as 0.3 version."
            ),
            reading=(
                "'Processed using the semantics of the requested version' is observable because "
                "the versions differ observably: 1.0 names its JSON-RPC methods with the "
                "PascalCase rpc names of section 9.1 (`SendMessage`), while 0.3 names them with "
                "the slash form (`message/send`). So: every version the card declares must be "
                "accepted when requested and answered with that version's method vocabulary, and "
                "a request with an absent or empty `A2A-Version` must be answered as 0.3. An "
                "agent that ignores the header and serves one vocabulary regardless is not "
                "processing per the requested version."
            ),
            tags=("versioning", "server"),
        ),
        # ── Section 10.1: gRPC binding ─────────────────────────────────────────────────────────
        Requirement(
            id="GRPC-SVC-003",
            level="MUST",
            section="10.1",
            sentence="- **Protocol:** gRPC over HTTP/2 with TLS",
            reading=(
                "Two conjuncts with different testability. HTTP/2 is a wire fact any client can "
                "observe and IS asserted. TLS is the same deployment property as AUTH-TLS-001 and "
                "is not establishable against a loopback rig -- the official TCK's own comment on "
                "this requirement reads 'Not tested: TLS is a production deployment concern'. The "
                "verdict is therefore reported as PARTIAL with both halves named, never as a PASS."
            ),
            tags=("grpc", "transport", "tls"),
        ),
    ]
}

MUST_IDS = tuple(r.id for r in REQUIREMENTS.values() if r.level == "MUST")
