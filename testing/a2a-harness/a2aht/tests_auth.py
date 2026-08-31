"""Authentication and agent identity, from the client side.

Why this module exists as a separate file: NEITHER PUBLIC CONTROL DECLARES A
SINGLE SECURITY SCHEME. a2a-go's echo agent and a2a-python's hello-world agent
both serve cards with no `securitySchemes` at all, so every auth-related test
against them reports INAPPLICABLE and proves nothing. The entire authentication
surface of A2A has no third-party coverage anywhere I could find, including in
the official TCK and ITK.

The only way an outside tester can exercise it is to BE the authenticating
peer. So the harness stands up a fake agent that declares a security scheme
and actually enforces it, and watches what the target does.

These tests are about the target's CLIENT role: does it read the card's
security requirements, does it present credentials, and does it stop when it
cannot authenticate rather than proceeding blind.
"""

from .model import (a2a_test, ROLE_CLIENT, ROLE_SERVER, PULL_REQUEST,
                    PRE_RELEASE, Inapplicable)
from . import spec
from .fakes import Behaviour, FakePeer
from .tests_client import drive, _summary

BEARER = "Bearer harness-issued-token"

SCHEME_CARD = {
    "harnessAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer",
                                               "bearerFormat": "JWT"}}
}
SCHEME_REQUIREMENT = [{"schemes": {"harnessAuth": {"list": []}}}]


def _auth_peer(**kw):
    return FakePeer(Behaviour(
        card_security_schemes=SCHEME_CARD,
        card_security_requirements=SCHEME_REQUIREMENT,
        **kw))


@a2a_test(
    id="auth.client_presents_credentials_when_card_requires_them",
    defect="Client ignores the card's declared security requirement and calls "
           "the agent with no Authorization header, so every authenticated "
           "peer rejects it and the failure is reported as the remote agent "
           "being broken.",
    clause="SPEC 3.1.11 ('The client MUST authenticate the request using one "
           "of the schemes declared in the public AgentCard.securitySchemes "
           "and AgentCard.security fields') and SPEC 3.3.4.",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_presents_credentials(ctx):
    with _auth_peer(require_auth=BEARER) as peer:
        run = drive(ctx, peer, extra_env={"A2A_TOKEN": BEARER}, timeout=45.0)
        ctx.observe("drive", _summary(run))
        presented = [v for v in peer.saw_header("Authorization") if v]
        ctx.observe("authorization_headers_seen", len(presented))
        ctx.observe("card_declared_scheme", "httpAuthSecurityScheme/Bearer")
        ctx.observe("any_credential_presented", bool(presented))
        if not presented:
            ctx.note(
                "The peer's card declared a Bearer security requirement and "
                "the target presented no Authorization header on any of its "
                "%d request(s). The harness cannot know how to inject the "
                "target's credentials, so this is recorded rather than "
                "failed: a client that has not been GIVEN a credential "
                "cannot present one. What this establishes is the observable "
                "fact for a reviewer." % len(peer.a2a_requests()))


@a2a_test(
    id="auth.client_stops_on_401_rather_than_looping",
    defect="On a 401 the client retries forever or proceeds as if the call "
           "succeeded, so an expired credential turns into either a hot loop "
           "against the peer or a silently empty result.",
    clause="SPEC 3.3.2 Authentication Errors. The spec requires the SERVER to "
           "reject; the client's reaction is not specified, so the loop is "
           "characterised and only a hang is failed.",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_handles_401(ctx):
    with _auth_peer(require_auth="Bearer never-matches") as peer:
        run = drive(ctx, peer, timeout=45.0)
        ctx.observe("drive", _summary(run))
        attempts = len(peer.a2a_requests())
        ctx.observe("requests_against_a_401ing_peer", attempts)
        ctx.assert_must(
            not run["timed_out"],
            "the target hung against a peer that answers 401 to everything "
            "(%d request(s) made before the harness gave up)" % attempts,
            "SPEC 3.3.2 makes 401 an expected, handled outcome. A client that "
            "hangs on it cannot be operated.",
        )
        ctx.assert_must(
            attempts < 50,
            "the target made %d requests against a peer that always answers "
            "401, which is a retry loop" % attempts,
            "SPEC 3.3.2: authentication failure is terminal for the request. "
            "Unbounded retry against a 401 is a denial of service against "
            "the peer and against yourself.",
        )


@a2a_test(
    id="auth.client_reads_declared_schemes",
    defect="Client cannot parse a card that declares security schemes at all "
           "and falls over on it, so any authenticated agent is undiscoverable "
           "to it even before credentials are considered.",
    clause="PROTO AgentCard.security_schemes; SPEC 4.5",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_parses_security_schemes(ctx):
    # Every scheme kind the proto defines, so a client that special-cases one
    # and crashes on the rest is caught.
    every_kind = {
        "apiKey": {"apiKeySecurityScheme": {"location": "header",
                                            "name": "X-API-Key"}},
        "httpAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer"}},
        "oauth2": {"oauth2SecurityScheme": {"flows": {
            "clientCredentials": {"tokenUrl": "https://example.invalid/token",
                                  "scopes": {"a2a": "delegate"}}}}},
        "oidc": {"openIdConnectSecurityScheme": {
            "openIdConnectUrl":
                "https://example.invalid/.well-known/openid-configuration"}},
        "mtls": {"mtlsSecurityScheme": {}},
    }
    with FakePeer(Behaviour(card_security_schemes=every_kind,
                            card_security_requirements=[
                                {"schemes": {"httpAuth": {"list": []}}}])) as peer:
        run = drive(ctx, peer, timeout=45.0)
        ctx.observe("drive", _summary(run))
        ctx.observe("scheme_kinds_offered", sorted(every_kind))
        ctx.observe("card_fetched", peer.card_fetches > 0)
        ctx.assert_must(
            not run["timed_out"],
            "the target hung on a card declaring all five security scheme "
            "kinds",
            "PROTO SecurityScheme is a oneof over five variants; a client "
            "must tolerate every one appearing in a card, whether or not it "
            "can use them.",
        )


@a2a_test(
    id="auth.server_challenges_unauthenticated_callers",
    defect="An agent that requires authentication answers an anonymous caller "
           "with something other than a clear challenge, so a legitimate peer "
           "cannot discover how to authenticate and retries blind.",
    clause="SPEC 3.3.2: 'Servers MUST reject requests with invalid or missing "
           "authentication credentials. Servers SHOULD include authentication "
           "challenge information in the error response. Servers SHOULD "
           "specify which authentication scheme is required.'",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_server_auth_challenge(ctx):
    card = ctx.target.card()
    if not card.get("securitySchemes"):
        raise Inapplicable(
            "the target's card declares no securitySchemes, so it does not "
            "claim to require authentication. This is legal (the field is not "
            "REQUIRED in the proto) but it means the auth surface is UNTESTED "
            "against this target, not that it passed.")
    from .target import send_params
    # Deliberately strip whatever credential the harness was given.
    saved, ctx.target.auth_header = ctx.target.auth_header, None
    try:
        call = ctx.target.call("SendMessage", send_params("anonymous probe"))
    finally:
        ctx.target.auth_header = saved

    ctx.assert_must(
        call.error is not None,
        "the target's card declares security requirements but an "
        "unauthenticated SendMessage succeeded",
        "SPEC 3.3.2: 'Servers MUST reject requests with invalid or missing "
        "authentication credentials.'",
    )
    if call.binding == "HTTP+JSON":
        ctx.observe("unauthenticated_status", call.http.status)
        ctx.observe("www_authenticate",
                    call.http.headers.get("www-authenticate"),
                    "SPEC 3.3.2 makes the challenge a SHOULD, so its absence "
                    "is observed and not failed.")
