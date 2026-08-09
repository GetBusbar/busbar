"""Normative constants for the Agent2Agent (A2A) protocol.

Everything in this module is transcribed from primary sources ONLY:

  SPEC   github.com/a2aproject/A2A, tag v1.0.1, docs/specification.md
  PROTO  github.com/a2aproject/A2A, tag v1.0.1, specification/a2a.proto

Per SPEC section 1.4 ("Normative Content"), a2a.proto is "the single
authoritative normative definition of all protocol data objects and
request/response messages", and the generated a2a.json is explicitly a
"non-normative build artifact". Where the prose and the proto disagree, this
module follows the proto and records the disagreement in AMBIGUITIES below.

Nothing here is derived from any implementation. If a rule cannot be cited it
does not belong in this file; put it in RECOMMENDATIONS instead, which the
harness never treats as a conformance requirement.
"""

SPEC_TAG = "v1.0.1"
SPEC_REPO = "https://github.com/a2aproject/A2A"
PROTOCOL_VERSION = "1.0"

# SPEC 3.6: "The specific version of the A2A protocol in use is identified
# using the Major.Minor elements (e.g. 1.0)... Patch version numbers SHOULD NOT
# be used in requests, responses and Agent Cards."
VERSION_HEADER = "A2A-Version"
EXTENSIONS_HEADER = "A2A-Extensions"

# SPEC 3.6.2: "Agents MUST interpret empty value as 0.3 version."
DEFAULT_VERSION_WHEN_HEADER_ABSENT = "0.3"

# SPEC 8.2 and 14.3. The IANA registration template in 14.3 gives the URI
# suffix as "agent-card.json" and states the resource "MUST return an AgentCard
# object as defined in Section 4.4.1".
WELL_KNOWN_CARD_PATH = "/.well-known/agent-card.json"

# SPEC 11.1: "Content-Type: application/a2a+json SHOULD be used for requests
# and responses" (HTTP+JSON binding).
# SPEC 9.1: "Content-Type: application/json for requests and responses"
# (JSON-RPC binding).
MEDIA_TYPE_A2A_JSON = "application/a2a+json"
MEDIA_TYPE_JSON = "application/json"
MEDIA_TYPE_SSE = "text/event-stream"

# PROTO enum TaskState. SPEC 5.5 requires ProtoJSON enum serialisation, i.e.
# the string name exactly as defined in the proto.
TASK_STATES = (
    "TASK_STATE_UNSPECIFIED",
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_REJECTED",
    "TASK_STATE_AUTH_REQUIRED",
)

# PROTO comments on TaskState mark exactly these four as terminal:
# COMPLETED "This is a terminal state", FAILED "This is a terminal state",
# CANCELED "This is a terminal state", REJECTED "This is a terminal state".
# SPEC 3.1.2 repeats the same four as the set that closes a stream.
TERMINAL_STATES = frozenset(
    (
        "TASK_STATE_COMPLETED",
        "TASK_STATE_FAILED",
        "TASK_STATE_CANCELED",
        "TASK_STATE_REJECTED",
    )
)

# PROTO marks these two "This is an interrupted state". SPEC 3.2.2 lists the
# same two as the interrupted set that terminates a blocking SendMessage.
INTERRUPTED_STATES = frozenset(
    ("TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED")
)

# PROTO enum Role.
ROLES = ("ROLE_UNSPECIFIED", "ROLE_USER", "ROLE_AGENT")

# SPEC 5.3 "Method Mapping Reference". JSON-RPC method names are PascalCase
# per SPEC 9.1.
JSONRPC_METHODS = (
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "CreateTaskPushNotificationConfig",
    "GetTaskPushNotificationConfig",
    "ListTaskPushNotificationConfigs",
    "DeleteTaskPushNotificationConfig",
    "GetExtendedAgentCard",
)

# SPEC 11.3, and PROTO google.api.http annotations on service A2AService.
# Note the subscribe divergence recorded in AMBIGUITIES.
REST_ROUTES = {
    "SendMessage": ("POST", "/message:send"),
    "SendStreamingMessage": ("POST", "/message:stream"),
    "GetTask": ("GET", "/tasks/{id}"),
    "ListTasks": ("GET", "/tasks"),
    "CancelTask": ("POST", "/tasks/{id}:cancel"),
    "CreateTaskPushNotificationConfig": (
        "POST",
        "/tasks/{id}/pushNotificationConfigs",
    ),
    "GetTaskPushNotificationConfig": (
        "GET",
        "/tasks/{id}/pushNotificationConfigs/{configId}",
    ),
    "ListTaskPushNotificationConfigs": (
        "GET",
        "/tasks/{id}/pushNotificationConfigs",
    ),
    "DeleteTaskPushNotificationConfig": (
        "DELETE",
        "/tasks/{id}/pushNotificationConfigs/{configId}",
    ),
    "GetExtendedAgentCard": ("GET", "/extendedAgentCard"),
}

# SPEC 5.4 "Error Code Mappings". These are the canonical mappings and the
# table is introduced with MUST ("All A2A-specific errors ... MUST be mapped").
# Tuple order: (json-rpc code, grpc status, http status)
ERROR_MAP = {
    "TaskNotFoundError": (-32001, "NOT_FOUND", 404),
    "TaskNotCancelableError": (-32002, "FAILED_PRECONDITION", 400),
    "PushNotificationNotSupportedError": (-32003, "FAILED_PRECONDITION", 400),
    "UnsupportedOperationError": (-32004, "FAILED_PRECONDITION", 400),
    "ContentTypeNotSupportedError": (-32005, "INVALID_ARGUMENT", 400),
    "InvalidAgentResponseError": (-32006, "INTERNAL", 500),
    "ExtendedAgentCardNotConfiguredError": (-32007, "FAILED_PRECONDITION", 400),
    "ExtensionSupportRequiredError": (-32008, "FAILED_PRECONDITION", 400),
    "VersionNotSupportedError": (-32009, "FAILED_PRECONDITION", 400),
}

JSONRPC_CODE_TO_ERROR = {v[0]: k for k, v in ERROR_MAP.items()}

# SPEC 9.5 "Standard JSON-RPC Error Codes".
JSONRPC_STANDARD_ERRORS = {
    -32700: "JSONParseError",
    -32600: "InvalidRequestError",
    -32601: "MethodNotFoundError",
    -32602: "InvalidParamsError",
    -32603: "InternalError",
}

# SPEC 11.6: for HTTP+JSON, "implementations MUST include a google.rpc.ErrorInfo
# object in the details array for A2A-specific errors with ... reason: The A2A
# error type in UPPER_SNAKE_CASE without the Error suffix ... domain: set to
# a2a-protocol.org".
ERROR_INFO_DOMAIN = "a2a-protocol.org"


def error_reason(error_name):
    """TaskNotFoundError -> TASK_NOT_FOUND. SPEC 11.6."""
    stem = error_name[: -len("Error")] if error_name.endswith("Error") else error_name
    out = []
    for i, ch in enumerate(stem):
        if ch.isupper() and i and not stem[i - 1].isupper():
            out.append("_")
        out.append(ch.upper())
    return "".join(out)


# ---------------------------------------------------------------------------
# Required fields, transcribed from PROTO [(google.api.field_behavior) =
# REQUIRED] annotations. SPEC 5.7 gives these annotations their normative
# force: "Fields marked with [(google.api.field_behavior) = REQUIRED] indicate
# that the field MUST be present and set in valid messages... Arrays marked as
# required MUST contain at least one element."
#
# Names below are the camelCase JSON forms mandated by SPEC 5.5.
# ---------------------------------------------------------------------------

AGENT_CARD_REQUIRED = (
    "name",
    "description",
    "supportedInterfaces",
    "version",
    "capabilities",
    "defaultInputModes",
    "defaultOutputModes",
    "skills",
)

# PROTO AgentCard: fields NOT annotated REQUIRED.
AGENT_CARD_OPTIONAL = (
    "provider",
    "documentationUrl",
    "securitySchemes",
    "securityRequirements",
    "signatures",
    "iconUrl",
)

# SPEC 5.7: "Arrays marked as required MUST contain at least one element."
AGENT_CARD_REQUIRED_NONEMPTY_ARRAYS = (
    "supportedInterfaces",
    "defaultInputModes",
    "defaultOutputModes",
    "skills",
)

AGENT_INTERFACE_REQUIRED = ("url", "protocolBinding", "protocolVersion")
AGENT_SKILL_REQUIRED = ("id", "name", "description", "tags")
AGENT_PROVIDER_REQUIRED = ("url", "organization")
TASK_REQUIRED = ("id", "status")
TASK_STATUS_REQUIRED = ("state",)
MESSAGE_REQUIRED = ("messageId", "role", "parts")
ARTIFACT_REQUIRED = ("artifactId", "parts")
STATUS_UPDATE_REQUIRED = ("taskId", "contextId", "status")
ARTIFACT_UPDATE_REQUIRED = ("taskId", "contextId", "artifact")
LIST_TASKS_RESPONSE_REQUIRED = ("tasks", "nextPageToken", "pageSize", "totalSize")
CARD_SIGNATURE_REQUIRED = ("protected", "signature")

# PROTO AgentInterface.protocol_binding: "The core ones officially supported
# are JSONRPC, GRPC and HTTP+JSON." The field is explicitly "an open form
# string, to be easily extended", so an unknown value is NOT a violation.
CORE_PROTOCOL_BINDINGS = ("JSONRPC", "GRPC", "HTTP+JSON")

# PROTO SecurityScheme oneof field names, camelCased per SPEC 5.5.
SECURITY_SCHEME_KINDS = (
    "apiKeySecurityScheme",
    "httpAuthSecurityScheme",
    "oauth2SecurityScheme",
    "openIdConnectSecurityScheme",
    "mtlsSecurityScheme",
)

# PROTO StreamResponse oneof payload. SPEC 3.1.2 / 4.3.3: "containing exactly
# one of the following".
STREAM_PAYLOAD_KINDS = ("task", "message", "statusUpdate", "artifactUpdate")

# PROTO SendMessageResponse oneof payload.
SEND_PAYLOAD_KINDS = ("task", "message")

# PROTO APIKeySecurityScheme.location: "Valid values are query, header, or
# cookie."
API_KEY_LOCATIONS = ("query", "header", "cookie")

# SPEC 8.4.1: canonicalisation is RFC 8785 JCS, the signatures field MUST be
# excluded, and the JWS protected header MUST include alg, kid; typ SHOULD be
# "JOSE" (SPEC 8.4.2).
JWS_PROTECTED_REQUIRED = ("alg", "kid")
JWS_PROTECTED_SHOULD = ("typ",)

# SPEC 3.1.4: "If unspecified, at most 50 tasks will be returned. The minimum
# value is 1. The maximum value is 100." (PROTO ListTasksRequest.page_size)
LIST_TASKS_PAGE_SIZE_MIN = 1
LIST_TASKS_PAGE_SIZE_MAX = 100
LIST_TASKS_PAGE_SIZE_DEFAULT = 50


# ---------------------------------------------------------------------------
# Ambiguities. Each entry is a place where two conformant implementations may
# legally diverge, or where the spec contradicts itself. The harness NEVER
# fails a test on any of these; it records both readings and reports a
# divergence for a human. Adding a hard assertion for anything in this list is
# a bug in the harness.
# ---------------------------------------------------------------------------

AMBIGUITIES = {
    "SUBSCRIBE_HTTP_METHOD": {
        "summary": "SubscribeToTask REST binding is GET in the proto and POST "
        "in the prose.",
        "reading_a": "GET /tasks/{id}:subscribe -- PROTO a2a.proto, "
        "rpc SubscribeToTask, option (google.api.http) = { get: "
        '"/tasks/{id=*}:subscribe" }.',
        "reading_b": "POST /tasks/{id}:subscribe -- SPEC 5.3 Method Mapping "
        "Reference table, and SPEC 11.3.2.",
        "resolution": "SPEC 1.4 makes the proto normative, so GET wins on a "
        "strict reading. Both are attempted; the harness records which verbs "
        "the target accepts and never fails on the choice.",
    },
    "CARD_SECURITY_FIELD_NAME": {
        "summary": "The agent card security requirements field has two names "
        "in the spec.",
        "reading_a": 'securityRequirements -- PROTO AgentCard field 9 is '
        "repeated SecurityRequirement security_requirements, which camelCases "
        "to securityRequirements under SPEC 5.5.",
        "reading_b": 'security -- SPEC 8.5 Sample Agent Card literally emits '
        '"security": [{ "google": [...] }].',
        "resolution": "Accept either. The field is not REQUIRED in the proto, "
        "so its absence is legal too. Recorded as an observation.",
    },
    "JSONRPC_METHOD_NAMING_EXAMPLE": {
        "summary": "SPEC 9.3 shows a JSON-RPC method placeholder of "
        '"category/action", which is the 0.3-era naming.',
        "reading_a": "PascalCase, e.g. SendMessage -- SPEC 9.1 Method Naming, "
        "SPEC 5.3 table, and every worked example in SPEC 9.4.",
        "reading_b": 'Slash-separated, e.g. message/send -- SPEC 9.3 Base '
        "Request Structure placeholder text.",
        "resolution": "Overwhelming weight is PascalCase; 9.3 looks like an "
        "un-updated placeholder. The harness sends PascalCase and, if that "
        "yields MethodNotFound, records the 0.3 name as an observation rather "
        "than a failure, because a 0.3 interface is legal (SPEC 3.6.2).",
    },
    "VERSION_ERROR_BODY_SHAPE": {
        "summary": "VersionNotSupportedError has two different response body "
        "shapes in the spec.",
        "reading_a": "google.rpc.Status JSON with an ErrorInfo detail -- "
        "SPEC 11.6, which says implementations MUST include ErrorInfo.",
        "reading_b": "RFC 9457 problem+json with type/title/status/detail and "
        "a supportedVersions array -- SPEC 6.4 worked example, which emits "
        "Content-Type: application/problem+json.",
        "resolution": "Only the HTTP status code (400) and the fact that an "
        "error occurred are asserted. The body shape is observed.",
    },
    "MESSAGE_ID_ON_AGENT_MESSAGES": {
        "summary": "messageId is REQUIRED on Message in the proto but the "
        "spec's own examples omit it on agent-authored status messages.",
        "reading_a": "Always required -- PROTO Message.message_id is annotated "
        "REQUIRED, and SPEC 5.7 says required fields MUST be present.",
        "reading_b": "Omissible on server-authored status messages -- SPEC "
        "6.3 Response (Input Required) shows a status message with role and "
        "parts but no messageId.",
        "resolution": "Recorded as an observation on agent-authored messages. "
        "Asserted as a hard requirement only on messages the harness itself "
        "sends, where the harness is the one that must comply.",
    },
    "CONTENT_TYPE_STRICTNESS": {
        "summary": "HTTP+JSON content type is SHOULD, not MUST.",
        "reading_a": "application/a2a+json -- SPEC 11.1.",
        "reading_b": "application/json is not forbidden, because SPEC 11.1 "
        "says SHOULD.",
        "resolution": "Observed, never failed. Enforcing a SHOULD would be a "
        "bug in the test.",
    },
    "CARD_AT_INTERFACE_URL": {
        "summary": "The spec does not say the well-known card path is served "
        "relative to the interface URL or to the bare origin.",
        "reading_a": "Origin-relative -- SPEC 8.2 gives the literal "
        "https://{server_domain}/.well-known/agent-card.json.",
        "reading_b": "Path-prefix-relative, e.g. an agent mounted at "
        "/agents/foo serving /agents/foo/.well-known/agent-card.json. The "
        "spec neither blesses nor forbids this.",
        "resolution": "The harness probes the origin form first, then the "
        "prefixed form, and records which one answered. Neither is a failure.",
    },
    "TASK_ID_REUSE_AFTER_PURGE": {
        "summary": "Whether a task id may be reused after a task is purged.",
        "reading_a": "Ids are unique forever -- PROTO Task.id 'Unique "
        "identifier (e.g. UUID) for the task'.",
        "reading_b": "Reuse is not forbidden; SPEC 3.3.1 explicitly "
        "contemplates a task being 'already canceled and purged'.",
        "resolution": "Observation only.",
    },
    "STREAM_TRAILING_TASK_SNAPSHOT": {
        "summary": "Whether a terminal stream ends with a final Task snapshot.",
        "reading_a": "It may -- SPEC 11.7: implementations 'MAY optionally "
        "resend a final Task snapshot before closing'.",
        "reading_b": "It may not -- the same clause makes it optional.",
        "resolution": "Observation only. The harness asserts the stream closes "
        "at a terminal state, not what the last frame is.",
    },
}


# ---------------------------------------------------------------------------
# Recommendations. These are MY OPINION as the test author. They are not spec
# requirements and the harness must never report them as conformance failures.
# They are emitted as advisory notes only.
# ---------------------------------------------------------------------------

RECOMMENDATIONS = {
    "CARD_NO_CREDENTIALS": "An agent card is a public document. It should not "
    "contain bearer tokens, API keys or private URLs. The spec does not say "
    "this anywhere; it is my recommendation.",
    "STABLE_CARD_BETWEEN_FETCHES": "A card fetched twice in quick succession "
    "with no deployment in between should be byte-identical or differ only in "
    "fields whose change is announced by the version field. SPEC 8.6 gives "
    "caching guidance but never forbids a card from changing silently.",
    "REJECT_UNSIGNED_AFTER_SIGNED": "Once a client has seen a signed card "
    "from a provider it should not silently accept an unsigned one from the "
    "same origin. SPEC 8.4.3 says clients SHOULD verify at least one "
    "signature, but says nothing about downgrade.",
    "ARTIFACT_MEDIA_TYPE_HONESTY": "A part whose bytes do not match its "
    "declared mediaType should be treated as hostile. The spec has no clause "
    "requiring an agent to police this.",
}
