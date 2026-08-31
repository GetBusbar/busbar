// Spec clause registry.
//
// Every conformance assertion in this battery cites a clause here. A clause is
// a verbatim quote from the published Model Context Protocol specification plus
// the URL it came from. If a rule is NOT in this registry, it is not a
// conformance requirement and must not be asserted as one; use a variance point
// or a RECOMMENDATION instead.
//
// Revision under test: 2026-07-28 (the "modern", stateless revision).
// Source of truth: https://modelcontextprotocol.io/specification/2026-07-28/

export const REVISION = '2026-07-28';

const S = 'https://modelcontextprotocol.io/specification/2026-07-28';

function clause(id, level, url, quote) {
  return { id, level, url, quote };
}

export const CLAUSES = Object.fromEntries(
  [
    // ---- Base protocol: messages -------------------------------------------
    clause(
      'BASE.REQ.ID-PRESENT', 'MUST', `${S}/basic#requests`,
      'Requests MUST include a string or integer ID.'),
    clause(
      'BASE.REQ.ID-NOT-NULL', 'MUST NOT', `${S}/basic#requests`,
      'Unlike base JSON-RPC, the ID MUST NOT be `null`.'),
    clause(
      'BASE.REQ.ID-UNIQUE', 'MUST NOT', `${S}/basic#requests`,
      'The request ID MUST NOT match the ID of any other request the sender has issued and not yet received a response for.'),
    clause(
      'BASE.RES.ID-MATCHES', 'MUST', `${S}/basic#result-responses`,
      'Result responses MUST include the same ID as the request they correspond to.'),
    clause(
      'BASE.RES.HAS-RESULT', 'MUST', `${S}/basic#result-responses`,
      'Result responses MUST include a `result` field.'),
    clause(
      'BASE.RES.RESULTTYPE', 'MUST', `${S}/basic#result-responses`,
      'The `result` MUST include a `resultType` field to indicate the type of the result.'),
    clause(
      'BASE.RES.RESULTTYPE-ABSENT-IS-COMPLETE', 'MUST', `${S}/basic#resulttype`,
      'For backward compatibility with servers implementing earlier protocol versions, which do not include `resultType`, clients MUST treat an absent `resultType` as "complete".'),
    clause(
      'BASE.ERR.ID-MATCHES', 'MUST', `${S}/basic#error-responses`,
      'Error responses MUST include the same ID as the request they correspond to (except in error cases where the ID could not be read due a malformed request).'),
    clause(
      'BASE.ERR.SHAPE', 'MUST', `${S}/basic#error-responses`,
      'Error responses MUST include an `error` field with a `code` and `message`.'),
    clause(
      'BASE.ERR.CODE-INTEGER', 'MUST', `${S}/basic#error-responses`,
      'Error codes MUST be integers.'),
    clause(
      'BASE.ERR.RESERVED-RANGE', 'MUST NOT', `${S}/basic#error-codes`,
      'Implementations MUST NOT emit any code from this sub-range that is not defined by this specification and MUST use defined codes only with their specified meanings.'),
    clause(
      'BASE.ERR.NO-RETIRED-CODES', 'MUST NOT', `${S}/basic#error-codes`,
      'Codes defined by earlier protocol versions remain reserved and will not be reused. Implementations of this protocol version MUST NOT emit these codes: -32002 ... -32042 ...'),
    clause(
      'BASE.NOTIF.NO-ID', 'MUST NOT', `${S}/basic#notifications`,
      'Notifications MUST NOT include an ID.'),
    clause(
      'BASE.NOTIF.NO-RESPONSE', 'MUST NOT', `${S}/basic#notifications`,
      'The receiver MUST NOT send a response.'),

    // ---- Base protocol: statelessness and _meta ----------------------------
    clause(
      'BASE.STATELESS.NO-PRIOR-REQUESTS', 'MUST NOT', `${S}/basic#statelessness`,
      'Servers MUST NOT rely on prior requests over the same connection to establish context (e.g., capabilities, protocol version, client identity). Every request supplies this metadata in its `_meta` field.'),
    clause(
      'BASE.META.REQUIRED-FIELDS', 'MUST', `${S}/basic#meta`,
      'A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code -32602 (Invalid params). On HTTP, the response status MUST be 400 Bad Request.'),
    clause(
      'BASE.META.MISSING-CAPABILITY', 'MUST', `${S}/basic#meta`,
      'A server MUST NOT rely on capabilities the client has not declared. If processing a request requires a capability the client did not include in `io.modelcontextprotocol/clientCapabilities`, the server MUST return a MissingRequiredClientCapabilityError (-32021) whose `data.requiredCapabilities` lists the missing capabilities.'),
    clause(
      'BASE.SCHEMA.NO-NETWORK-REF', 'MUST NOT', `${S}/basic#ref-resolution`,
      'Implementations MUST NOT automatically dereference `$ref` values that resolve to a network URI.'),

    // ---- Versioning --------------------------------------------------------
    clause(
      'VER.UNSUPPORTED-ERROR', 'MUST', `${S}/basic/versioning#protocol-version-negotiation`,
      'If the server does not implement the requested version (whether the version is unknown to the server, or is a known version the server has chosen not to support), it MUST respond with an UnsupportedProtocolVersionError listing the versions it does support.'),
    clause(
      'VER.DISCOVER-REQUIRED', 'MUST', `${S}/basic/versioning#protocol-version-negotiation`,
      'Servers MUST implement `server/discover`.'),

    // ---- Message patterns --------------------------------------------------
    clause(
      'PAT.SERVER-NO-REQUESTS', 'MUST NOT', `${S}/basic/patterns`,
      'Servers MUST NOT initiate JSON-RPC requests, and clients do not send JSON-RPC responses.'),
    clause(
      'PAT.MRTR.ONLY-SUPPORTED-METHODS', 'MUST NOT', `${S}/basic/patterns/mrtr#supported-requests`,
      'Servers MUST NOT send `InputRequiredResult` responses on any other client requests.'),
    clause(
      'PAT.MRTR.AT-LEAST-ONE-FIELD', 'MUST', `${S}/basic/patterns/mrtr#server-requirements-basic-workflow`,
      'Servers MUST include at least one of `inputRequests` or `requestState` in every `InputRequiredResult` response.'),
    clause(
      'PAT.MRTR.NO-UNDECLARED-CAPABILITY', 'MUST NOT', `${S}/basic/patterns/mrtr#server-requirements-basic-workflow`,
      'Servers MUST NOT send an `inputRequests` that the client has not declared support for in its capabilities.'),
    clause(
      'PAT.MRTR.REQUEST-KINDS', 'MUST', `${S}/basic/patterns/mrtr#server-requirements-basic-workflow`,
      '`inputRequests` values are request objects that MUST be one of ElicitRequest, CreateMessageRequest, or ListRootsRequest.'),
    clause(
      'PAT.MRTR.KEYS-UNIQUE', 'MUST', `${S}/basic/patterns/mrtr#server-requirements-basic-workflow`,
      '`inputRequests` keys are server assigned identifiers and MUST be unique within the scope of the request.'),
    clause(
      'PAT.MRTR.ECHO-STATE', 'MUST', `${S}/basic/patterns/mrtr#client-requirements-basic-workflow`,
      'If an `InputRequiredResult` contains the `requestState` field, the client MUST echo back the exact value of that field when retrying the original request.'),
    clause(
      'PAT.MRTR.NO-STATE-INVENTION', 'MUST NOT', `${S}/basic/patterns/mrtr#client-requirements-basic-workflow`,
      'If the `InputRequiredResult` does not contain a `requestState` field, the client MUST NOT include one in the retry.'),
    clause(
      'PAT.MRTR.NEW-ID', 'MUST', `${S}/basic/patterns/mrtr#client-requirements-basic-workflow`,
      'The JSON-RPC `id` MUST be different between the initial request and the retry, as they are independent requests.'),
    clause(
      'PAT.MRTR.STATE-UNTRUSTED', 'MUST', `${S}/basic/patterns/mrtr#server-requirements-basic-workflow`,
      'If a client request contains a `requestState` field, servers MUST treat `requestState` as an attacker-controlled input. If `requestState` influences authorization, resource access, or business logic, servers MUST protect its integrity (e.g. HMAC or AEAD) and MUST reject state that fails verification.'),

    // ---- Cancellation ------------------------------------------------------
    clause(
      'CANCEL.SERVER-ONLY-SUBSCRIPTIONS', 'MUST NOT', `${S}/basic/patterns/cancellation`,
      'Servers MUST NOT send `notifications/cancelled` for any other purpose.'),
    clause(
      'CANCEL.STDIO-CLIENT-SENDS', 'MUST', `${S}/basic/patterns/cancellation#transport-specific-cancellation`,
      'stdio: There is no per-request stream to close. The client MUST send a `notifications/cancelled` notification referencing the request ID.'),
    clause(
      'CANCEL.HTTP-DISCONNECT', 'MUST', `${S}/basic/patterns/cancellation#transport-specific-cancellation`,
      'Streamable HTTP: Closing the SSE response stream is the cancellation signal. The server MUST treat a client disconnect as cancellation of that request.'),
    clause(
      'CANCEL.NO-FURTHER-MESSAGES', 'MUST NOT', `${S}/basic/transports/stdio#cancellation`,
      'Servers SHOULD stop work on a cancelled request as soon as practical and MUST NOT send any further messages for it.'),
    clause(
      'CANCEL.RACE-GRACEFUL', 'MUST', `${S}/basic/patterns/cancellation#timing-considerations`,
      'Both parties MUST handle these race conditions gracefully.'),

    // ---- Subscriptions -----------------------------------------------------
    clause(
      'SUB.NO-UNREQUESTED-TYPES', 'MUST NOT', `${S}/basic/patterns/subscriptions#opening-a-stream`,
      'The server MUST NOT send notification types the client has not explicitly requested.'),
    clause(
      'SUB.ACK-FIRST', 'MUST', `${S}/basic/patterns/subscriptions#acknowledgment`,
      'The server MUST send `notifications/subscriptions/acknowledged` as the first message carrying the subscription\'s ID in `_meta` under `io.modelcontextprotocol/subscriptionId`, and MUST NOT send any notification on the subscription before it.'),
    clause(
      'SUB.ID-ON-EVERY-NOTIFICATION', 'MUST', `${S}/basic#meta`,
      'On notifications delivered via a `subscriptions/listen` stream, the server MUST include `io.modelcontextprotocol/subscriptionId` in `_meta` so the client can correlate the notification with the originating subscription request.'),
    clause(
      'SUB.CLIENT-CORRELATES', 'MUST', `${S}/basic/patterns/subscriptions#receiving-notifications`,
      'On stdio, where all messages share a single channel, clients MUST use this field to correlate notifications with their originating subscription.'),
    clause(
      'SUB.STDIO-RESUBSCRIBE', 'MUST', `${S}/basic/patterns/subscriptions#graceful-closure`,
      'On stdio, if the connection is terminated and then re-established, the client MUST re-send `subscriptions/listen` to re-establish its subscriptions.'),

    // ---- Transports: stdio -------------------------------------------------
    clause(
      'STDIO.NO-EMBEDDED-NEWLINES', 'MUST NOT', `${S}/basic/transports/stdio`,
      'Messages are delimited by newlines, and MUST NOT contain embedded newlines.'),
    clause(
      'STDIO.STDOUT-ONLY-MCP', 'MUST NOT', `${S}/basic/transports/stdio`,
      'The server MUST NOT write anything to its `stdout` that is not a valid MCP message.'),
    clause(
      'STDIO.STDERR-NOT-ERROR', 'SHOULD NOT', `${S}/basic/transports/stdio`,
      'The client MAY capture, forward, or ignore the server\'s `stderr` output and SHOULD NOT assume `stderr` output indicates error conditions.'),
    clause(
      'STDIO.SERVER-NO-REQUESTS', 'MUST NOT', `${S}/basic/transports/stdio#receiving-messages`,
      'The server MUST NOT write JSON-RPC requests to `stdout`.'),
    clause(
      'STDIO.CLIENT-NO-RESPONSES', 'MUST NOT', `${S}/basic/transports/stdio#sending-messages`,
      'The client MUST NOT write JSON-RPC responses.'),
    clause(
      'STDIO.EXIT-ON-EOF', 'SHOULD', `${S}/basic/transports/stdio#shutdown`,
      'Servers SHOULD exit promptly when their standard input is closed or reads return end-of-file.'),
    clause(
      'STDIO.CLIENT-SHUTDOWN-SEQUENCE', 'SHOULD', `${S}/basic/transports/stdio#shutdown`,
      'The client SHOULD initiate shutdown by: 1. Closing the input stream to the child process (the server). 2. Waiting for the server to exit. 3. If the server does not exit within a reasonable time, forcibly terminating the process.'),
    clause(
      'STDIO.FALLBACK-NOT-CODE-KEYED', 'MUST NOT', `${S}/basic/transports/stdio#backward-compatibility`,
      'The fallback MUST NOT be keyed to one specific error code: legacy servers respond to unknown pre-`initialize` requests with implementation-defined errors (commonly -32601 or -32602) or not at all.'),

    // ---- Transports: Streamable HTTP ---------------------------------------
    clause(
      'HTTP.POST-ENDPOINT', 'MUST', `${S}/basic/transports/streamable-http`,
      'The server MUST provide a single HTTP endpoint path (hereafter referred to as the MCP endpoint) that supports POST.'),
    clause(
      'HTTP.CLIENT-POST', 'MUST', `${S}/basic/transports/streamable-http#sending-messages`,
      'The client MUST use HTTP POST to send JSON-RPC messages.'),
    clause(
      'HTTP.ACCEPT-BOTH', 'MUST', `${S}/basic/transports/streamable-http#sending-messages`,
      'The client MUST include an `Accept` header listing both `application/json` and `text/event-stream` as supported content types.'),
    clause(
      'HTTP.SINGLE-MESSAGE-BODY', 'MUST', `${S}/basic/transports/streamable-http#sending-messages`,
      'The body of the HTTP POST MUST be a single JSON-RPC request or notification. The client MUST NOT send JSON-RPC responses.'),
    clause(
      'HTTP.NOTIFICATION-202', 'MUST', `${S}/basic/transports/streamable-http#sending-messages`,
      'If the server accepts it, the server MUST return HTTP status code 202 Accepted with no body.'),
    clause(
      'HTTP.RESPONSE-CONTENT-TYPE', 'MUST', `${S}/basic/transports/streamable-http#sending-messages`,
      'If the body is a JSON-RPC request, the server MUST return either `Content-Type: application/json` (a single JSON object) or `Content-Type: text/event-stream` (an SSE response stream). The client MUST support both.'),
    clause(
      'HTTP.NO-SERVER-REQUESTS-ON-SSE', 'MUST NOT', `${S}/basic/transports/streamable-http#receiving-messages`,
      'The server MUST NOT send independent JSON-RPC requests on this stream.'),
    clause(
      'HTTP.NOTIFICATIONS-RELATE-TO-REQUEST', 'MUST', `${S}/basic/transports/streamable-http#receiving-messages`,
      'These notifications MUST relate to the originating client request.'),
    clause(
      'HTTP.ORIGIN-VALIDATION', 'MUST', `${S}/basic/transports/streamable-http#security--endpoint`,
      'Servers MUST validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks. If the `Origin` header is present and invalid, servers MUST respond with HTTP 403 Forbidden.'),
    clause(
      'HTTP.PROTOCOL-VERSION-HEADER', 'MUST', `${S}/basic/transports/streamable-http#protocol-version-header`,
      'Every POST request to the MCP endpoint MUST include an `MCP-Protocol-Version` header.'),
    clause(
      'HTTP.HEADER-BODY-VERSION-MATCH', 'MUST', `${S}/basic/transports/streamable-http#protocol-version-header`,
      'The header value MUST match the `io.modelcontextprotocol/protocolVersion` field carried in the request body\'s `_meta`. If the values do not match, the server MUST reject the request with 400 Bad Request and a `HeaderMismatch` JSON-RPC error.'),
    clause(
      'HTTP.UNSUPPORTED-VERSION-400', 'MUST', `${S}/basic/transports/streamable-http#protocol-version-header`,
      'If the server does not implement the requested protocol version ... it MUST respond with 400 Bad Request and an UnsupportedProtocolVersionError listing its supported versions.'),
    clause(
      'HTTP.UNKNOWN-METHOD-404', 'MUST', `${S}/basic/transports/streamable-http#protocol-version-header`,
      'If the server does not implement the requested RPC method, it MUST respond with 404 Not Found and a JSON-RPC error with code -32601 (Method not found).'),
    clause(
      'HTTP.STANDARD-HEADERS', 'MUST', `${S}/basic/transports/streamable-http#standard-request-headers`,
      'Mcp-Method (source field `method`) is required for all requests; Mcp-Name (source `params.name` or `params.uri`) is required for tools/call, resources/read, prompts/get requests. These headers are REQUIRED for compliance.'),
    clause(
      'HTTP.HEADER-MISMATCH-32020', 'MUST', `${S}/basic/transports/streamable-http#server-validation`,
      'Servers MUST reject requests with a 400 Bad Request HTTP status and JSON-RPC error code -32020 (HeaderMismatch) if any validation fails.'),
    clause(
      'HTTP.HEADER-NAME-CASE-INSENSITIVE', 'MUST', `${S}/basic/transports/streamable-http#case-sensitivity`,
      'Header names ... are case-insensitive. Clients and servers MUST use case-insensitive comparisons for header names. Header values (such as method names) are case-sensitive.'),
    clause(
      'HTTP.NO-RESUMABILITY', 'STATEMENT', `${S}/basic/transports/streamable-http#receiving-messages`,
      'Resumable SSE streams via `Last-Event-ID` are not supported.'),
    clause(
      'HTTP.LEGACY-GET-DELETE-405', 'SHOULD', `${S}/basic/transports/streamable-http#earlier-streamable-http-revisions`,
      'HTTP GET or DELETE to the MCP endpoint: respond with 405 Method Not Allowed.'),
    clause(
      'HTTP.NO-SESSION-IDS', 'SHOULD', `${S}/basic/transports/streamable-http#earlier-streamable-http-revisions`,
      'An `Mcp-Session-Id` header on a request: ignore it, and do not mint or echo session IDs.'),
    clause(
      'HTTP.CLIENT-MIRRORS-PARAM-HEADERS', 'MUST', `${S}/basic/transports/streamable-http#custom-headers-from-tool-parameters`,
      'While the use of `x-mcp-header` is optional for servers, clients MUST support this feature. When a server\'s tool definition includes `x-mcp-header` annotations, conforming clients MUST mirror the designated parameter values into HTTP headers.'),
    clause(
      'HTTP.CLIENT-REJECTS-BAD-XMCPHEADER', 'MUST', `${S}/basic/transports/streamable-http#schema-extension`,
      'Clients using the Streamable HTTP transport MUST reject tool definitions where any `x-mcp-header` value violates these constraints. Rejection means the client MUST exclude the invalid tool from the result of `tools/list`.'),
    clause(
      'HTTP.VALUE-ENCODING-SENTINEL', 'MUST', `${S}/basic/transports/streamable-http#value-encoding`,
      'The prefix `=?base64?` and suffix `?=` indicate that the value is Base64-encoded. These markers are case-sensitive and MUST appear exactly as shown (lowercase).'),

    // ---- Tools -------------------------------------------------------------
    clause(
      'TOOLS.CAPABILITY-DECLARED', 'MUST', `${S}/server/tools#capabilities`,
      'Servers that support tools MUST declare the `tools` capability.'),
    clause(
      'TOOLS.LIST-RESPONDS', 'MUST', `${S}/server/tools#capabilities`,
      'Servers that declare the `tools` capability MUST respond to `tools/list` requests with the set of tools currently available to the requesting client.'),
    clause(
      'TOOLS.SET-NOT-CONNECTION-SCOPED', 'MUST NOT', `${S}/server/tools#capabilities`,
      'This set MAY be empty and MAY change over time ... but MUST NOT vary per-connection or as a side effect of other requests on the connection.'),
    clause(
      'TOOLS.DETERMINISTIC-ORDER', 'SHOULD', `${S}/server/tools#capabilities`,
      'Servers SHOULD return tools in a deterministic order (i.e., the same ordering across requests when the underlying set of tools has not changed).'),
    clause(
      'TOOLS.INPUTSCHEMA-VALID', 'MUST', `${S}/server/tools#tool`,
      'inputSchema ... MUST be a valid JSON Schema object (not `null`).'),
    clause(
      'TOOLS.OUTPUTSCHEMA-CONFORMANCE', 'MUST', `${S}/server/tools#output-schema`,
      'If an output schema is provided: Servers MUST provide structured results that conform to this schema.'),
    clause(
      'TOOLS.ANNOTATIONS-UNTRUSTED', 'MUST', `${S}/server/tools#tool`,
      'For trust & safety and security, clients MUST consider tool annotations to be untrusted unless they come from trusted servers.'),
    clause(
      'TOOLS.PROTOCOL-VS-EXECUTION-ERROR', 'STATEMENT', `${S}/server/tools#error-handling`,
      'Protocol Errors indicate issues with the request structure itself ... Unknown tool, Malformed requests ... They are returned as standard JSON-RPC errors. Tool Execution Errors ... are reported in tool results with `isError: true`.'),
    clause(
      'TOOLS.VALIDATE-INPUTS', 'MUST', `${S}/server/tools#security-considerations`,
      'Servers MUST: Validate all tool inputs.'),
    clause(
      'TOOLS.NAME-CHARSET', 'SHOULD', `${S}/server/tools#tool-names`,
      'The following SHOULD be the only allowed characters: uppercase and lowercase ASCII letters (A-Z, a-z), digits (0-9), underscore (_), hyphen (-), and dot (.)'),

    // ---- Pagination --------------------------------------------------------
    clause(
      'PAGE.NO-FIXED-SIZE', 'MUST NOT', `${S}/server/utilities/pagination#pagination-model`,
      'Page size is determined by the server, and clients MUST NOT assume a fixed page size.'),
    clause(
      'PAGE.CURSOR-OPAQUE', 'MUST', `${S}/server/utilities/pagination#implementation-guidelines`,
      'Clients MUST treat cursors as opaque tokens: Do not make assumptions about cursor format. Do not attempt to parse or modify cursors.'),
    clause(
      'PAGE.EMPTY-CURSOR-IS-VALID', 'MUST NOT', `${S}/server/utilities/pagination#implementation-guidelines`,
      'Do not make any determination based on cursor value other than whether a non-null value was provided (e.g. an empty string is a valid cursor and thus MUST NOT be treated as the end of results).'),
    clause(
      'PAGE.INVALID-CURSOR-32602', 'SHOULD', `${S}/server/utilities/pagination#error-handling`,
      'Invalid cursors SHOULD result in an error with code -32602 (Invalid params).'),

    // ---- Caching -----------------------------------------------------------
    clause(
      'CACHE.HINTS-REQUIRED', 'MUST', `${S}/server/utilities/caching#cacheable-results`,
      'Servers MUST include caching hints on results with `resultType: "complete"` returned by the following operations: `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `resources/read`.'),
    clause(
      'CACHE.TTL-NON-NEGATIVE', 'MUST', `${S}/server/utilities/caching#time-to-live-ttl-field`,
      'Servers MUST provide a `ttlMs` value that is >= 0.'),
    clause(
      'CACHE.CLIENT-TOLERATES-ABSENT-TTL', 'SHOULD', `${S}/server/utilities/caching#time-to-live-ttl-field`,
      'If `ttlMs` is absent, clients SHOULD assume a default of `0` (immediately stale) and rely on their own caching heuristics or notifications. This should only occur in older server versions.'),
    clause(
      'CACHE.SCOPE-VALUES', 'STATEMENT', `${S}/server/utilities/caching#cache-scope-field`,
      'The `cacheScope` field indicates the intended scope of the cached response, either `"public"` or `"private"`.'),
    clause(
      'CACHE.INTERIM-NOT-CACHEABLE', 'STATEMENT', `${S}/server/utilities/caching#cacheable-results`,
      'Interim results with `resultType: "input_required"` are not cacheable and carry no caching hints.'),

    // ---- Elicitation -------------------------------------------------------
    clause(
      'ELICIT.NO-SECRETS-IN-FORM', 'MUST NOT', `${S}/client/elicitation#user-interaction-model`,
      'Servers MUST NOT use form mode elicitation to request sensitive information such as passwords, API keys, access tokens, or payment credentials.'),
    clause(
      'ELICIT.URL-MODE-FOR-SENSITIVE', 'MUST', `${S}/client/elicitation#user-interaction-model`,
      'Servers MUST use URL mode for interactions involving such sensitive information.'),
    clause(
      'ELICIT.NO-UNSUPPORTED-MODES', 'MUST NOT', `${S}/client/elicitation#capabilities`,
      'Servers MUST NOT send elicitation requests with modes that are not supported by the client.'),
    clause(
      'ELICIT.DEFAULT-MODE-FORM', 'MUST', `${S}/client/elicitation#protocol-messages`,
      'For backwards compatibility, servers MAY omit the `mode` field for form mode elicitation requests. Clients MUST treat requests without a `mode` field as form mode.'),
    clause(
      'ELICIT.CLIENT-NO-PREFETCH', 'MUST NOT', `${S}/client/elicitation#safe-url-handling`,
      'MUST NOT automatically pre-fetch the URL or any of its metadata.'),
    clause(
      'ELICIT.CLIENT-NO-AUTO-OPEN', 'MUST NOT', `${S}/client/elicitation#safe-url-handling`,
      'MUST NOT open the URL without explicit consent from the user.'),
    clause(
      'ELICIT.SHOW-FULL-URL', 'MUST', `${S}/client/elicitation#safe-url-handling`,
      'MUST show the full URL to the user for examination before consent.'),
    clause(
      'ELICIT.NO-SENSITIVE-IN-URL', 'MUST NOT', `${S}/client/elicitation#safe-url-handling`,
      'MUST NOT include sensitive information about the end-user, including credentials, personally identifiable information, etc., in the URL sent to the client in a URL elicitation request.'),

    // ---- Icons -------------------------------------------------------------
    clause(
      'ICON.SCHEME-RESTRICTION', 'MUST', `${S}/basic#icons`,
      'Ensure that the icon URI is either a HTTPS or `data:` URI. Clients MUST reject icon URIs that use unsafe schemes and redirects, such as `javascript:`, `file:`, `ftp:`, `ws:`, or local app URI schemes.'),
  ].map((c) => [c.id, c]),
);

export function cite(id) {
  const c = CLAUSES[id];
  if (!c) throw new Error(`unknown spec clause: ${id}`);
  return c;
}

// A RECOMMENDATION is this battery's own opinion, not a spec requirement.
// Recommendations never fail a run; they are reported as advisory only.
export function recommendation(id, text) {
  return { id, level: 'RECOMMENDATION (this battery, not the spec)', url: null, quote: text };
}
