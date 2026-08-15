#!/usr/bin/env bash
# BOOT BUSBAR AS THE CONFORMANCE SUBJECT, IN THE JOB, ON LOOPBACK.
#
# WHY THE SUBJECT IS BOOTED HERE INSTEAD OF BEING A URL SOMEBODY DEPLOYED.
#
# The first arming of this leg read an endpoint out of a repository variable, i.e. an externally
# deployed busbar. That makes a RELEASE GATE depend on a live deployment being up, reachable and
# correctly configured at the moment CI happens to run, and it makes both verdicts unreadable: a
# green says "the deployment was fine yesterday" and a red says "somebody redeployed". Neither is a
# statement about the commit under test, which is the only thing a release gate is for.
#
# So the subject is BUILT FROM THIS COMMIT AND BOOTED IN THIS JOB, and the suite is pointed at
# loopback. The sibling A2A workflow settled the equivalent question the same way for its control
# peer. The `MCP_CONFORMANCE_SUBJECT_URL` variable survives as an OPTIONAL EXTRA leg for an operator
# who also wants a real deployment judged -- it is no longer how the gate gets armed.
#
# THE HARD PART IS THE CREDENTIAL, AND IT IS SOLVED WITHOUT WEAKENING ANYTHING.
#
# busbar's MCP endpoint is an OAuth resource server: every request needs a bearer whose audience is
# exactly `mcp.canonical_uri`. The conformance suite cannot be told to send one (its `server`
# command has no header or token option and reads no environment variable for either), and busbar
# has no issuance surface -- it is deliberately the RESOURCE server, and the in-tree mint helper the
# plane-boundary tests use is `cfg(test)` and unreachable from any shipped binary.
#
# The job therefore takes the authorization server's role, which is the role it is already in: IT
# GENERATED THE SIGNING KEY, with `busbar --generate-signing-key`, and handed busbar the same bytes
# through `auth.signing_key`. Signing one token with a key you own is not a bypass; it is the
# documented fleet-shared-secret relationship. Every check inside busbar runs untouched.
#
# AND THAT CLAIM IS PROVEN, NOT ASSERTED. `prove_the_boundary_is_intact` below presents four tokens
# to the SAME booted process, directly, past the shim:
#     no audience         -> must be 401
#     a different audience-> must be 401
#     a flipped signature -> must be 401
#     the right audience  -> must be 200
# If the audience check had been weakened, relaxed or bypassed to make this leg pass, the first
# three would answer 200 and this function would fail the job. A leg that authenticated itself by
# breaking the thing under test is worth less than an unarmed one, so the disproof runs first.

# ---------------------------------------------------------------------------------------------
# Configuration knobs. All optional; the defaults are what CI uses.
#   MCP_SUBJECT_BUSBAR_BIN   the busbar binary to boot. THIS IS WHAT ARMS THE LEG.
#   MCP_SUBJECT_WORKDIR      scratch directory for the config, the key and the logs.
# ---------------------------------------------------------------------------------------------

# The one place the subject's canonical resource identifier is written. It names the address the
# SUITE posts to (the shim), not busbar's own listener, because an RFC 8707 resource indicator names
# the resource as its clients reach it -- and because busbar derives its mount path from this value,
# so the path the suite posts to and the identifier its token is bound to cannot drift apart.
subject_canonical_uri() { printf 'http://127.0.0.1:%s/mcp' "$1"; }

# FOUR FREE PORTS, asked of the OS rather than hard-coded. A hard-coded port is a red that is not a
# defect the first time a runner image happens to have something on it.
subject_free_ports() {
  node -e '
    const net = require("net");
    const grab = () => new Promise((ok) => {
      const s = net.createServer();
      s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => ok(p)); });
    });
    Promise.all([grab(), grab(), grab(), grab()]).then((ps) => console.log(ps.join(" ")));
  '
}

# The smallest config that makes this deployment an MCP server. Everything absent is absent on
# purpose: no providers, no models, no pools. The MCP plane needs none of them, and a subject that
# also carries an LLM fleet would invite a failure that is about the fleet.
#
# `auth.chain: [keys]` IS LOAD-BEARING AND IS THE OPPOSITE OF A SHORTCUT. An EMPTY chain would make
# `/mcp` answer anonymously -- with WILDCARD grants, because a request with no key is not narrowed
# by one -- and every scenario below would run with no credential at all. That is the false green
# this file exists to refuse: it would report conformance for a busbar nobody runs. The chain is
# closed, and the token is real.
#
# AND IT REGISTERS AN UPSTREAM, which is what gives most of the suite something to reach. A busbar
# with an empty registry answers every content scenario with "is not a tool this server exposes",
# which is the CORRECT answer for a gateway fronting nothing and tells nobody anything about
# busbar's conformance. The registration goes through the ordinary path in full: a server id, a
# declared authenticity root, and a per-tool approved digest. Nothing here is bypassed — a tool the
# operator has not approved a digest for is catalogued and refuses to dispatch, so an approval had
# to be written for each one, exactly as an operator would.
#
# The server id is `test` and the tools are named without that prefix, because busbar's routing key
# is `{server}_{tool}`: `test` + `simple_text` is the `test_simple_text` the suite asks for, produced
# by the real namespacing rather than around it. See `diagnostic-upstream.mjs` for why the spec
# authors' own reference server cannot be dropped in here unchanged.
# THE APPROVED DIGEST OF ONE FIXTURE TOOL — looked up from `$dir/digests.txt`, which
# `subject_collect_digests` wrote by asking each fixture upstream what it ACTUALLY serves and
# hashing it exactly as busbar's rug-pull defence does (`tool-digest.mjs`, cross-language-pinned).
#
# WHY THE APPROVALS ARE REAL DIGESTS AND NOT LABELS. `schema_hash:` is the operator's approved
# digest, and `mcp::connect::refresh` compares it against the live observation — on the operator's
# `connect` verb and, unattended, on the trust sweep. The placeholder strings this replaced
# ("sha256:diagnostic-simple-text") could never match anything an upstream serves, so the FIRST
# successful observation of any registration was a drift and the registration was QUARANTINED —
# busbar's defence working exactly as built, against a rig that lied about what it had approved.
# Whether any given battery test survived was then a race between the suite's progress and the
# 30-second sweep tick: fast machines usually won it, the CI runner lost it on every push, and the
# five SEAM.* clauses reported "the seam was never crossed" about a subject that crosses it
# correctly. An approval that is TRUE is the fix; everything else is rearranging the race.
dg() {
  awk -v s="$1" -v t="$2" '$1==s && $2==t {print $3}' "$SUBJECT_DIGESTS"
}

# Ask every fixture upstream for its served tool list and record each tool's busbar-digest, AFTER
# proving the node re-implementation still agrees with busbar's (`--selftest`, see tool-digest.mjs).
subject_collect_digests() {
  local dir="$1" upstream_port="$2"
  SUBJECT_DIGESTS="$dir/digests.txt"
  node scripts/mcp-subject/tool-digest.mjs --selftest \
    || die "tool-digest.mjs no longer agrees with busbar's digest layout; no approval it writes \
can be trusted. Re-align it with mcp::client::catalogue::tool_digest and the pinned fixture."
  : > "$SUBJECT_DIGESTS"
  local sid
  for sid in test json slow failing protocol confirm multi greeter; do
    node scripts/mcp-subject/tool-digest.mjs "http://127.0.0.1:$upstream_port/mcp/$sid" \
      | sed "s/^/$sid /" >> "$SUBJECT_DIGESTS" \
      || die "could not digest the served tool list of the '$sid' fixture registration."
  done
  # The hostile seam peer serves its HONEST list until a test arms a mode, and boot happens before
  # any test: what is approved is the honest `echo`, which is exactly what an operator fronting
  # this peer would have seen and vouched for. `probe` fronts the same peer at the same digest.
  if [ -n "${MCP_SEAM_UPSTREAM_URL:-}" ]; then
    node scripts/mcp-subject/tool-digest.mjs "$MCP_SEAM_UPSTREAM_URL" \
      | sed "s/^/seam /" >> "$SUBJECT_DIGESTS" \
      || die "could not digest the seam peer's honest tool list."
    node scripts/mcp-subject/tool-digest.mjs "$MCP_SEAM_UPSTREAM_URL" \
      | sed "s/^/probe /" >> "$SUBJECT_DIGESTS" \
      || die "could not digest the seam peer's honest tool list for the probe registration."
  fi
  say "   fixture digests recorded: $(wc -l < "$SUBJECT_DIGESTS" | tr -d ' ') approvals in $SUBJECT_DIGESTS"
}

subject_write_config() {
  local dir="$1" mcp_port="$2" data_port="$3" admin_port="$4" upstream_port="$5"
  cat > "$dir/providers.yaml" <<'YAML'
# No providers. The MCP plane needs none, and an empty catalog cannot fail for a reason that is
# about a provider.
{}
YAML
  cat > "$dir/config.yaml" <<YAML
listen: "127.0.0.1:$data_port"
admin_listen: "127.0.0.1:$admin_port"
providers: {}
models: {}
pools: {}
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { file: $dir/signing.key }
mcp:
  canonical_uri: "$(subject_canonical_uri "$mcp_port")"
  authorization_servers:
    - "http://127.0.0.1:$admin_port"
  scopes_supported: ["mcp:tools:list", "mcp:tools:call"]
tools:
  # A SECOND REGISTERED SERVER, and its id is load-bearing rather than decorative.
  #
  # The suite asks for a tool named `json_schema_2020_12_tool` -- BARE, unlike every other diagnostic
  # tool it names, which all carry a `test_` prefix. busbar's routing key is `{server}_{tool}` and
  # there is no way to publish an un-namespaced name, so the id `json` plus the tool
  # `schema_2020_12_tool` produces exactly the string the scenario looks for, through the REAL
  # namespacing with nothing bypassed -- the same trick the `test` server already uses, and the same
  # reason the header of this file gives for it.
  json:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/json"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
        # `json-schema-2020-12`. THE SCHEMA IS THE POINT: the scenario reads `inputSchema` off
        # \`tools/list\` and asserts the 2020-12 keywords survived. Declared here in full because busbar
        # publishes the OPERATOR's schema, never the upstream's -- so this is a test of the \`tools:\`
        # grammar carrying \$defs / \$anchor / \$ref / allOf / if-then-else without flattening them.
        schema_2020_12_tool:
          schema_hash: "$(dg json schema_2020_12_tool)"
          description: "Tool with JSON Schema 2020-12 features for conformance testing (SEP-1613, SEP-2106)"
          input_schema:
            \$schema: "https://json-schema.org/draft/2020-12/schema"
            type: object
            \$defs:
              address:
                \$anchor: addressDef
                type: object
                properties:
                  street: { type: string }
                  city: { type: string }
            properties:
              name: { type: string }
              address: { \$ref: "#/\$defs/address" }
              contactMethod: { type: string, enum: ["phone", "email"] }
              phone: { type: string }
              email: { type: string }
            allOf:
              - anyOf:
                  - required: ["phone"]
                  - required: ["email"]
            if:
              properties:
                contactMethod: { const: "phone" }
              required: ["contactMethod"]
            then:
              required: ["phone"]
            else:
              required: ["email"]
            additionalProperties: false

  test:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/test"
    # The upstream is on loopback and speaks plaintext. allow_private is what an operator must say
    # out loud to permit that, and saying it here is honest rather than convenient: the SSRF guard
    # refuses a private address by default and this registration genuinely is an internal one.
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    # A DESCRIPTION PER TOOL, because busbar publishes the OPERATOR's description rather than the
    # upstream's: what an approval means is that this operator vouched for this tool, and echoing
    # text the upstream can rewrite at will would let it edit its own approval. The suite requires
    # every listed tool to carry one, which is the same requirement read from the other side.
    tools_allow:
      simple_text:
        schema_hash: "$(dg test simple_text)"
        description: "Returns a single text content block."
      image_content:
        schema_hash: "$(dg test image_content)"
        description: "Returns a single image content block."
      audio_content:
        schema_hash: "$(dg test audio_content)"
        description: "Returns a single audio content block."
      embedded_resource:
        schema_hash: "$(dg test embedded_resource)"
        description: "Returns an embedded resource content block."
      multiple_content_types:
        schema_hash: "$(dg test multiple_content_types)"
        description: "Returns text, image and resource content blocks together."
      error_handling:
        schema_hash: "$(dg test error_handling)"
        description: "Always reports a tool-level error."
      # ── SEP-2322 / MRTR: THE ASKS BUSBAR MAKES OF ITS OWN CALLER ──────────────────────────────
      #
      # Every \`ask_caller:\` block below is OPERATOR TEXT. busbar composes an InputRequiredResult
      # from exactly these bytes, filters it by the capabilities the caller declared in
      # \`_meta.io.modelcontextprotocol/clientCapabilities\`, and seals it with a requestState busbar
      # MINTS — bound to the authenticated principal, the method, the tool, a digest of the
      # arguments and the catalogue generation, with a short TTL and a round index.
      #
      # THIS IS NOT A RELAY, AND THE DISTINCTION IS THE WHOLE POINT. An upstream's own
      # InputRequiredResult still TERMINATES at busbar (\`mcp/inputreq.rs\`): busbar either satisfies
      # it under a grant the operator gave that server, or fails the call with a busbar-attributed
      # error. It is never handed to the caller. What is on the wire here is a demand busbar makes
      # in its own name, which is the only kind it is entitled to make — the same rule that already
      # makes busbar publish the OPERATOR's tool description rather than the upstream's, applied to
      # the field where it matters most.
      #
      # Minting rather than relaying is also the only conformant option. mrtr.mdx:232 makes it a
      # MUST to reject state that fails verification, and mrtr.mdx:130 makes an upstream's state
      # opaque to everyone but that upstream — so a relayer could only forward it blind. Worse,
      # mrtr.mdx:235 requires the state to bind the authenticated principal, and the only principal
      # an upstream can see is busbar, identically for every one of busbar's callers: relayed state
      # would make caller A's state redeemable by caller B.
      #
      # NOBODY SHOULD PRETEND THERE IS AN OPERATOR BEHIND THE \`roots/list\` ASK. There is a scenario
      # behind it. That is legitimate — this is operator config exactly like the six approvals
      # above, and it puts no \`test_*\` literal into crates/*/src — but it is worth saying out loud
      # that a real deployment would declare an ask because it wants a confirmation gate, not
      # because a suite asked for one.
      input_required_result_elicitation:
        schema_hash: "$(dg test input_required_result_elicitation)"
        description: "Asks the caller for a name before it runs."
        ask_caller:
          # The KEY IS ASSERTED BY NAME by sep-2322-elicitation-incomplete. It is not decorative.
          - user_name:
              method: elicitation/create
              params:
                mode: form
                message: "What is your name?"
                requestedSchema:
                  type: object
                  properties:
                    name:
                      type: string
                      description: "Your name"
                  required: ["name"]
      # A1.4. The upstream answers this one as a STREAM: progress frames, then the result.
      # No \`ask_caller:\` -- what is judged is whether busbar carries the upstream's progress
      # through to its own caller, and an ask would put a different exchange in the way.
      tool_with_progress:
        schema_hash: "$(dg test tool_with_progress)"
        description: "Reports progress while it runs."
      # SEP-2575, the \`server-stateless\` scenario. Four of its checks reported "Not testable"
      # because these three tools were not exposed, and the suite counts an untestable check as a
      # FAILURE — so the summary read like a broken implementation when nothing had been exercised.
      #
      # \`missing_capability\` asks for a SAMPLING round trip while the scenario declares NO
      # capabilities, so what is judged is busbar's own refusal: \`-32021\`
      # (MissingRequiredClientCapability) rather than the generic \`-32000\` every other upstream
      # failure collapses to. The ask lives here rather than in the fixture for the same reason every
      # other one does — busbar composes the demand in its OWN name and never relays the upstream's.
      missing_capability:
        schema_hash: "$(dg test missing_capability)"
        description: "Requires the caller's sampling capability before it runs."
        ask_caller:
          - llm_answer:
              method: sampling/createMessage
              params:
                maxTokens: 16
                messages:
                  - role: user
                    content: { type: text, text: "Reply with the single word: pong" }
      # Must NOT ask the caller for anything: the check asserts the response stream carries no
      # INDEPENDENT top-level JSON-RPC request, so an \`ask_caller:\` here would be the very thing
      # being tested for.
      streaming_elicitation:
        schema_hash: "$(dg test streaming_elicitation)"
        description: "Returns a result whose stream carries no independent requests."
      # ── SEP-2663 COMPOSITION: \`test\` + \`tool_with_task\` = \`test_tool_with_task\` ─────────────
      #
      # The one tasks fixture that belongs on THIS server rather than on its own, because the name
      # the suite asks for already carries the \`test_\` prefix busbar's namespacing produces here.
      #
      # \`task_support: required\` AND an \`ask_caller:\` round, which is the whole point of the
      # scenario: the first round is the SYNCHRONOUS SEP-2322 ask (an InputRequiredResult carrying no
      # taskId, because no task exists yet), and the second — the retry that answers it — escalates to
      # a CreateTaskResult. A server that wired MRTR and tasks as independent surfaces returns a
      # plain result on the second round and fails.
      #
      # The gathered answer must survive into the TASK's eventual result, end to end. busbar binds
      # an ask keyed \`user_name\` to the tool argument of that name, and the upstream echoes it —
      # see \`tool_with_task\` in diagnostic-upstream.mjs.
      tool_with_task:
        schema_hash: "$(dg test tool_with_task)"
        description: "Gathers a name, then escalates to a task that greets it."
        task_support: required
        ask_caller:
          - user_name:
              method: elicitation/create
              params:
                mode: form
                message: "What is your name?"
                requestedSchema:
                  type: object
                  properties:
                    name:
                      type: string
                      description: "Your name"
                  required: ["name"]
      # ── SEP-2243 CUSTOM PARAM HEADERS ────────────────────────────────────────────────────────
      #
      # THE SCHEMA IS THE FIXTURE. The suite scans \`tools/list\` for the first tool whose
      # \`inputSchema\` carries an \`x-mcp-header\` annotation on a STRING property, then drives six
      # cases against the header that annotation names. Without one, all five of that scenario's
      # requirement checks report "not testable" — which the suite counts as a FAILURE, so the
      # summary reads like a broken implementation while nothing has been exercised.
      #
      # It is declared HERE, in operator config, because busbar publishes the OPERATOR's schema and
      # never the upstream's: the annotation is an operator's statement that this parameter is
      # mirrored into an HTTP header for intermediaries to route on, and an upstream that could
      # rewrite it could decide which of its own parameters got policed.
      #
      # \`tenant\` is not decorative. A tenant selector is the realistic case for this feature and
      # the reason the mismatch rule is a MUST rather than a nicety: if the header and the body can
      # disagree, the proxy rate-limits one tenant while the server runs the call for another.
      header_param:
        schema_hash: "$(dg test header_param)"
        description: "Echoes a parameter that is mirrored into an Mcp-Param request header."
        input_schema:
          type: object
          properties:
            tenant:
              type: string
              description: "The tenant this call is for; mirrored into Mcp-Param-Tenant."
              x-mcp-header: "Tenant"
      # ── THE OUTPUT SCHEMA, DECLARED BY THE OPERATOR ─────────────────────────────────────────
      #
      # \`output_schema:\` is the operator's, exactly as \`input_schema:\` and \`description:\` are, and
      # it matters more than either: publishing an \`outputSchema\` makes conforming structured
      # results a MUST for the server that published it, and that server is BUSBAR — a caller never
      # speaks to the upstream and could not attribute a violation to it. An upstream that could
      # write this schema could rewrite the promise busbar is held to.
      #
      # busbar published NO outputSchema on any tool until this commit
      # (\`tools.withOutputSchema: control ["echo","add","always_fails"] / subject []\`), which made
      # SRV.TOOLS.OUTPUTSCHEMA-CONFORMS vacuous for busbar and blinded every validating client: with
      # no schema on the wire there is nothing to check a structured result against.
      structured_report:
        schema_hash: "$(dg test structured_report)"
        description: "Returns a structured report alongside its text."
        input_schema:
          type: object
          properties:
            subject:
              type: string
              description: "What the report is about."
        output_schema:
          type: object
          properties:
            subject: { type: string }
            status: { type: string, enum: ["ok", "degraded", "failed"] }
            findings: { type: integer }
          required: ["subject", "status", "findings"]
          additionalProperties: false
      logging_tool:
        schema_hash: "$(dg test logging_tool)"
        description: "Exercises the request-scoped, logLevel-gated log channel."
      input_required_result_sampling:
        schema_hash: "$(dg test input_required_result_sampling)"
        description: "Asks the caller's model for a completion before it runs."
        ask_caller:
          - capital_question:
              method: sampling/createMessage
              params:
                maxTokens: 100
                messages:
                  - role: user
                    content: { type: text, text: "What is the capital of France?" }
      input_required_result_list_roots:
        schema_hash: "$(dg test input_required_result_list_roots)"
        description: "Asks the caller for its roots before it runs."
        ask_caller:
          - client_roots:
              method: roots/list
      input_required_result_request_state:
        schema_hash: "$(dg test input_required_result_request_state)"
        description: "Asks for input and seals the exchange with request state."
        ask_caller:
          - confirmation:
              method: elicitation/create
              params:
                mode: form
                message: "Confirm to continue."
                requestedSchema:
                  type: object
                  properties:
                    confirm: { type: boolean }
      input_required_result_multiple_inputs:
        schema_hash: "$(dg test input_required_result_multiple_inputs)"
        description: "Asks for three kinds of input in one round."
        ask_caller:
          # THREE KEYS AND THREE DISTINCT METHODS. sep-2322-multiple-inputs-incomplete asserts both
          # (>= 3 keys AND a method set containing all three), so two keys sharing a method passes
          # neither half.
          - user_name:
              method: elicitation/create
              params:
                mode: form
                message: "What is your name?"
                requestedSchema:
                  type: object
                  properties:
                    name: { type: string }
            summary:
              method: sampling/createMessage
              params:
                maxTokens: 100
                messages:
                  - role: user
                    content: { type: text, text: "Summarise the task." }
            client_roots:
              method: roots/list
      input_required_result_multi_round:
        schema_hash: "$(dg test input_required_result_multi_round)"
        description: "Asks in two ordered rounds before it runs."
        # TWO ROUNDS. sep-2322-multi-round-r2 additionally requires the second requestState to
        # DIFFER from the first; that is a property of the seal (a fresh nonce and an incremented
        # round index per mint), not of this list.
        ask_caller:
          - step1:
              method: elicitation/create
              params:
                mode: form
                message: "Step 1: what is your name?"
                requestedSchema:
                  type: object
                  properties:
                    name: { type: string }
          - step2:
              method: elicitation/create
              params:
                mode: form
                message: "Step 2: confirm."
                requestedSchema:
                  type: object
                  properties:
                    confirm: { type: boolean }
      input_required_result_tampered_state:
        schema_hash: "$(dg test input_required_result_tampered_state)"
        description: "Asks for input under integrity-protected request state."
        ask_caller:
          - confirmation:
              method: elicitation/create
              params:
                mode: form
                message: "Confirm to continue."
                requestedSchema:
                  type: object
                  properties:
                    ok: { type: boolean }
      input_required_result_capabilities:
        schema_hash: "$(dg test input_required_result_capabilities)"
        description: "Asks only for what the caller declared it can do."
        # DECLARES ONE OF EACH, deliberately. sep-2322-respect-client-capabilities calls this tool
        # declaring sampling and omitting elicitation, and fails on EITHER an elicitation ask
        # surviving OR a complete result — so the filter needs something to remove and something to
        # keep. A single-ask block would pass one half of that check vacuously.
        ask_caller:
          - confirmation:
              method: elicitation/create
              params:
                mode: form
                message: "Confirm to continue."
                requestedSchema:
                  type: object
                  properties:
                    ok: { type: boolean }
            draft:
              method: sampling/createMessage
              params:
                maxTokens: 100
                messages:
                  - role: user
                    content: { type: text, text: "Draft a one-line summary." }
    # RESOURCES, LIKE PROMPTS, ARE THE OPERATOR'S OWN CONTENT — served from this config with no
    # upstream round trip, because a resource an operator approved BY URI is a thing they vouched
    # for, and proxying the body would let the upstream edit what it was approved to serve.
    #
    # THE URIs ARE THE SUITE'S OWN, verbatim, and that is the point of this block. Until the routing
    # key changed, busbar published `test_test://static-text` for a resource whose URI is
    # `test://static-text` — so a suite that asks for the identifier the SPEC fixes could not reach
    # it, and declaring these here would have proved nothing. The URI is now the wire identity, so
    # these are addressable exactly as the reference server's are.
    resources_allow:
      "test://static-text":
        name: "Static Text Resource"
        description: "A static text resource for testing"
        mime_type: "text/plain"
        text: "This is the content of the static text resource."
      # A 1x1 PNG, the reference server's own bytes. `blob` rather than `text` because
      # ResourceContents is a union of the two forms and base64 in a text field is prose to every
      # client that reads it.
      "test://static-binary":
        name: "Static Binary Resource"
        description: "A static binary resource (image) for testing"
        mime_type: "image/png"
        blob: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg=="
    # A TEMPLATE is an approval over a SHAPE rather than over one URI, which is why it is a separate
    # map: `{id}` is bound from the caller's expanded URI and substituted into the body.
    resource_templates_allow:
      "test://template/{id}/data":
        name: "Resource Template"
        description: "A resource template with parameter substitution"
        mime_type: "application/json"
        text: '{"id":"{id}","templateTest":true,"data":"Data for ID: {id}"}'
    # PROMPTS ARE SERVED FROM THE OPERATOR'S CONFIG, not proxied: a prompt template is an
    # instruction busbar puts into a model's context, so it is the operator's text by construction
    # and there is no upstream round trip to make. The namespaced name is test_simple_prompt.
    prompts_allow:
      simple_prompt:
        description: "A simple prompt for testing."
        template: "This is a simple prompt for testing."
      prompt_with_arguments:
        description: "A prompt that names arguments."
        template: "Prompt with arguments: arg1='{arg1}', arg2='{arg2}'"
      # sep-2322-non-tool-incomplete drives \`prompts/get\`, not \`tools/call\`. It is the CLEANEST
      # member of the family for busbar and the one that settles the argument on its own: prompts
      # are served entirely from the operator's config with NO upstream round trip at all, so the
      # InputRequiredResult on this path is provably busbar's own — there is no other party in the
      # exchange for it to have come from.
      input_required_result_prompt:
        description: "A prompt that asks the caller for context first."
        template: "Prompt rendered with the caller-supplied context."
        ask_caller:
          - context:
              method: elicitation/create
              params:
                mode: form
                message: "What context should this prompt use?"
                requestedSchema:
                  type: object
                  properties:
                    context: { type: string }
      # THE TYPED FORM. A "template:" is a single {type:"text"} message and cannot express an image
      # or an embedded resource at all — base64 in a "text" field is prose to every client that
      # reads it — so these two are written with "messages:", which is the shape B4 added. They are
      # still ENTIRELY the operator's own content: a prompt is an instruction busbar puts into a
      # model's context, so there is no upstream round trip to make and nothing here is proxied.
      prompt_with_image:
        description: "A prompt carrying an image and a question about it."
        messages:
          - content:
              type: image
              data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
              mime_type: "image/png"
          - content:
              type: text
              text: "Please analyze the image above."
      prompt_with_embedded_resource:
        description: "A prompt carrying an embedded resource and a question about it."
        messages:
          # The URI is the caller's own resourceUri argument, substituted the same way a text
          # template's placeholders are — which is what the scenario asks for and what a template
          # form could not have expressed.
          - content:
              type: resource
              resource:
                uri: "{resourceUri}"
                mime_type: "text/plain"
                text: "Embedded resource content for testing."
          - content:
              type: text
              text: "Please process the embedded resource above."

  # ── THE SEP-2663 TASK SERVERS ─────────────────────────────────────────────────────────────────
  #
  # FIVE REGISTRATIONS FOR FIVE TOOLS, and the fan-out is the routing key doing its job rather than
  # being worked around. busbar's wire name is \`{server}_{tool}\`, so the bare names the tasks
  # scenarios ask for are produced by choosing the server id that composes each one:
  #
  #     slow     + compute    = slow_compute
  #     failing  + job        = failing_job
  #     protocol + error_job  = protocol_error_job
  #     confirm  + delete     = confirm_delete
  #     multi    + input      = multi_input
  #
  # Every one goes through the REAL registration path in full — a declared authenticity root and a
  # per-tool approved digest — exactly as \`test\` and \`json\` do, and for the reason this file's
  # header gives: a tool the operator has not approved a digest for is catalogued and refuses to
  # dispatch, so an approval had to be written for each.
  #
  # \`greet\` IS THE SIXTH, AND IT IS REACHED THE OTHER WAY. It is the one name the suite asks for
  # that contains no separator, so no server id composes it — see \`greeter:\` below.
  slow:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/slow"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      # \`optional\`, NOT \`required\`, and the difference is asserted directly:
      # sep-2663-server-rejects-undeclared-client calls this tool from a session that declared
      # nothing and requires a plain synchronous ToolResult with content[]. \`required\` would answer
      # -32021 there, which is the correct answer for a different declaration and the wrong one for
      # this tool.
      compute:
        schema_hash: "$(dg slow compute)"
        description: "Sleeps for the requested number of seconds and then returns a result."
        task_support: optional
        input_schema:
          type: object
          properties:
            seconds:
              type: number
              description: "How long the work takes."
            label:
              type: string
              description: "A label echoed back in the result."

  failing:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/failing"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      # \`required\` HERE, and it is what tasks-required-task-error reads. That scenario calls this
      # tool from a client that declared no extension and requires -32021 with
      # data.requiredCapabilities — an error returned BEFORE the handler runs, which is only
      # possible because the declaration is registration-time config rather than something busbar
      # could discover by trying.
      #
      # The tool's own behaviour is a TOOL-LEVEL error, which is a different axis entirely: with the
      # extension declared it creates a task, the task runs, and the run reports failure — so the
      # terminal status is \`completed\` with \`result.isError\`, never \`failed\`.
      job:
        schema_hash: "$(dg failing job)"
        description: "Always reports a tool-execution error."
        task_support: required

  protocol:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/protocol"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      # The OTHER half of the error-semantics pair: this upstream answers a JSON-RPC error, so
      # nothing ran and there is no tool output to report. The task settles \`failed\` with an
      # inlined error{code,message} and no \`result\` at all.
      error_job:
        schema_hash: "$(dg protocol error_job)"
        description: "Fails at the protocol level rather than reporting a tool error."
        task_support: optional

  confirm:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/confirm"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      # \`task_ask_caller:\` RATHER THAN \`ask_caller:\`, and the two are not interchangeable.
      # \`ask_caller:\` is the SEP-2322 synchronous exchange — busbar answers tools/call with an
      # InputRequiredResult and the caller retries, which is what the eight input-required-result
      # fixtures above use. This one is the SEP-2663 exchange: busbar answers with a
      # CreateTaskResult, parks the task in \`input_required\`, surfaces the ask as the task's
      # \`inputRequests\`, and the caller answers with tasks/update. Writing this round under
      # \`ask_caller:\` would produce the wrong shape on the wire for the same operator intent, which
      # is exactly why they are two lists and not one list with a mode.
      delete:
        schema_hash: "$(dg confirm delete)"
        description: "Deletes the named file once the caller has confirmed."
        task_support: optional
        task_ask_caller:
          - confirmation:
              method: elicitation/create
              params:
                mode: form
                message: "Confirm deletion?"
                requestedSchema:
                  type: object
                  properties:
                    confirm: { type: boolean }
                  required: ["confirm"]
        input_schema:
          type: object
          properties:
            filename:
              type: string
              description: "The file to delete."

  multi:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/multi"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      # TWO KEYS IN ONE ROUND, which is what makes partial fulfilment testable at all: the scenario
      # answers one key, requires the task to STAY \`input_required\` with only the other still
      # listed, then answers the second and requires it to complete. Two SEPARATE rounds would park
      # on one key at a time and the partial case would never arise.
      input:
        schema_hash: "$(dg multi input)"
        description: "Runs once the caller has answered both parallel input requests."
        task_support: optional
        task_ask_caller:
          - first_name:
              method: elicitation/create
              params:
                mode: form
                message: "What is your name?"
                requestedSchema:
                  type: object
                  properties:
                    name: { type: string }
            second_confirm:
              method: elicitation/create
              params:
                mode: form
                message: "Confirm to continue."
                requestedSchema:
                  type: object
                  properties:
                    confirm: { type: boolean }

  # ── \`greet\`: THE ONE NAME NO SERVER ID COMPOSES ───────────────────────────────────────────────
  #
  # Every other bare name the suite asks for contains the separator, so it is produced by choosing
  # the server id that composes it — \`slow\`+\`compute\`, \`json\`+\`schema_2020_12_tool\`, and the rest.
  # \`greet\` has no separator, so \`{server}{_}{tool}\` cannot express it at all. That is not a fixture
  # problem to work around, and it was not worked around: the grammar gained
  # \`tools_allow.<tool>.publish_as:\`, an OPTIONAL per-tool wire-name override whose ABSENCE leaves
  # every existing config publishing byte-identical names.
  #
  # THE INVARIANT IS NOT WEAKENED, IT IS RE-KEPT. One published name must resolve to exactly one
  # (server, tool) — because \`mcp/catalogue.rs\` gates on \`grant("mcp_server", server) &&
  # grant("mcp_tool", published)\`, so a name meaning two pairs would mean one grant authorizing
  # two upstreams. It used to hold by construction; it now holds by
  # \`mcp::config::validate_published_names\`, which builds the FULL published set — every namespaced
  # default AND every override — and REFUSES BOOT on a duplicate, naming both sides. So this
  # registration is exactly as safe as the five above and it fails loudly, at boot, if it ever stops
  # being.
  #
  # THE REAL PATH, with nothing bypassed: a declared authenticity root and a per-tool approved
  # digest, like every other fixture here. No \`task_support\`, because all four checks that call this
  # tool require a plain synchronous ToolResult with a non-empty content[] — a tool that could
  # answer with a task would make the sync baseline depend on which branch ran.
  #
  # The server id \`greeter\` is not decorative either: it is the proof that the default would have
  # been \`greeter_greet\` and that \`publish_as\` is what makes it \`greet\`.
  greeter:
    # A PATH OF ITS OWN. Each registration is answered exactly the tool set it approves
    # (`SUBSETS` in diagnostic-upstream.mjs): eight registrations sharing one flat list
    # meant every honest observation carried 20-odd `added` tools, which is DRIFT, which
    # is a quarantine on the first unattended sweep tick. See `dg` below.
    url: "http://127.0.0.1:$upstream_port/mcp/greeter"
    allow_private: true
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      greet:
        publish_as: greet
        schema_hash: "$(dg greeter greet)"
        description: "Returns a greeting for the supplied name."
        input_schema:
          type: object
          properties:
            name:
              type: string
              description: "Who to greet."
YAML

  # ── THE SEAM UPSTREAM: THE BATTERY'S HOSTILE PEER, MOUNTED ───────────────────────────────────
  #
  # APPENDED ONLY WHEN `MCP_SEAM_UPSTREAM_URL` IS SET, so every other run of this file produces a
  # byte-identical config. It is what turns the six `SEAM.*` clauses from "the seam could not be
  # reached" into a judgement: those tests drive busbar's front door and observe what busbar sends
  # out of its back door, and there is nothing to observe until a peer we control is registered.
  #
  # THE `publish_as: echo` IS MANDATORY, NOT COSMETIC. The seam suite calls the bare name `echo`,
  # because that is the tool the battery's own `fakepeer/fake-server.mjs` has always exposed, and
  # busbar's routing key is `{server}_{tool}` — which cannot compose a name with no separator in it.
  # Without the override every seam `tools/call` is answered "unknown tool", nothing reaches an
  # upstream, and FIVE OF THE SIX CLAUSES GO GREEN VACUOUSLY: each of them is looking for something
  # that must NOT appear on the upstream connection, and nothing appears on a connection that was
  # never opened. That is a worse outcome than the red it replaces, and the suite now refuses it
  # independently — see `requireUpstreamWasReached` in `src/suites/seam.mjs`.
  #
  # `timeout: 10s` IS THE SECOND LOAD-BEARING LINE. `SEAM.UPSTREAM-FAILURE-IS-TOOL-ERROR` arms the
  # `stall` mode and waits 20 seconds for busbar to answer its own client. busbar's default deadline
  # is 30 seconds, so the clause was RED ON ARRIVAL against a busbar behaving exactly as configured.
  # The fix is the per-server deadline in the `tools:` grammar, used here as an operator would use
  # it — a loopback diagnostic that answers in milliseconds does not need thirty seconds — and NOT a
  # constant tuned to the battery.
  #
  # Everything else goes through the ordinary path in full, exactly as the six registrations above
  # do: a declared authenticity root, a per-tool approved digest, and `allow_private` said out loud
  # because the peer is on loopback.
  if [ -n "${MCP_SEAM_UPSTREAM_URL:-}" ]; then
    cat >> "$dir/config.yaml" <<YAML

  seam:
    url: "$MCP_SEAM_UPSTREAM_URL"
    allow_private: true
    timeout: 10s
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      echo:
        publish_as: echo
        schema_hash: "$(dg seam echo)"
        description: "Returns the string it was given."
        input_schema:
          type: object
          properties:
            text:
              type: string
              description: "The text to echo."

  # ── THE CLIENT-ROLE PROBE: the registration \`client-arm.sh\` refreshes ─────────────────────────
  #
  # The CLI.* scenarios judge what BUSBAR-AS-A-CLIENT puts on the wire, and busbar's client
  # direction sends a \`tools/list\` on exactly one path: the connect/refresh leg
  # (\`mcp::connect::refresh\`), which fetches an upstream's LIVE tool list to compare against the
  # operator's approved digests. The front-door \`tools/list\` never reaches any peer — busbar
  # answers it from the operator's own catalogue, correctly — so a rig that drives only the front
  # door leaves \`CLI.CACHE.TOLERATES-ABSENT-HINTS\` reporting "client did not call tools/list even
  # against an honest server" about a client that provably does.
  #
  # A REGISTRATION OF ITS OWN, pointed at the SAME hostile peer, and the separation is the
  # load-bearing part. The refresh it exists to receive re-hashes what the peer actually serves and
  # compares it against the approved digest below. Against the honest baseline the observation is
  # CLEAN — the approval is the honest \`echo\`'s real digest — but the CLI scenarios drive this
  # refresh under HOSTILE modes too, and \`rugpull\` serves a changed schema: that observation lands
  # as DRIFT and \`connect\` records a durable demotion, which is busbar-the-client detecting a
  # rug-pull, i.e. the very behaviour that scenario judges. On \`probe\` the demotion costs nothing
  # (no scenario dispatches through \`probe\`, and the next honest connect is the agreeing
  # observation that clears it). On \`seam\` it would quarantine the one registration every SEAM.*
  # clause dispatches through, mid-run, from an unrelated leg. The transcript the CLI scenarios
  # read is written by the peer BEFORE any verdict busbar reaches about the answer, so the judged
  # bytes are unaffected by the demotion.
  probe:
    url: "$MCP_SEAM_UPSTREAM_URL"
    allow_private: true
    timeout: 10s
    pin:
      mechanism: cert_spki
      key: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    tools_allow:
      echo:
        schema_hash: "$(dg probe echo)"
        description: "Returns the string it was given."
YAML
    say "   seam upstream registered: $MCP_SEAM_UPSTREAM_URL (published as echo, 10s deadline; refresh probe: probe)"
  fi
}

# One MCP JSON-RPC request, answered with its HTTP status only. Carries the mirrored headers AND
# the required `params._meta` members this revision demands, so a non-401 status is a statement
# about AUTH and not about the envelope.
#
# `io.modelcontextprotocol/clientCapabilities` is not decoration. `2026-07-28` has no handshake, so
# the schema makes it a REQUIRED member of every request's `_meta`, and a server that accepts its
# absence is deciding on the client's behalf what that client can do. busbar refuses the omission
# with `-32602`/`400`. Without it here the control probe below would read `400` and this harness
# would declare the audience boundary broken over a defect in its own request — the exact class of
# false red this file exists to avoid.
subject_probe_status() {
  local url="$1" bearer="${2:-}"
  local -a auth=()
  [ -n "$bearer" ] && auth=(-H "authorization: Bearer $bearer")
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "$url" \
    -H 'content-type: application/json' \
    -H 'mcp-method: tools/list' \
    -H 'mcp-protocol-version: 2026-07-28' \
    "${auth[@]}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
}

# THE DISPROOF. Four tokens, one process, one endpoint. Three of them MUST be refused.
prove_the_boundary_is_intact() {
  local direct="$1" plain="$2" bound="$3" wrong="$4"
  local failures=0 got

  say "   proving the audience boundary is INTACT before believing any verdict from this leg:"

  got=$(subject_probe_status "$direct")
  if [ "$got" = "401" ]; then say "     ok:  no credential            -> 401"
  else say "     BAD: no credential            -> $got (expected 401)"; failures=$((failures+1)); fi

  got=$(subject_probe_status "$direct" "$plain")
  if [ "$got" = "401" ]; then say "     ok:  token with NO audience   -> 401"
  else say "     BAD: token with NO audience   -> $got (expected 401)"; failures=$((failures+1)); fi

  got=$(subject_probe_status "$direct" "$wrong")
  if [ "$got" = "401" ]; then say "     ok:  token, WRONG audience    -> 401"
  else say "     BAD: token, WRONG audience    -> $got (expected 401)"; failures=$((failures+1)); fi

  # The signature, altered by one character. Flipped to a DIFFERENT character deliberately, so the
  # token stays the same length and still base64url-decodes -- a truncated token would be refused as
  # malformed, which proves the parser works and says nothing about the signature check.
  local tampered last
  last="${bound: -1}"
  if [ "$last" = "A" ]; then tampered="${bound%?}B"; else tampered="${bound%?}A"; fi
  got=$(subject_probe_status "$direct" "$tampered")
  if [ "$got" = "401" ]; then say "     ok:  flipped signature        -> 401"
  else say "     BAD: flipped signature        -> $got (expected 401)"; failures=$((failures+1)); fi

  # And the control, without which the four above are equally consistent with a busbar that refuses
  # everything -- which would make the whole leg vacuous in the other direction.
  got=$(subject_probe_status "$direct" "$bound")
  if [ "$got" = "200" ]; then say "     ok:  token, RIGHT audience    -> 200"
  else say "     BAD: token, RIGHT audience    -> $got (expected 200)"; failures=$((failures+1)); fi

  [ "$failures" -eq 0 ] || die "the audience boundary did not behave as declared ($failures of 5 \
probes wrong). Either busbar's plane boundary has been weakened -- in which case this leg would be \
green about a busbar nobody runs, and that is worse than leaving it unarmed -- or the harness is \
minting the wrong thing. Either way no verdict from this leg means anything until it is fixed."
}

# Boot busbar, obtain a credential for it, and put a credential-holding client shim in front.
# Sets SUBJECT_URL (what the suite is pointed at) and SUBJECT_PIDS (what the caller must reap).
boot_busbar_subject() {
  local bin="${MCP_SUBJECT_BUSBAR_BIN:?boot_busbar_subject needs MCP_SUBJECT_BUSBAR_BIN}"
  [ -x "$bin" ] || die "MCP_SUBJECT_BUSBAR_BIN=$bin is not an executable. The subject leg judges a \
busbar built FROM THIS COMMIT; if the build step did not produce one, that is the finding."

  local dir="${MCP_SUBJECT_WORKDIR:-.mcp-conformance/subject-run}"
  rm -rf "$dir"; mkdir -p "$dir"
  dir="$(cd "$dir" && pwd)"

  local mcp_port data_port admin_port upstream_port
  read -r mcp_port data_port admin_port upstream_port <<<"$(subject_free_ports)"
  [ -n "${upstream_port:-}" ] || die "could not obtain four free loopback ports."
  local canonical; canonical="$(subject_canonical_uri "$mcp_port")"
  say "   busbar $data_port · admin $admin_port · suite-facing $mcp_port"
  say "   canonical resource: $canonical"

  # The signing key. GENERATED BY THIS JOB, which is the whole basis on which it may sign anything:
  # it is not extracted from busbar, and busbar is handed the same bytes rather than the other way
  # round. Written 0600 out of habit rather than need -- it is a throwaway on a throwaway runner.
  ( umask 077; "$bin" --generate-signing-key > "$dir/signing.key" 2>"$dir/generate-key.log" ) \
    || { cat "$dir/generate-key.log" >&2; die "busbar --generate-signing-key failed."; }

  # THE REGISTERED UPSTREAM, booted before busbar so the registration points at something live.
  node scripts/mcp-subject/diagnostic-upstream.mjs "$upstream_port" >"$dir/upstream.log" 2>&1 &
  SUBJECT_PIDS="$!"
  say "   diagnostic upstream on $upstream_port"

  # Listening, before anything asks it for a tool list. `000` is curl's "no connection".
  local upstream_waited=0
  until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$upstream_port/mcp")" != "000" ]; do
    upstream_waited=$((upstream_waited+1))
    [ "$upstream_waited" -lt 30 ] || { tail -20 "$dir/upstream.log" >&2; die "the diagnostic upstream did not come up."; }
    sleep 1
  done

  subject_collect_digests "$dir" "$upstream_port"
  subject_write_config "$dir" "$mcp_port" "$data_port" "$admin_port" "$upstream_port"
  # A lookup that missed writes `schema_hash: ""`, which busbar may refuse for its own reasons;
  # this names the actual defect — the digest table and the config disagree about a tool.
  if grep -n 'schema_hash: ""' "$dir/config.yaml" >&2; then
    die "a fixture tool has no digest in $SUBJECT_DIGESTS; the registration above would be armed \
with an empty approval."
  fi

  # An admin credential for THIS boot only, from the OS CSPRNG. Never a fixed string: the admin
  # plane is loopback-only here, and a fixed token in a public repository is a habit that eventually
  # gets copied somewhere it matters.
  local admin_token; admin_token="$(node -e 'console.log(require("crypto").randomBytes(24).toString("hex"))')"

  BUSBAR_CONFIG="$dir/config.yaml" BUSBAR_ADMIN_TOKEN="$admin_token" \
    "$bin" >"$dir/busbar.log" 2>&1 &
  local busbar_pid=$!
  SUBJECT_PIDS="$SUBJECT_PIDS $busbar_pid"

  # READINESS BY OBSERVATION. The wait ends when `/mcp` answers ANYTHING -- and here it will answer
  # `401`, which is a perfectly good proof that a resource server is listening. Waiting for a `200`
  # would make readiness depend on the very credential path this function has not built yet.
  local direct="http://127.0.0.1:$data_port/mcp" waited=0
  until [ "$(subject_probe_status "$direct")" != "000" ]; do
    kill -0 "$busbar_pid" 2>/dev/null || { tail -40 "$dir/busbar.log" >&2; die "busbar exited during boot."; }
    waited=$((waited+1))
    [ "$waited" -lt 60 ] || { tail -40 "$dir/busbar.log" >&2; die "busbar did not become ready within 60s."; }
    sleep 1
  done
  say "   busbar ready after ${waited}s"

  # A REAL BINDING, minted the ordinary way through the admin API. The subject and the generation
  # are read back off the token it returns; nothing here invents either, because a subject busbar
  # never minted and a generation that does not match the durable row are both refused -- correctly.
  local plain
  plain=$(curl -s --max-time 15 -X POST "http://127.0.0.1:$admin_port/api/v1/admin/keys" \
            -H "authorization: Bearer $admin_token" -H 'content-type: application/json' \
            -d '{"name":"mcp-conformance-subject"}' \
          | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const t=JSON.parse(s).token; if(!t){console.error(s);process.exit(1);} process.stdout.write(t);})') \
    || die "the admin API did not mint a key. Without a real binding there is no subject to bind a \
token to, and a made-up one would be refused."

  local minter="scripts/mcp-subject/mint-audience-token.mjs"
  local bound wrong
  bound=$(node "$minter" "$dir/signing.key" "$plain" "$canonical") || die "could not mint the audience-bound token."
  # The counterfactual, minted for an audience this deployment is not. Used only to prove the check
  # is live; if it were ever admitted, the plane boundary would be gone.
  wrong=$(node "$minter" "$dir/signing.key" "$plain" "${canonical}-not-this-resource") \
    || die "could not mint the wrong-audience counterfactual."

  prove_the_boundary_is_intact "$direct" "$plain" "$bound" "$wrong"

  # ── THE FIRST LOOK, TAKEN BY THE OPERATOR, NOW ─────────────────────────────────────────────────
  #
  # `connect` every registration once, before any scenario runs, and REQUIRE it to land `approved`.
  # Two things this buys, and both are the honest version of something the rig used to get by
  # racing:
  #
  #   1. PROOF THE APPROVALS ARE TRUE. The digests written above came from the fixtures' own served
  #      lists; if any of that machinery is wrong, this loop fails the boot naming the registration,
  #      instead of the drift surfacing minutes later as a quarantine that reads like a scattering
  #      of unrelated scenario failures.
  #   2. A STAMPED LEDGER. The unattended trust sweep re-checks a registration when it has NEVER
  #      been checked or when its `refresh_ttl:` (default 6h) lapses. Un-connected, every
  #      registration was due on the sweep's FIRST 30-second tick — mid-battery, with the hostile
  #      seam peer armed in whatever mode the current test chose, so what the sweep observed (and
  #      therefore whether the whole seam family was quarantined mid-run) depended on which test the
  #      tick landed in. Checked HERE, while the peer serves its honest baseline, nothing is due
  #      again for six hours and no tick can re-observe the seam mid-attack. The defence is not
  #      weakened: the same sweep runs, the same comparison bites, and a real drift on an operator's
  #      deployment quarantines exactly as before.
  local connect_subjects="test json slow failing protocol confirm multi greeter"
  [ -n "${MCP_SEAM_UPSTREAM_URL:-}" ] && connect_subjects="$connect_subjects seam probe"
  local s view
  for s in $connect_subjects; do
    view=$(curl -s --max-time 45 -X POST "http://127.0.0.1:$admin_port/api/v1/admin/tools/$s/connect" \
             -H "authorization: Bearer $admin_token")
    case "$view" in
      *'"state":"approved"'*) ;;
      *) die "the boot-time connect of '$s' did not land approved — the rig's approvals disagree \
with what the fixture actually serves: $view" ;;
    esac
  done
  say "   all $(echo "$connect_subjects" | wc -w | tr -d ' ') registrations connected and approved; next unattended re-check is refresh_ttl away"

  node scripts/mcp-subject/credential-shim.mjs "$mcp_port" "$data_port" "$bound" \
    >"$dir/credential-shim.log" 2>&1 &
  SUBJECT_PIDS="$SUBJECT_PIDS $!"

  waited=0
  until [ "$(subject_probe_status "$canonical")" = "200" ]; do
    waited=$((waited+1))
    [ "$waited" -lt 30 ] || {
      cat "$dir/credential-shim.log" >&2
      die "the credential shim never produced a 200 from busbar, though busbar answered 200 to the \
same token directly. That is a finding about the shim, not about busbar."
    }
    sleep 1
  done
  say "   the suite-facing endpoint answers tools/list 200 through a real, verified credential"

  # SET FOR THE CALLER, which is `official_subject` in scripts/mcp-conformance.sh: the URL the suite
  # is pointed at, and the pids it must reap. Deliberately not `local`.
  # shellcheck disable=SC2034
  SUBJECT_URL="$canonical"

  # AND THE ADMIN SURFACE, for the one leg that needs an OPERATOR's verb rather than a caller's:
  # `client-arm.sh` drives `POST /api/v1/admin/tools/probe/connect` so busbar's client direction
  # emits the `tools/list` the CLI.* scenarios exist to judge. The token is this boot's own
  # CSPRNG-minted one — handing it to a sibling script of this harness is the operator using their
  # own credential, not a credential escaping: it never reaches the suite, the peer or any
  # transcript.
  # shellcheck disable=SC2034
  SUBJECT_ADMIN_URL="http://127.0.0.1:$admin_port"
  # shellcheck disable=SC2034
  SUBJECT_ADMIN_TOKEN="$admin_token"
}
