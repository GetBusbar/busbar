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
  test:
    url: "http://127.0.0.1:$upstream_port/mcp"
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
        schema_hash: "sha256:diagnostic-simple-text"
        description: "Returns a single text content block."
      image_content:
        schema_hash: "sha256:diagnostic-image-content"
        description: "Returns a single image content block."
      audio_content:
        schema_hash: "sha256:diagnostic-audio-content"
        description: "Returns a single audio content block."
      embedded_resource:
        schema_hash: "sha256:diagnostic-embedded-resource"
        description: "Returns an embedded resource content block."
      multiple_content_types:
        schema_hash: "sha256:diagnostic-multiple-content-types"
        description: "Returns text, image and resource content blocks together."
      error_handling:
        schema_hash: "sha256:diagnostic-error-handling"
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
        schema_hash: "sha256:diagnostic-input-required-elicitation"
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
      input_required_result_sampling:
        schema_hash: "sha256:diagnostic-input-required-sampling"
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
        schema_hash: "sha256:diagnostic-input-required-list-roots"
        description: "Asks the caller for its roots before it runs."
        ask_caller:
          - client_roots:
              method: roots/list
      input_required_result_request_state:
        schema_hash: "sha256:diagnostic-input-required-request-state"
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
        schema_hash: "sha256:diagnostic-input-required-multiple-inputs"
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
        schema_hash: "sha256:diagnostic-input-required-multi-round"
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
        schema_hash: "sha256:diagnostic-input-required-tampered-state"
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
        schema_hash: "sha256:diagnostic-input-required-capabilities"
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
YAML
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

  subject_write_config "$dir" "$mcp_port" "$data_port" "$admin_port" "$upstream_port"

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
}
