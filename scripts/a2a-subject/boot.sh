#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# BOOT BUSBAR AS THE A2A CONFORMANCE SUBJECT, IN THE JOB, ON LOOPBACK.
#
# WHY THE SUBJECT IS BOOTED HERE INSTEAD OF BEING A URL SOMEBODY DEPLOYED.
#
# The first arming of this leg read an endpoint out of `vars.BUSBAR_A2A_ENDPOINT`, i.e. an
# externally deployed busbar. That makes a RELEASE GATE depend on a live deployment being up,
# reachable and correctly configured at the moment CI happens to run, and it makes both verdicts
# unreadable: a green says "the deployment was fine yesterday" and a red says "somebody
# redeployed". Neither is a statement about the commit under test, which is the only thing a
# release gate is for. The sibling MCP battery settled exactly this question the same way
# (`scripts/mcp-subject/boot.sh`), and the variable is kept only as an OPTIONAL EXTRA leg for an
# operator who also wants a real deployment judged.
#
# It was worse here than there, because the variable was never set: the leg's two real steps were
# `skipped` on every run while the job reported `success`. There has therefore never been an A2A
# conformance number of any kind — not a low one, none — and every other job in
# `.github/workflows/a2a-conformance.yml` judges a pinned third-party peer.
#
# THE CREDENTIAL, SOLVED THE SAME HONEST WAY MCP SOLVED IT.
#
# busbar's A2A mount is an OAuth resource server. `crates/busbar-core/src/a2a/serve.rs` derives the
# plane's RFC 8707 canonical URI from `public_url` (`<public_url>/a2a`), and `auth/mod.rs` refuses
# any credential whose readable audience is not exactly that — an OPAQUE key is refused outright,
# so there is no "just use an API key" path. The independent battery can be handed a header
# (`--auth`), but the official TCK cannot: `run_tck.py` takes `--sut-host` and nothing else.
#
# So this job takes the AUTHORIZATION SERVER's role, which is the role it is already in: IT
# GENERATED THE SIGNING KEY, with `busbar --generate-signing-key`, and handed busbar the same bytes
# through `auth.signing_key`. Signing one token with a key you own is not a bypass; it is the
# documented fleet-shared-secret relationship. Every check inside busbar runs untouched, and the
# token is attached on the CLIENT side of the connection.
#
# WHERE THAT TOKEN LIVES DEPENDS ON THE INSTRUMENT, and it is not a detail. The TCK's lives in the
# credential shim the MCP leg uses — reused rather than copied, because two spellings of "hold a
# bearer and attach it" is exactly the duplication that has already produced three security defects
# in this release. The BATTERY holds its own (`--auth`) and gets NO shim, because a forwarder whose
# job is to attach a credential to any request that carries none makes an ANONYMOUS request
# unrepresentable — and "an anonymous caller is refused with a usable challenge" (SPEC 3.3.2) is one
# of the server-role MUSTs the battery asserts. With the shim in front, that test was reporting on
# the shim. See `boot_busbar_a2a_subject`.
#
# AND THAT CLAIM IS PROVEN, NOT ASSERTED. `prove_the_boundary_is_intact` presents four credentials
# to the SAME booted process, on its own listener, past any shim:
#     no credential      -> must be 401
#     no audience        -> must be 401
#     a different audience-> must be 401
#     a flipped signature -> must be 401
#     the right audience  -> must be ADMITTED (anything but 401/403)
# If the audience check had been weakened to make this leg reach the endpoint, the first four would
# stop answering 401 and this function would fail the job.
#
# WHAT THE FIFTH PROBE IS ALLOWED TO ANSWER, AND WHY IT IS NOT PINNED TO ONE STATUS.
#
# It asserts ADMITTED, not `200`. The endpoint behind it is a real fronted agent whose backend is a
# real process, and pinning a status here would make this proof red for something that is not an
# auth fact. The status is PRINTED so a reader can see which side of the trust machine answered.
#
# THE FRONTED AGENT IS REAL, AND THAT IS THE CHANGE THIS FILE MOST NEEDED.
#
# Until now the registration below named `https://backend.a2a-conformance.invalid/a2a` — a backend
# that could never be fetched — because two things made a hermetic rig impossible, and both are now
# fixed on `dev` and USED here:
#
#   1. A registration is born `Pending` and something must promote it. `A2aPlane::from_config`
#      deliberately does not lift an operator's declared pin into an approval, which is right: an
#      approval is a statement about a document a human actually saw. The verbs that capture a
#      sighting and act on it are now MOUNTED — `POST /api/v1/admin/agents/{name}/connect` and
#      `.../approve` — so this script drives the sequence a real operator drives, in that order,
#      echoing back the fingerprint `connect` reported. Nothing is auto-approved.
#   2. A loopback backend is refused unless the operator says so. `agents.<name>.allow_private:` is
#      the same knob, the same spelling and the same fail-closed default the `tools:` sibling has,
#      and it is set here — out loud, in the config this script writes — because the backend really
#      is on loopback and claiming otherwise would be a lie about the deployment.
#
# WHAT THE BACKEND IS, AND WHY IT IS NO LONGER THE PINNED CONTROL.
#
# It was `a2a-go` in `--echo` mode, chosen so that the peer busbar fronts is the same peer the
# control legs judge and any gap between the two numbers is a gap busbar opened. That bought
# comparability at a price nobody had priced: echo finishes every task on the first turn, so the
# suite could never park a task in a non-terminal state, and every requirement whose setup begins
# by parking one — cancel, resubscribe, history, second turn — was reported in busbar's column
# without a single byte of it reaching busbar. ELEVEN MUSTs were in that state. A fixture's silence
# printed as a subject's failure is the same false verdict as a green that judged nothing, and it
# points the other way.
#
# The backend is now `testing/a2a-tck/scenario-agent`, which implements the behaviour contract the
# TCK PUBLISHES for the system it tests — `docs/SUT_REQUIREMENTS.md` and the Gherkin feature files
# that document names as the source of truth — on the A2A project's own Python SDK, at the version
# this repository already pins as its a2a-python control. The behaviour is the suite authors', the
# protocol is the publisher's, and nothing in it mentions, detects or accommodates busbar. It gives
# busbar MORE to get wrong, not less: file, URL and structured-data artifacts, chunked appends, a
# bare Message where no task exists, tasks that stay open across turns.
#
# AND THE COMPARISON IS REBUILT RATHER THAN ABANDONED. The subject number is no longer measured
# against the peer `run-tck.sh control-jsonrpc` judges, so it may not be read against that number.
# `run-tck.sh control-scenario` judges THIS agent directly, with no busbar in the path; that is the
# ceiling this leg can reach and the only control the subject number may be read against.
#
# It is fronted through `signing-vendor.mjs`, which signs the agent's card with an Ed25519 issuer
# key it generates and proxies everything else untouched. That is not a way around any check — see
# that file's header: busbar refuses to approve a registration with no authenticity root, the two
# TLS-rooted mechanisms need a certificate the platform trusts, and a JWS-signed card is the root a
# vendor with no PKI relationship actually offers. busbar performs the whole verification against
# the operator-supplied key and refuses if it fails.
#
# WHAT IS STILL NOT PROVEN HERE, stated rather than left to be discovered:
#
#   * THE DELEGATING DIRECTION. busbar's A2A client side is driven by a relay this rig does not
#     drive from the far end, so `--battery` still runs `--role server`.
#   * THE HTTP+JSON BINDING. busbar's card advertises `JSONRPC` and `GRPC`, so the TCK arms both and
#     skips HTTP+JSON, whose requirements still report as untested rather than as failures busbar has
#     been given a chance to pass. The gRPC leg IS armed: busbar serves `/lf.a2a.v1.A2AService/*` on
#     its own listener over h2c, the card publishes that binding's authority, and the shim in front
#     carries the credential on that connection as well as on the HTTP one.
#   * PUSH DELIVERY. `PUSH-DELIVER-001/002/003` are RED and are WAIVED with the reason recorded in
#     `testing/a2a-tck/WAIVERS.md`. Read that before "fixing the rig's topology": the suite's
#     receiver URL is `http://` by literal and busbar refuses a plaintext webhook before it looks at
#     the address at all, so a non-loopback receiver does not reach the refusal that fires. Two of
#     the three are implementation gaps behind it. Nothing here is silenced — all three still run,
#     still fail, and are still counted in the MUST row below.
#
# MODES
#   --battery    the independent battery (testing/a2a-harness) against the booted subject
#   --tck        the official TCK (testing/a2a-tck) against the booted subject
#   --supplement busbar-authored coverage of requirements the pinned TCK declares and does NOT
#                execute (testing/a2a-supplement). REPORTED SEPARATELY, never added to the TCK
#                number -- see that directory's README for why.
#   --probe [who] boot and prove the boundary only; print the endpoint and stop. `who` is who holds
#                the client credential — `shim` (default, the TCK's topology) or `instrument` (the
#                battery's, with no shim in front of busbar at all).
#   --selftest   prove the arming rule and the boundary proof BITE, before any verdict is trusted
#
# ARMING
#   A2A_SUBJECT_BUSBAR_BIN   THE ARM: a busbar binary built from THIS COMMIT. Not a URL, not a
#                            secret, not a repository variable — a FILE this job just built, so the
#                            leg cannot silently disarm because somebody deleted a variable or let a
#                            deployment lapse. It can only disarm by the build failing, which is
#                            itself red.
#   BUSBAR_A2A_ENDPOINT      an EXTERNAL, already-deployed busbar. OPTIONAL EXTRA only.

set -euo pipefail
# The repository root, two levels up: this file lives in `scripts/a2a-subject/`. Every path below is
# written from the root so the script reads the same whether it is invoked from CI, from the root,
# or from its own directory.
cd "$(dirname "$0")/../.."

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# ARMED OR RED, in one function so it can be tested in one place — the same shape and the same
# reasoning as `mcp-conformance.sh::require_armed`. The death is the point: it is what turns
# `NOT ARMED, SO NOT RUN` from a green tick into a failure.
require_armed() {
  local label="$1"; shift
  local v
  for v in "$@"; do
    if [ -n "${!v:-}" ]; then
      say "   armed by $v"
      return 0
    fi
  done
  printf '\n' >&2
  printf 'FAIL: %s\n' "NOT ARMED, SO NOT RUN — and that is RED." >&2
  cat >&2 <<BANNER

  This leg judges BUSBAR ($label). Disarmed, it judges nothing, and it reports the
  same green tick as a leg that judged busbar and passed. That is the false green
  this whole gate exists to refuse — and it is the state this leg was actually in
  on every run until now — so an unarmed subject leg FAILS.

  Arm it with any ONE of:
BANNER
  for v in "$@"; do printf '      %s=...\n' "$v" >&2; done
  printf '\n' >&2
  exit 1
}

# THE AGENT ID busbar fronts in this rig. One, named, and referenced by every path below so the
# endpoint the suite is pointed at and the registration it reaches cannot drift apart.
SUBJECT_AGENT_ID="conformance"

# FIVE FREE PORTS, asked of the OS rather than hard-coded.
#
# suite-facing | busbar data | busbar admin | the control agent | the signing vendor in front. A hard-coded port is a red that is not
# a defect the first time a runner image happens to have something on it.
subject_free_ports() {
  python3 - <<'PY'
import socket
socks = []
for _ in range(5):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    socks.append(s)
print(" ".join(str(s.getsockname()[1]) for s in socks))
for s in socks:
    s.close()
PY
}

# The smallest config that makes this deployment an A2A server. Everything absent is absent on
# purpose: no providers, no models, no pools. The A2A plane needs none of them, and a subject that
# also carried an LLM fleet would invite a failure that is about the fleet.
#
# `public_url:` IS THE WHOLE MOUNT. `A2aPlane::admission()` answers `None` without it and
# `a2a::ingress::mount` then adds NO ROUTE AT ALL, so a subject missing this line is not an A2A
# server that fails the suite -- it is a busbar the suite cannot see. It names WHATEVER ADDRESS THE
# INSTRUMENT ACTUALLY POSTS TO -- the shim's port when a shim holds the credential, busbar's own
# listener when the instrument holds it (`boot_busbar_a2a_subject`'s parameter) -- because it is
# simultaneously the RFC 8707 resource indicator every token must be minted for and the base of every
# URL the served card publishes: one reading means the address the suite posts to, the audience
# busbar demands, and the endpoint the card advertises cannot drift apart.
#
# `auth.chain: [keys]` IS LOAD-BEARING AND IS THE OPPOSITE OF A SHORTCUT. An empty chain would let
# the mount answer anonymously and every scenario below would run with no credential at all -- the
# false green this file exists to refuse. The chain is closed and the token is real.
#
# `agents.conformance` NAMES THE PINNED CONTROL AGENT, on loopback, behind the signing vendor. Every
# line of it is the operator surface a real deployment uses, and each is written out loud rather
# than defaulted: see the header for why `allow_private:` is honest here and why the trust root is
# `jws_issuer_key` rather than one of the two TLS-rooted mechanisms.
subject_write_config() {
  local dir="$1" public_port="$2" data_port="$3" admin_port="$4" vendor_port="$5" issuer="$6"
  cat > "$dir/providers.yaml" <<'YAML'
# No providers. The A2A plane needs none, and an empty catalog cannot fail for a reason that is
# about a provider.
{}
YAML
  cat > "$dir/config.yaml" <<YAML
listen: "127.0.0.1:$data_port"
admin_listen: "127.0.0.1:$admin_port"
public_url: "http://127.0.0.1:$public_port"
providers: {}
models: {}
pools: {}
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { file: $dir/signing.key }
agents:
  $SUBJECT_AGENT_ID:
    url: "http://127.0.0.1:$vendor_port/"
    allow_private: true
    pin: { mechanism: jws_issuer_key, key: "$issuer" }
YAML
}

# One request to the fronted agent's endpoint, answered with its HTTP status only.
subject_probe_status() {
  local url="$1" bearer="${2:-}"
  local -a auth=()
  [ -n "$bearer" ] && auth=(-H "authorization: Bearer $bearer")
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 "${auth[@]}" "$url"
}

# THE DISPROOF. Five credentials, one process, one endpoint. Four of them MUST be refused, and the
# fifth MUST be admitted — without which the four are equally consistent with a busbar that refuses
# everything, which would make the whole leg vacuous in the other direction.
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
  # token stays the same length and still base64url-decodes — a truncated token would be refused as
  # malformed, which proves the parser works and says nothing about the signature check.
  local tampered last
  last="${bound: -1}"
  if [ "$last" = "A" ]; then tampered="${bound%?}B"; else tampered="${bound%?}A"; fi
  got=$(subject_probe_status "$direct" "$tampered")
  if [ "$got" = "401" ]; then say "     ok:  flipped signature        -> 401"
  else say "     BAD: flipped signature        -> $got (expected 401)"; failures=$((failures+1)); fi

  # THE CONTROL, and the one place this differs from the MCP leg's. MCP requires `200`; here the
  # bar is ADMITTED, because on `dev` the correctly-bound token is admitted by auth and then refused
  # by the TRUST machine with `503 … is not serving (Pending)` — the finding in the header. Pinning
  # `200` would make this script red for the thing the leg is supposed to REPORT, and pinning `503`
  # would make it red on the day the finding is fixed. So the assertion is the one that is true
  # either way — the audience boundary let the right token through — and the status is PRINTED, so
  # nobody has to infer which side of the trust machine answered.
  got=$(subject_probe_status "$direct" "$bound")
  case "$got" in
    401|403|000)
      say "     BAD: token, RIGHT audience    -> $got (expected to be ADMITTED)"
      failures=$((failures+1)) ;;
    *)
      say "     ok:  token, RIGHT audience    -> $got (admitted past the audience check)" ;;
  esac
  SUBJECT_ADMITTED_STATUS="$got"

  [ "$failures" -eq 0 ] || die "the audience boundary did not behave as declared ($failures of 5 \
probes wrong). Either busbar's plane boundary has been weakened — in which case this leg would be \
reporting about a busbar nobody runs, and that is worse than leaving it unarmed — or this harness \
is minting the wrong thing. Either way no verdict from this leg means anything until it is fixed."
}

# THE EXTENDED AGENT CARD, over the real wire, with the real credential — because the official
# suite cannot report on it.
#
# The TCK declares `CARD-EXT-001` and `CARD-EXT-002` and has no test that exercises a WORKING
# extended card: `CORE-CAP-003` only runs when the capability is absent, and `CARD-EXT-002` skips
# itself the moment the card is configured. So a busbar that answers this verb perfectly and a
# busbar that answers it with garbage produce the same TCK output, and the number cannot be the
# instrument for this cell. This is.
#
# Both spellings are driven, because both are live: SPEC 9.1 makes the JSON-RPC name the PascalCase
# rpc name, and SPEC 3.6.2 makes a version-less request 0.3 — whose name is the slash form. An
# implementation that serves one is broken for every client that speaks the other.
#
# AND THE LEAK CHECK IS HERE TOO. The extended card is the ONE busbar document built from several
# vendors' text at once, so the property `serve_tests.rs` walks over a single served card is
# re-asserted here over the merged one, against the real backend authority this rig runs.
report_the_extended_agent_card() {
  local plane_url="$1" bearer="$2" vendor_port="$3"
  local method body

  say "   the extended agent card, asked for in both live spellings of its name:"
  for method in GetExtendedAgentCard agent/getAuthenticatedExtendedCard; do
    body=$(curl -s --max-time 15 \
      -H "authorization: Bearer $bearer" \
      -H 'content-type: application/json' \
      -H 'a2a-version: 1.0' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":\"xcard\",\"method\":\"$method\"}" \
      "$plane_url") || die "the extended agent card request failed outright ($method)"

    # The response travels in the ENVIRONMENT rather than on stdin, because stdin is the script.
    A2A_XCARD_BODY="$body" python3 - "$method" "$vendor_port" <<'PY' || die "the extended agent card is not what busbar declares it serves"
import json, os, sys
method, vendor_port = sys.argv[1], sys.argv[2]
doc = json.loads(os.environ["A2A_XCARD_BODY"])
if "error" in doc:
    print(f"     BAD: {method} -> error {doc['error'].get('code')}: {doc['error'].get('message')}")
    raise SystemExit(1)
card = doc.get("result") or {}
skills = card.get("skills") or []
ids = [s.get("id") for s in skills]
if not card.get("capabilities", {}).get("extendedAgentCard"):
    print(f"     BAD: {method} -> the extended card denies the capability that served it")
    raise SystemExit(1)
if not ids:
    print(f"     BAD: {method} -> the caller is entitled to an agent and the card names none")
    raise SystemExit(1)
# THE BACKEND AUTHORITY, NOWHERE, AT ANY DEPTH. The whole document, as a string.
if f"127.0.0.1:{vendor_port}" in json.dumps(card):
    print(f"     BAD: {method} -> the extended card names the backend authority")
    raise SystemExit(1)
print(f"     ok:  {method} -> entitled agents {ids}, backend authority absent")
PY
  done
}


# Wait for one URL to answer 200, or die naming what did not come up and showing its log.
subject_await() {
  local url="$1" what="$2" log="$3" waited=0
  until [ "$(subject_probe_status "$url")" = "200" ]; do
    waited=$((waited+1))
    [ "$waited" -lt 60 ] || { cat "$log" >&2; die "$what did not come up at $url."; }
    sleep 1
  done
}

# PROMOTE THE REGISTRATION THE WAY AN OPERATOR PROMOTES ONE, and no other way.
#
# `connect` fetches, verifies and REPORTS; it grants nothing, by construction. `approve` is a second,
# explicit act that must echo back the fingerprint `connect` reported — busbar re-fetches and
# re-verifies and refuses if the two disagree. Nothing here approves anything busbar did not itself
# authenticate against the operator's issuer key, and there is no path in this script that writes a
# trust state directly.
subject_promote() {
  local admin_port="$1" admin_token="$2" dir="$3"
  local preview fingerprint
  preview="$(curl -s --max-time 30 -X POST \
    "http://127.0.0.1:$admin_port/api/v1/admin/agents/$SUBJECT_AGENT_ID/connect" \
    -H "authorization: Bearer $admin_token")"
  printf '%s\n' "$preview" > "$dir/connect.json"
  fingerprint="$(printf '%s' "$preview" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("fingerprint") or "")
except Exception:
    print("")')"
  [ -n "$fingerprint" ] || die "\`connect\` reported no fingerprint for \`$SUBJECT_AGENT_ID\`, so \
there is nothing an operator could approve. The preview was: $preview"
  say "   connect: the card verified against the operator's issuer key, fingerprint $fingerprint"

  local approved state
  approved="$(curl -s --max-time 30 -X POST \
    "http://127.0.0.1:$admin_port/api/v1/admin/agents/$SUBJECT_AGENT_ID/approve" \
    -H "authorization: Bearer $admin_token" -H 'content-type: application/json' \
    -d "{\"fingerprint\":\"$fingerprint\"}")"
  printf '%s\n' "$approved" > "$dir/approve.json"
  state="$(printf '%s' "$approved" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("state") or "")
except Exception:
    print("")')"
  [ "$state" = "approved" ] || die "\`approve\` left \`$SUBJECT_AGENT_ID\` in state \`$state\`, so \
busbar fronts nothing and every instrument below would be measuring a 503. The answer was: $approved"
  say "   approve: the registration is APPROVED against the fingerprint the operator saw"
}

# THE CARD BUSBAR SERVES FOR THE AGENT IT FRONTS, waited for rather than assumed.
#
# An approval records the pin; the CARD is cached by the re-verification sweep, which runs on its own
# tick. Until it has, the registration is approved and has no document to match a task shape
# against, so the catalogue excludes it and every submission answers 503. That window is a real
# property of this build and is waited out here rather than papered over — see the report.
subject_await_serving() {
  local url="$1" token="$2" waited=0
  until curl -s --max-time 15 -H "authorization: Bearer $token" "$url" \
        | grep -q '"protocolVersion"'; do
    waited=$((waited+1))
    [ "$waited" -lt 90 ] || die "busbar never served a card for \`$SUBJECT_AGENT_ID\`. The \
registration is approved, so this is the re-verification sweep not having cached the document."
    sleep 2
  done
  say "   busbar serves the fronted agent's card after ${waited}s of sweep"
}

# Boot busbar, obtain a credential for it, and decide WHO HOLDS THAT CREDENTIAL.
# Sets SUBJECT_URL (what the instruments are pointed at), SUBJECT_TOKEN and SUBJECT_PIDS.
#
# ── WHO HOLDS THE CREDENTIAL, AND WHY IT IS NOW A PARAMETER ──
#
#   shim        a credential-holding forwarder sits in front of busbar and attaches the token to any
#               request that arrives without one. The official TCK CANNOT be handed a header —
#               `run_tck.py` takes `--sut-host` and nothing else — so for that instrument this is the
#               only place a client credential can live.
#   instrument  no shim at all: the instrument holds the token itself and busbar's own listener is
#               the endpoint. The independent battery takes `--auth`, so it can.
#
# THIS IS NOT A TOPOLOGY PREFERENCE. It is what `auth.server_challenges_unauthenticated_callers`
# measures. That test asserts SPEC 3.3.2 — "Servers MUST reject requests with invalid or missing
# authentication credentials" — by deliberately STRIPPING its credential and calling `SendMessage`
# anonymously. Behind a shim whose entire job is to attach a credential to any request that carries
# none, that stripped request is re-credentialed one hop later and reaches busbar authenticated: the
# call succeeds, and the battery reports "an unauthenticated SendMessage succeeded" against busbar
# for a request busbar never saw unauthenticated. The rig was answering the question, and answering
# it wrong. busbar's real answer to that request is `401` with an RFC 6750 challenge naming its
# RFC 9728 metadata document, which `prove_the_boundary_is_intact` has been printing in the same run
# all along — the two lines contradicted each other and the rig was the one lying.
#
# So the battery, which can hold its own credential, is pointed straight at busbar and can therefore
# make a genuinely anonymous request. NOTHING about busbar is relaxed either way: the token is the
# same real audience-bound credential, the same five boundary probes run against the same booted
# process, and the same `auth.chain: [keys]` refuses everything else.
#
# `public_url:` FOLLOWS THE ENDPOINT, because it must. It is simultaneously the address the
# instrument posts to, the RFC 8707 audience every token is minted for, and the base of every URL the
# served card publishes — and the instruments CALL THE URL THE CARD ADVERTISES, not the one they were
# handed. Pointing the battery at busbar while the card still advertised the shim would send every
# call back through the shim and change nothing.
boot_busbar_a2a_subject() {
  local credential_held_by="${1:-shim}"
  case "$credential_held_by" in
    shim|instrument) ;;
    *) die "boot_busbar_a2a_subject: unknown credential holder \`$credential_held_by\` (shim|instrument)" ;;
  esac
  local bin="${A2A_SUBJECT_BUSBAR_BIN:?boot_busbar_a2a_subject needs A2A_SUBJECT_BUSBAR_BIN}"
  [ -x "$bin" ] || die "A2A_SUBJECT_BUSBAR_BIN=$bin is not an executable. The subject leg judges a \
busbar built FROM THIS COMMIT; if the build step did not produce one, that is the finding."
  # RESOLVED TO AN ABSOLUTE PATH, HERE, WHERE THE `-x` TEST JUST PASSED AGAINST IT.
  #
  # busbar is launched below from inside `$dir` — deliberately, so its mutable-config overlay lands
  # in the scratch directory — and a RELATIVE arm does not survive that `cd`. The workflow's arm is
  # `A2A_SUBJECT_BUSBAR_BIN: target/debug/busbar`, so every armed run since this leg was written has
  # passed the executable check at the repository root and then died with
  # `.a2a-conformance/subject-run/target/debug/busbar: No such file or directory`. The leg has
  # therefore never booted busbar in CI at all: not a low conformance number, no number, behind an
  # error that reads like a missing build rather than a resolved-in-the-wrong-directory path.
  #
  # Resolved at the point of the check rather than at the point of use, so the file that was proven
  # executable and the file that is executed cannot be two different files.
  case "$bin" in
    /*) ;;
    *) bin="$PWD/$bin" ;;
  esac

  local dir="${A2A_SUBJECT_WORKDIR:-.a2a-conformance/subject-run}"
  rm -rf "$dir"; mkdir -p "$dir"
  dir="$(cd "$dir" && pwd)"

  local suite_port data_port admin_port agent_port vendor_port
  read -r suite_port data_port admin_port agent_port vendor_port <<<"$(subject_free_ports)"
  [ -n "${vendor_port:-}" ] || die "could not obtain five free loopback ports."
  # THE PUBLISHED PORT: the shim's when a shim holds the credential, busbar's own when the
  # instrument does. One value, so the address the suite posts to, the audience busbar demands and
  # the endpoint the card advertises cannot drift apart in either topology.
  local public_port="$suite_port"
  [ "$credential_held_by" = "instrument" ] && public_port="$data_port"
  say "   busbar $data_port · admin $admin_port · suite-facing $public_port"
  say "   scenario agent $agent_port · signing vendor $vendor_port"
  say "   the client credential is held by the $credential_held_by"

  # ── THE AGENT BUSBAR FRONTS: the TCK SCENARIO AGENT, behind the signing vendor. ──
  #
  # WHAT IT REPLACED, AND WHY. This used to be the pinned `a2a-go` control in `--echo` mode, on the
  # reasoning that fronting the same peer the control legs judge makes the gap between the two
  # numbers a gap BUSBAR opened. That reasoning was right about comparability and wrong about
  # coverage. Echo completes every task in a single step, so the suite could never get a task into
  # a non-terminal state, and every requirement that begins by parking a task — cancelling it,
  # resubscribing to it, reading its history, taking a second turn on it — reported against busbar
  # without ever reaching busbar. Eleven MUSTs were in that state. They were not busbar's answers;
  # they were the fixture's silence, printed in busbar's column.
  #
  # WHAT IT IS NOW. `testing/a2a-tck/scenario-agent` implements the behaviour contract the TCK
  # PUBLISHES for the system it tests — `docs/SUT_REQUIREMENTS.md` and the Gherkin feature files it
  # names as the source of truth — on top of the A2A project's own Python SDK at the version this
  # repository already pins as its a2a-python control. Every behaviour in it was specified by the
  # suite's authors, none of it mentions or detects busbar, and the protocol on the wire is the
  # publisher's implementation rather than ours. See that file's header.
  #
  # AND IT MAKES THE SUBJECT HARDER, NOT EASIER. It answers with file, URL and structured-data
  # artifacts, chunked artifact appends, a bare Message where no task was created, and tasks that
  # stay open across turns — every one of them a fresh opportunity for the gateway in front of it
  # to mistranslate, and the suite says so when it does.
  #
  # WHAT THIS COSTS, STATED HERE RATHER THAN DISCOVERED LATER: the subject number is no longer
  # measured against the same peer as `run-tck.sh control-jsonrpc`. `run-tck.sh control-scenario`
  # is the leg that restores the comparison — it judges THIS agent, directly, with no busbar in
  # the path — and it is that number, not the a2a-go one, that the subject number may be read
  # against.
  testing/a2a-tck/scenario-agent/serve.sh "$agent_port" \
    >"$dir/scenario-agent.log" 2>&1 &
  SUBJECT_PIDS="${SUBJECT_PIDS:-}$!"
  subject_await "http://127.0.0.1:$agent_port/.well-known/agent-card.json" \
    "the TCK scenario agent" "$dir/scenario-agent.log"

  # `A2A_SUBJECT_RECORD_UPSTREAM` arms the vendor's request recorder — see that file's header. It is
  # OFF for every leg that does not ask for it, and the vendor is byte-identical in behaviour either
  # way; what it buys is the only vantage point in this rig from which busbar's CLIENT role is
  # observable at all (SPEC 3.6.1). The path is derived here rather than passed in so that it lands
  # in the same scratch directory as every other artefact of this boot.
  SUBJECT_UPSTREAM_RECORD=""
  if [ -n "${A2A_SUBJECT_RECORD_UPSTREAM:-}" ]; then
    SUBJECT_UPSTREAM_RECORD="$dir/upstream-requests.jsonl"
    : > "$SUBJECT_UPSTREAM_RECORD"
  fi
  A2A_VENDOR_RECORD="$SUBJECT_UPSTREAM_RECORD" \
  node scripts/a2a-subject/signing-vendor.mjs "$vendor_port" "$agent_port" "$dir/issuer.spki" \
    >"$dir/signing-vendor.log" 2>&1 &
  SUBJECT_PIDS="$SUBJECT_PIDS $!"
  subject_await "http://127.0.0.1:$vendor_port/.well-known/agent-card.json" \
    "the signing vendor" "$dir/signing-vendor.log"
  local issuer
  issuer="$(cat "$dir/issuer.spki")"
  [ -n "$issuer" ] || die "the signing vendor published no issuer key, so there is no trust root \
for this registration and busbar would correctly refuse to approve it."

  # The signing key. GENERATED BY THIS JOB, which is the whole basis on which it may sign anything:
  # it is not extracted from busbar, and busbar is handed the same bytes rather than the other way
  # round.
  ( umask 077; "$bin" --generate-signing-key > "$dir/signing.key" 2>"$dir/generate-key.log" ) \
    || { cat "$dir/generate-key.log" >&2; die "busbar --generate-signing-key failed."; }

  subject_write_config "$dir" "$public_port" "$data_port" "$admin_port" "$vendor_port" "$issuer"

  # An admin credential for THIS boot only, from the OS CSPRNG. Never a fixed string: the admin
  # plane is loopback-only here, and a fixed token in a public repository is a habit that
  # eventually gets copied somewhere it matters.
  local admin_token
  admin_token="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"

  # Started from `$dir` so the mutable-config overlay busbar writes lands in the scratch directory
  # rather than in the checkout. The REDIRECTION IS ON THE WHOLE SUBSHELL, not on the binary alone:
  # a subshell that inherits this script's stdout keeps that pipe open for as long as busbar lives,
  # and a caller reading our output through a pipe would then hang after the script had finished.
  ( cd "$dir" && BUSBAR_CONFIG="$dir/config.yaml" BUSBAR_ADMIN_TOKEN="$admin_token" \
      exec "$bin" ) >"$dir/busbar.log" 2>&1 &
  local busbar_pid=$!
  SUBJECT_PIDS="$SUBJECT_PIDS $busbar_pid"

  # READINESS BY OBSERVATION, on the plane's OWN unauthenticated metadata document rather than on
  # `/healthz` — `/healthz` answers 503 on a deployment with no pools, which is correct and says
  # nothing about whether the A2A plane mounted. A 200 here proves the mount exists; the audience
  # it publishes is then compared against the one this script minted for, so a `public_url`
  # misreading is caught here instead of as fourteen unexplained 401s later.
  local metadata="http://127.0.0.1:$data_port/.well-known/oauth-protected-resource/a2a"
  local direct="http://127.0.0.1:$data_port/a2a/agents/$SUBJECT_AGENT_ID"
  local waited=0
  until [ "$(subject_probe_status "$metadata")" = "200" ]; do
    kill -0 "$busbar_pid" 2>/dev/null || { cat "$dir/busbar.log" >&2; die "busbar exited during boot."; }
    waited=$((waited+1))
    [ "$waited" -lt 60 ] || { cat "$dir/busbar.log" >&2; die "busbar did not publish A2A \
protected-resource metadata within 60s. Either the plane did not mount — \`agents:\` and \
\`public_url:\` are both required, and either one missing means NO ROUTE AT ALL rather than a \
failing one — or busbar never came up."; }
    sleep 1
  done
  say "   busbar ready after ${waited}s"

  local canonical
  canonical="$(curl -s --max-time 15 "$metadata" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["resource"])')"
  say "   canonical resource, read from busbar's own metadata: $canonical"
  [ "$canonical" = "http://127.0.0.1:$public_port/a2a" ] || die "busbar publishes the audience \
\`$canonical\`, but this rig points the suite at 127.0.0.1:$public_port. A token minted for one and \
spent at the other is refused, and the leg would read as fourteen auth failures instead of as the \
configuration mistake it is."

  # A REAL BINDING, minted the ordinary way through the admin API. The subject and the generation
  # are read back off the token it returns; nothing here invents either, because a subject busbar
  # never minted and a generation that does not match the durable row are both refused — correctly.
  local plain
  plain=$(curl -s --max-time 15 -X POST "http://127.0.0.1:$admin_port/api/v1/admin/keys" \
            -H "authorization: Bearer $admin_token" -H 'content-type: application/json' \
            -d '{"name":"a2a-conformance-subject"}' \
          | python3 -c 'import json,sys
d = sys.stdin.read()
try:
    t = json.loads(d)["token"]
except Exception:
    sys.exit("the admin API did not return a token: %s" % d)
sys.stdout.write(t)') \
    || die "the admin API did not mint a key. Without a real binding there is no subject to bind a \
token to, and a made-up one would be refused."

  # THE MINTER IS THE MCP LEG'S, REUSED RATHER THAN COPIED. busbar's token format is one format
  # across both planes — `governance/signing.rs` verifies MCP's and A2A's identically, and only the
  # `a` (audience) claim differs — so a second copy of it here would be a second thing to keep in
  # step with a wire format, which is precisely the duplication this release has already paid for
  # three times.
  local minter="scripts/mcp-subject/mint-audience-token.mjs"
  [ -f "$minter" ] || die "$minter is missing; the A2A subject leg mints its credential with the \
same helper the MCP leg does, because busbar's token format is one format across both planes."
  local bound wrong
  bound=$(node "$minter" "$dir/signing.key" "$plain" "$canonical") \
    || die "could not mint the audience-bound token."
  # The counterfactual, minted for an audience this deployment is not. Used only to prove the check
  # is live; if it were ever admitted, the plane boundary would be gone.
  wrong=$(node "$minter" "$dir/signing.key" "$plain" "${canonical}-not-this-resource") \
    || die "could not mint the wrong-audience counterfactual."

  # ── A SECOND, DISTINCT PRINCIPAL. ──
  #
  # Minted the same ordinary way, through the same admin verb, differing only in the name — so it
  # is a different SUBJECT with the same audience and the same issuer, which is exactly the pair
  # SPEC 13.1's scoping requirements are about. Nothing about the deployment is relaxed to produce
  # it; two API keys is the most ordinary thing an operator does.
  #
  # WHY IT IS MINTED FOR EVERY BOOT rather than only for the leg that uses it: a credential that
  # only exists when a particular leg runs is a credential nobody notices has stopped working, and
  # the boundary proof below is the place a broken minting shows up cheaply. It is unused by the
  # TCK and battery legs and costs one admin call.
  local plain_b
  plain_b=$(curl -s --max-time 15 -X POST "http://127.0.0.1:$admin_port/api/v1/admin/keys" \
              -H "authorization: Bearer $admin_token" -H 'content-type: application/json' \
              -d '{"name":"a2a-conformance-subject-second-principal"}' \
            | python3 -c 'import json,sys
d = sys.stdin.read()
try:
    t = json.loads(d)["token"]
except Exception:
    sys.exit("the admin API did not return a second token: %s" % d)
sys.stdout.write(t)') \
    || die "the admin API did not mint a SECOND key. AUTH-SCOPE-002 and AUTH-SCOPE-003 cannot be \
decided with one identity — with a single principal an implementation that scopes perfectly and \
one that does not scope at all are observationally identical — so this is fatal rather than a \
reason to run those checks anyway."
  local bound_b
  bound_b=$(node "$minter" "$dir/signing.key" "$plain_b" "$canonical") \
    || die "could not mint the second principal's audience-bound token."
  [ "$bound" != "$bound_b" ] || die "the two principals' tokens are IDENTICAL, so they are not two \
principals. Every scoping check would then be comparing an identity with itself and would pass \
vacuously."

  # ── THE REGISTRATION IS PROMOTED, by the operator verbs, before anything is measured. ──
  subject_promote "$admin_port" "$admin_token" "$dir"
  subject_await_serving "$direct" "$bound"

  prove_the_boundary_is_intact "$direct" "$plain" "$bound" "$wrong"
  report_the_extended_agent_card "http://127.0.0.1:$data_port/a2a" "$bound" "$vendor_port"

  # THE SHIM, for the instrument that cannot be handed a header. `run_tck.py` takes `--sut-host` and
  # nothing else, so for the TCK the credential has to live where a CLIENT holds it: a transparent
  # forwarder that adds `Authorization` only when the request carries none.
  #
  # AND IT IS NOT STARTED FOR AN INSTRUMENT THAT HOLDS ITS OWN CREDENTIAL. "Adds a credential to any
  # request that has none" is precisely what makes an ANONYMOUS request unrepresentable, and one of
  # the battery's server-role MUSTs is that an anonymous request is refused. See this function's
  # header: with the shim in front, that test was reporting on the shim.
  #
  # IT IS THIS PLANE'S OWN AND NO LONGER THE MCP LEG'S, and the reason is the gRPC binding. busbar
  # serves gRPC on the SAME listener as its HTTP bindings, and the address its card publishes for the
  # gRPC interface is derived from the same `public_url` as everything else — so the suite dials ONE
  # port for two protocols, and the MCP leg's shim is an `http.createServer`, i.e. HTTP/1.1 only.
  # `binding-shim.mjs` serves whichever protocol arrived on the connection, relaying gRPC's
  # trailers (where `grpc-status` lives) as well as its headers. See that file's own header.
  local through="http://127.0.0.1:$public_port/a2a/agents/$SUBJECT_AGENT_ID"
  if [ "$credential_held_by" = "shim" ]; then
    node scripts/a2a-subject/binding-shim.mjs "$suite_port" "$data_port" "$bound" \
      >"$dir/credential-shim.log" 2>&1 &
    SUBJECT_PIDS="$SUBJECT_PIDS $!"

    waited=0
    until [ "$(subject_probe_status "$through")" = "$SUBJECT_ADMITTED_STATUS" ]; do
      waited=$((waited+1))
      [ "$waited" -lt 30 ] || {
        cat "$dir/credential-shim.log" >&2
        die "the credential shim never reproduced the status busbar gave the same token directly \
($SUBJECT_ADMITTED_STATUS). That is a finding about the shim, not about busbar."
      }
      sleep 1
    done
    say "   the suite-facing endpoint reaches busbar through a real, verified credential"
  else
    # No hop to verify: the endpoint the instrument is pointed at IS the endpoint the five boundary
    # probes just ran against, and it is the one the card advertises.
    [ "$through" = "$direct" ] || die "the instrument would be pointed at \`$through\` while the \
boundary was proven at \`$direct\`. Two endpoints, one verdict, is how a leg comes to report about a \
busbar nobody probed."
    say "   the instrument holds the credential and reaches busbar with no hop in between"
  fi

  # SET FOR THE CALLER. Deliberately not `local`.
  # shellcheck disable=SC2034
  SUBJECT_URL="http://127.0.0.1:$public_port"
  # shellcheck disable=SC2034
  SUBJECT_AGENT_URL="$through"
  # shellcheck disable=SC2034
  SUBJECT_TOKEN="$bound"
  # shellcheck disable=SC2034
  SUBJECT_TOKEN_B="$bound_b"
  # THE OPERATOR SURFACE OF THIS BOOT. Loopback-only and ephemeral (the token is 24 CSPRNG bytes
  # regenerated every boot), exported so that a check about busbar's role as a CARD VERIFIER can
  # drive the same operator verbs a human drives -- `PUT /agents/{name}` then `connect`. That is
  # busbar's documented admin API, not a back door: CARD-SIGN-004 constrains the verifying party,
  # and the only way to observe a verification from outside is to ask for one.
  # shellcheck disable=SC2034
  SUBJECT_ADMIN_BASE="http://127.0.0.1:$admin_port"
  # shellcheck disable=SC2034
  SUBJECT_ADMIN_TOKEN="$admin_token"
  # shellcheck disable=SC2034
  SUBJECT_VENDOR_URL="http://127.0.0.1:$vendor_port/"
  # shellcheck disable=SC2034
  SUBJECT_DIR="$dir"

  # BUSBAR'S AGENT-CARD ISSUER KEY, read off the ONE channel busbar publishes it on.
  #
  # `main.rs` logs it at plane start, deliberately and with a comment saying why: it is a PUBLIC
  # key, and a pin is only a trust root if a human can read it off the deployment and hand it to a
  # counterparty out of band. Reading it here is that operator step, performed by the rig — NOT a
  # peek inside busbar. Nothing else in this file, and nothing in `testing/a2a-supplement`, reads
  # busbar's source or its private state; the supplement is handed the same base64 string an
  # operator would paste into a counterparty's `pin.key:`.
  #
  # Absence is NOT fatal here, because the TCK and battery legs do not need it. The supplement leg
  # checks for it and fails loudly if it is missing, which is where the failure belongs.
  # shellcheck disable=SC2034
  SUBJECT_ISSUER_KEY="$(python3 - "$dir/busbar.log" <<'PY'
import re, sys
try:
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
except OSError:
    sys.exit(0)
# The log line is ANSI-decorated (`issuer_key<ESC>[2m=<ESC>[0m"..."`), so the pattern skips
# whatever sits between the field name and its value rather than assuming `=` is adjacent.
hits = re.findall(r'issuer_key.{0,20}?"([A-Za-z0-9+/=]{40,})"', text, re.S)
print(hits[-1] if hits else "")
PY
)"
  [ -n "$SUBJECT_ISSUER_KEY" ] \
    && say "   busbar publishes its agent-card issuer key: ${SUBJECT_ISSUER_KEY:0:24}..." \
    || say "   NOTE: busbar published no agent-card issuer key in its log on this boot."
}

reap_subject() { [ -n "${SUBJECT_PIDS:-}" ] && kill $SUBJECT_PIDS 2>/dev/null || true; }

# ---------------------------------------------------------------------------------------------
# The legs.
# ---------------------------------------------------------------------------------------------

# The instruments are pointed at whichever subject is armed. The BINARY is the primary arm; the URL
# is the optional extra, and when it is the only arm the log says out loud that the verdict is about
# somebody's deployment rather than about this commit.
#
# The argument is WHO HOLDS THE CLIENT CREDENTIAL for this leg (`shim` or `instrument`), passed
# straight through to `boot_busbar_a2a_subject`; see its header for why that is a property of the
# instrument rather than of the rig.
arm_subject() {
  local credential_held_by="${1:-shim}"
  require_armed "A2A subject" A2A_SUBJECT_BUSBAR_BIN BUSBAR_A2A_ENDPOINT
  if [ -n "${A2A_SUBJECT_BUSBAR_BIN:-}" ]; then
    boot_busbar_a2a_subject "$credential_held_by"
    trap reap_subject EXIT
  else
    SUBJECT_URL="$BUSBAR_A2A_ENDPOINT"
    SUBJECT_AGENT_URL="$BUSBAR_A2A_ENDPOINT"
    SUBJECT_TOKEN=""
    say "   armed by an EXTERNAL endpoint only: $SUBJECT_URL"
    say "   NOTE: this judges whatever is deployed there, which may not be this commit."
  fi
}

leg_battery() {
  say "== A2A INDEPENDENT BATTERY · SUBJECT leg (busbar) =="
  # THE BATTERY HOLDS ITS OWN CREDENTIAL (`--auth`, below), so no shim stands in front of busbar and
  # the battery can make a request with NO credential at all — which is the only way to observe
  # SPEC 3.3.2, one of the server-role MUSTs it asserts.
  arm_subject instrument
  mkdir -p testing/a2a-harness/reports
  # `--card-url` NAMES THE FRONTED AGENT'S ENDPOINT, and it is not a convenience. busbar mounts the
  # card at `/a2a/agents/{id}` and serves NOTHING at the well-known path on this commit, so without
  # it the battery's preflight stops at "no agent card at any of […]" and exits 3 having run no
  # test — a red with no number, which is the state this whole item exists to end. Naming the real
  # endpoint lets the battery reach busbar and REPORT the well-known gap as one of its own findings
  # rather than as a reason it could not start. Nothing is silenced: `--card-url` changes where the
  # card is looked for, never what is asserted about it.
  #
  # `--role server`: busbar's A2A CLIENT direction is driven by a relay this rig cannot exercise
  # (see the header's finding 2), so a `--client-drive` command would be a lie. The client-role
  # tests report NOT_CONFIGURED and are RED without it, which is the correct answer and is why they
  # are excluded by ROLE here rather than silenced.
  #
  # AND THE NARROWING IS SAID OUT LOUD, HERE AND IN THE BATTERY'S OWN SUMMARY. This is the same
  # shape of hole the MCP battery had: a role-filtered run produces a count with no direction
  # attached to it, and a count with no direction attached gets quoted as if it covered both. The
  # battery now prints `ROLE NOT RUN client -- N scenario(s) ... NOT selected` immediately above its
  # own totals (`a2aht/runner.py::role_audit`), and records it under `meta.role_audit` in the JSON,
  # so no reader and no downstream script can pick up the number without the direction.
  say "   ROLE-NARROWED: --role server. busbar's A2A CLIENT direction is NOT measured by this leg."
  say "   Whatever number the battery prints below is a SERVER-ROLE number. It is not a verdict on"
  say "   the delegating direction, and it must never be quoted as one."
  local rc=0
  ( cd testing/a2a-harness && python3 -m a2aht run \
      --endpoint "$SUBJECT_URL" \
      --card-url "$SUBJECT_AGENT_URL" \
      ${SUBJECT_TOKEN:+--auth "authorization: Bearer $SUBJECT_TOKEN"} \
      --label "subject:busbar" \
      --tier pull-request \
      --role server \
      --json reports/subject.json ) || rc=$?
  say ""
  say "   battery exit $rc"
  # DELIBERATELY NOT BASELINE-COMPARED, for the reason `run-tck.sh` gives for the same decision: a
  # subject baseline would pin our own defects as the expectation.
  #
  # THE TWO REDS ARE NOT THE SAME RED, and conflating them is the failure this item exists to
  # correct. `1` means the battery ran and busbar failed tests — a NUMBER, printed above. `3` means
  # the battery never started, so there is no number at all, which is the state this leg has been in
  # since it was written. They are named separately so a reader of the log can tell "busbar is bad
  # at A2A" from "busbar was never tested".
  case "$rc" in
    0) ;;
    3) die "the battery could not START: busbar served no agent card, so NOTHING WAS TESTED and \
there is no conformance number from this instrument. This is not a low score — it is the absence of \
a score, and it is the exact state A4.4 exists to end. See the header's finding 1: a registration \
booted from YAML is \`Pending\` for ever, so \`/a2a/agents/{id}\` answers 503 and there is no \
card anywhere for the battery to read." ;;
    *) die "the independent battery found defects in busbar's A2A implementation (exit $rc). Read \
the counts line above; it is the number this leg exists to produce." ;;
  esac
}

leg_tck() {
  say "== A2A OFFICIAL TCK · SUBJECT leg (busbar) =="
  # The TCK takes `--sut-host` and nothing else, so its credential lives in the shim.
  arm_subject shim
  local out="${A2A_SUBJECT_TCK_LOG:-.a2a-conformance/tck-subject.txt}"
  mkdir -p "$(dirname "$out")"
  # `run-tck.sh subject` DELIBERATELY EXITS 0 whatever the TCK found — it swallows pytest's status
  # and, for a subject, does no baseline comparison (correctly: a subject baseline would pin our own
  # defects as the expectation). So this leg's verdict cannot be that script's exit code, and the
  # step is piped through `tee` rather than read from `$?`.
  BUSBAR_A2A_ENDPOINT="$SUBJECT_URL" testing/a2a-tck/run-tck.sh subject 2>&1 | tee "$out"
  # SAME PATH ARITHMETIC AS `run-tck.sh`'s own `$OUT` (`${A2A_TCK_OUT:-${A2A_TCK_WORK:-$TMPDIR/a2a-tck-work}/out}`),
  # duplicated rather than sourced because `run-tck.sh` is a `case` dispatcher with no function this
  # script can call standalone. If that arithmetic ever moves, this one has to move with it -- there
  # is no third place either could drift to unnoticed, because `assert_tck_number` below dies loudly
  # when the file it computes is not there.
  local work="${A2A_TCK_WORK:-${TMPDIR:-/tmp}/a2a-tck-work}"
  local report_json="${A2A_TCK_OUT:-$work/out}/subject.json"
  assert_tck_number "$out" "$report_json"
}

# READ THE REQUIREMENT LEVEL, not the transport-parameterised row, and hold it to the PINNED WAIVER
# SET -- and refuse both ways the report can be absent.
#
# WHAT WAS WRONG BEFORE. This function used to read the TCK's own `MUST` table row
# (`83 passed, 26 failed, ... of 114`) and gate on `failed == 0`. That row is not what it looks
# like: `check-baseline.py`'s pinned control run of the SAME TCK against a2a-go, the reference SDK,
# shows the identical shape -- 21 of "26 failed" are MUST requirements the suite marks
# `NOT TESTED` (no scenario in this TCK release exercises them against ANY implementation; verified
# by diffing this run's per-requirement report against `testing/a2a-tck/baselines/`, where those
# same 21 ids read `NOT TESTED` for a2a-go too), folded into the TCK's own "Failed" column by the
# TCK's own summary printer. Reading that row as "busbar failed 26 requirements" was misattributing
# a pinned-suite limitation, shared by the reference implementation, as a busbar defect count. Only
# 5 MUST requirements are ever reported `FAIL` (a real, executed, failing assertion) against busbar:
# `PUSH-DELIVER-001/002/003`, `CARD-EXT-001`, `GRPC-ERR-001` -- exactly the set `WAIVERS.md` names
# and dates.
#
# THE GATE NOW READS `reports/compatibility.json`'s `per_requirement` map (the same file
# `check-baseline.py` diffs the control legs against), which reports ONE status per requirement
# rather than one row per transport parameterisation, and separates truly `NOT TESTED` from `FAIL`.
# `NOT TESTED` requirements are reported, never gated on: they are not evidence about busbar.
# `FAIL` requirements are gated on the PINNED SET in `testing/a2a-tck/subject-waivers.json` --
# anything failing OUTSIDE that pin is RED. `WAIVERS.md` documents more than that pin
# (`CARD-EXT-001` is also marked waived there); this gate deliberately pins only the LOCKED
# `PUSH-DELIVER` trio, so `CARD-EXT-001` and `GRPC-ERR-001` stay RED here -- named, dated, and
# understood in `WAIVERS.md`, not silenced by this gate.
assert_tck_number() {
  local out="$1" report_json="$2"
  local waivers="${3:-testing/a2a-tck/subject-waivers.json}"
  python3 - "$out" "$report_json" "$waivers" <<'PY'
import json, re, sys

out_path, report_path, waivers_path = sys.argv[1], sys.argv[2], sys.argv[3]

text = open(out_path, encoding="utf-8", errors="replace").read()

# The MUST row of the TCK's own level table: │ MUST │ passed │ failed │ skipped │ total │. Still
# read and printed -- it is the suite's own headline number and a reader will look for it -- but it
# is NOT what this gate decides on; see the function's doc comment for why.
row = re.search(r"MUST\s*\D+?(\d+)\s*\D+?(\d+)\s*\D+?(\d+)\s*\D+?(\d+)", text)
if row is None:
    sys.exit(
        "the TCK printed no MUST row, so this leg produced NO NUMBER. An armed leg that executed\n"
        "nothing is the state the old skipping leg would have rotted into: configured, green and\n"
        "vacuous. Read the captured output above for why the suite did not report."
    )
passed, failed, skipped, total = (int(g) for g in row.groups())
print("")
print("A2A OFFICIAL TCK vs busbar (the commit under test), from the suite's own stdout:")
print("  MUST      %d passed, %d failed, %d skipped, of %d  (suite's own row; folds NOT TESTED" % (passed, failed, skipped, total))
print("            into 'failed' -- read on for the requirement-level breakdown this gate uses)")
if total == 0:
    sys.exit("the MUST total is zero: the suite ran nothing. That is not a score.")
print("")
print("  NOTE: the suite ALSO prints `OVERALL COMPATIBILITY: 100.0%` above this table. That figure")
print("  is the per-transport rollup, not the requirement result. Neither it nor the MUST row above")
print("  is this gate's number; both are printed for a human, not read by this script.")

try:
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
except OSError as exc:
    sys.exit(
        "\nno per-requirement report at %s (%s). The MUST row above is the suite's own summary,\n"
        "but this gate needs the requirement-level detail to tell a suite limitation from a busbar\n"
        "defect, and cannot make that call from the summary row alone." % (report_path, exc)
    )
except ValueError as exc:
    sys.exit("\n%s is not valid JSON (%s)." % (report_path, exc))

per = report.get("per_requirement")
if not isinstance(per, dict) or not per:
    sys.exit("\n%s carries no `per_requirement` map. The TCK's report shape changed." % report_path)

with open(waivers_path, encoding="utf-8") as fh:
    pin = json.load(fh)
waived = set(pin.get("waived") or [])
if not waived:
    sys.exit("\n%s pins no waivers at all; refusing to trust an empty pin silently." % waivers_path)

must = {k: v for k, v in per.items() if isinstance(v, dict) and v.get("level") == "MUST"}
not_tested = sorted(k for k, v in must.items() if v.get("status") == "NOT TESTED")
failing = sorted(k for k, v in must.items() if v.get("status") == "FAIL")
unwaived = sorted(k for k in failing if k not in waived)
waived_and_failing = sorted(k for k in failing if k in waived)
waived_but_passing = sorted(k for k in waived if must.get(k, {}).get("status") not in (None, "FAIL"))

print("")
print("  REQUIREMENT-LEVEL BREAKDOWN (%d MUST requirements, %d NOT TESTED, %d FAIL):"
      % (len(must), len(not_tested), len(failing)))
print("    NOT TESTED (suite limitation, not busbar evidence -- confirmed identical against the")
print("    pinned a2a-go control in testing/a2a-tck/baselines/, so this is not gated):")
for r in not_tested:
    print("      %s" % r)
print("    FAIL, PINNED WAIVED (see WAIVERS.md; expected, not gated):")
for r in waived_and_failing:
    print("      %s" % r)
if waived_but_passing:
    print("    PINNED WAIVED BUT NOW PASSING (retire from testing/a2a-tck/subject-waivers.json and")
    print("    WAIVERS.md -- this is good news, not a failure):")
    for r in waived_but_passing:
        print("      %s" % r)
print("    FAIL, UNWAIVED (RED):")
for r in unwaived:
    print("      %s" % r)
if not unwaived:
    print("      (none)")

if unwaived:
    sys.exit(
        "\nbusbar failed %d MUST requirement(s) outside the pinned waiver set: %s.\n"
        "That is the number this leg exists to produce, and it is RED until it is zero or the\n"
        "requirement is waived, dated and reasoned, in WAIVERS.md AND the pin." % (len(unwaived), ", ".join(unwaived))
    )
PY
}

leg_probe() {
  say "== A2A SUBJECT · boundary probe only =="
  arm_subject "${1:-shim}"
  say "   subject endpoint: $SUBJECT_URL"
  say "   fronted agent:    $SUBJECT_AGENT_URL"
  # A held boot, for a human who wants to look at the subject with their own tools. Never used by
  # a gate: it does not terminate.
  if [ -n "${A2A_SUBJECT_HOLD:-}" ]; then
    say "   HOLDING (A2A_SUBJECT_HOLD is set). Artefacts in: $SUBJECT_DIR"
    say "   token A: $SUBJECT_TOKEN"
    say "   token B: ${SUBJECT_TOKEN_B:-}"
    say "   issuer key: ${SUBJECT_ISSUER_KEY:-<none>}"
    while true; do sleep 3600; done
  fi
}

# ---------------------------------------------------------------------------------------------
# THE SUPPLEMENTARY LEG, AND THE ONE RULE THAT GOVERNS IT.
#
# `testing/a2a-supplement` is BUSBAR-AUTHORED. The official TCK is not. Those two numbers are
# reported separately, they are never added, and a supplementary pass is never described as a TCK
# pass. See `testing/a2a-supplement/README.md` for why the suite exists at all and what would have
# to be true for it to stop existing.
#
# WHY THE INSTRUMENT HOLDS THE CREDENTIAL HERE (`arm_subject instrument`, not `shim`). More than
# half of what this suite asserts is about which credential gets in: anonymous, forged, principal
# A, principal B. The credential shim adds an Authorization header to any request that carries
# none, which makes an ANONYMOUS request unrepresentable — with the shim in front, every AUTH-*
# check would be reporting on the shim. This is the same reasoning `leg_battery` gives for the same
# choice, and it is not optional here: it is the difference between measuring busbar and measuring
# a forwarder.
leg_supplement() {
  say "== A2A SUPPLEMENTARY COVERAGE · SUBJECT leg (busbar) =="
  say "   THIS IS NOT THE OFFICIAL TCK NUMBER. It is busbar-authored coverage of requirements the"
  say "   pinned TCK declares and does not execute. The two numbers are reported separately and"
  say "   MUST NOT be added: a suite's author grading their own implementation is weaker evidence"
  say "   than a third party's, and adding the two would launder the weaker into the stronger."
  export A2A_SUBJECT_RECORD_UPSTREAM=1
  arm_subject instrument
  [ -n "${SUBJECT_TOKEN_B:-}" ] || die "no second principal was minted, so the scoping checks \
cannot be decided. See boot_busbar_a2a_subject."
  local rc=0
  # The UPSTREAM vendor's public key, written by the vendor itself at boot. It is the positive
  # control for CARD-SIGN-004: without a key that IS trusted, refusing an untrusted one proves
  # nothing, because a subject that refuses everything would pass.
  A2ASUP_RIGHT_ISSUER_KEY="$(cat "$SUBJECT_DIR/issuer.spki" 2>/dev/null || true)"
  export A2ASUP_RIGHT_ISSUER_KEY
  # THE INTERPRETER IS THE PINNED TCK'S, and that is a deliberate coupling rather than laziness.
  # The supplement drives the gRPC binding, and it does so through `specification/generated/a2a_pb2`
  # -- the stubs the SPECIFICATION publishes -- for the same reason `run-tck.sh` wires the
  # publisher's suite instead of writing a gRPC driver: a hand-rolled protobuf encoder would make
  # the suite test its own encoder. Borrowing the pinned checkout's venv means the proto this
  # instrument speaks and the proto the official one speaks are the same bytes at the same pin,
  # verified in ONE place.
  local tck_dir tck_python
  tck_dir="$(testing/a2a-tck/run-tck.sh prepare | sed -n 's/^A2A_TCK_DIR=//p')"
  tck_python="$(testing/a2a-tck/run-tck.sh prepare | sed -n 's/^A2A_TCK_PYTHON=//p')"
  [ -x "$tck_python" ] || die "the pinned TCK's interpreter is not at \`$tck_python\`. The \
supplement borrows it for the specification's own generated gRPC stubs; without it the gRPC \
binding would have to be hand-encoded, which is the thing neither instrument does."
  ( cd testing/a2a-supplement && PYTHONPATH="$tck_dir:${PYTHONPATH:-}" "$tck_python" -m a2asup \
      --label "subject:busbar" \
      --card-url "$SUBJECT_URL/.well-known/agent-card.json" \
      --token "$SUBJECT_TOKEN" \
      --token-b "$SUBJECT_TOKEN_B" \
      ${SUBJECT_ISSUER_KEY:+--issuer-key "$SUBJECT_ISSUER_KEY"} \
      ${SUBJECT_UPSTREAM_RECORD:+--upstream-record "$SUBJECT_UPSTREAM_RECORD"} \
      ${SUBJECT_ADMIN_BASE:+--admin-base "$SUBJECT_ADMIN_BASE"} \
      ${SUBJECT_ADMIN_TOKEN:+--admin-token "$SUBJECT_ADMIN_TOKEN"} \
      ${SUBJECT_VENDOR_URL:+--verifier-agent-url "$SUBJECT_VENDOR_URL"} \
      --json reports/subject.json ) || rc=$?
  say ""
  say "   supplement exit $rc"
  case "$rc" in
    0) ;;
    3) die "the supplement could not START — it read no usable agent card, so NOTHING was tested \
and there is no number from this instrument. That is the absence of a score, not a low one." ;;
    *) die "the supplementary suite found busbar failing requirements the official TCK does not \
execute. Read the table above; that is the number this leg exists to produce." ;;
  esac
}

# A THIN WRAPPER so the self-test can hand `assert_tck_number` a disposable pin, without the real
# `testing/a2a-tck/subject-waivers.json` (or the real report path arithmetic) anywhere near it.
_assert_tck_number_with_pin() {
  assert_tck_number "$1" "$2" "$3"
}

# --selftest: prove the arming rule and the boundary proof BITE, before any verdict from this
# script is believed. Same discipline as `mcp-conformance.sh --selftest`: a rule whose enforcement
# is only ever exercised by the real thing is a rule nobody has watched work.
selftest() {
  say "== a2a-subject SELF-TEST (the arming rule cannot be lied to) =="
  local failures=0

  # RED 1: nothing armed at all. This is the state the leg was ACTUALLY in on every run until now,
  # so it is the one case that must be watched to fail.
  if ( unset A2A_ARMTEST_A A2A_ARMTEST_B; require_armed "selftest" A2A_ARMTEST_A A2A_ARMTEST_B ) \
       >/dev/null 2>&1; then
    say "  MISS: an unarmed subject leg was accepted"; failures=$((failures+1))
  else
    say "  ok: an unarmed subject leg is RED"
  fi

  # RED 2: an EMPTY variable. An unset repository variable expands to the empty string, not to an
  # unset name, so this is the shape an unarmed CI run actually has.
  if ( export A2A_ARMTEST_A=""; require_armed "selftest" A2A_ARMTEST_A A2A_ARMTEST_B ) \
       >/dev/null 2>&1; then
    say "  MISS: an EMPTY arming variable was accepted as armed"; failures=$((failures+1))
  else
    say "  ok: an empty arming variable is not armed"
  fi

  # GREEN 1 and 2: armed on the FIRST name, and on the SECOND. Both, because a check that only ever
  # reads its first argument would pass every red above and still leave the URL leg unarmable.
  if ( export A2A_ARMTEST_A="x"; require_armed "selftest" A2A_ARMTEST_A A2A_ARMTEST_B ) \
       >/dev/null 2>&1; then
    say "  ok: the first arming variable arms the leg"
  else
    say "  MISS: a leg armed by its first variable was still refused"; failures=$((failures+1))
  fi
  if ( export A2A_ARMTEST_B="x"; require_armed "selftest" A2A_ARMTEST_A A2A_ARMTEST_B ) \
       >/dev/null 2>&1; then
    say "  ok: the second arming variable also arms the leg"
  else
    say "  MISS: a leg armed by its second variable was refused"; failures=$((failures+1))
  fi

  # RED 3: a binary that is not there. The arm is a FILE, so "armed" must mean the file exists and
  # is executable — an arm satisfied by a typo'd path is an arm that disarms silently.
  if ( A2A_SUBJECT_BUSBAR_BIN="/nonexistent/busbar" boot_busbar_a2a_subject ) >/dev/null 2>&1; then
    say "  MISS: a non-existent subject binary was accepted as an arm"; failures=$((failures+1))
  else
    say "  ok: a non-existent subject binary is RED"
  fi

  # RED 4: the boundary proof must FAIL when a refusal turns into an admission. Driven against a
  # local stand-in that answers 200 to everything, which is what a weakened audience check would
  # look like from here.
  local port
  port="$(subject_free_ports | cut -d' ' -f1)"
  python3 - "$port" <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
  local fake=$!
  local waited=0
  until [ "$(subject_probe_status "http://127.0.0.1:$port/")" = "200" ]; do
    waited=$((waited+1)); [ "$waited" -lt 30 ] || break; sleep 1
  done
  if ( prove_the_boundary_is_intact "http://127.0.0.1:$port/" p b w ) >/dev/null 2>&1; then
    say "  MISS: a peer that admits EVERY credential passed the boundary proof"; failures=$((failures+1))
  else
    say "  ok: a peer that admits every credential fails the boundary proof"
  fi
  kill "$fake" 2>/dev/null || true

  # RED 5: TCK output with NO MUST row. This is what a suite that never reported looks like, and it
  # is the one shape that would otherwise let an armed leg pass having produced no number.
  local tmp; tmp="$(mktemp)"
  printf 'OVERALL COMPATIBILITY: 100.0%%\nnothing else at all\n' > "$tmp"
  if ( assert_tck_number "$tmp" "" ) >/dev/null 2>&1; then
    say "  MISS: TCK output carrying no MUST row was accepted as a result"; failures=$((failures+1))
  else
    say "  ok: TCK output with no MUST row produces no number, and is RED"
  fi

  # RED 6: a MUST row is present, but there is no requirement-level report to read. The suite's own
  # row is not this gate's number precisely because it cannot tell a suite limitation from a busbar
  # defect on its own -- so an armed leg that produced only the row and no report is RED, not a pass
  # read off the summary.
  printf 'OVERALL COMPATIBILITY: 100.0%%\n| MUST | 4 | 110 | 0 | 114 |\n' > "$tmp"
  if ( assert_tck_number "$tmp" "$tmp.no-such-report.json" ) >/dev/null 2>&1; then
    say "  MISS: a MUST row with no requirement-level report behind it was accepted"; failures=$((failures+1))
  else
    say "  ok: a MUST row with no requirement-level report behind it is RED"
  fi

  # A minimal, disposable waiver pin used by the next four cases, so they do not depend on --
  # or drift with -- the real testing/a2a-tck/subject-waivers.json.
  local pin; pin="$(mktemp)"
  printf '{"waived": ["PUSH-DELIVER-001"]}\n' > "$pin"
  local report; report="$(mktemp)"

  # RED 7: an UNWAIVED MUST requirement reports FAIL. Red regardless of the suite's own row, and
  # regardless of how many other requirements pass.
  printf '| MUST | 113 | 1 | 0 | 114 |\n' > "$tmp"
  python3 -c "
import json
json.dump({'per_requirement': {
    'SOME-REQ-001': {'level': 'MUST', 'status': 'FAIL'},
}}, open('$report', 'w'))
"
  if _assert_tck_number_with_pin "$tmp" "$report" "$pin"; then
    say "  MISS: an unwaived FAIL requirement was accepted"; failures=$((failures+1))
  else
    say "  ok: an unwaived FAIL requirement is RED"
  fi

  # GREEN 1: the ONLY FAIL requirement is inside the pin. Green, because that failure is expected
  # and dated in WAIVERS.md, not because nothing failed.
  python3 -c "
import json
json.dump({'per_requirement': {
    'PUSH-DELIVER-001': {'level': 'MUST', 'status': 'FAIL'},
}}, open('$report', 'w'))
"
  if _assert_tck_number_with_pin "$tmp" "$report" "$pin"; then
    say "  ok: a FAIL requirement inside the pinned waiver set is accepted"
  else
    say "  MISS: a pinned, waived FAIL requirement was refused"; failures=$((failures+1))
  fi

  # GREEN 2: NOT TESTED requirements are never gated on, however many there are -- they are the
  # suite's own limitation, not evidence about busbar. This is the case that used to be misread as
  # 21 busbar failures.
  python3 -c "
import json
per = {'NOT-TESTED-%03d' % i: {'level': 'MUST', 'status': 'NOT TESTED'} for i in range(21)}
per['PUSH-DELIVER-001'] = {'level': 'MUST', 'status': 'FAIL'}
json.dump({'per_requirement': per}, open('$report', 'w'))
"
  if _assert_tck_number_with_pin "$tmp" "$report" "$pin"; then
    say "  ok: NOT TESTED requirements are reported, not gated on"
  else
    say "  MISS: NOT TESTED requirements were treated as failures"; failures=$((failures+1))
  fi

  # RED 8: an empty pin is refused outright -- an empty waiver file would silently exempt nothing
  # while looking configured, which is a gate that always passes for the wrong reason.
  printf '{"waived": []}\n' > "$pin"
  python3 -c "
import json
json.dump({'per_requirement': {
    'SOME-REQ-001': {'level': 'MUST', 'status': 'PASS'},
}}, open('$report', 'w'))
"
  if _assert_tck_number_with_pin "$tmp" "$report" "$pin"; then
    say "  MISS: an empty waiver pin was accepted"; failures=$((failures+1))
  else
    say "  ok: an empty waiver pin is refused"
  fi
  rm -f "$tmp" "$pin" "$report"

  # GREEN 3: a clean report (no FAIL, no NOT TESTED) is accepted, so none of the checks above is one
  # that refuses everything.
  local tmp2; tmp2="$(mktemp)"; local report2; report2="$(mktemp)"; local pin2; pin2="$(mktemp)"
  printf '| MUST | 114 | 0 | 0 | 114 |\n' > "$tmp2"
  printf '{"waived": ["PUSH-DELIVER-001"]}\n' > "$pin2"
  python3 -c "
import json
json.dump({'per_requirement': {
    'SOME-REQ-001': {'level': 'MUST', 'status': 'PASS'},
}}, open('$report2', 'w'))
"
  if _assert_tck_number_with_pin "$tmp2" "$report2" "$pin2"; then
    say "  ok: a clean requirement-level report is accepted"
  else
    say "  MISS: a clean requirement-level report was refused"; failures=$((failures+1))
  fi
  rm -f "$tmp2" "$report2" "$pin2"

  [ "$failures" -eq 0 ] || die "$failures self-test expectation(s) did not hold. No verdict from \
this script means anything until they do."
  say "  a2a-subject self-test: every arming and boundary expectation held."
}

case "${1:-}" in
  --battery)  leg_battery ;;
  --tck)      leg_tck ;;
  --supplement) leg_supplement ;;
  --probe)    leg_probe "${2:-shim}" ;;
  --selftest) selftest ;;
  *) sed -n '/^# MODES/,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
