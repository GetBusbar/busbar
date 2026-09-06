#!/usr/bin/env bash
# testing/fleet-fixtures/fixture-selftest.sh — the probes' fixtures, held to the probes' own bar.
#
# A FIXTURE THAT CANNOT SAY NO MAKES THE PROBE VACUOUS. vault-fixture.py and mock-upstream.py both
# state that rule in their own headers, and it is the whole reason those two check a token: a backend
# that hands the secret to anyone lets a plugin that sends no token pass, and an upstream that
# accepts any key lets a busbar that never resolved the credential pass. The rule is not specific to
# those two files — it is the property EVERY fixture in this directory has to have, because a probe
# can only be as sharp as the thing it points at.
#
# Nothing was checking that the fixtures still had it. The probes need a real busbar binary and real
# packed plugins to run, so the fixtures' own refusals were exercised only as a side effect of a full
# probe run, on a machine that had both — which is to say, in practice, never on a laptop, and never
# at all for the arms no probe drove. This file closes that: every case below drives a fixture
# DIRECTLY over HTTP and asserts what it refuses, with no busbar and no plugins anywhere.
#
# Decided through the SAME ledger-and-verdict inversion every gate in this tree uses (lib.sh +
# verdict.sh), for the same three reasons: no case can mask another, an owed case that recorded
# nothing is DID NOT RUN rather than a pass, and ZERO ROWS IS RED.
#
# Usage: fixture-selftest.sh            (no arguments, no docker, no network, no busbar)
#   Ports are the 508xx fixture-selftest band and are PROVEN free before anything binds them; they
#   are deliberately clear of the probes' 180xx defaults and of the shadow oracle's 487xx/496xx.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
here="$(pwd)"
repo="$(cd "${here}/../.." && pwd)"

WORK="${repo}/.qa-work/fixture-selftest"
rm -rf "$WORK"; mkdir -p "$WORK"
export LEDGER="${WORK}/ledger.tsv"; : >"$LEDGER"
export GATE_NAME="fleet fixture selftest"
# shellcheck source=testing/fleet-fixtures/lib.sh
. ./lib.sh

IDP_PORT="${SELFTEST_IDP_PORT:-50843}"

OWED=""
owe() { OWED="${OWED} $1"; }

need() {  # need <cmd> — a missing tool is RED, never a skip: an unrun case is not a pass
  command -v "$1" >/dev/null 2>&1 && return 0
  record "fixture|tooling" FAIL "${1} is required by the fixture selftest and is missing" \
    "install ${1}; a case that could not run is not a case that passed"
  return 1
}
need jq || { EXPECTED_IDS="fixture|tooling" bash "${here}/verdict.sh"; exit $?; }
need openssl || { EXPECTED_IDS="fixture|tooling" bash "${here}/verdict.sh"; exit $?; }

# ── stub-idp.py: the issuer must mint credentials that MUST BE REFUSED ───────────────────────────
# The fixture used to serve exactly one token and it was always valid, so every credential
# probe-auth.sh could present was one that SHOULD be accepted — and an `oidc` provider that fetched
# no JWKS, verified no signature and read neither `exp` nor `aud` passed the probe byte-for-byte.
# Each arm below is wrong in exactly ONE way and correct in every other, so a probe's refusal names
# the property that was checked. This case asserts the fixture actually produces them, using real
# RS256 verification against the key the fixture itself publishes (jwk-verify.py) rather than
# trusting the arm's name.
idp_case() {
  local iss="http://127.0.0.1:${IDP_PORT}/" aud="fixture-selftest-aud" sub="fixture-selftest-sub"
  local w="${WORK}/idp"; mkdir -p "$w"

  owe "fixture|idp-refusal-arms"
  if ! assert_port_free "$IDP_PORT"; then
    record "fixture|idp-refusal-arms" FAIL "port ${IDP_PORT} is already in use" \
      "refusing to bind a port something else holds; the case would be reporting on another process"
    return
  fi
  python3 stub-idp.py "$IDP_PORT" "http://127.0.0.1:${IDP_PORT}" "$iss" "$aud" "$sub" groups eng \
    >"${w}/idp.log" 2>&1 &
  track_pid $!
  if ! wait_for_http "http://127.0.0.1:${IDP_PORT}/jwks" 10; then
    record "fixture|idp-refusal-arms" FAIL "the stub IdP did not come up" "$(tail -c 300 "${w}/idp.log")"
    return
  fi
  curl -fsS -m 10 "http://127.0.0.1:${IDP_PORT}/jwks" -o "${w}/jwks.json" 2>/dev/null

  local bad=""
  # arm | must the signature verify | claim assertion (jq over the decoded payload)
  check_arm() {  # check_arm <path> <expect-verify:yes|no> <jq-claim-predicate> <what>
    local path="$1" expect="$2" pred="$3" what="$4" tok payload rc
    tok="$(curl -fsS -m 10 "http://127.0.0.1:${IDP_PORT}${path}" 2>/dev/null || true)"
    if [ -z "$tok" ]; then bad="${bad}${path}(no token) "; return; fi
    payload="$(python3 jwk-verify.py "${w}/jwks.json" "$tok" 2>/dev/null)"; rc=$?
    if [ "$rc" -ge 2 ]; then bad="${bad}${path}(not a JWT) "; return; fi
    if [ "$expect" = yes ] && [ "$rc" != 0 ]; then bad="${bad}${path}(signature does not verify, it must) "; return; fi
    if [ "$expect" = no ] && [ "$rc" = 0 ]; then bad="${bad}${path}(signature VERIFIES against the published JWKS, so ${what} is not what it claims to be) "; return; fi
    printf '%s' "$payload" | jq -e "$pred" >/dev/null 2>&1 || bad="${bad}${path}(${what}) "
  }

  local now; now="$(date +%s)"
  # the positive control: verifies, right audience, not expired
  check_arm /mint yes ".aud == \"${aud}\" and .exp > ${now}" "the happy-path token is not a valid, correctly-audienced, unexpired token"
  # bad signature: NOT verifiable, and wrong in nothing else
  check_arm /mint/bad-signature no ".aud == \"${aud}\" and .exp > ${now}" "the bad-signature arm"
  # expired: verifiable, right audience, exp in the past
  check_arm /mint/expired yes ".aud == \"${aud}\" and .exp < ${now}" "the expired arm is not expired, or is wrong in some second way"
  # wrong audience: verifiable, not expired, different aud
  check_arm /mint/wrong-audience yes ".aud != \"${aud}\" and .exp > ${now}" "the wrong-audience arm has the right audience, or is wrong in some second way"

  # AND AN UNKNOWN ARM IS 404, NOT A VALID TOKEN. A fixture that answered /mint/expierd with the
  # happy-path token would silently turn a probe's refusal arm back into the positive control.
  local typo; typo="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${IDP_PORT}/mint/expierd" 2>/dev/null || echo 000)"
  [ "$typo" = "404" ] || bad="${bad}/mint/<typo>(answered HTTP ${typo}, not 404) "

  if [ -z "$bad" ]; then
    record "fixture|idp-refusal-arms" PASS \
      "the stub IdP mints a valid token AND three that a verifier must refuse" \
      "bad-signature (key not in its own JWKS), expired, wrong-audience; an unknown /mint arm is 404"
  else
    record "fixture|idp-refusal-arms" FAIL \
      "the stub IdP cannot produce a credential that must be refused, so probe-auth.sh's exchange proves nothing" \
      "${bad}— an issuer whose every token is valid lets an oidc provider that verifies nothing pass the probe byte-for-byte"
  fi
}

idp_case

GATE_NAME="fleet fixture selftest" EXPECTED_IDS="$OWED" LEDGER="$LEDGER" bash "${here}/verdict.sh"
