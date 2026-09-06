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
VAULT_PORT="${SELFTEST_VAULT_PORT:-50844}"

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

# ── vault-fixture.py: the secret is served ONLY on the configured path, and only as the ───────────
#    configured FIELD.
# The fixture never read self.path, so every URL returned the secret and the `path` setting in
# probe-secret.sh's reference was decorative: a plugin that ignored it, or hardcoded its own, still
# resolved the value. The envelope also held exactly one key, which made "read the field the config
# names" indistinguishable from "return whichever value is in there".
vault_case() {
  local tok="fixture-selftest-vault-token" val="THE-SECRET-VALUE-selftest" field="api_key"
  local path="secret/data/busbar"

  owe "fixture|vault-path-and-field"
  if ! assert_port_free "$VAULT_PORT"; then
    record "fixture|vault-path-and-field" FAIL "port ${VAULT_PORT} is already in use" \
      "refusing to bind a port something else holds"
    return
  fi
  python3 vault-fixture.py "$VAULT_PORT" "$tok" "$field" "$val" "$path" >/dev/null 2>&1 &
  track_pid $!
  wait_for_http "http://127.0.0.1:${VAULT_PORT}/v1/${path}" 10 >/dev/null 2>&1 || true
  local i=0
  while [ "$i" -lt 50 ] && assert_port_free "$VAULT_PORT"; do sleep 0.1; i=$((i + 1)); done

  get() { curl -sS -m 10 -H "X-Vault-Token: ${1}" "http://127.0.0.1:${VAULT_PORT}/v1/${2}" 2>/dev/null || true; }
  has_secret() { printf '%s' "$1" | grep -q "$val"; }

  local bad="" body
  body="$(get "$tok" "$path")"
  has_secret "$body" || bad="${bad}the CONFIGURED path does not serve the secret; "
  # the field is the configured one, and it is neither the first nor the last key in the envelope —
  # so a plugin taking "the one value in there" cannot be accidentally right
  printf '%s' "$body" | jq -e --arg f "$field" --arg v "$val" '.data.data[$f] == $v' >/dev/null 2>&1 \
    || bad="${bad}the secret is not under the configured field name; "
  printf '%s' "$body" | jq -e --arg f "$field" '(.data.data | keys_unsorted) as $k | ($k | length) >= 3 and $k[0] != $f and ($k | last) != $f' >/dev/null 2>&1 \
    || bad="${bad}the envelope has no decoy before AND after the field, so a first-value or last-value shortcut is indistinguishable from reading the field; "
  # every decoy value must be WRONG, or the decoys forgive the shortcut they exist to catch
  printf '%s' "$body" | jq -e --arg f "$field" --arg v "$val" '[.data.data | to_entries[] | select(.key != $f) | .value] | all(. != $v)' >/dev/null 2>&1 \
    || bad="${bad}a decoy field carries the real secret; "
  # THE PATH
  has_secret "$(get "$tok" "secret/data/some-other-path")" \
    && bad="${bad}a WRONG PATH serves the secret, so the reference's \`path\` setting is unverified; "
  has_secret "$(get "$tok" "${path}-suffixed")" \
    && bad="${bad}a path that merely has the configured path as a PREFIX serves the secret; "
  has_secret "$(get "$tok" "")" \
    && bad="${bad}the ROOT path serves the secret; "
  # THE TOKEN — the one refusal the fixture already had; asserted here so it cannot quietly go away
  has_secret "$(get "wrong-${tok}" "$path")" \
    && bad="${bad}a WRONG TOKEN serves the secret; "

  if [ -z "$bad" ]; then
    record "fixture|vault-path-and-field" PASS \
      "the fixture Vault serves the secret only on the configured path, only under the configured field, only to the token" \
      "wrong path / prefixed path / root / wrong token all refused; decoy fields flank the real one"
  else
    record "fixture|vault-path-and-field" FAIL \
      "the fixture Vault hands the secret to a caller that did not ask correctly, so probe-secret.sh proves nothing about the reference's settings" \
      "${bad}a plugin that ignored \`path\` or \`field\` would resolve the value anyway and pass."
  fi
}

idp_case
vault_case

GATE_NAME="fleet fixture selftest" EXPECTED_IDS="$OWED" LEDGER="$LEDGER" bash "${here}/verdict.sh"
