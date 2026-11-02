#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Suite `slsa-verifier` (registry id kept; the site matches on it): the signed build attestation of
# each DEV build, verified by cosign (pinned release asset, sha256-checked).
#
# WHY NOT slsa-verifier: it accepts provenance only from slsa-github-generator's reusable workflows,
# signed keyless through GitHub's OIDC identity (verifiers/internal/gha/builder.go at v2.7.1). Actions
# is retired, so dev builds' provenance moves to ModernCI's signed in-toto check output
# (predicateType https://modernci.dev/attestation/check-output/v1, signed with ModernCI's builder
# key; ModernCI RP-7). That is a signed in-toto attestation, NOT SLSA provenance v1.0, and no SLSA
# Build level is claimed. `cosign verify-blob-attestation --key` judges it.
#
# THE SUBJECT'S INPUTS (SLSA-NEEDS.md states what is expected):
#   testing/conformance/modernci-builder.pub   ModernCI's builder PUBLIC key, the trust anchor, committed
#                                              here (never fetched from the place the attestation is)
#   <release>/busbar-linux-x86_64-<sha>  <release>/busbar-linux-aarch64-<sha>
#   <release>/busbar-linux-<sha>.att.json      the DSSE envelope over an in-toto statement whose
#                                              subjects are those binaries' sha256
# The assets must be supplied by the immutable current build (or the explicit fixture directory),
# never selected from a moving historical release. Until the signed source-identity contract and
# native delivery exist the verdict is `not-run` (armed=false), never a pass.
#
# THE THREE LEGS (pass only when all hold):
#   CONTROL           (1) a third-party artifact attested keyless by its project (slsa-verifier's own
#                     v2.7.1 release asset and its published attestation) verifies with the same
#                     cosign verb; (2) the key path used for the subject accepts an attestation of the
#                     check-output type signed by a throwaway key, made here;
#   NEGATIVE CONTROL  the throwaway attestation is refused for a tampered artifact, a wrong key and a
#                     wrong predicate type; on the subject, a tampered binary and a wrong key are
#                     refused, each for the stated reason;
#   SUBJECT           every published dev binary verifies against ModernCI's key and the type.
# The attestation's tlog is not consulted (--insecure-ignore-tlog): a key-signed ModernCI attestation
# is not uploaded to Rekor; the key is the only trust root. A signature and subject digest alone do
# not prove which source was built. RP-7 has no shipped predicate schema or producer yet, so this
# rig cannot promote even a cryptographically valid envelope to a current-source pass.
#
# Test hooks: BUSBAR_DEV_PROVENANCE_DIR=<dir with the assets>, BUSBAR_BUILDER_PUB=<key file>.
set -uo pipefail

: "${CONFORMANCE_OUT:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COSIGN_TAG=v2.6.5
SV_BASE="https://github.com/slsa-framework/slsa-verifier/releases/download/v2.7.1"
PTYPE=https://modernci.dev/attestation/check-output/v1
PUB="${BUSBAR_BUILDER_PUB:-$here/testing/conformance/modernci-builder.pub}"
NOTRUN="dev builds' provenance moves from GitHub to ModernCI-signed attestations (ModernCI RP-7 not shipped)"
EXPECTED_HEAD="${CONF_HEAD:-${MODERNCI_COMMIT:-$(git -C "$here" rev-parse HEAD)}}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
say() { printf 'slsa-verifier: %s\n' "$*" >&2; }

verdict() { # <status> <armed true|false> <reason>
  python3 -I - "$CONFORMANCE_OUT/verdict.json" "$1" "$2" "$3" "$EXPECTED_HEAD" <<'PY'
import json, sys
out, status, armed, reason, head = sys.argv[1:6]
json.dump({"suite": "slsa-verifier", "status": status, "armed": armed == "true",
           "repo": "GetBusbar/busbar", "commit": head, "core_pin": head,
           "standard": "Signed build attestation (in-toto, ModernCI check output)",
           "plan": "cosign verify-blob-attestation of the dev build binaries against ModernCI's builder key",
           "spec_version": "cosign v2.6.5; " + "https://modernci.dev/attestation/check-output/v1",
           "reason": reason}, open(out, "w"), indent=1)
PY
}
fail() { say "FAIL: $*"; verdict fail true "$*"; exit 0; }
notrun() { say "not-run: $*"; verdict not-run false "$*"; exit 0; }

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fetch() { # <url> <sha256> <dest>
  curl -fsSL --retry 3 -o "$3" "$1" || return 1
  [ "$(sha256 "$3")" = "$2" ] || { say "sha256 mismatch for $1"; return 1; }
}

# --- the tool: pinned release asset -----------------------------------------------------------
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  plat=linux-amd64;  sha=c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644 ;;
  Linux-aarch64) plat=linux-arm64;  sha=426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7 ;;
  Darwin-x86_64) plat=darwin-amd64; sha=0f8a1a70c81de9740a2b62e91307ff396ce54e7dd80568d42411bb2d9d44269c ;;
  Darwin-arm64)  plat=darwin-arm64; sha=4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab ;;
  *) fail "no pinned cosign for $(uname -s)-$(uname -m)" ;;
esac
CS="$W/tool/cosign"; mkdir -p "$W/tool"
fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_TAG/cosign-$plat" "$sha" "$CS" \
  || fail "could not fetch the pinned cosign $COSIGN_TAG ($plat)"
chmod +x "$CS"
export COSIGN_PASSWORD=""

# vkey <pub> <envelope> <artifact>: the verb the subject is judged with.
vkey() { "$CS" verify-blob-attestation --insecure-ignore-tlog=true --type "$PTYPE" --key "$1" --signature "$2" "$3"; }

# --- CONTROL 1: a third party's keyless attestation of its own release asset ----------------------
mkdir -p "$W/ctl"
fetch "$SV_BASE/slsa-verifier-linux-amd64" 946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339 "$W/ctl/art" \
  && fetch "$SV_BASE/slsa-verifier-linux-amd64.intoto.jsonl" b567f5ed9a08d0cbddffc169c4ad2d4101abc6b29f9a4c81893a801e432df1f4 "$W/ctl/att.json" \
  || fail "control inputs could not be fetched"
python3 -I - "$W/ctl/att.json" "$W/ctl/cert.pem" <<'PY' || fail "CONTROL: the third-party attestation has no certificate"
import json, sys, base64
e = json.loads(open(sys.argv[1]).readline())
c = e["signatures"][0]["cert"]
open(sys.argv[2], "wb").write(c.encode() if c.startswith("-----") else base64.b64decode(c))
PY
"$CS" verify-blob-attestation --signature "$W/ctl/att.json" --certificate "$W/ctl/cert.pem" --type slsaprovenance \
  --certificate-identity 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.0.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$W/ctl/art" >"$W/c1.log" 2>&1 \
  || { sed 's/^/  /' "$W/c1.log" >&2; fail "CONTROL: cosign refused slsa-verifier v2.7.1's published, attested release asset"; }
cp "$W/ctl/art" "$W/ctl/tam"; printf x >>"$W/ctl/tam"
if "$CS" verify-blob-attestation --signature "$W/ctl/att.json" --certificate "$W/ctl/cert.pem" --type slsaprovenance \
  --certificate-identity 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.0.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$W/ctl/tam" >/dev/null 2>&1; then
  fail "NEGATIVE CONTROL: the tampered third-party artifact was ACCEPTED"
fi
say "control 1 ok: third-party keyless attestation verified, tampered copy refused"

# --- CONTROL 2 + its negatives: the key path, with a throwaway key ---------------------------------
K="$W/key"; mkdir -p "$K"; echo ok >"$K/art"; echo '{"check":"control"}' >"$K/pred.json"
( cd "$K" && "$CS" generate-key-pair >/dev/null 2>&1 && mv cosign.key a.key && mv cosign.pub a.pub \
  && "$CS" generate-key-pair >/dev/null 2>&1 && mv cosign.pub b.pub ) || fail "CONTROL: could not mint the throwaway keys"
"$CS" attest-blob --key "$K/a.key" --predicate "$K/pred.json" --type "$PTYPE" --tlog-upload=false --yes "$K/art" >"$K/env.json" 2>/dev/null \
  || fail "CONTROL: could not make the throwaway attestation"
vkey "$K/a.pub" "$K/env.json" "$K/art" >"$W/c2.log" 2>&1 || { sed 's/^/  /' "$W/c2.log" >&2; fail "CONTROL: the key path refused a good throwaway attestation"; }
cp "$K/art" "$K/tam"; printf x >>"$K/tam"
vkey "$K/a.pub" "$K/env.json" "$K/tam" >"$W/n1.log" 2>&1 && fail "NEGATIVE CONTROL: a tampered artifact was ACCEPTED by the key path"
grep -q 'no matching subject digest' "$W/n1.log" || fail "NEGATIVE CONTROL: the tampered artifact was refused, but not for its digest"
vkey "$K/b.pub" "$K/env.json" "$K/art" >"$W/n2.log" 2>&1 && fail "NEGATIVE CONTROL: a wrong key was ACCEPTED"
grep -q 'do not match threshold' "$W/n2.log" || fail "NEGATIVE CONTROL: the wrong key was refused, but not for the signature"
"$CS" verify-blob-attestation --insecure-ignore-tlog=true --type https://example.invalid/other/v1 --key "$K/a.pub" --signature "$K/env.json" "$K/art" >"$W/n3.log" 2>&1 \
  && fail "NEGATIVE CONTROL: a wrong predicate type was ACCEPTED"
grep -q 'invalid predicate type' "$W/n3.log" || fail "NEGATIVE CONTROL: the wrong type was refused, but not for the type"
say "control 2 ok: key path accepts a good attestation; tampered artifact, wrong key and wrong type refused"

# --- the subject's inputs --------------------------------------------------------------------------
[[ "$EXPECTED_HEAD" =~ ^[0-9a-f]{40}$ ]] || fail "the expected source commit is not a full sha"
[ "${BUSBAR_PIN:-$EXPECTED_HEAD}" = "$EXPECTED_HEAD" ] || fail "this core suite's pin differs from its expected source commit"
[ -s "$PUB" ] || notrun "no ModernCI builder public key at $PUB"
A="$W/asset"; mkdir -p "$A"
if [ -n "${BUSBAR_DEV_PROVENANCE_DIR:-}" ]; then
  cp "$BUSBAR_DEV_PROVENANCE_DIR"/* "$A"/ 2>/dev/null || notrun "BUSBAR_DEV_PROVENANCE_DIR unreadable"
else
  notrun "$NOTRUN; no immutable native attestation delivery for $EXPECTED_HEAD"
fi
sha="$EXPECTED_HEAD"
att="$A/busbar-linux-$sha.att.json"
[ -s "$att" ] || notrun "no attestation for the exact expected source $sha; historical builds cannot qualify"
bins=(); for arch in x86_64 aarch64; do [ -f "$A/busbar-linux-$arch-$sha" ] && bins+=("$A/busbar-linux-$arch-$sha"); done
[ "${#bins[@]}" = 2 ] || fail "SUBJECT: the release holds ${#bins[@]} of the two binaries (x86_64, aarch64) for $sha"
say "subject: attestation candidate for the exact expected source $sha"

# --- NEGATIVE CONTROLS on the subject ------------------------------------------------------------
b0="${bins[0]}"; cp "$b0" "$W/tam"; printf x >>"$W/tam"
vkey "$PUB" "$att" "$W/tam" >"$W/s1.log" 2>&1 && fail "NEGATIVE CONTROL: a tampered busbar binary was ACCEPTED"
grep -q 'no matching subject digest' "$W/s1.log" || fail "NEGATIVE CONTROL: the tampered binary was refused, but not for its digest"
vkey "$K/b.pub" "$att" "$b0" >"$W/s2.log" 2>&1 && fail "NEGATIVE CONTROL: the busbar attestation verified under a wrong key"
grep -q 'do not match threshold' "$W/s2.log" || fail "NEGATIVE CONTROL: the wrong key was refused, but not for the signature"
say "negative controls ok on the subject"

# --- SUBJECT ----------------------------------------------------------------------------------------
for b in "${bins[@]}"; do
  vkey "$PUB" "$att" "$b" >"$W/s.log" 2>&1 \
    || { sed 's/^/  /' "$W/s.log" >&2; fail "SUBJECT: cosign refused $(basename "$b"): $(tail -n1 "$W/s.log" | cut -c1-300)"; }
  say "subject ok: $(basename "$b")"
done
# Do not invent RP-7 predicate fields or treat the artifact's filename as signed source proof.
# Enable a pass only with the producer's published source/repo/builder binding and native receipt.
notrun "${#bins[@]} binary digests and envelope signatures verified for filenames naming $sha; $NOTRUN, so the signed source commit/repo/builder binding is unproved"
