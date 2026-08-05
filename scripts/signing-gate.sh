#!/usr/bin/env bash
# signing-gate.sh — end-to-end plugin SIGNING VERIFICATION gate.
#
# Proves, against a REAL busbar binary with a REAL (ephemeral) embedded release key, that:
#   1. POSITIVE:  a correctly first-party-signed plugin tarball passes `busbar --validate`
#                 (referenced by the config, strict trust posture: NO allow_unsigned).
#   2. UNSIGNED:  the same tarball packed --allow-unsigned is REFUSED (names allow_unsigned).
#   3. WRONG KEY: the same tarball signed by a DIFFERENT ed25519 key is REFUSED
#                 ("first-party signature failed").
#   4. TAMPERED (lib):      post-signing byte-flip in the cdylib is REFUSED ("integrity").
#   5. TAMPERED (manifest): post-signing manifest edit is REFUSED (signature failed).
#
# Usage:
#   signing-gate.sh <busbar_checkout_dir> <plugin_crate> <plugin_kind> <plugin_alias> <cdylib_path>
# e.g.
#   signing-gate.sh busbarAI busbar-store-valkey-plugin store valkey plugin/target/debug/libbusbar_store_valkey_plugin.so
#
# Requirements: the busbar checkout must be buildable (cargo). python3 + tar for the tamper cases.
# The busbar binary and busbar-plugin-pack are built here WITH the ephemeral key embedded — the
# gate never touches the real release key.
set -euo pipefail

BUSBAR_DIR=$(cd "${1:?busbar checkout dir}" && pwd)
PLUGIN_CRATE=${2:?plugin crate name}
PLUGIN_KIND=${3:?plugin kind (store|auth|hook|secret)}
PLUGIN_ALIAS=${4:?plugin alias}
LIB=$(cd "$(dirname "${5:?cdylib path}")" && pwd)/$(basename "$5")
[ -f "$LIB" ] || { echo "FAIL: cdylib not found: $LIB" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PACK="$BUSBAR_DIR/target/release/busbar-plugin-pack"
BUSBAR="$BUSBAR_DIR/target/release/busbar"

# ── 0. Ephemeral keypair ─────────────────────────────────────────────────────────────────────────
# CI may pre-generate the pair (BUSBAR_GATE_SIGN_KEY/BUSBAR_GATE_PUBKEY) so the busbar binary built
# here — with that public key embedded — is byte-reusable by later workflow steps with no rebuild.
(cd "$BUSBAR_DIR" && cargo build --release -q -p busbar-plugin-pack)
if [ -n "${BUSBAR_GATE_SIGN_KEY:-}" ] && [ -n "${BUSBAR_GATE_PUBKEY:-}" ]; then
  PRIV=$BUSBAR_GATE_SIGN_KEY; PUB=$BUSBAR_GATE_PUBKEY
else
  "$PACK" keygen > "$WORK/keys"
  PRIV=$(sed -n 's/^private.*: //p' "$WORK/keys")
  PUB=$(sed -n 's/^public.*: //p' "$WORK/keys")
fi
[ ${#PRIV} -eq 64 ] && [ ${#PUB} -eq 64 ] || { echo "FAIL: keygen output unparseable" >&2; exit 1; }
echo "gate: ephemeral release pubkey $PUB"

# ── 1. Build busbar with the ephemeral PUBLIC key embedded ───────────────────────────────────────
# option_env!("BUSBAR_RELEASE_PUBKEY") is COMPILE-time; cargo tracks env-var deps of env!/option_env!
# in dep-info, but touch the crate anyway so a cached no-key build can never be reused.
touch "$BUSBAR_DIR/crates/plugin-sign/src/lib.rs"
(cd "$BUSBAR_DIR" && BUSBAR_RELEASE_PUBKEY="$PUB" cargo build --release -q --bin busbar)
BUSBAR_VERSION=$("$BUSBAR" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "gate: busbar $BUSBAR_VERSION built with embedded ephemeral key"

# ── 2. Pack the four artifacts ───────────────────────────────────────────────────────────────────
# Version must be >= the binary's version: a verified first-party plugin below the binary version is
# hard-rejected by the AUTOMATIC first-party anti-downgrade floor (plugin-sign evaluate()).
pack() { # $1=signing key ("" = unsigned) $2=out $3...=extra flags
  local key=$1 out=$2; shift 2
  # env -u guards the unsigned case even when the CI environment carries a real BUSBAR_SIGN_KEY.
  if [ -n "$key" ]; then
    BUSBAR_SIGN_KEY="$key" "$PACK" pack --lib "$LIB" --name "$PLUGIN_CRATE" \
      --alias "$PLUGIN_ALIAS" --kind "$PLUGIN_KIND" --version "$BUSBAR_VERSION" \
      --publisher busbar --license Apache-2.0 --out "$out" "$@"
  else
    env -u BUSBAR_SIGN_KEY "$PACK" pack --lib "$LIB" --name "$PLUGIN_CRATE" \
      --alias "$PLUGIN_ALIAS" --kind "$PLUGIN_KIND" --version "$BUSBAR_VERSION" \
      --publisher busbar --license Apache-2.0 --out "$out" "$@"
  fi
}
pack "$PRIV" "$WORK/signed.tar.gz"
pack ""      "$WORK/unsigned.tar.gz" --allow-unsigned
OTHER_PRIV=$("$PACK" keygen | sed -n 's/^private.*: //p')
pack "$OTHER_PRIV" "$WORK/wrongkey.tar.gz"

# Tampered variants: unpack the SIGNED tarball, mutate, repack (signature/manifest kept as-was).
mkdir "$WORK/t1" "$WORK/t2"
tar -xzf "$WORK/signed.tar.gz" -C "$WORK/t1"
python3 - "$WORK/t1" <<'EOF'
import sys, os
d = sys.argv[1]
lib = next(f for f in os.listdir(d) if f != "manifest.json")
p = os.path.join(d, lib)
b = bytearray(open(p, "rb").read()); b[len(b)//2] ^= 0xFF
open(p, "wb").write(bytes(b))
EOF
# Repack listing members explicitly — busbar rejects any non-regular-file entry (e.g. tar's "./").
tar -czf "$WORK/tampered-lib.tar.gz" -C "$WORK/t1" $(ls "$WORK/t1")
tar -xzf "$WORK/signed.tar.gz" -C "$WORK/t2"
python3 - "$WORK/t2/manifest.json" <<'EOF'
import sys, json
p = sys.argv[1]
m = json.load(open(p)); m["version"] = "999.0.0"   # forge an upgrade post-signing
json.dump(m, open(p, "w"))
EOF
tar -czf "$WORK/tampered-manifest.tar.gz" -C "$WORK/t2" $(ls "$WORK/t2")

# ── 3. Config that REFERENCES the plugin, strict trust posture (no allow_unsigned) ───────────────
mkdir -p "$WORK/plugins"
cat > "$WORK/providers.yaml" <<'EOF'
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
EOF
# The reference must be written in the CURRENT config grammar, per kind. 1.5.3 made two of these
# DEFINE-ONCE maps, and the pre-1.5.3 spellings are now fail-closed boot refusals — which this gate
# felt as its FIRST assertion (`signed-ok`) failing with a CONFIG error instead of a trust verdict,
# i.e. it stopped testing signing at all:
#   * auth — `auth.chain:` is a list of BARE NAMES into `identity-providers:`; a name with no
#     definition there is "auth.chain references '<alias>', which is not defined in
#     `identity-providers:`" (resolve_auth, crates/busbar/src/config/mod.rs). A plugin-backed provider
#     needs only `module:`; `token:` is the built-in admin-tokens credential and is REJECTED on any
#     other module, so it must not appear here.
#   * hook — top-level `global_hooks:` was REMOVED; hooks are a named-definition map (`hooks: <name>:
#     { module: … }`) referenced from `pools.hooks:`. `global_hooks:` is now a detect_legacy_markers
#     hit that refuses to boot.
# store/secret are unchanged. Each kind gets ONLY its own reference: a store or hook invocation must
# not grow a spurious `identity-providers:` entry, which would itself be a dangling-module error.
case "$PLUGIN_KIND" in
  store)  REF=$'store:\n  module: '"$PLUGIN_ALIAS" ;;
  auth)   REF=$'identity-providers:\n  '"$PLUGIN_ALIAS"$':\n    module: '"$PLUGIN_ALIAS"$'\nauth:\n  chain: ['"$PLUGIN_ALIAS"$']' ;;
  hook)   REF=$'hooks:\n  signing-gate-ref:\n    module: '"$PLUGIN_ALIAS"$'\n    kind: tap' ;;
  # kind:secret has no config-reference preflight — the trust verdict is asserted from the
  # --validate summary instead (see the SKIP-mode assertions below).
  secret) REF="" ;;
  *) echo "FAIL: unknown plugin kind '$PLUGIN_KIND'" >&2; exit 1 ;;
esac
cat > "$WORK/config.yaml" <<EOF
listen: "127.0.0.1:0"
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
plugins:
  enabled: true
  dir: '$WORK/plugins'
$REF
EOF

validate() { # runs --validate against whatever is in $WORK/plugins; captures combined output
  rm -f "$WORK/out"
  BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" \
    "$BUSBAR" --validate > "$WORK/out" 2>&1
}
expect() { # $1=case $2=want_rc $3=must-contain regex
  local c=$1 want=$2 re=$3 rc=0
  validate || rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL [$c]: expected exit $want, got $rc"; sed 's/^/    /' "$WORK/out"; exit 1
  fi
  if ! grep -qE "$re" "$WORK/out"; then
    echo "FAIL [$c]: exit $rc as expected but output lacks /$re/"; sed 's/^/    /' "$WORK/out"; exit 1
  fi
  echo "PASS [$c] (exit $rc, matched /$re/)"
}
install_only() { rm -f "$WORK/plugins/"*.tar.gz; cp "$1" "$WORK/plugins/p.tar.gz"; }

# For kind:secret there is no reference, so an UNTRUSTED-but-structurally-valid tarball is skipped
# (exit 0) instead of hard-failing — assert the trust verdict from the summary lines instead.
POS_RC=0; POS_RE='1 validated, 0 skipped'
if [ "$PLUGIN_KIND" = secret ]; then
  UNS_RC=0;  UNS_RE='skipped:.*manifest carries no signature'
  WRK_RC=0;  WRK_RE='skipped:.*first-party signature failed'
  TMM_RC=0;  TMM_RE='skipped:.*first-party signature failed'
else
  UNS_RC=1;  UNS_RE='was not loaded.*(manifest carries no signature|allow_unsigned)'
  WRK_RC=1;  WRK_RE='was not loaded.*first-party signature failed'
  TMM_RC=1;  TMM_RE='was not loaded.*first-party signature failed'
fi

# ── 4. The four assertions ───────────────────────────────────────────────────────────────────────
install_only "$WORK/signed.tar.gz";            expect "signed-ok"         "$POS_RC" "$POS_RE"
install_only "$WORK/unsigned.tar.gz";          expect "unsigned-refused"  "$UNS_RC" "$UNS_RE"
install_only "$WORK/wrongkey.tar.gz";          expect "wrongkey-refused"  "$WRK_RC" "$WRK_RE"
# A sha256/lib-bytes mismatch is a HARD structural failure for every kind, referenced or not:
install_only "$WORK/tampered-lib.tar.gz";      expect "tampered-lib-refused"      1 'integrity'
install_only "$WORK/tampered-manifest.tar.gz"; expect "tampered-manifest-refused" "$TMM_RC" "$TMM_RE"

echo "gate: ALL SIGNING ASSERTIONS PASSED for $PLUGIN_CRATE (kind $PLUGIN_KIND)"
