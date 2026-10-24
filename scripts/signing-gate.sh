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
#   and a RED plant, `plugins.trust.allow_unsigned: true`: under it the unsigned tarball must LOAD
#   (any refusal, for any reason, is RED: the plant did not take) and the unsigned arm must FAIL;
#   without it the same tarball is refused for the signing reason. Otherwise the arm proves nothing.
#   One refusal is the loader's to make under the plant and is asserted instead of the load: a
#   plugin whose Statement DECLARES a need in an egress class the host grants a first-party plugin
#   only (provider, loopback-allowed; operator-infrastructure is any trusted plugin's, so a networked
#   auth plugin LOADS) is refused at that grant, never loaded, when unsigned. For it the arm asserts the signing refusal is gone and that grant refusal,
#   word for word, is the only one; any other refusal is RED as before.
#
# A LINKED ROW ANSWERING THE REFERENCE (busbar links busbar-store-memory, alias `memory`): the
# config's reference then resolves in-process whatever the tarball's fate, so `--validate` exits 0
# with the unsigned tarball skipped, and an exit code cannot tell refusal from acceptance. The gate
# PROBES for that (the config validated with NO tarball installed) and, when a linked row answers,
# judges the refusing arms by the LOADER'S verdict on the tarball under test (the summary line
# naming it skipped, for the trust reason, and nothing validated), never by the config's
# resolution. Without a linked row the refusing arms keep their exit-1 refusal.
#
# Usage:
#   signing-gate.sh <busbar_checkout_dir> <plugin_crate> <plugin_kind> <plugin_alias> <cdylib_path> [<manifest_name>]
#
# <manifest_name> is the signed manifest's `name`, the plugin's identity at load: what its release
# packs (plugins.yaml `manifest_name`, default the repo). Default here: <plugin_crate>. A plugin
# busbar also LINKS carries the linked row's canonical name, so the tarball is the same plugin by
# the other door (one identity whichever door it arrives by), not a claim conflict.
# e.g.
#   signing-gate.sh busbar busbar-store-valkey-plugin store valkey plugin/target/debug/libbusbar_store_valkey_plugin.so
#
# Requirements: the busbar checkout must be buildable (cargo). python3 + tar for the tamper cases.
# The busbar binary and busbar-plugin-pack are built here WITH the ephemeral key embedded — the
# gate never touches the real release key.
#
# package-selector: busbar-secret-env-plugin -- qa/pipeline-checks.json -- the signing-gate check builds this plugin from the fleet busbar-secret-env checkout (cargo --manifest-path into that workspace, resolved from Cargo.lock), where the package exists; it is not a package of this workspace
set -euo pipefail

BUSBAR_DIR=$(cd "${1:?busbar checkout dir}" && pwd)
PLUGIN_CRATE=${2:?plugin crate name}
PLUGIN_KIND=${3:?plugin kind (store|auth|hook|secret)}
PLUGIN_ALIAS=${4:?plugin alias}
LIB=$(cd "$(dirname "${5:?cdylib path}")" && pwd)/$(basename "$5")
MANIFEST_NAME=${6:-$PLUGIN_CRATE}
[ -f "$LIB" ] || { echo "FAIL: cdylib not found: $LIB" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# Where cargo puts what it builds below: CARGO_TARGET_DIR when the caller set one (relative to the
# checkout, where the builds run), else the checkout's own target/. Reading target/ unconditionally
# ran the PREVIOUS build's binaries, or none, under a runner that sets a target dir.
TARGET_DIR=${CARGO_TARGET_DIR:-target}
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$BUSBAR_DIR/$TARGET_DIR" ;; esac
PACK="$TARGET_DIR/release/busbar-plugin-pack"
BUSBAR="$TARGET_DIR/release/busbar"

# ── 0. Ephemeral keypair ─────────────────────────────────────────────────────────────────────────
# CI may pre-generate the pair (BUSBAR_GATE_SIGN_KEY/BUSBAR_GATE_PUBKEY) so the busbar binary built
# here — with that public key embedded — is byte-reusable by later workflow steps with no rebuild.
(cd "$BUSBAR_DIR" && cargo build --release -q -p busbar-plugin-loader --features pack --bin busbar-plugin-pack)
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
touch "$BUSBAR_DIR/crates/plugin-loader/src/sign.rs"
(cd "$BUSBAR_DIR" && BUSBAR_RELEASE_PUBKEY="$PUB" cargo build --release -q --bin busbar)
BUSBAR_VERSION=$("$BUSBAR" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "gate: busbar $BUSBAR_VERSION built with embedded ephemeral key"

# ── 2. Pack the four artifacts ───────────────────────────────────────────────────────────────────
# No --version: the packer stamps the version the plugin's own Statement states, as a release must
# (busbar-plugin-pack refuses a --version the Statement does not state: one version per plugin).
pack() { # $1=signing key ("" = unsigned) $2=out $3...=extra flags
  local key=$1 out=$2; shift 2
  # env -u guards the unsigned case even when the CI environment carries a real BUSBAR_SIGN_KEY.
  if [ -n "$key" ]; then
    BUSBAR_SIGN_KEY="$key" "$PACK" pack --lib "$LIB" --name "$MANIFEST_NAME" \
      --alias "$PLUGIN_ALIAS" --kind "$PLUGIN_KIND" \
      --publisher busbar --license Apache-2.0 --out "$out" "$@"
  else
    env -u BUSBAR_SIGN_KEY "$PACK" pack --lib "$LIB" --name "$MANIFEST_NAME" \
      --alias "$PLUGIN_ALIAS" --kind "$PLUGIN_KIND" \
      --publisher busbar --license Apache-2.0 --out "$out" "$@"
  fi
}
pack "$PRIV" "$WORK/signed.tar.gz"
pack ""      "$WORK/unsigned.tar.gz" --allow-unsigned
OTHER_PRIV=$("$PACK" keygen | sed -n 's/^private.*: //p')
# The FIRST keypair is length-checked above; this one was not, and it is the one that decides what
# the wrong-key case actually tests. `pack` branches on `[ -n "$key" ]`, so an unparseable keygen
# here silently packs the "wrong key" tarball UNSIGNED — a different defect than the one the case
# is named for, asserted against a message about signatures.
[ ${#OTHER_PRIV} -eq 64 ] \
  || { echo "FAIL: second keygen output unparseable — the wrong-key case would be packed UNSIGNED, testing a different defect than its name claims" >&2; exit 1; }
pack "$OTHER_PRIV" "$WORK/wrongkey.tar.gz"

# THE DECLARED FIRST-PARTY NEED, read from the unsigned tarball's own signed manifest: the first need
# its Statement rendering (`manifest.statement`, hex; the format is
# crates/busbar-contract/src/abi/mechanism/rendering.rs's) declares in an egress class the host grants
# a FIRST-PARTY plugin only (crates/plugin-loader/src/sign.rs FIRST_PARTY_EGRESS, the table
# `egress_grant` reads; the classes are busbar_contract::abi::host::conn::connector's EGRESS_*). Printed
# as `<transport>\t<class>`, or nothing for a plugin declaring none (a cold plugin states no
# Statement). This is a FACT about the plugin, never its name: section 5 judges the loader's refusal
# against it, not the other way round. A statement that is not one whole rendering fails the gate.
GRANT_NEED=$(python3 - "$WORK/unsigned.tar.gz" <<'EOF'
import json, struct, sys, tarfile
FIRST_PARTY = {1: "provider", 4: "loopback-allowed"}
with tarfile.open(sys.argv[1]) as t:
    m = json.load(t.extractfile("manifest.json"))
st = m.get("statement")
if st is None:
    sys.exit(0)
if st != st.lower():
    sys.exit("manifest statement is not lowercase hex")
b, at = bytes.fromhex(st), 0
def take(n):
    global at
    if at + n > len(b):
        sys.exit(f"manifest statement is not a Statement rendering: it ends at byte {len(b)}")
    s = b[at:at + n]; at += n; return s
u8 = lambda: take(1)[0]
u32 = lambda: struct.unpack("<I", take(4))[0]
u64 = lambda: struct.unpack("<Q", take(8))[0]
def count():
    n = u32()
    if n > (len(b) - at) // 4:
        sys.exit(f"manifest statement is not a Statement rendering: a count at byte {at - 4}")
    return n
def string():
    return take(u32()).decode("utf-8")
def blob():
    u32(); u32(); take(u32())
strs = lambda: [string() for _ in range(count())]
if take(8) != b"BBSTMT01":
    sys.exit("manifest statement is not a Statement rendering: the magic")
u32(); u32(); u32(); u32()                       # mechanism, kind, kind_abi, max_inflight
string(); string()                               # name, version
for _ in range(count()):                         # families
    string(); string(); string(); strs(); u8()
strs(); u32(); blob(); strs(); blob(); u64()     # diag_ids, kind_tail, extensions, secret_refs, settings_schema, marks
for _ in range(count()): u32(); string()         # mark_words
for _ in range(count()): u32(); string(); string()  # rewrites
for _ in range(count()): string(); u32()         # sections
needs = []
for _ in range(count()):
    u32(); klass = u32(); transport = string()   # direction, egress_class, transport
    string(); string(); string(); blob(); u64()  # auth, target_from, trust_from, details, timeout_ms
    needs.append((klass, transport))
string(); string(); strs(); strs()               # target_from, trust_from, answers, claims
if at != len(b):
    sys.exit(f"manifest statement is not a Statement rendering: trailing bytes at {at}")
for klass, transport in needs:
    if klass in FIRST_PARTY:
        print(f"{transport}\t{FIRST_PARTY[klass]}")
        break
EOF
) || { echo "FAIL: cannot read the declared needs from the unsigned tarball's manifest statement" >&2; exit 1; }

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
#     `identity-providers:`" (resolve_auth, crates/busbar-core/src/config/mod.rs). A plugin-backed provider
#     needs only `module:`; `token:` is the built-in admin-tokens credential and is REJECTED on any
#     other module, so it must not appear here.
#   * hook — top-level `global_hooks:` was REMOVED; hooks are a named-definition map (`hooks: <name>:
#     { module: … }`) referenced from `pools.hooks:`. `global_hooks:` is now a detect_legacy_markers
#     hit that refuses to boot.
# store/secret are unchanged. Each kind gets ONLY its own reference: a store or hook invocation must
# not grow a spurious `identity-providers:` entry, which would itself be a dangling-module error.
# The module is named by the plugin's manifest NAME ($MANIFEST_NAME), never its alias: a build that
# links a plugin answering to the same alias (busbar links busbar-store-memory, alias `memory`)
# keeps the linked row for that alias, so an alias reference would resolve the linked plugin and
# never judge the tarball under test (crates/busbar/tests/cli_validate.rs pins this).
case "$PLUGIN_KIND" in
  store)  REF=$'store:\n  module: '"$MANIFEST_NAME" ;;
  auth)   REF=$'identity-providers:\n  '"$PLUGIN_ALIAS"$':\n    module: '"$MANIFEST_NAME"$'\nauth:\n  chain: ['"$PLUGIN_ALIAS"$']' ;;
  hook)   REF=$'hooks:\n  signing-gate-ref:\n    module: '"$MANIFEST_NAME"$'\n    kind: tap' ;;
  # kind:secret has no config-reference preflight — the trust verdict is asserted from the
  # --validate summary instead (see the SKIP-mode assertions below).
  secret) REF="" ;;
  *) echo "FAIL: unknown plugin kind '$PLUGIN_KIND'" >&2; exit 1 ;;
esac
# A config names its store (Q-STORE = (B), #465): every kind but store, whose reference IS the
# `store:` block above, boots on the compiled-in memory store.
STORE_REF=""
[ "$PLUGIN_KIND" = store ] || STORE_REF=$'store:\n  module: memory'
write_config() { # $1 = extra `plugins:` lines (the RED plant's trust opt-in), else none
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
${1:-}
$STORE_REF
$REF
EOF
}
write_config ""

validate() { # runs --validate against whatever is in $WORK/plugins; captures combined output
  rm -f "$WORK/out"
  # MOCK_KEY must be SET, for the same reason the grammar note above exists. 1.5.3 made `--validate`
  # RESOLVE built-in `env:`/`file:` secret references and exit 1 when one cannot, rather than
  # checking only the reference's shape. The config above names `env: MOCK_KEY`, no CI runner sets
  # it, and so this gate's FIRST assertion (`signed-ok`) failed with a SECRET error instead of a
  # trust verdict: it had stopped testing signing at all, exactly the way the grammar change broke it
  # before. The value is never used for anything; nothing here talks to an upstream.
  MOCK_KEY="${MOCK_KEY:-signing-gate-placeholder}" \
  BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" \
    "$BUSBAR" --validate > "$WORK/out" 2>&1
}
check() { # $1=case $2=want_rc $3...=regexes the output must ALL match; 0 = held, 1 = did not
  local c=$1 want=$2 rc=0 re; shift 2
  validate || rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL [$c]: expected exit $want, got $rc"; sed 's/^/    /' "$WORK/out"; return 1
  fi
  for re in "$@"; do
    if ! grep -qE "$re" "$WORK/out"; then
      echo "FAIL [$c]: exit $rc as expected but output lacks /$re/"; sed 's/^/    /' "$WORK/out"; return 1
    fi
  done
  echo "PASS [$c] (exit $rc, matched $(printf '/%s/ ' "$@"))"
}
expect() { check "$@" || exit 1; }
install_only() { rm -f "$WORK/plugins/"*.tar.gz; cp "$1" "$WORK/plugins/p.tar.gz"; }

# THE LINKED-ROW PROBE: the config validated with NO tarball installed. Exit 0 for a kind whose
# reference is checked (every kind but secret) means a row this build links answers the reference,
# so the refusing arms below cannot be read off the exit code.
rm -f "$WORK/plugins/"*.tar.gz
PROBE_RC=0; validate || PROBE_RC=$?
LINKED=0
if [ "$PLUGIN_KIND" != secret ] && [ "$PROBE_RC" -eq 0 ]; then
  LINKED=1
  echo "gate: a linked row answers the reference to '$MANIFEST_NAME'; the refusing arms are judged by the loader's verdict on the tarball"
fi
# The loader's own skip line for the tarball under test, and nothing validated beside it.
skipped_for() { # $1 = the trust reason's regex
  printf '%s\n' "skipped: $MANIFEST_NAME \\(p\\.tar\\.gz\\) .*$1" '0 validated, 1 skipped'
}

# For kind:secret there is no reference, so an UNTRUSTED-but-structurally-valid tarball is skipped
# (exit 0) instead of hard-failing — assert the trust verdict from the summary lines instead.
POS_RC=0; POS_RE='1 validated, 0 skipped'
if [ "$PLUGIN_KIND" = secret ] || [ "$LINKED" = 1 ]; then
  UNS_RC=0;  mapfile -t UNS_RE < <(skipped_for 'manifest carries no signature')
  WRK_RC=0;  mapfile -t WRK_RE < <(skipped_for 'first-party signature failed')
  TMM_RC=0;  mapfile -t TMM_RE < <(skipped_for 'first-party signature failed')
else
  UNS_RC=1;  UNS_RE=('was not loaded.*(manifest carries no signature|allow_unsigned)')
  WRK_RC=1;  WRK_RE=('was not loaded.*first-party signature failed')
  TMM_RC=1;  TMM_RE=('was not loaded.*first-party signature failed')
fi

# ── 4. The four assertions ───────────────────────────────────────────────────────────────────────
install_only "$WORK/signed.tar.gz";            expect "signed-ok"         "$POS_RC" "$POS_RE"
install_only "$WORK/unsigned.tar.gz";          expect "unsigned-refused"  "$UNS_RC" "${UNS_RE[@]}"
install_only "$WORK/wrongkey.tar.gz";          expect "wrongkey-refused"  "$WRK_RC" "${WRK_RE[@]}"
# A sha256/lib-bytes mismatch is a HARD structural failure for every kind, referenced or not.
# The needle is the two-word phrase plugin-sign's evaluate() actually emits ("library bytes do not
# match the manifest sha256 (integrity failure)"), not the bare word `integrity`. The bare word,
# paired only with exit 1, is satisfied by any boot refusal whose output happens to contain it —
# and this gate has TWICE been reduced to asserting an unrelated exit-1 refusal (the 1.5.3 config
# grammar break, then the --validate secret-resolution change), each time still printing PASS while
# testing nothing about signing. A one-word needle is how that keeps being possible.
install_only "$WORK/tampered-lib.tar.gz";      expect "tampered-lib-refused"      1 'integrity failure'
install_only "$WORK/tampered-manifest.tar.gz"; expect "tampered-manifest-refused" "$TMM_RC" "${TMM_RE[@]}"

# ── 5. RED: the unsigned arm must FAIL when the loader ACCEPTS the unsigned tarball ─────────────
# The plant is `plugins.trust.allow_unsigned: true`, and the arm asserts the outcome it plants, not
# merely that the unsigned arm stops passing:
#   a. under the plant the unsigned tarball LOADS, judged exactly as the signed one is (`signed-ok`'s
#      exit and summary). Any refusal here, for whatever reason, makes the arm itself RED with the
#      loader's output shown: the plant did not take, so nothing below proves anything. (Before
#      this, only (b) was asked, and a refusal for another reason satisfied it: hook-webrequest's
#      unsigned tarball is refused for an egress class under allow_unsigned, and the arm passed.)
#   b. under the plant the unsigned arm FAILS: its expectations are not met by an accepted tarball,
#      so it cannot be satisfied by a linked row or a config error.
#   c. without the plant the same tarball is refused again, for the signing reason (the unsigned
#      arm's own expectations), so the one difference between (a) and (c) is the trust posture.
# (a) has ONE exception, decided by the plugin's DECLARED needs (GRANT_NEED above), never by the
# refusal under judgment: a plugin declaring a need in a first-party egress class is admitted on
# trust under the plant and then refused at the egress-class grant (crates/plugin-loader/src/
# registry.rs phase 2b, sign::egress_grant), because it is not first-party. It can never load
# unsigned, so for it (a) becomes:
#   a'. under the plant the signing refusal is GONE (no "manifest carries no signature", no
#       "refusing to load an unsigned plugin", no allow_unsigned text), and the ONLY refusal is the
#       grant's, word for word, naming this plugin and the first first-party need it declares. Any
#       other refusal, alone or beside it, is RED exactly as in (a).
write_config $'  trust:\n    allow_unsigned: true'
install_only "$WORK/unsigned.tar.gz"
if [ -z "$GRANT_NEED" ]; then
  if ! check "unsigned-loads (planted: allow_unsigned)" "$POS_RC" "$POS_RE"; then
    echo "FAIL [unsigned-refused RED]: under allow_unsigned the unsigned tarball did not load (output above), so the plant proves nothing about signing"
    exit 1
  fi
else
  GRANT_TRANSPORT=$(printf '%s' "${GRANT_NEED%%$'\t'*}" | sed 's/[][\.*^$(){}?+|/]/\\&/g')
  GRANT_CLASS=${GRANT_NEED#*$'\t'}
  GRANT_REASON="plugin '$MANIFEST_NAME' declares a \`$GRANT_TRANSPORT\` need in the \`$GRANT_CLASS\` egress class, which the host grants to a first-party plugin only"
  echo "gate: '$MANIFEST_NAME' declares a \`${GRANT_NEED%%$'\t'*}\` need in the \`$GRANT_CLASS\` egress class (first-party only): under allow_unsigned its only refusal must be that grant"
  if [ "$PLUGIN_KIND" = secret ] || [ "$LINKED" = 1 ]; then
    GRANT_RC=0
    GRANT_RE=("^    skipped: $MANIFEST_NAME \\(p\\.tar\\.gz\\) — $GRANT_REASON\$" '0 validated, 1 skipped')
    REFUSALS='^    skipped: '
  else
    GRANT_RC=1
    GRANT_RE=("^\\[error\\] BUSBAR-6009: .* \\(p\\.tar\\.gz\\) but (it )?was not loaded: $GRANT_REASON\$")
    REFUSALS='was not loaded|^\[error\]'
  fi
  if ! check "unsigned-refused-only-at-the-egress-grant (planted: allow_unsigned)" "$GRANT_RC" "${GRANT_RE[@]}"; then
    echo "FAIL [unsigned-refused RED]: under allow_unsigned the unsigned tarball was not refused at the egress-class grant its Statement declares (output above), so the plant proves nothing about signing"
    exit 1
  fi
  if grep -qE 'manifest carries no signature|refusing to load an unsigned plugin|allow_unsigned' "$WORK/out"; then
    echo "FAIL [unsigned-refused RED]: under allow_unsigned the signing refusal is still present beside the egress-class grant"; sed 's/^/    /' "$WORK/out"
    exit 1
  fi
  if [ "$(grep -cE "$REFUSALS" "$WORK/out")" -ne 1 ]; then
    echo "FAIL [unsigned-refused RED]: under allow_unsigned the egress-class grant is not the only refusal"; sed 's/^/    /' "$WORK/out"
    exit 1
  fi
fi
if check "unsigned-refused (planted: allow_unsigned)" "$UNS_RC" "${UNS_RE[@]}"; then
  echo "FAIL [unsigned-refused RED]: an unsigned tarball the loader ACCEPTED still passed the unsigned arm"
  exit 1
fi
write_config ""
install_only "$WORK/unsigned.tar.gz"
expect "unsigned-refused (plant removed)" "$UNS_RC" "${UNS_RE[@]}"
if [ -z "$GRANT_NEED" ]; then
  echo "PASS [unsigned-refused RED] (the unsigned tarball loads under allow_unsigned, the arm fails there, and it is refused for the signing reason without it)"
else
  echo "PASS [unsigned-refused RED] (under allow_unsigned the signing refusal is gone and the declared egress-class grant is the only refusal, the arm fails there, and it is refused for the signing reason without it)"
fi

# ── 6. With NO linked row answering, an unsigned tarball the config references still EXITS 1 ─────
# The same unsigned artifact under a name and alias no row this build links claims, referenced by
# the config: nothing in-process can answer, so the strict posture's refusal is the exit code, as
# it is for every plugin busbar does not link (secret: no reference preflight, so not this kind).
if [ "$PLUGIN_KIND" != secret ]; then
  UNLINKED="signing-gate-unlinked-$PLUGIN_ALIAS"
  env -u BUSBAR_SIGN_KEY "$PACK" pack --lib "$LIB" --name "$UNLINKED" --alias "$UNLINKED" \
    --kind "$PLUGIN_KIND" --publisher busbar --license Apache-2.0 \
    --out "$WORK/unlinked-unsigned.tar.gz" --allow-unsigned
  KEEP_REF=$REF
  REF=${REF//"$MANIFEST_NAME"/"$UNLINKED"}
  write_config ""
  install_only "$WORK/unlinked-unsigned.tar.gz"
  expect "unsigned-refused (no linked row)" 1 'was not loaded.*(manifest carries no signature|allow_unsigned)'
  REF=$KEEP_REF
  write_config ""
fi

echo "gate: ALL SIGNING ASSERTIONS PASSED for $MANIFEST_NAME ($PLUGIN_CRATE, kind $PLUGIN_KIND)"
