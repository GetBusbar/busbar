#!/usr/bin/env bash
# plugin-pack-release.sh - the BUILD half of a first-party plugin release (SECURITY-FIRST-PLAN C1).
#
# Builds every plugin a release pins and packs it UNSIGNED, beside the bytes the owner signs. No
# signing key is read or needed here. The ModernCI check `plugin-pack` (.ci/dev.yaml) runs it and
# keeps <out-dir> as its stored output, so the publish check (`plugin-publish`, `needs:` this one)
# signs exactly these bytes and never a rebuild.
#
# Usage:
#   scripts/plugin-pack-release.sh <pins.tsv> <out-dir>
#
# <pins.tsv> holds one line per plugin: `<repo>\t<40-hex commit>`. <repo> is a plugins.yaml entry,
# and the commit is that repo's release commit. The plugin's version is the one its Statement
# states (the packer stamps it), so the pin names a commit only.
#
# <out-dir> receives:
#   unsigned/<asset_prefix>-<version>-<triple>.tar.gz   the unsigned tarball
#   canonical/<asset>.canonical                         its manifest's canonical bytes: what the owner signs
#   CANONICAL.SHA256SUMS                                each .canonical's sha256
#
# The target is this machine's host triple: a ModernCI backend is Linux. The darwin targets need a
# Mac backend (ModernCI #1728), and the release's other targets need a backend each.
set -euo pipefail

usage="usage: plugin-pack-release.sh <pins.tsv> <out-dir>"
PINS="${1:?$usage}"; OUT="${2:?$usage}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$(command -v python3 || command -v python)"
die() { echo "plugin-pack-release: $*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

[ -f "$PINS" ] || die "no pins file: $PINS"
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then die "$OUT is not empty"; fi
mkdir -p "$OUT/unsigned" "$OUT/canonical"
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
case "$TRIPLE" in *-apple-darwin) LIBEXT=dylib ;; *) LIBEXT=so ;; esac
WORK="$(mktemp -d "${TMPDIR:-/tmp}/plugin-pack-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The packer from THIS tree. It packs unsigned, so the key list it embeds is not consulted here.
(cd "$ROOT" && cargo build --release --locked -q -p busbar-plugin-loader --features pack --bin busbar-plugin-pack)
PACK="${CARGO_TARGET_DIR:-$ROOT/target}/release/busbar-plugin-pack"
[ -x "$PACK" ] || die "no packer at $PACK"

# Every pin resolved against plugins.yaml: one tab-separated line per pin with the pack inputs, in
# the pins file's order. Refuses a repo plugins.yaml does not register, a pending_crate repo, a
# malformed commit and a repo pinned twice.
"$PY" - "$ROOT/plugins.yaml" "$PINS" >"$WORK/plan.tsv" <<'PYEOF'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
try:
    import yaml  # type: ignore
    plugins = yaml.safe_load(text).get("plugins") or []
except ModuleNotFoundError:
    # The plain parser plugin-registry-check.sh uses, plus `[a, b]` lists.
    plugins, cur, section = [], None, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if re.match(r"^\S", line):
            section = line.rstrip(":")
            continue
        if section != "plugins":
            continue
        m = re.match(r"^  - (\w+):\s*(.*)$", line)
        if m:
            cur = {m.group(1): m.group(2).strip().strip('"')}
            plugins.append(cur)
            continue
        m = re.match(r"^    (\w+):\s*(.*)$", line)
        if m and cur is not None:
            v = m.group(2).strip()
            if v.startswith("[") and v.endswith("]"):
                v = [x.strip().strip('"') for x in v[1:-1].split(",") if x.strip()]
            else:
                v = v.strip('"')
            cur[m.group(1)] = v
by_repo = {p["repo"]: p for p in plugins}
seen, bad = set(), []
for n, raw in enumerate(open(sys.argv[2], encoding="utf-8"), 1):
    line = raw.split("#", 1)[0].strip()
    if not line:
        continue
    parts = line.split("\t")
    if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{40}", parts[1]):
        bad.append(f"pins line {n}: not <repo>\\t<40-hex commit>")
        continue
    repo, commit = parts
    p = by_repo.get(repo)
    if p is None:
        bad.append(f"pins line {n}: {repo} is not in plugins.yaml")
        continue
    if str(p.get("pending_crate", "")).lower() == "true":
        bad.append(f"pins line {n}: {repo} is pending_crate (no crates to build)")
        continue
    if repo in seen:
        bad.append(f"pins line {n}: {repo} is pinned twice")
        continue
    seen.add(repo)
    former = p.get("former_names") or []
    if isinstance(former, str):
        former = [former]
    kind_name = repo[len("busbar-"):]
    def f(k):
        v = p.get(k, "")
        return "" if v is None else str(v).lower() if isinstance(v, bool) else str(v)
    # \x1f, not a tab: bash `read` collapses runs of a whitespace IFS, which would shift an empty field.
    print("\x1f".join([
        repo, commit, p["crate"], p["kind"], p["alias"],
        f("manifest_name") or repo, f("asset_prefix") or repo, f("description"),
        f("lib_only") or "false", f("needs_prompt"), f("needs_user"), f("declares"),
        " ".join(former), f("lang") or "rust", kind_name,
    ]))
if bad:
    sys.exit("\n".join(bad))
if not seen:
    sys.exit("the pins file pins no plugin")
PYEOF

while IFS=$'\x1f' read -r repo commit crate kind alias name prefix desc lib_only n_prompt n_user declares former lang cdir; do
  echo "== $repo @ $commit"
  src="$WORK/src/$repo"
  git clone -q "https://github.com/GetBusbar/$repo.git" "$src"
  git -C "$src" -c advice.detachedHead=false checkout -q "$commit"
  lib_name="lib${crate//-/_}.$LIBEXT"
  lib_dir="$WORK/target/$repo/release"
  if [ "$lang" = c ]; then
    mkdir -p "$lib_dir"
    cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -shared -fPIC -I "$ROOT/crates/busbar-contract/include" \
      -o "$lib_dir/$lib_name" "$src/$cdir"/*.c
  else
    flags=(--release --locked -p "$crate" --target-dir "$WORK/target/$repo")
    [ "$lib_only" = true ] && flags+=(--lib)
    if cargo metadata --format-version 1 --no-deps --manifest-path "$src/Cargo.toml" \
        | "$PY" -c 'import json,sys; sys.exit(0 if any(p["name"]==sys.argv[1] and "dropped-in" in p["features"] for p in json.load(sys.stdin)["packages"]) else 1)' "$crate"; then
      flags+=(--features dropped-in)
    fi
    (cd "$src" && cargo build "${flags[@]}")
  fi
  [ -f "$lib_dir/$lib_name" ] || die "$repo: no library at $lib_dir/$lib_name"

  extra=(--allow-unsigned)
  [ -n "$n_prompt" ] && extra+=(--needs-prompt "$n_prompt")
  [ -n "$n_user" ] && extra+=(--needs-user "$n_user")
  if [ -n "$declares" ]; then
    [ -f "$src/$declares" ] || die "$repo: declares file $declares does not exist"
    extra+=(--declares-file "$src/$declares")
  fi
  for fn in $former; do extra+=(--former-name "$fn"); done
  tmp="$WORK/$repo.tar.gz"
  env -u BUSBAR_SIGN_KEY "$PACK" pack --lib "$lib_dir/$lib_name" --name "$name" --alias "$alias" \
    --kind "$kind" --publisher busbar --description "$desc" --license Apache-2.0 --out "$tmp" "${extra[@]}"
  "$PACK" canonical "$tmp" >"$WORK/$repo.canonical"
  version="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$WORK/$repo.canonical")"
  asset="${prefix}-${version}-${TRIPLE}.tar.gz"
  mv "$tmp" "$OUT/unsigned/$asset"
  mv "$WORK/$repo.canonical" "$OUT/canonical/$asset.canonical"
  printf '%s  %s\n' "$(sha256 "$OUT/canonical/$asset.canonical")" "$asset.canonical" >>"$OUT/CANONICAL.SHA256SUMS"
done <"$WORK/plan.tsv"

echo "plugin-pack-release: $(ls "$OUT/unsigned" | wc -l | tr -d ' ') unsigned tarball(s) for $TRIPLE -> $OUT"
