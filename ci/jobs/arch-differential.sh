#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# T1 differential: scripts/architecture/check.py and tools/busbar-arch judge the
# same tree and must agree exactly, so the Python can be deleted (slice D1).
#
#   check       same verdict; on refusal the same `architecture:` reason line; on
#               success the same receipt, except that the Python compiler-witness
#               count must equal the Rust trybuild-case count (the witnesses
#               moved to tools/busbar-arch/witnesses, run by `cargo test`).
#   plan        native_policy.native_settings / conformance_rows equal
#               `busbar-arch plan` for core and every classified repository.
#   lock-align  check_shared_core_resolution equals `busbar-arch lock-align`.
#
# Both tools run in the same scratch path (emptied in between), so paths in
# messages are identical. Any difference fails the job and is printed.
#
# Usage: ci/jobs/arch-differential.sh [--work DIR] [--fleet] [--mutations]
#   --fleet      also every classified plugin repository at its forge dev head
#   --mutations  also one planted violation per rule on a copy of this tree
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
work="" fleet=0 mutations=0
while [ $# -gt 0 ]; do
  case "$1" in
    --work) work="$2"; shift 2 ;;
    --fleet) fleet=1; shift ;;
    --mutations) mutations=1; shift ;;
    *) echo "usage: $0 [--work DIR] [--fleet] [--mutations]" >&2; exit 2 ;;
  esac
done
[ -n "$work" ] || work="$(mktemp -d "${TMPDIR:-/tmp}/arch-differential.XXXXXX")"
mkdir -p "$work/report"
work="$(cd "$work" && pwd -P)"
report="$work/report"

refuse() {  # refuse <what> <why>
  printf 'arch-differential: refused: %s\n  why: %s\n' "$1" "$2" >&2
  exit 1
}

for tool in cargo python3 jq git; do
  command -v "$tool" >/dev/null || refuse "$tool is not installed" "both checkers need it"
done

# shellcheck source=ci/lib/forge.sh
. "$root/ci/lib/forge.sh"
forge_setup

cargo build --locked --quiet --manifest-path "$root/tools/busbar-arch/Cargo.toml" -p busbar-arch \
  --target-dir "$root/tools/busbar-arch/target" \
  || refuse "tools/busbar-arch does not build" "the Rust checker must exist to be compared"
arch="$root/tools/busbar-arch/target/debug/busbar-arch"
# One target directory for every build both checkers start (probes, harnesses, the
# workspace check), so the second checker reuses the first one's units.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$work/target}"
policy="$root/ci/architecture.toml"
differences=0 compared=0
: > "$report/summary.txt"

note() { printf '%s\n' "$*" | tee -a "$report/summary.txt"; }

reason() {  # reason <exit> <log>: the verdict line of one run
  if [ "$1" = 0 ]; then
    echo pass
  else
    # CalledProcessError quotes the argv list on some Python versions and not on
    # others; that quoting is the only part of a reason that is normalised.
    { grep -m1 '^architecture: ' "$2" || echo "no 'architecture:' reason (exit $1; last line: $(tail -n1 "$2"))"; } |
      sed -E "s/^architecture: Command '(\[.*\])' (returned|died)/architecture: Command \1 \2/"
  fi
}

# pair <label> <repository> <checkout> [--sdk DIR] [--policy FILE]: run both checkers.
pair() {
  local label="$1" repository="$2" checkout="$3"; shift 3
  local args=("$@") pol="$policy"
  if [ "${1:-}" = --policy ]; then pol="$2"; args=("${@:3}"); fi
  local scratch="$work/scratch" py_exit=0 rs_exit=0
  rm -rf "$scratch"
  python3 "$root/scripts/architecture/check.py" --policy "$pol" --repository "$repository" \
    --checkout "$checkout" --trusted "$checkout" --scratch "$scratch" \
    --output "$report/$label.python.json" "${args[@]}" > "$report/$label.python.log" 2>&1 || py_exit=$?
  rm -rf "$scratch"
  "$arch" check --policy "$pol" --repository "$repository" \
    --checkout "$checkout" --trusted "$checkout" --scratch "$scratch" \
    --output "$report/$label.rust.json" "${args[@]}" > "$report/$label.rust.log" 2>&1 || rs_exit=$?
  rm -rf "$scratch"
  compared=$((compared + 1))
  local py_reason rs_reason
  py_reason="$(reason "$py_exit" "$report/$label.python.log")"
  rs_reason="$(reason "$rs_exit" "$report/$label.rust.log")"
  if [ "$py_reason" != "$rs_reason" ]; then
    differences=$((differences + 1))
    note "DIFFERENT $label: python: $py_reason"
    note "          $label: rust:   $rs_reason"
    return 0
  fi
  if [ "$py_exit" = 0 ]; then
    local py_receipt rs_receipt py_witnesses rs_witnesses
    py_receipt="$(jq -S 'del(.compiler_witnesses, .production_features)' "$report/$label.python.json")"
    rs_receipt="$(jq -S 'del(.compiler_witnesses_trybuild)' "$report/$label.rust.json")"
    py_witnesses="$(jq -r '.compiler_witnesses // "none"' "$report/$label.python.json")"
    rs_witnesses="$(jq -r '.compiler_witnesses_trybuild // "none"' "$report/$label.rust.json")"
    if [ "$py_receipt" != "$rs_receipt" ] || [ "$py_witnesses" != "$rs_witnesses" ]; then
      differences=$((differences + 1))
      note "DIFFERENT $label: receipts differ (witnesses python=$py_witnesses rust=$rs_witnesses)"
      diff <(printf '%s\n' "$py_receipt") <(printf '%s\n' "$rs_receipt") | tee -a "$report/summary.txt" || true
      return 0
    fi
  fi
  note "same      $label: $py_reason"
}

# ---- plan and lock-align ----------------------------------------------------------
plan_python() {  # the Python view of every repository's plan, one JSON line each
  PYTHONPATH="$root/scripts/architecture" python3 -I -B -c '
import json, sys
sys.path.insert(0, sys.argv[1] + "/scripts/architecture")
from check import Policy, read
from native_policy import native_settings, conformance_rows
root, repository = sys.argv[1], sys.argv[2]
policy = Policy(read(root + "/ci/architecture.toml"))
try:
    out = {"native": native_settings(repository, policy),
           "required_suites": {k: v["command"] for k, v in conformance_rows(repository, policy, trusted=root).items()}}
except Exception as error:
    out = {"refused": str(error)}
print(json.dumps(out, sort_keys=True))
' "$root" "$1"
}

plan_rust() {
  local out
  if out="$("$arch" plan --repository "$1" --trusted "$root" 2> "$report/plan.err")"; then
    printf '%s' "$out" | jq -cS '{native, required_suites}'
  else
    jq -ncS --arg r "$(grep -m1 '^architecture: ' "$report/plan.err" | sed 's/^architecture: //')" '{refused: $r}'
  fi
}

plan_differences=0
for repository in GetBusbar/busbar $("$arch" repositories --checkout "$root" | jq -r '.[].repository'); do
  py="$(plan_python "$repository" | jq -cS .)"
  rs="$(plan_rust "$repository")"
  if [ "$py" != "$rs" ]; then
    plan_differences=$((plan_differences + 1))
    note "DIFFERENT plan $repository: python $py"
    note "          plan $repository: rust   $rs"
  fi
done
differences=$((differences + plan_differences))
note "plan: $([ "$plan_differences" = 0 ] && echo same || echo "$plan_differences differences") for core and $("$arch" repositories --checkout "$root" | jq length) repositories"

py_lock="$(PYTHONPATH="$root/scripts/architecture" python3 -I -B -c '
import sys
sys.path.insert(0, sys.argv[1] + "/scripts/architecture")
from check import check_shared_core_resolution, read
print(check_shared_core_resolution(read(sys.argv[1] + "/Cargo.lock"), read(sys.argv[1] + "/dist/default/Cargo.lock")))
' "$root" 2>&1 || true)"
rs_lock="$("$arch" lock-align --checkout "$root" 2>&1 | jq -r '.shared_core_packages' 2>/dev/null || true)"
if [ "$py_lock" = "$rs_lock" ]; then
  note "same      lock-align: $rs_lock shared core packages"
else
  differences=$((differences + 1))
  note "DIFFERENT lock-align: python $py_lock rust $rs_lock"
fi

# ---- check: this tree ---------------------------------------------------------------
pair core GetBusbar/busbar "$root"

# ---- check: planted violations, one per rule ------------------------------------------
if [ "$mutations" = 1 ]; then
  copy="$work/mutant"
  mutant() {  # mutant <label> <setup command...>: fresh copy of this tree, mutate, compare
    local label="$1"; shift
    rm -rf "$copy"
    git -C "$root" worktree add --quiet --detach "$copy" HEAD
    ( cd "$copy" && "$@" ) || refuse "mutation $label could not be planted" "the planted defect must apply to this tree"
    pair "mutant-$label" GetBusbar/busbar "$copy"
    git -C "$root" worktree remove --force "$copy"
  }
  append() { printf '%b' "$2" >> "$1"; }
  jq_edit() { jq "$2" "$1" > "$1.new" && mv "$1.new" "$1"; }
  first_rev_to_branch() {  # the first first-party git rev in dist/default becomes a branch
    local line
    line="$(grep -n 'git = "https://github.com/GetBusbar/busbar-[^"]*", rev = "' dist/default/Cargo.toml | head -n1 | cut -d: -f1)"
    [ -n "$line" ] && sed -i.bak -E "${line}s/rev = \"[0-9a-f]{40}\"/branch = \"dev\"/" dist/default/Cargo.toml
  }
  mutant cargo-config sh -c 'mkdir -p .cargo && printf "paths = [\"x\"]\n" > .cargo/config.toml'
  mutant first-party-patch append Cargo.toml '\n[patch."https://github.com/GetBusbar/busbar-auth-header"]\nbusbar-auth-header = { path = "x" }\n'
  mutant forbidden-declared-edge append crates/busbar-contract/Cargo.toml "\n[target.'cfg(any())'.dependencies]\nbusbar-kernel = { path = \"../busbar-kernel\", optional = true }\n"
  mutant shipping-feature-declaration append crates/busbar-kernel-audit/Cargo.toml "\n[target.'cfg(any())'.dependencies]\nbusbar-contract = { path = \"../busbar-contract\", optional = true, features = [\"test-seal\"] }\n"
  mutant missing-manifest rm crates/busbar-kernel-wal/Cargo.toml
  mutant package-identity sed -i.bak 's/^name = "busbar-kernel-wal"$/name = "busbar-kernel-wal-renamed"/' crates/busbar-kernel-wal/Cargo.toml
  mutant unclassified-member sh -c 'mkdir -p crates/extra/src && printf "[package]\nname = \"innocent\"\nversion = \"0.0.0\"\n" > crates/extra/Cargo.toml && : > crates/extra/src/lib.rs && sed -i.bak "s#^    \"crates/plugin-loader\",#    \"crates/plugin-loader\",\n    \"crates/extra\",#" Cargo.toml'
  mutant mutable-revision first_rev_to_branch
  mutant vector-sdk jq_edit scripts/ci-product-pins.json '.sdk = "dev"'
  mutant vector-product jq_edit scripts/ci-product-pins.json '.products[0].commit = "dev"'
  mutant vector-incomplete jq_edit scripts/ci-product-pins.json '.products |= .[1:]'
  mutant c-witness-vector jq_edit scripts/ci-product-pins.json '.c_witness.extra = "x"'
  mutant assembly-mismatch jq_edit scripts/ci-product-pins.json '.products[0].commit = "0000000000000000000000000000000000000000"'
  # shellcheck disable=SC2016 # a literal doc comment, nothing to expand
  mutant witness-inventory append crates/busbar-contract/src/plugin.rs '\n/// ```\n/// struct FakeSeal;\n/// ```\npub fn planted_witness() {}\n'
  mutant source-check append crates/busbar-kernel-wal/src/lib.rs '\n#[allow(dead_code)]\nfn planted_selector(name: &str) -> bool { name == "sqlite" }\n'
  # Policy-level refusals on an unmodified tree.
  sed 's/^version = 1$/version = 2/' "$policy" > "$work/policy-v2.toml"
  pair policy-version GetBusbar/busbar "$root" --policy "$work/policy-v2.toml"
  pair unclassified-repository GetBusbar/busbar-not-classified "$root"
fi

# ---- check: the plugin fleet at its forge dev heads --------------------------------------
if [ "$fleet" = 1 ]; then
  [ -n "${CI_SERVER_URL:-}" ] || refuse "--fleet needs CI_SERVER_URL and CI_JOB_TOKEN" "plugin heads are read from the forge only"
  "$arch" repositories --checkout "$root" | jq -r '.[] | "\(.repository) \(.language)"' |
  while read -r repository language; do
    name="${repository#*/}"
    checkout="$work/fleet/$name"
    rm -rf "$checkout"
    git clone --quiet --depth 1 --branch dev "${CI_SERVER_URL%/}/$repository.git" "$checkout" \
      || refuse "cannot clone $repository" "every classified repository must be compared; grant this job read access"
    extra=()
    if [ "$language" = c ]; then
      pin="$(awk '{print $1; exit}' "$checkout/.busbar-ref")"
      sdk="$work/fleet/sdk-$pin"
      if [ ! -d "$sdk" ]; then
        git init --quiet "$sdk"
        git -C "$sdk" fetch --quiet --depth 1 "${CI_SERVER_URL%/}/GetBusbar/busbar.git" "$pin"
        git -C "$sdk" checkout --quiet --detach FETCH_HEAD
      fi
      extra=(--sdk "$sdk")
    fi
    # Plugins are judged by core's policy and source checks (the trusted tree).
    scratch="$work/scratch" py_exit=0 rs_exit=0
    rm -rf "$scratch"
    python3 "$root/scripts/architecture/check.py" --policy "$policy" --repository "$repository" \
      --checkout "$checkout" --trusted "$root" --scratch "$scratch" \
      --output "$report/$name.python.json" "${extra[@]}" > "$report/$name.python.log" 2>&1 || py_exit=$?
    rm -rf "$scratch"
    "$arch" check --policy "$policy" --repository "$repository" \
      --checkout "$checkout" --trusted "$root" --scratch "$scratch" \
      --output "$report/$name.rust.json" "${extra[@]}" > "$report/$name.rust.log" 2>&1 || rs_exit=$?
    rm -rf "$scratch" "$checkout"
    py_reason="$(reason "$py_exit" "$report/$name.python.log")"
    rs_reason="$(reason "$rs_exit" "$report/$name.rust.log")"
    if [ "$py_reason" != "$rs_reason" ] || { [ "$py_exit" = 0 ] && \
        [ "$(jq -S . "$report/$name.python.json")" != "$(jq -S . "$report/$name.rust.json")" ]; }; then
      note "DIFFERENT $name: python: $py_reason; rust: $rs_reason"
      echo "$name" >> "$report/fleet-differences.txt"
    else
      note "same      $name: $py_reason"
    fi
  done
  if [ -s "$report/fleet-differences.txt" ]; then
    differences=$((differences + $(wc -l < "$report/fleet-differences.txt")))
  fi
fi

note "compared $compared core checks; $differences differences"
if [ "$differences" != 0 ]; then
  refuse "check.py and busbar-arch disagree ($differences differences; see $report/summary.txt)" \
    "the Rust port must give the same verdict and reason as the Python on every tree before the Python is deleted"
fi
