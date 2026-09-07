#!/usr/bin/env bash
#
# plugin-ci-refs.sh  -  decide WHICH busbar commits a plugin's CI must prove that plugin against,
# and emit them as a GitHub Actions matrix.
#
# WHY THIS EXISTS. A plugin's CI and a plugin's RELEASE used to build against two different
# busbars, and nothing anywhere compared them:
#   - CI      built against `inputs.busbar_ref` in plugin-ci.yml, which every caller sets to
#             `github.ref_name` or leaves at `main`. That is the MOVING engine.
#   - RELEASE builds against field 1 of the plugin repo's own `.busbar-ref`, a PINNED SHA that
#             release-on-upstream.yml rewrites only when it cuts. That is the engine the shipped
#             artifact is actually compiled and linked against.
# So a green CI proved the plugin worked against a busbar its release would never build, and any
# API or config-grammar break between the two refs stayed invisible until release day. That is what
# made the 1.5.3 fixture breaks latent across a long list of first-party repos whose CI was green
# the entire time they were writing configs 1.5.3 had already retired.
#
# WHY BOTH, RATHER THAN UNIFYING ON ONE. They answer different questions and dropping either loses
# real coverage:
#   PINNED  is the only ref whose green is load-bearing for SHIPPING. Red here means the release is
#           broken today.
#   MOVING  is the early warning. Testing only the pin is a ratchet that never turns: a plugin stays
#           green forever while drifting arbitrarily far from the engine, and the break finally
#           lands inside release-on-upstream.yml, which re-pins `.busbar-ref` AND cuts the tag in
#           one workflow. Discovering it there is discovering it too late to do anything about.
# Run both, fail on either. When the two resolve to the SAME COMMIT this emits ONE leg and says so,
# so a plugin that is up to date with the engine (the steady state) pays nothing.
#
# USAGE
#   plugin-ci-refs.sh --plugin-root <dir> --moving-ref <ref>   emit `matrix=<json>` on stdout
#   plugin-ci-refs.sh --selftest                               prove the decisions, offline
#
# The selftest is offline: ref resolution goes through BUSBAR_REFS_RESOLVE_CMD when it is set, so
# the decision table can be exercised without a network round trip. Unset, it uses `git ls-remote`
# against the real busbar repository.

set -euo pipefail

BUSBAR_REPO="${BUSBAR_REPO_URL:-https://github.com/GetBusbar/busbar.git}"

# Resolve a ref-ish string to a commit sha, or print nothing when busbar has no such ref.
# A 40-hex input is taken as a sha as-is: `git ls-remote` does not list arbitrary commit shas, so
# asking it about one would wrongly report a valid pin as missing.
resolve() {
  local want="$1" line
  [ -n "$want" ] || return 0
  if printf '%s' "$want" | grep -qE '^[0-9a-f]{40}$'; then printf '%s' "$want"; return 0; fi
  if [ -n "${BUSBAR_REFS_RESOLVE_CMD:-}" ]; then
    "$BUSBAR_REFS_RESOLVE_CMD" "$want"
    return 0
  fi
  line="$(git ls-remote "$BUSBAR_REPO" "$want" 2>/dev/null | head -1 || true)"
  printf '%s' "${line%%$'\t'*}"
}

# json_escape  -  the label carries a caller-supplied ref name into a JSON string.
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

emit() { printf 'matrix=%s\n' "$1"; }

build_matrix() {
  local plugin_root="$1" moving_want="$2"
  local pin="" pin_sha="" moving="$moving_want" moving_sha=""

  # -- PINNED: what this repo's release.yml will actually build against. Field 1 of `.busbar-ref`.
  if [ -f "${plugin_root}/.busbar-ref" ]; then
    pin="$(cut -d' ' -f1 "${plugin_root}/.busbar-ref" | tr -d '[:space:]')"
  fi
  # A MOVING REF IN FIELD 1 IS NOT A PIN, AND `resolve()` CANNOT TELL YOU SO. It turns a branch or
  # tag name into a sha just as happily as it passes a 40-hex sha through, so a `.busbar-ref`
  # reading `main` or `v1.6.0` resolved fine, matched whatever the moving leg resolved to, hit the
  # dedupe below, and this script emitted ONE leg while announcing "CI and release agree by
  # construction". They agreed about nothing: the "pinned" leg was tracking the same moving target
  # as the moving leg, the PINNED-vs-MOVING split this whole file exists to maintain was gone, and
  # the output said the opposite in the reassuring direction. release-on-upstream.yml writes a sha;
  # anything else in field 1 is a mis-write, and a mis-write here is invisible by construction.
  if [ -n "$pin" ] && ! printf '%s' "$pin" | grep -qE '^[0-9a-f]{40}$'; then
    echo "::error::.busbar-ref field 1 is '${pin}', which is not a 40-hex commit sha. A moving ref there is not a pin: the 'pinned' leg would track whatever that ref points at today, collapse into the moving leg, and this CI would report that the release and the engine agree while proving nothing about the commit the release will actually build. Re-pin .busbar-ref to a sha." >&2
    return 1
  fi
  if [ -z "$pin" ]; then
    # Not fatal: a brand-new plugin repo has no pin until its first cut. But it must never be
    # silent, because it means CI is proving nothing about the release.
    echo "::warning::${plugin_root} has no .busbar-ref, so CI cannot prove anything about the busbar its release will build against. The pinned leg is omitted. release-on-upstream.yml writes the file on the first cut." >&2
  else
    pin_sha="$(resolve "$pin")"
    if [ -z "$pin_sha" ]; then
      # HARD FAIL, deliberately. A pin busbar does not have is a release that cannot build. There
      # is no reading of that which is merely a warning.
      echo "::error::.busbar-ref pins busbar commit '${pin}', which busbar does not have. The release will not build. Re-pin .busbar-ref." >&2
      return 1
    fi
  fi

  # -- MOVING: the caller's opinion about which engine branch to track.
  moving_sha="$(resolve "$moving")"
  if [ -z "$moving_sha" ]; then
    # THE `<number>/merge` HOLE. Most callers pass `busbar_ref: ${{ github.ref_name }}`, meaning
    # "test against the same-named busbar branch". On a pull_request `github.ref_name` is not a
    # branch name at all: it is `<number>/merge`. Every PR therefore asked busbar for a branch
    # called `5/merge` and actions/checkout died with "The process '/usr/bin/git' failed with exit
    # code 1" and no mention of the ref, which reads exactly like the plugin's own tests being
    # broken. The same hole swallows feature-branch pushes: `ci/whatever` exists in the plugin repo
    # and not in busbar. Falling back is deliberate, and the fallback announces itself.
    echo "::warning::busbar has no ref '${moving}', so the moving leg used busbar@dev instead. On a pull_request, \`github.ref_name\` is '<number>/merge' rather than a branch name, which is the usual cause: pass \`busbar_ref: \${{ github.base_ref || github.ref_name }}\` from the caller to say what you meant." >&2
    moving="dev"
    moving_sha="$(resolve dev)"
  fi
  if [ -z "$moving_sha" ]; then
    echo "::error::could not resolve the moving busbar ref '${moving_want}', and the dev fallback did not resolve either." >&2
    return 1
  fi

  # -- DEDUPE. One busbar means one leg. Running the same commit twice buys nothing.
  if [ -n "$pin_sha" ] && [ "$pin_sha" = "$moving_sha" ]; then
    echo "::notice::.busbar-ref and busbar@${moving} are the same commit (${pin_sha}); running ONE leg. CI and release agree by construction." >&2
    emit "{\"include\":[{\"label\":\"pinned+$(json_escape "$moving") (same commit)\",\"ref\":\"${pin_sha}\"}]}"
    return 0
  fi

  if [ -n "$pin_sha" ]; then
    echo "::notice::.busbar-ref pins ${pin_sha} (what the release builds) but busbar@${moving} is ${moving_sha}. Running BOTH; either leg red is red." >&2
    emit "{\"include\":[{\"label\":\"pinned (.busbar-ref, what the release builds)\",\"ref\":\"${pin_sha}\"},{\"label\":\"moving (busbar@$(json_escape "$moving"))\",\"ref\":\"${moving_sha}\"}]}"
    return 0
  fi

  emit "{\"include\":[{\"label\":\"moving (busbar@$(json_escape "$moving"))\",\"ref\":\"${moving_sha}\"}]}"
}

# == SELFTEST ===
# Every case below is a decision this script makes that a reader would otherwise have to take on
# trust. A gate nobody watched fail is not a gate.
selftest() {
  local tmp fake fails=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # A fake resolver with a fixed, known ref table. Offline, deterministic, no network.
  fake="${tmp}/resolve"
  cat > "$fake" <<'FAKE'
#!/usr/bin/env bash
case "$1" in
  main) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ;;
  dev)  printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' ;;
  *)    printf '' ;;
esac
FAKE
  chmod +x "$fake"
  export BUSBAR_REFS_RESOLVE_CMD="$fake"

  # Capture a call's DIAGNOSTICS (stderr) without piping. `build_matrix ... | grep -q` is wrong
  # under `pipefail`: grep -q exits on its first match, build_matrix takes EPIPE, and the pipeline
  # reports failure regardless of whether the text was there. That produced a real false negative
  # in this selftest, and it would have been intermittent rather than reliable, which is worse.
  warns() {
    local out
    out="$("$@" 2>&1 >/dev/null || true)"
    case "$out" in
      *"$WARN_NEEDLE"*) echo yes ;;
      *) echo no ;;
    esac
  }

  check() {
    local name="$1" want="$2" got="$3"
    if [ "$got" = "$want" ]; then
      echo "  [ok] ${name}"
    else
      echo "  [FAIL] ${name}"
      echo "         want: ${want}"
      echo "         got : ${got}"
      fails=$((fails + 1))
    fi
  }

  echo "plugin-ci-refs.sh selftest"

  # 1. Pin and moving ref differ: TWO legs, pinned first.
  mkdir -p "${tmp}/two"
  printf 'cccccccccccccccccccccccccccccccccccccccc 1.5.3\n' > "${tmp}/two/.busbar-ref"
  check "differing pin and moving ref emit two legs" \
    'matrix={"include":[{"label":"pinned (.busbar-ref, what the release builds)","ref":"cccccccccccccccccccccccccccccccccccccccc"},{"label":"moving (busbar@main)","ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' \
    "$(build_matrix "${tmp}/two" main 2>/dev/null)"

  # 2. Pin IS the moving ref's commit: ONE leg. This is the steady state and it must cost nothing.
  mkdir -p "${tmp}/same"
  printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1.5.3\n' > "${tmp}/same/.busbar-ref"
  check "an up-to-date pin collapses to one leg" \
    'matrix={"include":[{"label":"pinned+main (same commit)","ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' \
    "$(build_matrix "${tmp}/same" main 2>/dev/null)"

  # 3. No .busbar-ref at all: the moving leg alone, and a warning, never a silent pass.
  mkdir -p "${tmp}/nopin"
  check "a repo with no .busbar-ref still emits the moving leg" \
    'matrix={"include":[{"label":"moving (busbar@main)","ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' \
    "$(build_matrix "${tmp}/nopin" main 2>/dev/null)"
  WARN_NEEDLE="has no .busbar-ref"
  check "a repo with no .busbar-ref warns that CI proves nothing about its release" \
    "yes" "$(warns build_matrix "${tmp}/nopin" main)"

  # 4. THE PULL-REQUEST BUG. `<number>/merge` is not a busbar branch; it must fall back to dev and
  #    say so, not fail the checkout with an unreadable git error.
  check "a pull_request ref_name falls back to dev" \
    'matrix={"include":[{"label":"pinned (.busbar-ref, what the release builds)","ref":"cccccccccccccccccccccccccccccccccccccccc"},{"label":"moving (busbar@dev)","ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}' \
    "$(build_matrix "${tmp}/two" '5/merge' 2>/dev/null)"
  WARN_NEEDLE="busbar has no ref '5/merge'"
  check "the pull_request fallback announces itself" \
    "yes" "$(warns build_matrix "${tmp}/two" '5/merge')"

  # 5. A PIN BUSBAR DOES NOT HAVE IS A HARD FAILURE. The release cannot build; a warning would be
  #    a lie. `cccc...` resolves only because the fake table is bypassed for 40-hex input, so this
  #    case uses a non-hex pin, which the fake resolver reports as unknown.
  mkdir -p "${tmp}/badpin"
  printf 'no-such-busbar-ref 1.5.3\n' > "${tmp}/badpin/.busbar-ref"
  check "an unresolvable .busbar-ref pin fails, it does not warn" \
    "exit1" \
    "$(build_matrix "${tmp}/badpin" main >/dev/null 2>&1 && echo exit0 || echo exit1)"

  # 5b. AN UNPINNED PIN IS A HARD FAILURE TOO, and it is the one that used to pass loudest. A
  #     `.busbar-ref` holding a moving ref resolves, matches the moving leg, dedupes to ONE leg and
  #     prints "CI and release agree by construction" — the reassuring output, for the case where
  #     the release/CI split has silently ceased to exist. `main` resolves in the fake table, so
  #     this proves the hex check and not merely another unresolvable ref.
  mkdir -p "${tmp}/movingpin"
  printf 'main 1.6.0\n' > "${tmp}/movingpin/.busbar-ref"
  check "a .busbar-ref holding a moving ref instead of a sha fails" \
    "exit1" \
    "$(build_matrix "${tmp}/movingpin" main >/dev/null 2>&1 && echo exit0 || echo exit1)"
  WARN_NEEDLE="is not a 40-hex commit sha"
  check "and it says the pin is not a pin, rather than dedupe-ing it away" \
    "yes" "$(warns build_matrix "${tmp}/movingpin" main)"
  # The positive control: a real 40-hex pin on the SAME moving ref must still collapse to one leg,
  # so the check is refusing an unpinned pin rather than refusing the steady state.
  check "a 40-hex pin equal to the moving ref still collapses to one leg" \
    'matrix={"include":[{"label":"pinned+main (same commit)","ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' \
    "$(build_matrix "${tmp}/same" main 2>/dev/null)"

  # 6. Every emitted matrix must be parseable JSON with a non-empty include list. A malformed
  #    matrix makes `fromJSON` fail at workflow level with a message that names neither this script
  #    nor the ref, so check it here where the error can say something useful.
  local json
  json="$(build_matrix "${tmp}/two" main 2>/dev/null)"
  json="${json#matrix=}"
  check "the emitted matrix is valid JSON with two legs" \
    "2" \
    "$(printf '%s' "$json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["include"]))' 2>/dev/null || echo parse-error)"

  echo
  if [ "$fails" -ne 0 ]; then
    echo "plugin-ci-refs.sh selftest FAILED (${fails} case(s))"
    return 1
  fi
  echo "plugin-ci-refs.sh selftest passed"
}

PLUGIN_ROOT="plugin"
MOVING_REF="main"
MODE="emit"
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) MODE="selftest" ;;
    --plugin-root) shift; PLUGIN_ROOT="${1:-}" ;;
    --moving-ref) shift; MOVING_REF="${1:-}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$MODE" in
  selftest) selftest ;;
  *) build_matrix "$PLUGIN_ROOT" "$MOVING_REF" ;;
esac
