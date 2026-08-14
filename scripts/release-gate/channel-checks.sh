#!/usr/bin/env bash
# scripts/release-gate/channel-checks.sh — every downstream channel that republishes a busbar
# release, plus the release object itself, plus the gate's own self-consistency.
#
# WHAT COUNTS AS A CHANNEL, AND WHY THE LIST IS NOT A JUDGEMENT CALL.
# It is derived from .github/release-notify-targets.txt (the repos release.yml repository_dispatches
# `upstream-release` to) split by the mixed-model rule that .github/workflows/verify-deploy.yml
# already documents:
#
#   TRACKS BUSBAR'S VERSION — must EQUAL the tag: the container registries (docker-checks.sh), the
#   GitHub Release + its /releases/latest pointer, the Helm chart's appVersion, the Homebrew tap,
#   install.sh, the marketing download page.
#
#   INDEPENDENT SEMVER — must be PUBLISHED, must not equal the tag: terraform-provider-busbar,
#   provider-busbar, pulumi-busbar, the three SDKs (busbar-python/js/go), busbar-admin,
#   validate-action. These are wrappers on their own version lines that only re-release when their
#   generated surface changes, so asserting equality is not a stricter gate, it is an assertion
#   that is false by construction. Asserting it WAS the bug that red-failed verify-deploy's (e).
#
# Usage: scripts/release-gate/channel-checks.sh <version>
set -uo pipefail
# `|| exit` and not a bare cd: every path below is repo-relative, so a failed cd would run the
# whole check suite against whatever directory the caller happened to be in and report confident
# nonsense. Failing here is the only honest outcome.
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

VERSION="${1:?usage: channel-checks.sh <version>}"
V="${VERSION#v}"
TAG="v${V}"
REPO="${BUSBAR_REPO:-GetBusbar/busbar}"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/relgate-channels-XXXXXX")"

# ── WHICH VERSION THE *POINTERS* OWE, WHICH IS NOT ALWAYS THE ONE UNDER TEST ────────────────────
#
# Two families of assertion live in this file and conflating them produces a gate that is wrong in
# both directions:
#
#   ARTIFACT checks (the release, its assets, the SBOM, the attestation) are about VERSION — the
#   thing named on the tag. Re-verifying 1.5.3 six months later must still assert 1.5.3's assets.
#
#   POINTER checks (/releases/latest, install.sh, the download page, the Homebrew formula, the Helm
#   appVersion) are about "what a user gets when they do not name a version", and the correct
#   answer to that is always the NEWEST published release. Asserting they equal an OLD version
#   under test would fail a `workflow_dispatch` re-verify of 1.5.3 for the sole reason that 1.5.4
#   exists and everything is working perfectly — a false red, which is how a gate gets ignored.
#
# On the case this gate is actually for (verifying the release that was just cut) the two are the
# same string and this distinction costs nothing. It only matters on the on-demand re-verify path,
# which is exactly the path that must not cry wolf.
NEWEST="$(gh api --paginate "repos/${REPO}/releases" \
  --jq '.[] | select(.draft==false and .prerelease==false) | .tag_name' 2>/dev/null \
  | sed 's/^v//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)"
if [ -z "${NEWEST:-}" ]; then
  # Not recoverable by guessing. Every pointer assertion below would be vacuous, and a vacuous
  # assertion that reports PASS is the failure mode this whole gate exists to eliminate.
  echo "::warning::could not enumerate ${REPO}'s published releases; pointer checks will assert against the version under test (${V})."
  NEWEST="$V"
fi
POINTER_NOTE=""
if [ "$NEWEST" != "$V" ]; then
  POINTER_NOTE=" (NOTE: ${V} is not the newest published release — ${NEWEST} is — so the default-pointer checks below correctly assert ${NEWEST}, not ${V}.)"
  echo "note: version under test is ${V}; newest published release is ${NEWEST}. Pointer checks assert ${NEWEST}."
fi
PTAG="v${NEWEST}"

# ── release:exists ──────────────────────────────────────────────────────────────────────────────
rel_json=""
fetch_release() { rel_json="$(gh release view "$TAG" --repo "$REPO" --json isDraft,assets,tagName 2>/dev/null)"; [ -n "$rel_json" ]; }
if retry 8 15 fetch_release; then
  if [ "$(printf '%s' "$rel_json" | jq -r '.isDraft')" = "true" ]; then
    record "release:exists" FAIL "Release ${TAG} exists but is still a DRAFT" \
      "a draft is invisible to /releases/latest, to install.sh and to every download button. Fix: promote the draft."
  else
    record "release:exists" PASS "Release ${TAG} exists and is published" ""
  fi
else
  record "release:exists" FAIL "GitHub Release ${TAG} does not exist" \
    "nothing downstream can be correct without it. Fix: re-run release.yml at ${TAG}."
fi

# ── release:latest-pointer ──────────────────────────────────────────────────────────────────────
# Every download button on getbusbar.com and install.sh itself resolve through this 302. It is
# checked over plain HTTP rather than api.github.com deliberately: the API is the exact dependency
# install:no-api-github forbids, and using it here would make the gate's own resolution the first
# thing to 403.
loc="$(curl -fsS --max-time 30 -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
if [ "${loc##*/releases/tag/}" = "$PTAG" ]; then
  record "release:latest-pointer" PASS "github.com/${REPO}/releases/latest -> ${PTAG}${POINTER_NOTE}" ""
else
  record "release:latest-pointer" FAIL "the /releases/latest redirect does not point at ${PTAG}" \
    "expected .../releases/tag/${PTAG} (the newest published release), observed '${loc:-<no redirect>}'. install.sh and every download button on getbusbar.com resolve through this, so all of them are handing users a different release. Fix: mark Release ${PTAG} as 'latest' — it is probably still a draft or flagged prerelease."
fi

# ── release:no-extras — the asset list is exactly the contract, in both directions ──────────────
# The per-target legs assert every contracted name is PRESENT. This asserts the converse: nothing
# is present that the contract does not know about. A stray asset is how a platform quietly gets
# renamed (`busbar-aarch64-apple-darwin.tgz` beside the expected `.tar.gz`) with the old name still
# missing — which the presence check catches, but which reads as an unexplained absence rather than
# a rename until you can see what IS there.
if [ -n "$rel_json" ]; then
  got="$(printf '%s' "$rel_json" | jq -r '.assets[].name' | sort)"
  want="$( { while read -r t; do
               [ -n "$t" ] || continue
               printf 'busbar-%s.%s\n' "$t" "$(target_field "$t" archive)"
             done < <(published_targets)
             jq -r --arg tag "$TAG" '.metadata_assets[].name | gsub("\\{TAG\\}"; $tag)' "$CONTRACT"
           } | sort )"
  extra="$(comm -23 <(printf '%s\n' "$got") <(printf '%s\n' "$want") | tr '\n' ' ')"
  if [ -z "${extra// /}" ]; then
    record "release:no-extras" PASS "Release ${TAG} publishes exactly the contracted asset set" ""
  else
    record "release:no-extras" FAIL "Release ${TAG} carries assets the contract does not account for" \
      "unaccounted: ${extra}. Either release.yml grew an artifact nobody verifies, or a contracted asset was renamed (in which case its old name is also reported missing above). Fix: add it to .github/release-targets.json so it is checked, or stop uploading it."
  fi
else
  record "release:no-extras" FAIL "cannot compare the asset list — Release ${TAG} was not readable" "see release:exists."
fi

# ── meta:cyclonedx / meta:openapi ───────────────────────────────────────────────────────────────
# Present, sized, downloadable AND PARSES. "Downloadable" is where verify-deploy stopped, and it
# cannot see a well-sized file of the wrong shape — an SBOM that is a GitHub error page is ~1KB of
# perfectly transferable HTML.
check_metadata_asset() {  # check_metadata_asset <id> <name> <min-bytes> <kind>
  local id="$1" name="$2" min="$3" kind="$4"
  local size url code
  size="$(printf '%s' "$rel_json" | jq -r --arg n "$name" '.assets[]? | select(.name == $n) | .size' 2>/dev/null)"
  url="https://github.com/${REPO}/releases/download/${TAG}/${name}"
  if [ -z "${size:-}" ]; then
    record "$id" FAIL "release asset ${name} is MISSING from ${TAG}" \
      "Fix: re-run release.yml's ${kind} job for ${TAG}."
    return
  fi
  if [ "$size" -lt "$min" ]; then
    record "$id" FAIL "release asset ${name} is implausibly small (${size} bytes, expected >= ${min})" \
      "a truncated upload lists identically to a good one. Fix: re-upload it on Release ${TAG}."
    return
  fi
  if ! retry 5 10 curl "${CURL_OPTS[@]}" -o "${WORK}/${name}" "$url"; then
    code="$(http_code "$url")"
    record "$id" FAIL "release asset ${name} is listed but not downloadable (HTTP ${code})" \
      "Fix: re-upload it on Release ${TAG}."
    return
  fi
  if ! jq -e . "${WORK}/${name}" >/dev/null 2>&1; then
    record "$id" FAIL "release asset ${name} is not valid JSON" \
      "it transferred ${size} bytes that do not parse — an error page or a truncated write. Fix: re-run release.yml's ${kind} job."
    return
  fi
  case "$kind" in
    cyclonedx)
      if ! jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' "${WORK}/${name}" >/dev/null 2>&1; then
        record "$id" FAIL "${name} is JSON but not a populated CycloneDX SBOM" \
          "expected .bomFormat == \"CycloneDX\" and a non-empty .components. Fix: re-run release.yml's sbom job."
        return
      fi
      ;;
    openapi)
      # The version inside the document, not just the filename: an OpenAPI doc generated from the
      # wrong ref is named right and describes the wrong API.
      local docver
      docver="$(jq -r '.info.version // ""' "${WORK}/${name}")"
      if ! printf '%s' "$(jq -r '.openapi // ""' "${WORK}/${name}")" | grep -q '^3\.1'; then
        record "$id" FAIL "${name} does not declare OpenAPI 3.1" \
          "observed openapi='$(jq -r '.openapi // "<absent>"' "${WORK}/${name}")'. Fix: re-run release.yml's openapi job."
        return
      fi
      if [ -n "$docver" ] && [ "$docver" != "$V" ]; then
        record "$id" FAIL "${name} describes version ${docver}, not ${V}" \
          "the document was generated from the wrong ref; its filename says ${TAG}. Fix: re-run release.yml's openapi job at ${TAG}."
        return
      fi
      ;;
  esac
  record "$id" PASS "${name} present (${size} bytes), downloadable and a well-formed ${kind} document" ""
}
if [ -n "$rel_json" ]; then
  check_metadata_asset "meta:cyclonedx" "busbar-${TAG}.cdx.json"     1000 cyclonedx
  check_metadata_asset "meta:openapi"   "busbar-openapi-${TAG}.json" 1000 openapi
else
  record "meta:cyclonedx" FAIL "cannot check the SBOM — Release ${TAG} was not readable" "see release:exists."
  record "meta:openapi"   FAIL "cannot check the OpenAPI document — Release ${TAG} was not readable" "see release:exists."
fi

# ── attest:provenance — the exact command the docs tell users to run, on real bytes ─────────────
# "The release is attested" used to mean a workflow step exited 0. It never meant a user could
# verify it. One real asset is enough here because the attestation is per-artifact and every
# per-target leg would otherwise pay a Sigstore round trip; the artifact chosen is the linux/x86_64
# tarball, the most-downloaded one.
probe_asset="busbar-x86_64-unknown-linux-gnu.tar.gz"
if retry 5 10 curl "${CURL_OPTS[@]}" -o "${WORK}/${probe_asset}" \
     "https://github.com/${REPO}/releases/download/${TAG}/${probe_asset}"; then
  if out="$(gh attestation verify "${WORK}/${probe_asset}" --repo "$REPO" 2>&1)"; then
    record "attest:provenance" PASS "gh attestation verify passes on the real published ${probe_asset}" ""
  else
    record "attest:provenance" FAIL "the documented \`gh attestation verify\` FAILS on the real published bytes" \
      "$(printf '%s' "$out" | tr '\n' '|' | tail -c 600). The docs tell users to run this before trusting a download; right now that instruction fails. Fix: confirm release.yml's actions/attest-build-provenance step ran for ${TAG} and covered this artifact's glob."
  fi
else
  record "attest:provenance" FAIL "could not download ${probe_asset} to attest it" "see asset:x86_64-unknown-linux-gnu."
fi

# ── helm:appversion ─────────────────────────────────────────────────────────────────────────────
# Read from the PUBLISHED chart index (GitHub Pages), never from helm-charts' own workflow claim.
appver=""
resolve_appver() {
  appver="$(curl -fsS --max-time 60 "https://getbusbar.github.io/helm-charts/index.yaml" 2>/dev/null \
    | awk '/^  busbar:/{f=1} f && /appVersion:/{print $2; exit}' | tr -d '"')"
  [ "$appver" = "$NEWEST" ]
}
if retry 8 15 resolve_appver; then
  record "helm:appversion" PASS "GetBusbar/helm-charts busbar chart appVersion == ${NEWEST}${POINTER_NOTE}" ""
else
  record "helm:appversion" FAIL "the published helm chart's appVersion is not ${NEWEST}" \
    "observed '${appver:-<none>}' in https://getbusbar.github.io/helm-charts/index.yaml. \`helm install\` deploys a different busbar than the newest release. Fix: re-run GetBusbar/helm-charts' release-on-upstream workflow for v${NEWEST}."
fi

# ── helm:render — the chart is not merely INDEXED, it renders ──────────────────────────────────
# An appVersion bump on a chart that does not template is a chart nobody can install, and the index
# cannot see that. `helm template` is a pure client-side render: no cluster, no network beyond the
# repo fetch.
if command -v helm >/dev/null 2>&1; then
  # RENDERED WITH A REAL CONFIG, BECAUSE THE CHART CORRECTLY REFUSES TO RENDER WITHOUT ONE.
  # `helm template busbar/busbar` with no values fails by design: busbar is a gateway and there is
  # no bootable zero-config default, so the chart raises `config is REQUIRED and is empty` rather
  # than templating something that would exit 1 at boot. That is the chart being right, and a check
  # that reported it as a broken chart would be a false red on healthy artifacts. So the render is
  # driven with the same minimal config the documented docker quickstart uses — which makes this a
  # stronger assertion than "it templates", because it is the config an operator would actually
  # supply.
  cat > "${WORK}/helm-values.yaml" <<'YAML'
secrets:
  data:
    ANTHROPIC_KEY: sk-ant-release-gate-dummy
    BUSBAR_ADMIN_TOKEN: release-gate-dummy-token
config:
  listen: "0.0.0.0:8080"
  providers:
    anthropic:
      api_key: { env: ANTHROPIC_KEY }
  models:
    claude-sonnet:
      provider: anthropic
  pools:
    default:
      members:
        - model: claude-sonnet
YAML
  if helm repo add busbar-gate https://getbusbar.github.io/helm-charts >/dev/null 2>&1 \
     && helm repo update busbar-gate >/dev/null 2>&1 \
     && helm template gate busbar-gate/busbar -f "${WORK}/helm-values.yaml" \
          > "${WORK}/rendered.yaml" 2>"${WORK}/helm.err"; then
    # The rendered manifests must reference the released image, or the chart renders happily and
    # deploys the wrong thing — the appVersion and the image tag are two different fields.
    if grep -qE "image: *\"?[^\"]*busbar:${NEWEST}\"?" "${WORK}/rendered.yaml"; then
      record "helm:render" PASS "the published chart renders (with a real config) and pins getbusbar/busbar:${NEWEST}${POINTER_NOTE}" ""
    else
      record "helm:render" FAIL "the published chart renders but does not deploy ${NEWEST}" \
        "no \`image: ...busbar:${NEWEST}\` in the rendered manifests. Observed image lines: $(grep -oE 'image: *"?[^"]*busbar:[^"]*' "${WORK}/rendered.yaml" | sort -u | tr '\n' ' '). appVersion and image.tag are two different fields, so a chart can index as the new release and deploy the old one. Fix: helm-charts' values.yaml image.tag must track appVersion."
    fi
  else
    record "helm:render" FAIL "the published busbar chart does not render" \
      "\`helm template\` failed: $(tr '\n' '|' < "${WORK}/helm.err" | tail -c 500). An indexed chart that cannot template is a chart nobody can install. Fix: see GetBusbar/helm-charts."
  fi
else
  # NOT a skip. helm is trivially installable on the runner (azure/setup-helm), so "helm is not
  # here" is a defect in this workflow, not an environmental fact about the release.
  record "helm:render" FAIL "helm is not installed on this runner" \
    "the gate cannot render the chart without it, and an unrendered chart is an unverified chart. Fix: add azure/setup-helm to the channels job in .github/workflows/release-gate.yml."
fi

# ── terraform:published — INDEPENDENT SEMVER, asserted as such ──────────────────────────────────
# The provider is a wrapper on its own v0.x line and only re-releases when its generated surface
# changes, so a busbar release may legitimately ship no new provider version. Asserting equality
# with ${V} is wrong on two counts and was the bug that red-failed verify-deploy's check (e). The
# meaningful invariant is that the listing exists and the newest version actually resolves — which
# still catches "the publish job never ran / the listing disappeared".
tf_latest=""
resolve_tf() {
  tf_latest="$(curl -fsS --max-time 30 "https://registry.terraform.io/v1/providers/getbusbar/busbar/versions" 2>/dev/null \
    | jq -r '.versions[]?.version' | sort -V | tail -1)"
  [ -n "$tf_latest" ]
}
if retry 6 15 resolve_tf; then
  if curl -fsS --max-time 30 -o /dev/null "https://registry.terraform.io/v1/providers/getbusbar/busbar/${tf_latest}/download/linux/amd64" 2>/dev/null; then
    record "terraform:published" PASS "registry.terraform.io lists getbusbar/busbar; newest ${tf_latest} resolves (independent semver; busbar is ${V})" ""
  else
    record "terraform:published" FAIL "registry.terraform.io lists getbusbar/busbar ${tf_latest} but it does not download" \
      "the version listing exists and the download endpoint for linux/amd64 does not resolve, so \`terraform init\` fails for every user. Fix: re-run terraform-provider-busbar's release workflow."
  fi
else
  record "terraform:published" FAIL "registry.terraform.io lists NO published versions of getbusbar/busbar" \
    "the provider's registry listing is missing. Fix: re-run GetBusbar/terraform-provider-busbar's publish workflow. NOTE: the provider keeps its OWN semver and is NOT expected to equal ${V}."
fi

# ── brew:formula-version ────────────────────────────────────────────────────────────────────────
formula="" fver=""
fetch_formula() {
  formula="$(curl -fsS --max-time 30 "https://raw.githubusercontent.com/GetBusbar/homebrew-busbar/main/Formula/busbar.rb" 2>/dev/null)"
  [ -n "$formula" ]
}
if retry 6 15 fetch_formula; then
  fver="$(printf '%s' "$formula" | sed -n 's/^ *version *"\([^"]*\)".*/\1/p' | head -1)"
  if [ "$fver" = "$NEWEST" ]; then
    record "brew:formula-version" PASS "the homebrew tap formula is version ${NEWEST}${POINTER_NOTE}" ""
  else
    record "brew:formula-version" FAIL "the homebrew tap formula is version '${fver:-<none>}', not ${NEWEST}" \
      "\`brew install getbusbar/busbar/busbar\` installs a different release than the newest one. Fix: re-run GetBusbar/homebrew-busbar's bump.yml for v${NEWEST}."
  fi
else
  record "brew:formula-version" FAIL "could not read GetBusbar/homebrew-busbar's Formula/busbar.rb" \
    "Fix: confirm the tap repo and the formula path still exist."
fi

# ── brew:asset-sha256 — every platform's URL AND checksum, not just this runner's ───────────────
# The formula names four URLs and four sha256s. Homebrew only ever exercises the one matching the
# machine doing the install, so three of the four have historically been asserted by nobody. A
# stale sha256 is a hard install failure on exactly the platform nobody tested.
if [ -n "$formula" ] && [ -z "$fver" ]; then
  record "brew:asset-sha256" FAIL "the formula was fetched but no \`version \"...\"\` line could be parsed out of it" \
    "without the formula's own version the URLs cannot be resolved, and guessing one would make this row assert nothing. Fix: update the parser in scripts/release-gate/channel-checks.sh, or see why the tap's formula shape changed."
elif [ -n "$formula" ]; then
  bad="" checked=0
  while read -r asset sha; do
    [ -n "$asset" ] || continue
    checked=$((checked + 1))
    # AT THE FORMULA'S OWN VERSION TAG, not the newest release. The formula's URLs and its four
    # sha256s are one self-consistent unit: `brew install` downloads exactly these bytes. Whether
    # that version is the newest is brew:formula-version's assertion, and checking it twice would
    # report one lagging tap bump as two unrelated failures.
    url="https://github.com/${REPO}/releases/download/v${fver}/${asset}"
    if ! retry 4 10 curl "${CURL_OPTS[@]}" -o "${WORK}/brew-${asset}" "$url"; then
      bad="${bad}${asset}(unreachable) "
      continue
    fi
    real="$( { shasum -a 256 "${WORK}/brew-${asset}" 2>/dev/null || sha256sum "${WORK}/brew-${asset}"; } | awk '{print $1}')"
    [ "$real" = "$sha" ] || bad="${bad}${asset}(sha ${real:0:12}… != formula ${sha:0:12}…) "
    rm -f "${WORK}/brew-${asset}"
  done < <(printf '%s\n' "$formula" | awk '
      /url +"/    { u=$0; sub(/.*\//,"",u); sub(/".*/,"",u); a=u }
      /sha256 +"/ { s=$0; sub(/.*sha256 +"/,"",s); sub(/".*/,"",s); if (a != "") { print a, s; a="" } }')
  if [ "$checked" -eq 0 ]; then
    record "brew:asset-sha256" FAIL "could not parse any url/sha256 pair out of the formula" \
      "the formula's shape changed and this check is now asserting nothing — which is why it reports FAIL rather than passing on zero rows. Fix: update the parser in scripts/release-gate/channel-checks.sh."
  elif [ -z "${bad// /}" ]; then
    record "brew:asset-sha256" PASS "all ${checked} formula URLs are live and their sha256s match the real assets" ""
  else
    record "brew:asset-sha256" FAIL "the homebrew formula's checksums/URLs do not match the released assets" \
      "${bad}. \`brew install\` fails outright on those platforms. Fix: re-run GetBusbar/homebrew-busbar's bump.yml for v${NEWEST}."
  fi
else
  record "brew:asset-sha256" FAIL "cannot check formula checksums — the formula was not readable" "see brew:formula-version."
fi

# ── install.sh (the three getbusbar.com rows; Cloudflare-skippable) ─────────────────────────────
# THE ONLY PLACE A SKIP IS LEGITIMATE, and it is decided by is_cloudflare_block() in lib.sh so it
# cannot drift per-check. 403/503/000 from getbusbar.com is Cloudflare refusing GitHub Actions'
# datacenter ranges — real users are served fine. 404 or a non-503 5xx is broken for everybody and
# stays a hard FAIL.
INSTALL_URL="https://getbusbar.com/install.sh"
code="$(http_code "$INSTALL_URL")"
script_body=""
if [ "$code" = "200" ]; then
  script_body="$(fetch "$INSTALL_URL" || true)"
fi
if [ -n "$script_body" ]; then
  record "install:script-live" PASS "${INSTALL_URL} is served (HTTP 200, $(printf '%s' "$script_body" | wc -c | tr -d ' ') bytes)" ""
elif is_cloudflare_block "$code"; then
  record "install:script-live" SKIP "${INSTALL_URL} is unreachable FROM THIS RUNNER (HTTP ${code})" \
    "Cloudflare bot protection blocks GitHub Actions' datacenter IP ranges; the page is healthy for real visitors. NOT VERIFIED, not passed. Fix (marketing-side): allowlist GitHub Actions egress, or serve install.sh from a path exempt from bot protection."
else
  record "install:script-live" FAIL "${INSTALL_URL} returns HTTP ${code}" \
    "this is not the Cloudflare-block signature (403/503) — it is broken for every visitor. \`curl -fsSL https://getbusbar.com/install.sh | sh\` is the first command in the docs. Fix: see GetBusbar/marketing."
fi

# install:no-api-github — asserts the ABSENCE of the fragile dependency in the SERVED script.
# THE TRAP this exists for: a runner talks to api.github.com from a different rate-limit pool than a
# user's laptop and usually has GITHUB_TOKEN in scope, so "it ran green in CI" proves nothing about
# a user's shell. Only absence generalises.
if [ -n "$script_body" ]; then
  # COMMENTS ARE STRIPPED FIRST, AND THAT IS A CORRECTNESS FIX, NOT A LOOSENING.
  # The served install.sh carries a comment explaining that api.github.com is deliberately NOT used
  # ("The REST API (api.github.com) is deliberately NOT used here, not even as a fallback: ..."),
  # which is exactly the documentation you want beside a load-bearing decision. A naive grep matches
  # it and reports the fixed script as broken — a false red on a healthy artifact, which is the
  # failure mode that teaches people to ignore a gate. The assertion is about what the script DOES,
  # so it is made against the executable lines only. `#` inside a string literal would false-strip,
  # which errs toward a false GREEN and is therefore checked for separately below.
  code_only="$(printf '%s\n' "$script_body" | sed 's/[[:space:]]*#.*$//')"
  if printf '%s' "$code_only" | grep -q 'api\.github\.com'; then
    record "install:no-api-github" FAIL "the served install.sh depends on api.github.com" \
      "matches (comments stripped): $(printf '%s' "$code_only" | grep -n 'api\.github\.com' | head -3 | tr '\n' '|'). Unauthenticated api.github.com is rate-limited per source IP and 403s users who have installed anything else that day — this is what broke install.sh in production. It passing in CI proves nothing: the runner has its own pool and a token. Fix: resolve the release through the plain /releases/latest 302 on github.com, which needs no token."
  elif printf '%s' "$script_body" | grep -qE '"[^"]*api\.github\.com|'"'"'[^'"'"']*api\.github\.com'; then
    # A reference that survives inside a quoted string but vanished when comments were stripped is
    # the one case where stripping could hide a real dependency. Named rather than trusted.
    record "install:no-api-github" FAIL "the served install.sh references api.github.com inside a string literal" \
      "comment-stripping removed it from the code view, but it appears inside quotes — so it may be a live URL the script builds at runtime. Fix: read the script and either remove the dependency or move the mention into a real comment."
  else
    record "install:no-api-github" PASS "the served install.sh has no api.github.com dependency" ""
  fi
elif is_cloudflare_block "$code"; then
  record "install:no-api-github" SKIP "cannot read the served install.sh from this runner (HTTP ${code})" \
    "Cloudflare blocks GitHub Actions IPs. NOT VERIFIED. Same marketing-side fix as install:script-live."
else
  record "install:no-api-github" FAIL "cannot read the served install.sh (HTTP ${code})" "see install:script-live."
fi

# install:e2e — run the LIVE script, with the environment scrubbed of GitHub credentials, and prove
# a binary lands and reports the version under test. Deliberately not ./install.sh from the
# checkout: a fix that merged and never deployed must still fail here.
if [ -n "$script_body" ]; then
  ins="${WORK}/install"; mkdir -p "$ins"
  printf '%s' "$script_body" > "${ins}/install.sh"
  if ( cd "$ins" && env -u GITHUB_TOKEN -u GH_TOKEN -u GITHUB_ACTIONS -u CI \
         BUSBAR_INSTALL_DIR="$ins" sh ./install.sh >"${ins}/out.log" 2>&1 ); then
    got="$("${ins}/busbar" --version 2>&1 || true)"
    if printf '%s' "$got" | grep -q "$NEWEST"; then
      record "install:e2e" PASS "the live install.sh installed busbar ${NEWEST} with GitHub credentials scrubbed${POINTER_NOTE}" ""
    else
      record "install:e2e" FAIL "the live install.sh installed the wrong version" \
        "expected ${NEWEST} (install.sh always installs the newest release), \`busbar --version\` said '${got}'. Fix: install.sh resolves through /releases/latest; see release:latest-pointer."
    fi
  else
    record "install:e2e" FAIL "the live install.sh does not complete" \
      "$(tail -20 "${ins}/out.log" 2>/dev/null | tr '\n' '|' | tail -c 700). This is the documented first command in the docs, run with GITHUB_TOKEN scrubbed exactly as a user's shell would. Fix: see the log — the 1.5.3-era failure was a 404 for the Apple Silicon asset and a 403 from api.github.com."
  fi
elif is_cloudflare_block "$code"; then
  record "install:e2e" SKIP "cannot run the live install.sh from this runner (HTTP ${code})" \
    "Cloudflare blocks GitHub Actions IPs. NOT VERIFIED. Same marketing-side fix as install:script-live."
else
  record "install:e2e" FAIL "cannot fetch the live install.sh to run it (HTTP ${code})" "see install:script-live."
fi

# ── site:download-page ──────────────────────────────────────────────────────────────────────────
# ANCHORED version match. The old unanchored substring grep passed v1.5.2 against a page
# advertising v1.5.20, which is the shape of bug that only shows up once the minor rolls over.
DL_URL="https://getbusbar.com/download/"
dl_code="$(http_code "$DL_URL")"
if [ "$dl_code" = "200" ]; then
  page="$(fetch "$DL_URL" || true)"
  # ANCHORED ON BOTH SIDES. The old unanchored substring grep passed v1.5.2 against a page
  # advertising v1.5.20 — a bug that only appears once the patch number rolls into two digits, so
  # it hides for years and then passes silently on exactly the release where it matters. The left
  # anchor is equally necessary: "21.5.4" contains "1.5.4".
  if printf '%s' "$page" | grep -qE "(^|[^0-9.])v?${NEWEST//./\\.}([^0-9.]|$)"; then
    record "site:download-page" PASS "getbusbar.com/download/ advertises ${NEWEST}${POINTER_NOTE}" ""
  else
    record "site:download-page" FAIL "getbusbar.com/download/ does not advertise ${NEWEST}" \
      "the live page is served but the busbar versions it names are: $(printf '%s' "$page" | grep -oE 'v1\.[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ' | tail -c 160). Fix: redeploy GetBusbar/marketing for v${NEWEST}."
  fi
elif is_cloudflare_block "$dl_code"; then
  record "site:download-page" SKIP "getbusbar.com/download/ unreachable FROM THIS RUNNER (HTTP ${dl_code})" \
    "Cloudflare blocks GitHub Actions IPs; healthy for real visitors. NOT VERIFIED, not passed. Same marketing-side fix as install:script-live."
else
  record "site:download-page" FAIL "getbusbar.com/download/ returns HTTP ${dl_code}" \
    "not the Cloudflare-block signature — broken for every visitor. Fix: see GetBusbar/marketing."
fi

# ── plugins:fleet-released ──────────────────────────────────────────────────────────────────────
# #52 was a case where the shipped busbar refused every correctly-signed plugin. The per-target
# plugin: rows prove the BINARY side of that against one probe plugin. This row proves the FLEET
# side: every first-party plugin in plugins.yaml actually has a published release with assets, so
# the probe is not the only plugin that exists in a usable form. Reuses the existing registry gate
# rather than reimplementing the list — plugins.yaml is the single source of truth and a second
# copy of it here is exactly the drift this gate exists to catch.
if [ -x scripts/plugin-registry-check.sh ]; then
  if out="$(scripts/plugin-registry-check.sh 2>&1)"; then
    record "plugins:fleet-released" PASS "every first-party plugin in plugins.yaml has a published release with assets" ""
  else
    record "plugins:fleet-released" FAIL "the first-party plugin fleet is not fully released" \
      "$(printf '%s' "$out" | grep -iE 'fail|missing|no release|phantom' | head -5 | tr '\n' '|' | tail -c 700). Fix: see scripts/plugin-registry-check.sh's output in full."
  fi
else
  record "plugins:fleet-released" FAIL "scripts/plugin-registry-check.sh is missing or not executable" \
    "the fleet cannot be verified without it. Fix: restore the script, or this row must be removed from expected-ids.sh deliberately rather than quietly failing."
fi

# ── contract:drift — the contract still describes the thing it claims to describe ───────────────
# The whole gate is derived from .github/release-targets.json. If release.yml grows a sixth target
# and the contract does not, the gate keeps passing while an entire platform ships unverified — the
# gate would be green and blind, which is worse than absent. So the target list is re-derived from
# release.yml's own build matrix and compared.
wf=".github/workflows/release.yml"
if [ -f "$wf" ]; then
  wf_targets="$(grep -oE '^ *- target: [A-Za-z0-9_.-]+' "$wf" | awk '{print $3}' | sort -u)"
  contract_targets="$(published_targets | sort -u)"
  if [ -z "$wf_targets" ]; then
    record "contract:drift" FAIL "could not read any build targets out of ${wf}" \
      "the matrix shape changed and this comparison is now asserting nothing — reported FAIL rather than passing on an empty set. Fix: update the parser in scripts/release-gate/channel-checks.sh."
  elif [ "$wf_targets" = "$contract_targets" ]; then
    record "contract:drift" PASS "${CONTRACT}'s published targets match ${wf}'s build matrix" ""
  else
    record "contract:drift" FAIL "${CONTRACT} and ${wf} disagree about which platforms a release ships" \
      "release.yml builds: $(printf '%s' "$wf_targets" | tr '\n' ' '); the contract publishes: $(printf '%s' "$contract_targets" | tr '\n' ' '). A target in one and not the other either ships unverified or is verified and never built. Fix: reconcile the two — the contract is the source of truth for the gate, release.yml for the build."
  fi
else
  record "contract:drift" FAIL "${wf} not found" "the gate cannot check itself for drift. Fix: run this from a full checkout."
fi
