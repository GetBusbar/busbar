# shellcheck shell=bash
# site-curl.sh -- OWNER RULING Q39 (2026-09-24). Sourced, never executed: defines site_curl.
#
# getbusbar.com sits behind Cloudflare bot protection and rate limiting that answer CI 403/429. The
# owner's Cloudflare WAF skip rule matches a SECRET request header, X-Busbar-Verify, whose value is
# the repo secret SITE_VERIFY_TOKEN. site_curl is `curl` plus that header -- for getbusbar.com and
# its subdomains ONLY, because the header is a credential:
#   * a call whose URL is any other host runs as plain `curl "$@"`, untouched, no header;
#   * a call naming a getbusbar.com URL together with any other URL is refused (one header, two
#     audiences);
#   * curl re-sends -H headers to whatever host a redirect names, so on a getbusbar.com call curl is
#     never allowed to follow (-L is stripped). site_curl follows each hop itself: the header travels
#     only while the hop stays on getbusbar.com, and the first off-site hop is fetched bare;
#   * the value reaches curl through a mktemp (0600) file, `-H @file`, never argv, so `ps` on a
#     shared self-hosted runner cannot read it;
#   * SITE_VERIFY_TOKEN empty -> an ::error:: naming it and the Q39 rule, exit 125, and NO request
#     is made. Never a silent unauthenticated fallback: that is the 403 this exists to end.
# THIS FILE IS THE ONE DEFINITION. verify-deploy.yml checks nothing out, so its jobs write a
# verbatim copy from a heredoc; .github/workflows/lint/workflow-invariants.py (check q39) fails the
# moment a copy drifts from this file.

SITE_CURL_NO_TOKEN=125

site_host() {  # site_host <url> -> 0 when the URL's host is getbusbar.com or a subdomain of it
  local a="$1"
  case "$a" in *://*) a="${a#*://}" ;; esac
  a="${a%%[/?#]*}"; a="${a##*@}"; a="${a%%:*}"; a="${a%.}"
  a="$(printf '%s' "$a" | tr '[:upper:]' '[:lower:]')"
  case "$a" in getbusbar.com|*.getbusbar.com) return 0 ;; *) return 1 ;; esac
}

site_curl() {  # site_curl [curl args...] <url> -- curl, plus X-Busbar-Verify for getbusbar.com only
  local -a args=() urls=()
  local a v skip=0 follow=0 site=0 other=0
  for a in "$@"; do
    if [ "$skip" = 1 ]; then args+=("$a"); skip=0; continue; fi
    case "$a" in
      -L|--location|--location-trusted) follow=1 ;;
      --max-time|--connect-timeout|--retry|--retry-delay|--retry-max-time|--range|--output|\
      --write-out|--header|--user-agent|--referer|--data|--request|--max-redirs|--user|--cookie|\
      --dump-header|--proto-redir|--config)
        args+=("$a"); skip=1 ;;
      --*) args+=("$a") ;;
      -?*)
        v="${a//L/}"
        [ "$v" = "$a" ] || follow=1
        [ "$v" = "-" ] || args+=("$v")
        case "$v" in -*[owHmAedXrDbcTFxKCEYyzuUQt]) skip=1 ;; esac ;;
      *)
        urls+=("$a")
        if site_host "$a"; then site=$((site + 1)); else other=$((other + 1)); fi ;;
    esac
  done
  if [ "$site" = 0 ]; then
    curl "$@"
    return
  fi
  if [ "$other" != 0 ] || [ "${#urls[@]}" != 1 ]; then
    echo "::error::site_curl refuses a call naming a getbusbar.com URL together with any other URL: X-Busbar-Verify is a credential and is sent to getbusbar.com only (OWNER RULING Q39). Split the call." >&2
    return 2
  fi
  if [ -z "${SITE_VERIFY_TOKEN:-}" ]; then
    echo "::error::SITE_VERIFY_TOKEN is empty, so ${urls[0]} cannot carry the X-Busbar-Verify header that the Q39 Cloudflare WAF skip rule matches (OWNER RULING Q39), and it was NOT fetched. Fix: map secrets.SITE_VERIFY_TOKEN into this job's env as SITE_VERIFY_TOKEN, and check the repo secret SITE_VERIFY_TOKEN exists on GetBusbar/busbar." >&2
    return "$SITE_CURL_NO_TOKEN"
  fi
  local hf out dh u="${urls[0]}" rc=0 code loc base hop=0
  hf="$(mktemp)"; out="$(mktemp)"; dh="$(mktemp)"
  chmod 600 "$hf"
  printf 'X-Busbar-Verify: %s\n' "$SITE_VERIFY_TOKEN" > "$hf"
  while :; do
    : > "$dh"
    rc=0
    curl ${args[@]+"${args[@]}"} -H "@$hf" -D "$dh" "$u" > "$out" || rc=$?
    [ "$follow" = 1 ] && [ "$rc" = 0 ] || break
    code="$(tr -d '\r' < "$dh" | awk '/^HTTP\//{c=$2} END{print c}')"
    loc="$(tr -d '\r' < "$dh" | awk 'tolower($1)=="location:"{l=$2} END{print l}')"
    case "$code" in 301|302|303|307|308) ;; *) break ;; esac
    [ -n "$loc" ] || break
    base="${u%%://*}://$(v="${u#*://}"; v="${v%%/*}"; printf '%s' "${v%%[?#]*}")"
    case "$loc" in
      http://*|https://*) ;;
      //*) loc="${u%%://*}:${loc}" ;;
      /*) loc="${base}${loc}" ;;
      *) loc="${u%/*}/${loc}" ;;
    esac
    hop=$((hop + 1))
    if [ "$hop" -gt 10 ]; then
      echo "site_curl: more than 10 redirects from ${urls[0]}" >&2
      rc=47
      break
    fi
    if site_host "$loc"; then
      u="$loc"
      continue
    fi
    # Off getbusbar.com: fetched WITHOUT the header, and curl may follow the rest itself.
    rc=0
    curl ${args[@]+"${args[@]}"} --location "$loc" > "$out" || rc=$?
    break
  done
  cat "$out"
  rm -f "$hf" "$out" "$dh"
  return "$rc"
}
