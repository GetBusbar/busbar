# Sourced by a ModernCI check: `. .ci/tool.sh nextest deny jq`
# Puts each named tool, at the version pinned below, on PATH. The checks own their toolchain:
# a tool already on PATH at exactly the pin is used; otherwise the official release asset is
# fetched with curl, verified against the sha256 pinned here, and cached under
# ${MODERNCI_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}}/busbar-ci-tools/<tool>-<version>/.
# No sudo, no package manager. Unknown tool, unsupported platform or sha mismatch: message, return 1.

_bbt_nextest_ver=0.9.148
_bbt_deny_ver=0.20.2
_bbt_jq_ver=1.7.1

# _bbt_pin <tool> <os-arch>: prints "<asset-url> <sha256> <path of the binary inside the asset>"
_bbt_pin() {
  case "$1" in
    nextest)
      _u=https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$_bbt_nextest_ver/cargo-nextest-$_bbt_nextest_ver
      case "$2" in
        linux-x86_64)  echo "$_u-x86_64-unknown-linux-gnu.tar.gz 223ba936714cc861a9cdedad5a8eb664dfdd69d6fbdf6cea6aa8184f523290dc cargo-nextest" ;;
        linux-aarch64) echo "$_u-aarch64-unknown-linux-gnu.tar.gz 81469eb963ef883fd590e60189e77d6aba3d91b418591d3391f50fe3e9480d2b cargo-nextest" ;;
        darwin-arm64)  echo "$_u-universal-apple-darwin.tar.gz 6c23b7fb4ca82c571fc8dfedbab45bfa773d45918f933170c85d21cd7f4b852b cargo-nextest" ;;
        *) return 1 ;;
      esac ;;
    deny)
      _u=https://github.com/EmbarkStudios/cargo-deny/releases/download/$_bbt_deny_ver/cargo-deny-$_bbt_deny_ver
      case "$2" in
        linux-x86_64)  echo "$_u-x86_64-unknown-linux-musl.tar.gz 9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f cargo-deny-$_bbt_deny_ver-x86_64-unknown-linux-musl/cargo-deny" ;;
        linux-aarch64) echo "$_u-aarch64-unknown-linux-musl.tar.gz 995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d cargo-deny-$_bbt_deny_ver-aarch64-unknown-linux-musl/cargo-deny" ;;
        darwin-arm64)  echo "$_u-aarch64-apple-darwin.tar.gz fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3 cargo-deny-$_bbt_deny_ver-aarch64-apple-darwin/cargo-deny" ;;
        *) return 1 ;;
      esac ;;
    jq)
      _u=https://github.com/jqlang/jq/releases/download/jq-$_bbt_jq_ver
      case "$2" in
        linux-x86_64)  echo "$_u/jq-linux-amd64 5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5 -" ;;
        linux-aarch64) echo "$_u/jq-linux-arm64 4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5 -" ;;
        darwin-arm64)  echo "$_u/jq-macos-arm64 0bbe619e663e0de2c550be2fe0d240d076799d6f8a652b70fa04aea8a8362e8a -" ;;
        *) return 1 ;;
      esac ;;
    *) return 1 ;;
  esac
}

_bbt_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# _bbt_ensure <tool>
_bbt_ensure() {
  case "$1" in
    nextest) _bin=cargo-nextest; _ver=$_bbt_nextest_ver; _want="cargo-nextest $_ver"; _vargs="nextest --version" ;;
    deny)    _bin=cargo-deny;    _ver=$_bbt_deny_ver;    _want="cargo-deny $_ver"; _vargs=--version ;;
    jq)      _bin=jq;            _ver=$_bbt_jq_ver;      _want="jq-$_ver"; _vargs=--version ;;
    *) echo "tool.sh: unknown tool '$1' (known: nextest deny jq)" >&2; return 1 ;;
  esac
  # Already on PATH at exactly the pinned version.
  if command -v "$_bin" >/dev/null 2>&1; then
    _have=$("$_bin" $_vargs 2>/dev/null | sed -n 1p)
    case "$_have" in
      "$_want" | "$_want "*) return 0 ;;
    esac
  fi
  _dir=${MODERNCI_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}}/busbar-ci-tools/$1-$_ver
  if [ ! -x "$_dir/$_bin" ]; then
    _os=$(uname -s | tr '[:upper:]' '[:lower:]'); _arch=$(uname -m)
    _pin=$(_bbt_pin "$1" "$_os-$_arch") || {
      echo "tool.sh: no pinned $1 $_ver for $_os-$_arch (supported: linux-x86_64 linux-aarch64 darwin-arm64)" >&2
      return 1
    }
    set -- "$1" $_pin
    _url=$2; _sha=$3; _inner=$4
    mkdir -p "$_dir.tmp.$$" || return 1
    echo "tool.sh: fetching $_bin $_ver ($_url)" >&2
    if ! curl -fsSL --retry 3 -o "$_dir.tmp.$$/asset" "$_url"; then
      echo "tool.sh: download of $_url failed" >&2; rm -rf "$_dir.tmp.$$"; return 1
    fi
    _got=$(_bbt_sha256 "$_dir.tmp.$$/asset")
    if [ "$_got" != "$_sha" ]; then
      echo "tool.sh: sha256 mismatch for $_url: expected $_sha, got $_got" >&2
      rm -rf "$_dir.tmp.$$"; return 1
    fi
    if [ "$_inner" = - ]; then
      mv "$_dir.tmp.$$/asset" "$_dir.tmp.$$/$_bin"
    else
      tar -xzf "$_dir.tmp.$$/asset" -C "$_dir.tmp.$$" "$_inner" || { rm -rf "$_dir.tmp.$$"; return 1; }
      mv "$_dir.tmp.$$/$_inner" "$_dir.tmp.$$/$_bin"
    fi
    chmod +x "$_dir.tmp.$$/$_bin"
    rm -f "$_dir.tmp.$$/asset"
    rm -rf "$_dir"
    mv "$_dir.tmp.$$" "$_dir" || { rm -rf "$_dir.tmp.$$"; [ -x "$_dir/$_bin" ] || return 1; }
  fi
  PATH="$_dir:$PATH"; export PATH
}

for _bbt_t in "$@"; do
  _bbt_ensure "$_bbt_t" || return 1
done
