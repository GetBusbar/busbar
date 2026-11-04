# SPDX-License-Identifier: Apache-2.0
#
# RENDERED by `busbar-release plugin heal` from GetBusbar/busbar-release template/conformance/tools.sh;
# a hand edit is overwritten by the next sync.
#
# Sourced by testing/conformance/run.sh: `. testing/conformance/tools.sh rust node`. Puts each named
# tool on PATH at the version pinned here. ModernCI compute has no node and no package manager, so the
# conformance instruments bring their own: the official release asset, fetched with curl, checked
# against the sha256 pinned here BEFORE it is unpacked, and cached under
# ${MODERNCI_CACHE_DIR:-$HOME/.cache}/conformance-tools/. A tool already on PATH at the pinned major is
# used as is. A platform with no pin, a failed download or a sha mismatch is a refusal (return 1),
# never a fall-back. An instrument that needs system libraries (a browser, a JVM suite) runs in a
# docker image pinned by digest in the suite's own script, not here.
#
#   rust  rustup 1.28.2 (sha-pinned rustup-init) installing what rust-toolchain.toml names; cargo
#         already on PATH is left alone
#   node  node v22.23.3 (nodejs.org)

_ct_root="${MODERNCI_CACHE_DIR:-${HOME:+$HOME/.cache}}"
[ -n "$_ct_root" ] || { echo "tools.sh: no cache root; set MODERNCI_CACHE_DIR or HOME" >&2; return 1; }
_ct_root="$_ct_root/conformance-tools"
_ct_node_ver=v22.23.3
_ct_node_major="${_ct_node_ver#v}"; _ct_node_major="${_ct_node_major%%.*}"
_ct_rustup_ver=1.28.2

_ct_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# _ct_fetch <url> <sha256> <dest>: the asset at dest, verified, or return 1.
_ct_fetch() (
  [ -f "$3" ] && [ "$(_ct_sha256 "$3")" = "$2" ] && exit 0
  mkdir -p "$(dirname "$3")" || exit 1
  part="$(mktemp "$3.part.XXXXXX")" || exit 1
  trap 'rm -f "$part"' EXIT
  trap 'exit 1' HUP INT TERM
  curl -fsSL --retry 3 --retry-max-time 660 --max-time 600 --max-filesize 536870912 --connect-timeout 30 --speed-limit 1024 --speed-time 60 -o "$part" "$1" || { echo "tools.sh: download failed" >&2; exit 1; }
  got="$(_ct_sha256 "$part")"
  [ "$got" = "$2" ] || { echo "tools.sh: sha256 mismatch: expected $2, got $got" >&2; exit 1; }
  mv "$part" "$3"
)

# _ct_publish <staged dir> <dir> <probe>: move a fully staged install into place in one rename; true
# only when <dir>/<probe> is executable after it. Concurrent runs share the cache: a run that finds
# <dir> never sees it half written, and the loser of a race drops its own copy and uses the winner's.
# A <dir> without its probe (an install interrupted before staging existed) is moved aside and
# replaced, never used.
_ct_publish() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import fcntl, os, shutil, sys
stage, dest, probe = sys.argv[1:4]
done = lambda: os.access(os.path.join(dest, probe), os.X_OK)
try:
    with open(dest + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not done():
            if os.path.lexists(dest):
                if os.path.islink(dest):
                    os.unlink(dest)
                else:
                    shutil.rmtree(dest)
            os.rename(stage, dest)
        if not done():
            raise OSError("published tool has no executable probe")
except OSError as error:
    print(f"tools.sh: cannot publish {dest}: {error}", file=sys.stderr)
    sys.exit(1)
finally:
    shutil.rmtree(stage, ignore_errors=True)
PY
}

_ct_plat() { # <os>-<arch> as nodejs.org names them
  local os arch
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) return 1 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) return 1 ;; esac
  echo "$os-$arch"
}

_ct_node() {
  local have plat sha dir
  have="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "$have" = "$_ct_node_major" ] && return 0
  plat="$(_ct_plat)" || { echo "tools.sh: no pinned node for $(uname -s)-$(uname -m)" >&2; return 1; }
  case "$plat" in
    linux-x64)    sha=1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af ;;
    linux-arm64)  sha=5ced2d48d1d7198739b7f86804de0171aefb6823b684b12341d3321afc3cb0b2 ;;
    darwin-x64)   sha=8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8 ;;
    darwin-arm64) sha=23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53 ;;
    *) echo "tools.sh: no pinned node for $plat" >&2; return 1 ;;
  esac
  dir="$_ct_root/node-$_ct_node_ver-$plat"
  if [ ! -x "$dir/bin/node" ]; then
    _ct_fetch "https://nodejs.org/dist/$_ct_node_ver/node-$_ct_node_ver-$plat.tar.gz" "$sha" "$_ct_root/node-$_ct_node_ver-$plat.tar.gz" || return 1
    (
      stage="$(mktemp -d "$_ct_root/.node-stage.XXXXXX")" || exit 1
      trap 'rm -rf "$stage"' EXIT
      trap 'exit 1' HUP INT TERM
      tar -xzf "$_ct_root/node-$_ct_node_ver-$plat.tar.gz" -C "$stage" || exit 1
      _ct_publish "$stage/node-$_ct_node_ver-$plat" "$dir" bin/node
    ) || return 1
  fi
  PATH="$dir/bin:$PATH"; export PATH
}

_ct_rust() {
  command -v cargo >/dev/null 2>&1 && return 0
  local t sha
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  t=x86_64-unknown-linux-gnu;  sha=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;;
    Linux-aarch64) t=aarch64-unknown-linux-gnu; sha=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;;
    Darwin-x86_64) t=x86_64-apple-darwin;      sha=9c331076f62b4d0edeae63d9d1c9442d5fe39b37b05025ec8d41c5ed35486496 ;;
    Darwin-arm64)  t=aarch64-apple-darwin;      sha=20ef5516c31b1ac2290084199ba77dbbcaa1406c45c1d978ca68558ef5964ef5 ;;
    *) echo "tools.sh: no pinned rustup for $(uname -s)-$(uname -m)" >&2; return 1 ;;
  esac
  local home="$_ct_root/rustup-$_ct_rustup_ver"
  RUSTUP_HOME="$home/rustup"; CARGO_HOME="$home/cargo"
  export RUSTUP_HOME CARGO_HOME
  if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
    _ct_fetch "https://static.rust-lang.org/rustup/archive/$_ct_rustup_ver/$t/rustup-init" "$sha" "$_ct_root/rustup-init-$t" || return 1
    chmod +x "$_ct_root/rustup-init-$t" || { echo "tools.sh: cannot make rustup installer executable" >&2; return 1; }
    (
      stage="$(mktemp -d "$_ct_root/.rustup-stage.XXXXXX")" || exit 1
      trap 'rm -rf "$stage"' EXIT
      trap 'exit 1' HUP INT TERM
      RUSTUP_HOME="$stage/rustup" CARGO_HOME="$stage/cargo" "$_ct_root/rustup-init-$t" -y --no-modify-path --default-toolchain none || exit 1
      _ct_publish "$stage" "$home" cargo/bin/cargo
    ) || return 1
  fi
  PATH="$CARGO_HOME/bin:$PATH"; export PATH
  [ -f rust-toolchain.toml ] || [ -f rust-toolchain ] || { echo "tools.sh: no pinned Rust toolchain" >&2; return 1; }
  python3 -I - "$home/toolchain.lock" <<'PY'
import fcntl, subprocess, sys
with open(sys.argv[1], "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    ready = subprocess.run(["rustup", "show", "active-toolchain"], stdout=subprocess.DEVNULL)
    if ready.returncode:
        sys.exit(subprocess.call(["rustup", "toolchain", "install"]))
PY
}

for _ct_t in "$@"; do
  case "$_ct_t" in
    rust) _ct_rust || return 1 ;;
    node) _ct_node || return 1 ;;
    *) echo "tools.sh: unknown tool '$_ct_t' (known: rust node)" >&2; return 1 ;;
  esac
done
