#!/usr/bin/env bash
# tls-lab.sh - serve the RELEASED image on the public lab host and assess its TLS (plan section 7).
#
# Runs ON the lab host: a machine joined to ModernCI that `provides: [tls-lab]`, whose public name
# tls-lab.getbusbar.com resolves to it, with ports 80 and 443 reachable from the internet. For each
# certificate variant (ecdsa, rsa) it:
#   1. obtains a public Let's Encrypt certificate by HTTP-01 on port 80 (lego, pinned by sha256).
#      No DNS API key exists anywhere in this flow.
#   2. runs ghcr.io/getbusbar/busbar@<digest> (the released image, by digest) terminating TLS itself
#      on 443 with that certificate (scripts/release/tls-lab-config.yaml);
#   3. runs scripts/release/tls_assess.py (testssl.sh 3.2.0, named assertions, never a grade);
#   4. stops the container.
# Writes target/tls-evidence/{testssl-*.json, assertions-*.json, assertions.json}.
#
# Usage: TESTSSL=<testssl.sh> scripts/release/tls-lab.sh <version> <sha256:image index digest>
set -euo pipefail
cd "$(dirname "$0")/../.."
V="${1:?usage: tls-lab.sh <version> <sha256:digest>}"; D="${2:?usage: tls-lab.sh <version> <sha256:digest>}"
[[ "$D" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "tls-lab: $D is not an image digest"; exit 2; }
HOST=tls-lab.getbusbar.com
IMAGE="ghcr.io/getbusbar/busbar@$D"
C="${MODERNCI_CACHE_DIR:-$HOME/.cache}/busbar-tls-lab"; mkdir -p "$C"

LEGO_VER=v5.5.2
case "$(uname -m)" in
  x86_64) A=amd64; S=2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef ;;
  aarch64|arm64) A=arm64; S=15b14ec2ab14fde69cc8396eb0204c5ce4327e31a486953225a6059b26db3e8c ;;
  *) echo "tls-lab: no pinned lego for $(uname -m)"; exit 3 ;;
esac
if [ ! -x "$C/lego-$LEGO_VER" ]; then
  curl -fsSL --retry 3 -o "$C/lego.tgz" "https://github.com/go-acme/lego/releases/download/$LEGO_VER/lego_${LEGO_VER}_linux_$A.tar.gz"
  echo "$S  $C/lego.tgz" | sha256sum -c - >/dev/null || { echo "tls-lab: lego sha256 mismatch"; exit 3; }
  tar -xzf "$C/lego.tgz" -C "$C" lego && mv "$C/lego" "$C/lego-$LEGO_VER" && rm "$C/lego.tgz"
fi

docker pull -q "$IMAGE" >/dev/null
for variant in ecdsa rsa; do
  kt=ec256; [ "$variant" = rsa ] && kt=rsa2048
  certs="$C/certs-$variant"; mkdir -p "$certs"
  "$C/lego-$LEGO_VER" --accept-tos --email security@getbusbar.com --domains "$HOST" --key-type "$kt" \
    --path "$certs" --http --http.port :80 run
  name="busbar-tls-lab-$variant-$$"
  docker run -d --rm --name "$name" -p 443:8443 \
    -e ANTHROPIC_KEY=lab-placeholder-not-a-credential -e BUSBAR_ADMIN_TOKEN="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    -v "$PWD/scripts/release/tls-lab-config.yaml:/etc/busbar/config.yaml:ro" \
    -v "$certs/certificates/$HOST.crt:/etc/busbar/tls/fullchain.pem:ro" \
    -v "$certs/certificates/$HOST.key:/etc/busbar/tls/privkey.pem:ro" \
    "$IMAGE" >/dev/null
  trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 60); do (exec 3<>"/dev/tcp/127.0.0.1/443") 2>/dev/null && break; sleep 1; done
  rc=0
  python3 scripts/release/tls_assess.py run --host "$HOST" --version "$V" --image-digest "$D" \
    --variant "$variant" --out target/tls-evidence || rc=$?
  docker rm -f "$name" >/dev/null 2>&1 || true
  [ "$rc" = 0 ] || { echo "tls-lab: $variant failed its assertions (exit $rc)"; exit "$rc"; }
done
echo "tls-lab: both variants pass; evidence in target/tls-evidence/assertions.json"
