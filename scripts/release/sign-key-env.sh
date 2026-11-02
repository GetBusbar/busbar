#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# sign-key-env.sh <signed-bytes-file> <sig-out>
#
# The interim release signer: the CI step supplies a fresh ECDSA P-256 private PEM in
# BUSBAR_RELEASE_SIGNER_KEY. Pass it through a pipe, never a file or command-line argument.
# OpenSSL writes the binary ASN.1 DER signature over SHA-256 used by release_trust::wire.
# A new root-signed keys document can replace this signer without rebuilding busbar.
# This wrapper never uses the permanently retired BUSBAR_SIGN_KEY.
set +x
set -euo pipefail
umask 077
[ "$#" -eq 2 ] || { echo "usage: $0 <signed-bytes-file> <sig-out>" >&2; exit 2; }
[ -f "$1" ] && [ -r "$1" ] || { echo "sign-key-env.sh: input must be a readable file" >&2; exit 2; }
[[ ! "$1" -ef "$2" ]] || { echo "sign-key-env.sh: signature output must differ from input" >&2; exit 2; }
: "${BUSBAR_RELEASE_SIGNER_KEY:?the CI secret store must provide BUSBAR_RELEASE_SIGNER_KEY}"
_busbar_signer_pem=$BUSBAR_RELEASE_SIGNER_KEY
export -n _busbar_signer_pem
unset BUSBAR_RELEASE_SIGNER_KEY
# Prefix relative inputs so an input named '-something' remains a filename to OpenSSL.
case "$1" in
  /*) _busbar_signed_file=$1 ;;
  *) _busbar_signed_file=./$1 ;;
esac
exec openssl dgst -sha256 -sign <(printf '%s\n' "$_busbar_signer_pem") -out "$2" "$_busbar_signed_file"
