#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# sign-key-env.sh <signed-bytes-file> <sig-out>
#
# The INTERIM release signer: an ECDSA P-256 private key (PEM) handed to the signing step by the CI
# secret store in BUSBAR_RELEASE_SIGNER_KEY. The key is read from the environment through a pipe,
# never written to disk, and the variable is the step's alone. Writes the ASN.1 DER signature over
# SHA-256 of the file, the encoding release_trust::wire reads for P-256. Replaced, with no new busbar
# binary, by ModernCI's release-signing feature through a new root-signed keys document.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 <signed-bytes-file> <sig-out>" >&2; exit 2; }
: "${BUSBAR_RELEASE_SIGNER_KEY:?the CI secret store must provide BUSBAR_RELEASE_SIGNER_KEY}"
exec openssl dgst -sha256 -sign <(printf '%s\n' "${BUSBAR_RELEASE_SIGNER_KEY}") -out "$2" "$1"
