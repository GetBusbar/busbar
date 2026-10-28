#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# sign-piv.sh <signed-bytes-file> <sig-out>
#
# Signs with the ECCP256 key in PIV slot 9C of the owner's YubiKey (`busbar-plugins-2026a`, the
# second root). yubico-piv-tool hashes the file with SHA-256 (-H SHA256) and the card signs that
# digest (PIV ECDSA signs a digest the host supplies); the card returns ASN.1 DER, the encoding
# release_trust::wire reads for P-256. The slot's policy asks for the PIN and a touch on every
# signature. Slots 9A and 9D are never named here.
#
# Needs yubico-piv-tool (`brew install yubico-piv-tool`). Its flags are NOT yet proven on this
# machine: before the first real use, run `yubico-piv-tool --help`, then the dry run in
# docs/design/release-trust.md ("Root ceremony"), which verifies a signature this script made.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 <signed-bytes-file> <sig-out>" >&2; exit 2; }
echo "PIV 9C: enter the PIN, then touch the YubiKey" >&2
exec yubico-piv-tool -a verify-pin -a sign -s 9c -A ECCP256 -H SHA256 -i "$1" -o "$2"
