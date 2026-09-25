#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""An independent derivation of the frozen amendment digests pinned by
`the_sealed_digest_of_an_amendment_is_the_frozen_hex` in `amend_tests.rs` beside this file.

The constants in that test must not be captured from the crate under test: a constant copied out of
a failing run proves only that the code agrees with itself. This script hashes the length-prefixed
framing of the same fixtures by hand, with nothing but the standard library, so the pinned values
come from a second implementation of the encoding.

The framing (`legacy::Framing::LengthPrefixed`): every field is an 8-byte big-endian length followed
by its bytes; a number is its 8-byte big-endian value, framed the same way; the digest is SHA-256 of
the concatenation, in lower-case hex.

It prints three digests:

  access      the access amendment (the first constant in the test)
  old adjust  the adjustment as it was encoded when it carried one money figure; retired, kept so the
              change of shape is reproducible
  new adjust  the adjustment as it is encoded now, counts per class plus the card epoch (the second
              constant in the test). An adjustment that names no pool (every one sealed before
              owner ruling Q64/Q67) still encodes exactly this way.
  pooled adjust
              the same adjustment naming the pool "pool-a" (Q64/Q67): the pool is one more text field,
              LAST, present only when the adjustment names one (the third constant in the test)

USAGE
    python3 amend_digest.py
"""

import hashlib
import struct


class Digest:
    """The length-prefixed framing, field by field."""

    def __init__(self):
        self.buf = b""

    def text(self, value):
        raw = value.encode()
        self.buf += struct.pack(">Q", len(raw)) + raw

    def num(self, value):
        raw = struct.pack(">Q", value)
        self.buf += struct.pack(">Q", len(raw)) + raw

    def hex(self):
        return hashlib.sha256(self.buf).hexdigest()


def access():
    d = Digest()
    d.text("")  # prev_hash: the genesis
    d.num(1)  # seq
    d.text("access")
    d.text("hook")
    d.text("compress")
    d.text("principal")
    d.text("pseudonym-1")
    d.text("chat.completion")
    d.num(2)
    d.text("messages")
    d.text("system")
    d.num(1_700_000_000)
    return d.hex()


def old_adjust(prev):
    d = Digest()
    d.text(prev)
    d.num(2)
    d.text("adjust")
    d.text("the-entry-being-amended")
    d.text("principal")
    d.text("pseudonym-1")
    d.text("1000")
    d.text("800")
    d.text("operator")
    d.text("duplicate charge on a retried request")
    d.num(1_700_000_100)
    return d.hex()


def new_adjust(prev, pool=None):
    # Lane "gpt-4o", card epoch 1_700_000_000_000 ms,
    # was {input_tokens: 1000, output_tokens: 200}, now {input_tokens: 800, output_tokens: 200}.
    d = Digest()
    d.text(prev)
    d.num(2)
    d.text("adjust")
    d.text("the-entry-being-amended")
    d.text("principal")
    d.text("pseudonym-1")
    d.text("gpt-4o")
    d.num(1_700_000_000_000)
    for side in (
        [("input_tokens", "1000"), ("output_tokens", "200")],
        [("input_tokens", "800"), ("output_tokens", "200")],
    ):
        d.num(len(side))
        for class_name, count in side:
            d.text(class_name)
            d.text(count)
    d.text("operator")
    d.text("duplicate charge on a retried request")
    d.num(1_700_000_100)
    if pool is not None:
        d.text(pool)
    return d.hex()


def main():
    acc = access()
    print("access", acc)
    print("old adjust", old_adjust(acc))
    print("new adjust", new_adjust(acc))
    print("pooled adjust", new_adjust(acc, "pool-a"))


if __name__ == "__main__":
    main()
