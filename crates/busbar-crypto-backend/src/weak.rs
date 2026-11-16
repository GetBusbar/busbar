//! AWS-LC has no small-order check, so the FIPS backend carries the 8 small-order Ed25519
//! point encodings (no arithmetic; a table compare). Includes the sign-bit and non-canonical (y >= p) variants.

const fn y_le(lo: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = lo;
    b
}

const P_MINUS_1: [u8; 32] = {
    let mut b = [0xffu8; 32];
    b[0] = 0xec;
    b[31] = 0x7f;
    b
};
const P: [u8; 32] = {
    let mut b = P_MINUS_1;
    b[0] = 0xed;
    b
};
const P_PLUS_1: [u8; 32] = {
    let mut b = P_MINUS_1;
    b[0] = 0xee;
    b
};
const ORDER8_A: [u8; 32] = [
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
];
const ORDER8_B: [u8; 32] = [
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
];

pub(crate) fn is_small_order(pk: &[u8; 32]) -> bool {
    let mut y = *pk;
    y[31] &= 0x7f; // the sign bit does not change the order
    [y_le(0), y_le(1), P_MINUS_1, P, P_PLUS_1, ORDER8_A, ORDER8_B]
        .iter()
        .any(|c| *c == y)
}

/// Whether `pk` is the canonical encoding of a point on edwards25519 (RFC 8032 §5.1.3): `y < p`,
/// `(y^2 - 1) / (d y^2 + 1)` is a square mod p, and the sign bit is clear when `x = 0`. curve25519-dalek
/// decompresses (it reduces `y` mod p and takes `-0 = 0`), so the canonical round trip refuses what it
/// would otherwise accept. Variable time is fine: public keys only. Input validation for pinned keys
/// (QE); no signature is verified here.
pub(crate) fn on_curve(pk: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*pk)
        .decompress()
        .is_some_and(|point| point.compress().0 == *pk)
}

/// Whether `pk` is acceptable as an Ed25519 public key encoding, by byte comparison alone (no
/// arithmetic; UNSAFE-MIN Q9b): the masked little-endian `y` is below `p` (canonical), and the two
/// points whose `x` is zero (`y` = 1 and `y` = p - 1) do not carry the sign bit, which would encode
/// "negative zero". A `y` with no point on the curve is not refused here: such a key verifies nothing,
/// so it fails closed at the first verify.
pub(crate) fn decodes(pk: &[u8; 32]) -> bool {
    let sign = pk[31] >> 7;
    let mut y = *pk;
    y[31] &= 0x7f;
    // y < p, compared from the most significant byte down (P holds p little-endian).
    let mut below = false;
    for i in (0..32).rev() {
        if y[i] != P[i] {
            below = y[i] < P[i];
            break;
        }
    }
    if !below {
        return false;
    }
    !(sign == 1 && (y == y_le(1) || y == P_MINUS_1))
}
