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
/// `(y^2 - 1) / (d y^2 + 1)` is a square mod p, and the sign bit is clear when `x = 0`. The
/// arithmetic is AWS-LC's BIGNUM (variable time: public keys only); aws-lc-rs exposes no
/// public-key check. Equivalent to ed25519-dalek's `VerifyingKey::from_bytes`.
#[allow(unsafe_code)]
pub(crate) fn decodes(pk: &[u8; 32]) -> bool {
    use aws_lc_sys as lc;
    // p = 2^255 - 19 and d = -121665/121666 mod p, big-endian.
    const P: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
    ];
    const D: [u8; 32] = [
        0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73, 0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
        0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab, 0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3,
    ];
    /// Owns every BIGNUM and the context; frees them on every path.
    struct Bn {
        ctx: *mut lc::BN_CTX,
        nums: Vec<*mut lc::BIGNUM>,
    }
    impl Drop for Bn {
        fn drop(&mut self) {
            // SAFETY: each pointer was returned by BN_new/BN_bin2bn/BN_le2bn/BN_CTX_new (or is
            // null, which both free functions accept) and is freed exactly once, here.
            unsafe {
                for n in self.nums.drain(..) {
                    lc::BN_free(n);
                }
                lc::BN_CTX_free(self.ctx);
            }
        }
    }
    let sign = pk[31] >> 7;
    let mut y_le = *pk;
    y_le[31] &= 0x7f;
    lc::init();
    // SAFETY: every pointer is checked for null before use and owned by `bn`, which frees it; the
    // byte buffers are live locals of the stated lengths; BN_* calls keep no pointer past the call.
    unsafe {
        let mut bn = Bn {
            ctx: lc::BN_CTX_new(),
            nums: Vec::with_capacity(9),
        };
        let mut new = |p: *mut lc::BIGNUM| {
            bn.nums.push(p);
            p
        };
        let p = new(lc::BN_bin2bn(P.as_ptr(), P.len(), core::ptr::null_mut()));
        let d = new(lc::BN_bin2bn(D.as_ptr(), D.len(), core::ptr::null_mut()));
        let y = new(lc::BN_le2bn(y_le.as_ptr(), y_le.len(), core::ptr::null_mut()));
        let y2 = new(lc::BN_new());
        let u = new(lc::BN_new());
        let v = new(lc::BN_new());
        let r = new(lc::BN_new());
        let e = new(lc::BN_new());
        let t = new(lc::BN_new());
        let ctx = bn.ctx;
        if ctx.is_null() || bn.nums.iter().any(|n| n.is_null()) {
            return false;
        }
        if lc::BN_cmp(y, p) >= 0 {
            return false; // non-canonical y
        }
        // u = y^2 - 1, v = d y^2 + 1 (mod p).
        if lc::BN_mod_mul(y2, y, y, p, ctx) != 1
            || lc::BN_mod_mul(v, d, y2, p, ctx) != 1
            || lc::BN_add_word(v, 1) != 1
            || lc::BN_set_word(u, 1) != 1
            || lc::BN_mod_sub(u, y2, u, p, ctx) != 1
        {
            return false;
        }
        if lc::BN_cmp(v, p) == 0 {
            return false; // v = 0 mod p: no inverse (cannot happen for edwards25519's d)
        }
        if lc::BN_is_zero(u) == 1 {
            // x = 0: valid only with the sign bit clear.
            return sign == 0;
        }
        // r = u / v; a point exists iff r is a square: r^((p-1)/2) == 1.
        if lc::BN_mod_inverse(r, v, p, ctx).is_null()
            || lc::BN_mod_mul(r, r, u, p, ctx) != 1
            || lc::BN_copy(e, p).is_null()
            || lc::BN_sub_word(e, 1) != 1
            || lc::BN_rshift1(e, e) != 1
            || lc::BN_mod_exp(t, r, e, p, ctx) != 1
        {
            return false;
        }
        lc::BN_is_one(t) == 1
    }
}
