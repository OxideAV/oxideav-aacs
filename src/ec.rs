//! Phase C — elliptic-curve arithmetic over the AACS 160-bit curve.
//!
//! AACS Common Final 0.953 §2.3 (Table 2-1) defines a single elliptic
//! curve `E: y² = x³ + a·x + b` over the prime field `GF(p)`, with
//! `a = -3`, used for every digital signature and for the Diffie-Hellman
//! style Bus-Key agreement in the §4.3 Drive Authentication Algorithm.
//! All five domain parameters below are transcribed directly from the
//! spec's Table 2-1 decimal values (converted to big-endian bytes).
//!
//! ```text
//!   p (field prime)  = 9DC9D81355ECCEB560BDB09EF9EAE7C479A7D7DF
//!   a                = -3  (≡ p-3 mod p)
//!   b                = 402DAD3EC1CBCD165248D68E1245E0C4DAACB1D8
//!   G.x (base point) = 2E64FC22578351E6F4CCA7EB81D0A4BDC54CCEC6
//!   G.y              = 0914A25DD05442889DB455C7F23C9A0707F5CBB9
//!   n (order of G)   = 9DC9D81355ECCEB560BDC44F54817B2C7F5AB017
//! ```
//!
//! This module is a **clean-room** big-integer + short-Weierstrass
//! point implementation written from the curve equations and the
//! schoolbook modular-arithmetic identities. No external crypto-library
//! source (RustCrypto, OpenSSL, …) was consulted; the `openssl` CLI is
//! used only as an opaque test-vector oracle in the test suite.
//!
//! # Representation
//!
//! Field elements are 160-bit non-negative integers held as five
//! little-endian `u32` limbs ([`Fp`]). Scalars mod the group order `n`
//! reuse the same [`U160`] limb type. Modular reduction is the generic
//! "subtract the modulus while ≥ modulus" schoolbook method rather than
//! a curve-specific fast reduction — correctness over speed, which is
//! the right trade for an authentication handshake that runs a handful
//! of point multiplications per disc.

/// A 160-bit unsigned integer as five little-endian 32-bit limbs.
///
/// `limbs[0]` is the least-significant word. Values are always kept
/// `< 2^160`; callers reduce modulo `p` or `n` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U160 {
    /// Little-endian 32-bit limbs (`limbs[0]` least significant).
    pub limbs: [u32; 5],
}

impl Ord for U160 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Compare most-significant limb first.
        for i in (0..5).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                core::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        core::cmp::Ordering::Equal
    }
}

impl PartialOrd for U160 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl U160 {
    /// The additive identity (`0`).
    pub const ZERO: U160 = U160 { limbs: [0; 5] };
    /// The multiplicative identity (`1`).
    pub const ONE: U160 = U160 {
        limbs: [1, 0, 0, 0, 0],
    };

    /// Construct from a 20-byte big-endian representation.
    pub fn from_be_bytes(b: &[u8; 20]) -> Self {
        let mut limbs = [0u32; 5];
        for (i, limb) in limbs.iter_mut().enumerate() {
            // Limb i (LE) covers big-endian bytes [16-4i .. 20-4i].
            let off = 16 - 4 * i;
            *limb = ((b[off] as u32) << 24)
                | ((b[off + 1] as u32) << 16)
                | ((b[off + 2] as u32) << 8)
                | (b[off + 3] as u32);
        }
        U160 { limbs }
    }

    /// Serialize to 20-byte big-endian.
    pub fn to_be_bytes(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let off = 16 - 4 * i;
            out[off] = (limb >> 24) as u8;
            out[off + 1] = (limb >> 16) as u8;
            out[off + 2] = (limb >> 8) as u8;
            out[off + 3] = limb as u8;
        }
        out
    }

    /// `true` if the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs == [0u32; 5]
    }

    /// Test bit `i` (0 = least significant). Returns `false` for
    /// `i >= 160`.
    pub fn bit(&self, i: usize) -> bool {
        if i >= 160 {
            return false;
        }
        (self.limbs[i / 32] >> (i % 32)) & 1 == 1
    }

    /// Number of significant bits (`0` for zero, else `1 + floor(log2)`).
    pub fn bit_len(&self) -> usize {
        for i in (0..5).rev() {
            if self.limbs[i] != 0 {
                return i * 32 + (32 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Add `self + other`, returning `(sum mod 2^160, carry_out)`.
    fn adc(&self, other: &U160) -> (U160, u32) {
        let mut limbs = [0u32; 5];
        let mut carry: u64 = 0;
        for (i, out) in limbs.iter_mut().enumerate() {
            let s = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            *out = s as u32;
            carry = s >> 32;
        }
        (U160 { limbs }, carry as u32)
    }

    /// Subtract `self - other`, returning `(diff mod 2^160, borrow_out)`.
    /// `borrow_out == 1` means `self < other`.
    fn sbb(&self, other: &U160) -> (U160, u32) {
        let mut limbs = [0u32; 5];
        let mut borrow: i64 = 0;
        for (i, out) in limbs.iter_mut().enumerate() {
            let d = self.limbs[i] as i64 - other.limbs[i] as i64 - borrow;
            if d < 0 {
                *out = (d + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                *out = d as u32;
                borrow = 0;
            }
        }
        (U160 { limbs }, borrow as u32)
    }
}

/// A field element of `GF(p)` for the AACS curve prime `p`.
///
/// Wraps a [`U160`] kept reduced in `[0, p)`. Arithmetic operators are
/// the modular versions; raw limb access is via `.value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fp {
    /// Reduced representative in `[0, p)`.
    pub value: U160,
}

/// The 160-bit field prime `p` (AACS Common Table 2-1).
pub const P: U160 = U160 {
    limbs: [
        0x79a7_d7df,
        0xf9ea_e7c4,
        0x60bd_b09e,
        0x55ec_ceb5,
        0x9dc9_d813,
    ],
};

/// The curve coefficient `b` (AACS Common Table 2-1).
pub const B: U160 = U160 {
    limbs: [
        0xdaac_b1d8,
        0x1245_e0c4,
        0x5248_d68e,
        0xc1cb_cd16,
        0x402d_ad3e,
    ],
};

/// Base-point x-coordinate `G.x` (AACS Common Table 2-1).
pub const GX: U160 = U160 {
    limbs: [
        0xc54c_cec6,
        0x81d0_a4bd,
        0xf4cc_a7eb,
        0x5783_51e6,
        0x2e64_fc22,
    ],
};

/// Base-point y-coordinate `G.y` (AACS Common Table 2-1).
pub const GY: U160 = U160 {
    limbs: [
        0x07f5_cbb9,
        0xf23c_9a07,
        0x9db4_55c7,
        0xd054_4288,
        0x0914_a25d,
    ],
};

/// Order `n` of the base point `G` (AACS Common Table 2-1).
pub const N: U160 = U160 {
    limbs: [
        0x7f5a_b017,
        0x5481_7b2c,
        0x60bd_c44f,
        0x55ec_ceb5,
        0x9dc9_d813,
    ],
};

impl Fp {
    /// Zero in `GF(p)`.
    pub const ZERO: Fp = Fp { value: U160::ZERO };
    /// One in `GF(p)`.
    pub const ONE: Fp = Fp { value: U160::ONE };

    /// Reduce an arbitrary [`U160`] (already `< 2^160`, hence at most a
    /// few subtractions above `p`) into `[0, p)`.
    pub fn from_u160(mut v: U160) -> Self {
        while v.cmp(&P) != core::cmp::Ordering::Less {
            let (r, _) = v.sbb(&P);
            v = r;
        }
        Fp { value: v }
    }

    /// Construct from a 20-byte big-endian field element.
    pub fn from_be_bytes(b: &[u8; 20]) -> Self {
        Fp::from_u160(U160::from_be_bytes(b))
    }

    /// Serialize the reduced value to 20-byte big-endian.
    pub fn to_be_bytes(self) -> [u8; 20] {
        self.value.to_be_bytes()
    }

    /// `true` if the element is zero.
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    /// Modular addition `(a + b) mod p`.
    pub fn add(&self, other: &Fp) -> Fp {
        let (sum, carry) = self.value.adc(&other.value);
        // Result may exceed p (and could be ≥ 2^160 if carry==1).
        // Conditionally subtract p.
        if carry == 1 {
            // sum + 2^160 ≥ p, subtract p once (2^160 - p < p so one
            // subtraction suffices to bring it back below 2^160 range
            // we track; then a final reduce).
            let (r, _) = sum.sbb(&P);
            Fp::from_u160(r)
        } else {
            Fp::from_u160(sum)
        }
    }

    /// Modular subtraction `(a - b) mod p`.
    pub fn sub(&self, other: &Fp) -> Fp {
        let (diff, borrow) = self.value.sbb(&other.value);
        if borrow == 1 {
            // self < other → add p back.
            let (r, _) = diff.adc(&P);
            Fp { value: r }
        } else {
            Fp { value: diff }
        }
    }

    /// Modular multiplication `(a · b) mod p` via 320-bit schoolbook
    /// product followed by reduction.
    pub fn mul(&self, other: &Fp) -> Fp {
        let prod = mul_wide(&self.value, &other.value);
        Fp {
            value: reduce_wide(&prod, &P),
        }
    }

    /// Modular squaring.
    pub fn square(&self) -> Fp {
        self.mul(self)
    }

    /// Modular negation `(-a) mod p`.
    pub fn neg(&self) -> Fp {
        if self.is_zero() {
            *self
        } else {
            let (r, _) = P.sbb(&self.value);
            Fp { value: r }
        }
    }

    /// Modular inverse `a^{-1} mod p` via Fermat's little theorem
    /// (`a^{p-2} mod p`). `p` is prime so this is well-defined for
    /// `a != 0`; returns zero for the (invalid) zero input.
    pub fn inv(&self) -> Fp {
        if self.is_zero() {
            return Fp::ZERO;
        }
        // exponent = p - 2
        let (mut e, _) = P.sbb(&U160 {
            limbs: [2, 0, 0, 0, 0],
        });
        // Reuse the modular-pow ladder over GF(p).
        let _ = &mut e;
        self.pow(&e)
    }

    /// Modular exponentiation `self^exp mod p` (square-and-multiply,
    /// MSB-first). Used by [`Fp::inv`] and the square-root routine.
    pub fn pow(&self, exp: &U160) -> Fp {
        let mut result = Fp::ONE;
        let bits = exp.bit_len();
        for i in (0..bits).rev() {
            result = result.square();
            if exp.bit(i) {
                result = result.mul(self);
            }
        }
        result
    }
}

/// 320-bit product as ten little-endian `u32` limbs.
fn mul_wide(a: &U160, b: &U160) -> [u32; 10] {
    let mut out = [0u64; 10];
    for i in 0..5 {
        let mut carry: u64 = 0;
        for j in 0..5 {
            let cur = out[i + j] + a.limbs[i] as u64 * b.limbs[j] as u64 + carry;
            out[i + j] = cur & 0xFFFF_FFFF;
            carry = cur >> 32;
        }
        out[i + 5] += carry;
    }
    let mut limbs = [0u32; 10];
    for i in 0..10 {
        limbs[i] = out[i] as u32;
    }
    limbs
}

/// Reduce a 320-bit value (ten limbs) modulo a 160-bit modulus `m` by
/// schoolbook long division (bit-by-bit). Slow but unambiguously
/// correct — adequate for the handful of reductions per handshake.
fn reduce_wide(wide: &[u32; 10], m: &U160) -> U160 {
    // Walk bits from the most significant (bit 319) down, building the
    // remainder via shift-and-subtract.
    let mut rem = U160::ZERO;
    for bit in (0..320).rev() {
        // rem <<= 1
        let mut carry = 0u32;
        for limb in rem.limbs.iter_mut() {
            let new_carry = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = new_carry;
        }
        // bring in the next bit of `wide`
        let wbit = (wide[bit / 32] >> (bit % 32)) & 1;
        rem.limbs[0] |= wbit;
        // if rem >= m, subtract m. The shift could overflow past
        // 2^160 (carry==1); treat that as "definitely >= m".
        if carry == 1 || rem.cmp(m) != core::cmp::Ordering::Less {
            let (r, _) = rem.sbb(m);
            rem = r;
        }
    }
    rem
}

// ---------------------------------------------------------------------
// Scalar arithmetic modulo the group order n
// ---------------------------------------------------------------------

/// Reduce a [`U160`] modulo the group order `n`.
pub fn scalar_reduce(mut v: U160) -> U160 {
    while v.cmp(&N) != core::cmp::Ordering::Less {
        let (r, _) = v.sbb(&N);
        v = r;
    }
    v
}

/// Reduce a 320-bit wide value modulo `n` (used to fold a full SHA-1
/// digest / random material into a scalar).
pub fn scalar_reduce_wide(wide: &[u32; 10]) -> U160 {
    reduce_wide(wide, &N)
}

/// Modular addition of two scalars mod `n`.
pub fn scalar_add(a: &U160, b: &U160) -> U160 {
    let (sum, carry) = a.adc(b);
    if carry == 1 {
        let (r, _) = sum.sbb(&N);
        scalar_reduce(r)
    } else {
        scalar_reduce(sum)
    }
}

/// Modular multiplication of two scalars mod `n`.
pub fn scalar_mul(a: &U160, b: &U160) -> U160 {
    let prod = mul_wide(a, b);
    reduce_wide(&prod, &N)
}

/// Modular inverse of a scalar mod `n` (Fermat: `a^{n-2} mod n`).
pub fn scalar_inv(a: &U160) -> U160 {
    if a.is_zero() {
        return U160::ZERO;
    }
    let (exp, _) = N.sbb(&U160 {
        limbs: [2, 0, 0, 0, 0],
    });
    scalar_pow(a, &exp)
}

/// Scalar modular exponentiation `base^exp mod n`.
fn scalar_pow(base: &U160, exp: &U160) -> U160 {
    let mut result = U160::ONE;
    let bits = exp.bit_len();
    for i in (0..bits).rev() {
        result = scalar_mul(&result, &result);
        if exp.bit(i) {
            result = scalar_mul(&result, base);
        }
    }
    result
}

// ---------------------------------------------------------------------
// Curve points (affine, with explicit point-at-infinity)
// ---------------------------------------------------------------------

/// An affine point on the AACS curve, or the point at infinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    /// The identity element (point at infinity).
    Infinity,
    /// An affine point `(x, y)` satisfying the curve equation.
    Affine {
        /// x-coordinate.
        x: Fp,
        /// y-coordinate.
        y: Fp,
    },
}

impl Point {
    /// The curve base point `G` from Table 2-1.
    pub fn generator() -> Point {
        Point::Affine {
            x: Fp::from_u160(GX),
            y: Fp::from_u160(GY),
        }
    }

    /// `true` if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        matches!(self, Point::Infinity)
    }

    /// Construct an affine point from two 20-byte big-endian
    /// coordinates, validating that it lies on the curve. Returns
    /// `None` if `(x, y)` does not satisfy `y² = x³ - 3x + b`.
    pub fn from_coords(x: &[u8; 20], y: &[u8; 20]) -> Option<Point> {
        let px = Fp::from_be_bytes(x);
        let py = Fp::from_be_bytes(y);
        let p = Point::Affine { x: px, y: py };
        if p.is_on_curve() {
            Some(p)
        } else {
            None
        }
    }

    /// Serialize an affine point to the 40-byte AACS EC-point encoding
    /// `x(20) || y(20)` big-endian. The point at infinity encodes as
    /// all-zero (it never appears as a valid `Dv`/`Hv`).
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        if let Point::Affine { x, y } = self {
            out[..20].copy_from_slice(&x.to_be_bytes());
            out[20..].copy_from_slice(&y.to_be_bytes());
        }
        out
    }

    /// Verify the curve equation `y² = x³ + a·x + b` with `a = -3`.
    pub fn is_on_curve(&self) -> bool {
        match self {
            Point::Infinity => true,
            Point::Affine { x, y } => {
                let three = Fp::from_u160(U160 {
                    limbs: [3, 0, 0, 0, 0],
                });
                let lhs = y.square();
                // x³ - 3x + b
                let x3 = x.square().mul(x);
                let rhs = x3.sub(&three.mul(x)).add(&Fp::from_u160(B));
                lhs == rhs
            }
        }
    }

    /// Point doubling `2P`.
    pub fn double(&self) -> Point {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => {
                if y.is_zero() {
                    return Point::Infinity;
                }
                // λ = (3x² + a) / (2y), a = -3.
                let three = Fp::from_u160(U160 {
                    limbs: [3, 0, 0, 0, 0],
                });
                let two = Fp::from_u160(U160 {
                    limbs: [2, 0, 0, 0, 0],
                });
                let num = three.mul(&x.square()).sub(&three); // 3x² - 3
                let den = two.mul(y);
                let lambda = num.mul(&den.inv());
                let x3 = lambda.square().sub(x).sub(x);
                let y3 = lambda.mul(&x.sub(&x3)).sub(y);
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    /// Point addition `P + Q`.
    pub fn add(&self, other: &Point) -> Point {
        match (self, other) {
            (Point::Infinity, _) => *other,
            (_, Point::Infinity) => *self,
            (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) => {
                if x1 == x2 {
                    if y1 == y2 {
                        return self.double();
                    }
                    // x1 == x2 but y1 == -y2 ⇒ result is infinity.
                    return Point::Infinity;
                }
                // λ = (y2 - y1) / (x2 - x1)
                let lambda = y2.sub(y1).mul(&x2.sub(x1).inv());
                let x3 = lambda.square().sub(x1).sub(x2);
                let y3 = lambda.mul(&x1.sub(&x3)).sub(y1);
                Point::Affine { x: x3, y: y3 }
            }
        }
    }

    /// Scalar multiplication `k·P` via MSB-first double-and-add, run in
    /// Jacobian projective coordinates so only a single field inversion
    /// is needed (at the final affine conversion) rather than one per
    /// step. The result matches the naive affine ladder exactly.
    pub fn mul_scalar(&self, k: &U160) -> Point {
        let base = match self {
            Point::Infinity => return Point::Infinity,
            Point::Affine { x, y } => Jacobian {
                x: *x,
                y: *y,
                z: Fp::ONE,
            },
        };
        let mut acc = Jacobian::INFINITY;
        let bits = k.bit_len();
        for i in (0..bits).rev() {
            acc = acc.double();
            if k.bit(i) {
                acc = acc.add(&base);
            }
        }
        acc.to_affine()
    }

    /// x-coordinate as a [`U160`] (panics on the point at infinity).
    pub fn x_u160(&self) -> U160 {
        match self {
            Point::Affine { x, .. } => x.value,
            Point::Infinity => U160::ZERO,
        }
    }
}

/// Jacobian projective point `(X : Y : Z)` representing the affine point
/// `(X/Z², Y/Z³)`, with `Z = 0` denoting the point at infinity. Used
/// internally by [`Point::mul_scalar`] to defer field inversions; the
/// `a = -3` doubling shortcut from the standard short-Weierstrass
/// formulae applies because this curve fixes `a = -3` (Table 2-1).
#[derive(Debug, Clone, Copy)]
struct Jacobian {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl Jacobian {
    /// The point at infinity (`Z = 0`).
    const INFINITY: Jacobian = Jacobian {
        x: Fp::ONE,
        y: Fp::ONE,
        z: Fp::ZERO,
    };

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Jacobian doubling using the `a = -3` formulae:
    /// `M = 3(X - Z²)(X + Z²)`, `S = 4XY²`, `X' = M² - 2S`,
    /// `Y' = M(S - X') - 8Y⁴`, `Z' = 2YZ`.
    fn double(&self) -> Jacobian {
        if self.is_infinity() || self.y.is_zero() {
            return Jacobian::INFINITY;
        }
        let two = Fp::from_u160(U160 {
            limbs: [2, 0, 0, 0, 0],
        });
        let three = Fp::from_u160(U160 {
            limbs: [3, 0, 0, 0, 0],
        });
        let four = Fp::from_u160(U160 {
            limbs: [4, 0, 0, 0, 0],
        });
        let eight = Fp::from_u160(U160 {
            limbs: [8, 0, 0, 0, 0],
        });
        let zz = self.z.square();
        let yy = self.y.square();
        let m = three.mul(&self.x.sub(&zz)).mul(&self.x.add(&zz));
        let s = four.mul(&self.x).mul(&yy);
        let x3 = m.square().sub(&two.mul(&s));
        let yyyy = yy.square();
        let y3 = m.mul(&s.sub(&x3)).sub(&eight.mul(&yyyy));
        let z3 = two.mul(&self.y).mul(&self.z);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed Jacobian + affine addition (`other.z == 1`). Falls back to
    /// doubling when the points coincide and to infinity for inverses.
    fn add(&self, other: &Jacobian) -> Jacobian {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        // other is affine (Z2 = 1): U1 = X1, U2 = X2·Z1², S1 = Y1,
        // S2 = Y2·Z1³.
        let z1z1 = self.z.square();
        let u2 = other.x.mul(&z1z1);
        let s2 = other.y.mul(&z1z1).mul(&self.z);
        let u1 = self.x;
        let s1 = self.y;
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            }
            return Jacobian::INFINITY;
        }
        let hh = h.square();
        let hhh = hh.mul(&h);
        let two = Fp::from_u160(U160 {
            limbs: [2, 0, 0, 0, 0],
        });
        let u1hh = u1.mul(&hh);
        let x3 = r.square().sub(&hhh).sub(&two.mul(&u1hh));
        let y3 = r.mul(&u1hh.sub(&x3)).sub(&s1.mul(&hhh));
        let z3 = self.z.mul(&h);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Convert back to an affine [`Point`] with a single field inversion.
    fn to_affine(self) -> Point {
        if self.is_infinity() {
            return Point::Infinity;
        }
        let zinv = self.z.inv();
        let zinv2 = zinv.square();
        let zinv3 = zinv2.mul(&zinv);
        Point::Affine {
            x: self.x.mul(&zinv2),
            y: self.y.mul(&zinv3),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u160_from_small(v: u32) -> U160 {
        U160 {
            limbs: [v, 0, 0, 0, 0],
        }
    }

    #[test]
    fn curve_params_round_trip_bytes() {
        // p, n etc. survive a byte round-trip.
        for v in [P, B, GX, GY, N] {
            let b = v.to_be_bytes();
            assert_eq!(U160::from_be_bytes(&b), v);
        }
    }

    #[test]
    fn generator_is_on_curve() {
        assert!(Point::generator().is_on_curve());
    }

    #[test]
    fn fp_add_sub_inverse() {
        let a = Fp::from_u160(u160_from_small(0x1234_5678));
        let b = Fp::from_u160(u160_from_small(0x9abc_def0));
        let c = a.add(&b);
        assert_eq!(c.sub(&b), a);
        assert_eq!(c.sub(&a), b);
    }

    #[test]
    fn fp_mul_inv_is_one() {
        let a = Fp::from_u160(GX);
        let inv = a.inv();
        let prod = a.mul(&inv);
        assert_eq!(prod, Fp::ONE);
    }

    #[test]
    fn scalar_inv_is_one() {
        let a = U160 {
            limbs: [0xdead_beef, 0x1234, 0x5678, 0x9abc, 0x0def],
        };
        let inv = scalar_inv(&a);
        assert_eq!(scalar_mul(&a, &inv), U160::ONE);
    }

    #[test]
    fn generator_order_n_is_infinity() {
        // n·G == O.
        let p = Point::generator().mul_scalar(&N);
        assert!(p.is_infinity());
    }

    #[test]
    fn double_matches_add_self() {
        let g = Point::generator();
        assert_eq!(g.double(), g.add(&g));
    }

    #[test]
    fn scalar_mul_distributes() {
        // (a + b)·G == a·G + b·G
        let a = u160_from_small(7);
        let b = u160_from_small(11);
        let g = Point::generator();
        let lhs = g.mul_scalar(&scalar_add(&a, &b));
        let rhs = g.mul_scalar(&a).add(&g.mul_scalar(&b));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn affine_round_trips_through_bytes() {
        let g = Point::generator();
        let bytes = g.to_bytes();
        let mut x = [0u8; 20];
        let mut y = [0u8; 20];
        x.copy_from_slice(&bytes[..20]);
        y.copy_from_slice(&bytes[20..]);
        assert_eq!(Point::from_coords(&x, &y), Some(g));
    }
}
