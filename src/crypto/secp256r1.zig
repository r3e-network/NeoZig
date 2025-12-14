//! secp256r1 elliptic curve implementation
//!
//! Production ECDSA implementation for Neo blockchain using P-256 curve.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Curve = std.crypto.ecc.P256;
const Hash = std.crypto.hash.sha2.Sha256;
const Prf = std.crypto.auth.hmac.Hmac(Hash);
const noise_length = Curve.scalar.encoded_length;

fn reduceToScalar(comptime unreduced_len: usize, s: [unreduced_len]u8) Curve.scalar.Scalar {
    if (unreduced_len >= 48) {
        var xs = [_]u8{0} ** 64;
        @memcpy(xs[xs.len - s.len ..], s[0..]);
        return Curve.scalar.Scalar.fromBytes64(xs, .big);
    }
    var xs = [_]u8{0} ** 48;
    @memcpy(xs[xs.len - s.len ..], s[0..]);
    return Curve.scalar.Scalar.fromBytes48(xs, .big);
}

fn deterministicScalar(h: [Hash.digest_length]u8, secret_key: Curve.scalar.CompressedScalar, noise: ?[noise_length]u8) Curve.scalar.Scalar {
    var k = [_]u8{0x00} ** h.len;
    var m = [_]u8{0x00} ** (h.len + 1 + noise_length + secret_key.len + h.len);
    var t = [_]u8{0x00} ** Curve.scalar.encoded_length;
    const m_v = m[0..h.len];
    const m_i = &m[m_v.len];
    const m_z = m[m_v.len + 1 ..][0..noise_length];
    const m_x = m[m_v.len + 1 + noise_length ..][0..secret_key.len];
    const m_h = m[m.len - h.len ..];

    @memset(m_v, 0x01);
    m_i.* = 0x00;
    if (noise) |n| @memcpy(m_z, &n);
    @memcpy(m_x, &secret_key);
    @memcpy(m_h, &h);
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    m_i.* = 0x01;
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    while (true) {
        var t_off: usize = 0;
        while (t_off < t.len) : (t_off += m_v.len) {
            const t_end = @min(t_off + m_v.len, t.len);
            Prf.create(m_v, m_v, &k);
            @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
        }
        if (Curve.scalar.Scalar.fromBytes(t, .big)) |s| return s else |_| {}
        m_i.* = 0x00;
        Prf.create(&k, m[0 .. m_v.len + 1], &k);
        Prf.create(m_v, m_v, &k);
    }
}

pub const Secp256r1 = struct {
    pub const P: u256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    pub const N: u256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    pub const HALF_CURVE_ORDER: u256 = N >> 1;
    pub const A: u256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    pub const B: u256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    pub const GX: u256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    pub const GY: u256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
};

pub const Point = struct {
    x: u256,
    y: u256,
    is_infinity: bool = false,

    pub fn init(x: u256, y: u256) Point {
        return Point{ .x = x, .y = y };
    }

    pub fn infinity() Point {
        return Point{ .x = 0, .y = 0, .is_infinity = true };
    }

    pub fn generator() Point {
        return Point.init(Secp256r1.GX, Secp256r1.GY);
    }

    pub fn multiply(self: Point, scalar: u256) Point {
        if (scalar == 0 or self.is_infinity) return Point.infinity();
        if (scalar == 1) return self;

        var result = Point.infinity();
        var addend = self;
        var k = scalar;

        while (k > 0) {
            if (k & 1 == 1) result = result.add(addend);
            addend = addend.double();
            k >>= 1;
        }
        return result;
    }

    pub fn add(self: Point, other: Point) Point {
        if (self.is_infinity) return other;
        if (other.is_infinity) return self;
        if (self.x == other.x) {
            return if (self.y == other.y) self.double() else Point.infinity();
        }

        const dx = modSub(other.x, self.x, Secp256r1.P);
        const dy = modSub(other.y, self.y, Secp256r1.P);
        const s = modDiv(dy, dx, Secp256r1.P);

        const x3 = modSub(modSub(modMul(s, s, Secp256r1.P), self.x, Secp256r1.P), other.x, Secp256r1.P);
        const y3 = modSub(modMul(s, modSub(self.x, x3, Secp256r1.P), Secp256r1.P), self.y, Secp256r1.P);

        return Point.init(x3, y3);
    }

    pub fn double(self: Point) Point {
        if (self.is_infinity or self.y == 0) return Point.infinity();

        const three_x_squared = modMul(3, modMul(self.x, self.x, Secp256r1.P), Secp256r1.P);
        const numerator = modAdd(three_x_squared, Secp256r1.A, Secp256r1.P);
        const denominator = modMul(2, self.y, Secp256r1.P);
        const s = modDiv(numerator, denominator, Secp256r1.P);

        const x3 = modSub(modMul(s, s, Secp256r1.P), modMul(2, self.x, Secp256r1.P), Secp256r1.P);
        const y3 = modSub(modMul(s, modSub(self.x, x3, Secp256r1.P), Secp256r1.P), self.y, Secp256r1.P);

        return Point.init(x3, y3);
    }
};

pub fn derivePublicKey(private_key: [32]u8, compressed: bool, allocator: std.mem.Allocator) ![]u8 {
    const key_pair = try loadKeyPair(private_key);
    if (compressed) {
        const encoded = key_pair.public_key.toCompressedSec1();
        const result = try allocator.alloc(u8, encoded.len);
        @memcpy(result, &encoded);
        return result;
    }

    const encoded = key_pair.public_key.toUncompressedSec1();
    const result = try allocator.alloc(u8, encoded.len);
    @memcpy(result, &encoded);
    return result;
}

pub fn sign(hash: [32]u8, private_key: [32]u8) ![64]u8 {
    const key_pair = try loadKeyPair(private_key);
    const z = reduceToScalar(Curve.scalar.encoded_length, hash);

    const k = deterministicScalar(hash, key_pair.secret_key.bytes, null);
    const p = Curve.basePoint.mul(k.toBytes(.big), .big) catch return errors.CryptoError.ECDSAOperationFailed;
    const xs = p.affineCoordinates().x.toBytes(.big);
    const r = reduceToScalar(Curve.Fe.encoded_length, xs);
    if (r.isZero()) return errors.CryptoError.ECDSAOperationFailed;

    const k_inv = k.invert();
    const d = Curve.scalar.Scalar.fromBytes(key_pair.secret_key.bytes, .big) catch return errors.CryptoError.InvalidKey;
    const zrs = z.add(r.mul(d));
    const s = k_inv.mul(zrs);
    if (s.isZero()) return errors.CryptoError.ECDSAOperationFailed;

    const signature = Ecdsa.Signature{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
    return signature.toBytes();
}

pub fn verify(hash: [32]u8, signature: [64]u8, public_key: []const u8) !bool {
    const pk = Ecdsa.PublicKey.fromSec1(public_key) catch {
        return errors.CryptoError.InvalidKey;
    };
    const sig = Ecdsa.Signature.fromBytes(signature);
    const r = Curve.scalar.Scalar.fromBytes(sig.r, .big) catch return false;
    const s = Curve.scalar.Scalar.fromBytes(sig.s, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    const z = reduceToScalar(Curve.scalar.encoded_length, hash);
    if (z.isZero()) return false;

    const s_inv = s.invert();
    const v1 = z.mul(s_inv).toBytes(.little);
    const v2 = r.mul(s_inv).toBytes(.little);

    const v1g = Curve.basePoint.mulPublic(v1, .little) catch return false;
    const v2pk = pk.p.mulPublic(v2, .little) catch return false;
    const v = v1g.add(v2pk);
    const x_bytes = v.affineCoordinates().x.toBytes(.big);
    const vr = reduceToScalar(Curve.Fe.encoded_length, x_bytes);

    return vr.equivalent(r);
}

pub fn recoverPoint(recovery_id: u8, r: u256, s: u256, message_hash: []const u8) ?Point {
    if (recovery_id >= 4 or message_hash.len != 32) return null;
    const n = Secp256r1.N;
    const p = Secp256r1.P;
    if (r == 0 or r >= n or s == 0 or s >= n) return null;

    const j = recovery_id >> 1;
    const is_odd = recovery_id & 1;
    const x_term = @as(u256, j) * n;
    const x_sum = @addWithOverflow(r, x_term);
    if (x_sum[1] != 0) return null;
    const x = x_sum[0];
    if (x >= p) return null;

    var compressed: [33]u8 = undefined;
    compressed[0] = if (is_odd == 0) 0x02 else 0x03;
    const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, x));
    @memcpy(compressed[1..], &x_bytes);

    const R = pointFromCompressed(&compressed) catch return null;
    if (!R.multiply(n).is_infinity) return null;

    const r_inv = modInverse(r, n);
    if (r_inv == 0) return null;

    const e = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, message_hash));
    const e_mod = e % n;
    const neg_e = modNeg(e_mod, n);

    const sr = modMul(s, r_inv, n);
    const er = modMul(neg_e, r_inv, n);

    const sr_point = R.multiply(sr);
    const er_point = Point.generator().multiply(er);
    const public_point = sr_point.add(er_point);
    if (public_point.is_infinity) return null;
    return public_point;
}

pub fn pointFromCompressed(compressed: []const u8) !Point {
    if (compressed.len != 33 or (compressed[0] != 0x02 and compressed[0] != 0x03)) {
        return errors.CryptoError.InvalidKey;
    }

    const x = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, compressed[1..33]));
    const y_is_even = compressed[0] == 0x02;

    const y_squared = modAdd(modAdd(modMul(modMul(x, x, Secp256r1.P), x, Secp256r1.P), modMul(Secp256r1.A, x, Secp256r1.P), Secp256r1.P), Secp256r1.B, Secp256r1.P);
    const y = modSqrt(y_squared, Secp256r1.P);
    const final_y = if (((y & 1) == 0) == y_is_even) y else modSub(Secp256r1.P, y, Secp256r1.P);

    return Point.init(x, final_y);
}

pub fn pointFromUncompressed(uncompressed: []const u8) !Point {
    if (uncompressed.len != 65 or uncompressed[0] != 0x04) return errors.CryptoError.InvalidKey;

    const x = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, uncompressed[1..33]));
    const y = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, uncompressed[33..65]));

    return Point.init(x, y);
}

fn modAdd(a: u256, b: u256, modulus: u256) u256 {
    // Use a wider intermediate to avoid incorrect reduction when `a + b`
    // overflows `u256` (modulus is not a power of two).
    const sum = @as(u512, a) + @as(u512, b);
    return @intCast(sum % @as(u512, modulus));
}

fn modSub(a: u256, b: u256, modulus: u256) u256 {
    if (a >= b) {
        return a - b;
    }
    const diff = b - a;
    return modulus - diff;
}

fn modMul(a: u256, b: u256, modulus: u256) u256 {
    const product = (@as(u512, a % modulus) * @as(u512, b % modulus));
    return @intCast(product % @as(u512, modulus));
}

fn modDiv(a: u256, b: u256, modulus: u256) u256 {
    return modMul(a, modInverse(b, modulus), modulus);
}

fn modInverse(a: u256, modulus: u256) u256 {
    var old_r = modulus;
    var r = a % modulus;
    var old_s: i512 = 0;
    var s: i512 = 1;

    while (r != 0) {
        const quotient = old_r / r;
        const temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        const temp_s = s;
        s = old_s - @as(i512, @intCast(quotient)) * s;
        old_s = temp_s;
    }

    if (old_r > 1) return 0;
    if (old_s < 0) old_s += @as(i512, @intCast(modulus));
    return @intCast(old_s);
}

fn modSqrt(a: u256, p: u256) u256 {
    if (a == 0) return 0;
    const exponent = (p + 1) / 4;
    return modPow(a, exponent, p);
}

fn modPow(base: u256, exponent: u256, modulus: u256) u256 {
    if (exponent == 0) return 1;
    var result: u256 = 1;
    var base_mod = base % modulus;
    var exp = exponent;

    while (exp > 0) {
        if (exp & 1 == 1) {
            result = @intCast((@as(u512, result) * @as(u512, base_mod)) % @as(u512, modulus));
        }
        base_mod = @intCast((@as(u512, base_mod) * @as(u512, base_mod)) % @as(u512, modulus));
        exp >>= 1;
    }
    return result;
}

fn modNeg(a: u256, modulus: u256) u256 {
    return if (a == 0) 0 else modulus - a;
}

fn loadKeyPair(private_key: [32]u8) errors.CryptoError!Ecdsa.KeyPair {
    const secret_key = try Ecdsa.SecretKey.fromBytes(private_key);
    return Ecdsa.KeyPair.fromSecretKey(secret_key) catch {
        return errors.CryptoError.InvalidKey;
    };
}
