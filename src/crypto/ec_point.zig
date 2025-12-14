//! Elliptic Curve Point implementation
//!
//! Complete conversion from NeoSwift ECPoint.swift extensions
//! Provides elliptic curve point operations for secp256r1.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const secp256r1 = @import("secp256r1.zig");

/// Elliptic curve point (converted from Swift ECPoint extensions)
pub const ECPoint = struct {
    x: u256,
    y: u256,
    infinity: bool,

    const Self = @This();

    /// Creates new EC point (equivalent to Swift ECPoint)
    pub fn init(x: u256, y: u256) Self {
        return Self{ .x = x, .y = y, .infinity = false };
    }

    /// Creates point at infinity (equivalent to Swift infinity point)
    pub fn infinityPoint() Self {
        return Self{ .x = 0, .y = 0, .infinity = true };
    }

    /// Gets generator point (equivalent to Swift generator access)
    pub fn generator() Self {
        return Self.init(secp256r1.Secp256r1.GX, secp256r1.Secp256r1.GY);
    }

    /// Point multiplication (equivalent to Swift multiply(_ k: BInt))
    pub fn multiply(self: Self, k: u256) Self {
        if (k == 0 or self.infinity) return Self.infinityPoint();
        if (k == 1) return self;

        var result = Self.infinityPoint();
        var addend = self;
        var scalar = k;

        while (scalar > 0) {
            if (scalar & 1 == 1) {
                result = result.add(addend);
            }
            addend = addend.double();
            scalar >>= 1;
        }

        return result;
    }

    /// Point addition (equivalent to Swift point addition)
    pub fn add(self: Self, other: Self) Self {
        if (self.infinity) return other;
        if (other.infinity) return self;

        if (self.x == other.x) {
            if (self.y == other.y) {
                return self.double();
            } else {
                return Self.infinityPoint();
            }
        }

        // Regular point addition using secp256r1 field operations
        const dx = modSub(other.x, self.x, secp256r1.Secp256r1.P);
        const dy = modSub(other.y, self.y, secp256r1.Secp256r1.P);
        const s = modDiv(dy, dx, secp256r1.Secp256r1.P);

        const x3 = modSub(modSub(modMul(s, s, secp256r1.Secp256r1.P), self.x, secp256r1.Secp256r1.P), other.x, secp256r1.Secp256r1.P);
        const y3 = modSub(modMul(s, modSub(self.x, x3, secp256r1.Secp256r1.P), secp256r1.Secp256r1.P), self.y, secp256r1.Secp256r1.P);

        return Self.init(x3, y3);
    }

    /// Point doubling (equivalent to Swift point doubling)
    pub fn double(self: Self) Self {
        if (self.infinity or self.y == 0) return Self.infinityPoint();

        // s = (3x^2 + a) / (2y)
        const three_x_squared = modMul(3, modMul(self.x, self.x, secp256r1.Secp256r1.P), secp256r1.Secp256r1.P);
        const numerator = modAdd(three_x_squared, secp256r1.Secp256r1.A, secp256r1.Secp256r1.P);
        const denominator = modMul(2, self.y, secp256r1.Secp256r1.P);
        const s = modDiv(numerator, denominator, secp256r1.Secp256r1.P);

        const x3 = modSub(modMul(s, s, secp256r1.Secp256r1.P), modMul(2, self.x, secp256r1.Secp256r1.P), secp256r1.Secp256r1.P);
        const y3 = modSub(modMul(s, modSub(self.x, x3, secp256r1.Secp256r1.P), secp256r1.Secp256r1.P), self.y, secp256r1.Secp256r1.P);

        return Self.init(x3, y3);
    }

    /// Gets encoded point (equivalent to Swift getEncoded(_ compressed: Bool))
    pub fn getEncoded(self: Self, compressed: bool, allocator: std.mem.Allocator) ![]u8 {
        if (self.infinity) return errors.CryptoError.InvalidCurvePoint;

        if (compressed) {
            var result = try allocator.alloc(u8, 33);

            // Determine prefix based on y coordinate parity
            result[0] = if (self.y & 1 == 0) 0x02 else 0x03;

            // Store x coordinate as big-endian bytes
            const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.x));
            @memcpy(result[1..33], &x_bytes);

            return result;
        } else {
            var result = try allocator.alloc(u8, 65);

            result[0] = 0x04; // Uncompressed prefix

            // Store x and y coordinates as big-endian bytes
            const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.x));
            const y_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.y));

            @memcpy(result[1..33], &x_bytes);
            @memcpy(result[33..65], &y_bytes);

            return result;
        }
    }

    /// Decodes point from encoded bytes (equivalent to Swift point decoding)
    pub fn fromEncoded(encoded: []const u8) !Self {
        if (encoded.len == 33) {
            // Compressed point
            if (encoded[0] != 0x02 and encoded[0] != 0x03) return errors.CryptoError.InvalidCurvePoint;

            const x = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, encoded[1..33]));
            const y_is_even = encoded[0] == 0x02;

            // Calculate y^2 = x^3 + ax + b (mod p)
            const x_cubed = modMul(modMul(x, x, secp256r1.Secp256r1.P), x, secp256r1.Secp256r1.P);
            const ax = modMul(secp256r1.Secp256r1.A, x, secp256r1.Secp256r1.P);
            const y_squared = modAdd(modAdd(x_cubed, ax, secp256r1.Secp256r1.P), secp256r1.Secp256r1.B, secp256r1.Secp256r1.P);

            // Calculate square root
            const y = modSqrt(y_squared, secp256r1.Secp256r1.P);

            // Choose correct root based on parity
            const final_y = if (((y & 1) == 0) == y_is_even) y else modSub(secp256r1.Secp256r1.P, y, secp256r1.Secp256r1.P);

            return Self.init(x, final_y);
        } else if (encoded.len == 65) {
            // Uncompressed point
            if (encoded[0] != 0x04) return errors.CryptoError.InvalidCurvePoint;

            const x = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, encoded[1..33]));
            const y = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, encoded[33..65]));

            const point = Self.init(x, y);
            if (!point.isOnCurve()) return errors.CryptoError.InvalidCurvePoint;

            return point;
        } else {
            return errors.CryptoError.InvalidCurvePoint;
        }
    }

    /// Validates point is on curve (equivalent to Swift curve validation)
    pub fn isOnCurve(self: Self) bool {
        if (self.infinity) return true;

        // Check y^2 = x^3 + ax + b (mod p)
        const y_squared = modMul(self.y, self.y, secp256r1.Secp256r1.P);
        const x_cubed = modMul(modMul(self.x, self.x, secp256r1.Secp256r1.P), self.x, secp256r1.Secp256r1.P);
        const ax = modMul(secp256r1.Secp256r1.A, self.x, secp256r1.Secp256r1.P);
        const right_side = modAdd(modAdd(x_cubed, ax, secp256r1.Secp256r1.P), secp256r1.Secp256r1.B, secp256r1.Secp256r1.P);

        return y_squared == right_side;
    }

    /// Compares points for equality
    pub fn eql(self: Self, other: Self) bool {
        if (self.infinity and other.infinity) return true;
        if (self.infinity or other.infinity) return false;
        return self.x == other.x and self.y == other.y;
    }
};

// Modular arithmetic helpers (use secp256r1 implementations)
fn modAdd(a: u256, b: u256, modulus: u256) u256 {
    // Use a wider intermediate to avoid incorrect reduction when `a + b`
    // overflows `u256` (modulus is not a power of two).
    const sum = @as(u512, a) + @as(u512, b);
    return @intCast(sum % @as(u512, modulus));
}

fn modSub(a: u256, b: u256, modulus: u256) u256 {
    if (a >= b) return a - b;
    // Avoid `a + modulus - b` which can overflow `u256` for large values.
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
    // Use extended Euclidean algorithm
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

    if (old_r > 1) return 0; // No inverse
    if (old_s < 0) old_s += @as(i512, @intCast(modulus));

    return @intCast(old_s);
}

fn modSqrt(a: u256, p: u256) u256 {
    // For secp256r1, p ≡ 3 (mod 4)
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

// Tests (converted from Swift ECPoint tests)
test "ECPoint creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    // Test generator point (equivalent to Swift generator tests)
    const generator = ECPoint.generator();
    try testing.expect(generator.isOnCurve());
    try testing.expect(!generator.infinity);

    // Test point at infinity
    const infinity_point = ECPoint.infinityPoint();
    try testing.expect(infinity_point.infinity);
    try testing.expect(infinity_point.isOnCurve());
}

test "ECPoint multiplication operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    const generator = ECPoint.generator();

    // Test point multiplication (equivalent to Swift multiply tests)
    const doubled = generator.multiply(2);
    try testing.expect(doubled.isOnCurve());
    try testing.expect(!doubled.infinity);

    // Test multiplication by 0
    const zero_mult = generator.multiply(0);
    try testing.expect(zero_mult.infinity);

    // Test multiplication by 1
    const identity_mult = generator.multiply(1);
    try testing.expect(identity_mult.eql(generator));

    // Test large scalar multiplication
    const large_scalar: u256 = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;
    const large_mult = generator.multiply(large_scalar);
    try testing.expect(large_mult.isOnCurve());
    try testing.expect(!large_mult.infinity);
}

test "ECPoint encoding operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const generator = ECPoint.generator();

    // Test compressed encoding (equivalent to Swift getEncoded(true))
    const compressed = try generator.getEncoded(true, allocator);
    defer allocator.free(compressed);

    try testing.expectEqual(@as(usize, 33), compressed.len);
    try testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03);

    // Test uncompressed encoding (equivalent to Swift getEncoded(false))
    const uncompressed = try generator.getEncoded(false, allocator);
    defer allocator.free(uncompressed);

    try testing.expectEqual(@as(usize, 65), uncompressed.len);
    try testing.expectEqual(@as(u8, 0x04), uncompressed[0]);

    // Test round-trip encoding
    const decoded_compressed = try ECPoint.fromEncoded(compressed);
    try testing.expect(generator.eql(decoded_compressed));

    const decoded_uncompressed = try ECPoint.fromEncoded(uncompressed);
    try testing.expect(generator.eql(decoded_uncompressed));
}

test "ECPoint addition and doubling" {
    const testing = std.testing;

    const generator = ECPoint.generator();

    // Test point doubling (equivalent to Swift doubling tests)
    const doubled_direct = generator.double();
    const doubled_mult = generator.multiply(2);

    try testing.expect(doubled_direct.eql(doubled_mult));
    try testing.expect(doubled_direct.isOnCurve());

    // Test point addition
    const point1 = generator;
    const point2 = generator.double();
    const sum = point1.add(point2);

    try testing.expect(sum.isOnCurve());
    try testing.expect(!sum.infinity);

    // Test addition with infinity
    const infinity = ECPoint.infinityPoint();
    const sum_with_infinity = generator.add(infinity);
    try testing.expect(sum_with_infinity.eql(generator));

    // Test addition of point with its negation
    const negated_generator = ECPoint.init(generator.x, secp256r1.Secp256r1.P - generator.y);
    const sum_with_negation = generator.add(negated_generator);
    try testing.expect(sum_with_negation.infinity);
}

test "ECPoint curve validation" {
    const testing = std.testing;

    // Test valid points are on curve
    const generator = ECPoint.generator();
    try testing.expect(generator.isOnCurve());

    const doubled = generator.double();
    try testing.expect(doubled.isOnCurve());

    const multiplied = generator.multiply(12345);
    try testing.expect(multiplied.isOnCurve());

    // Test point at infinity is valid
    const infinity = ECPoint.infinityPoint();
    try testing.expect(infinity.isOnCurve());

    // Test invalid point (not on curve)
    const invalid_point = ECPoint.init(1, 1); // (1,1) is not on secp256r1
    try testing.expect(!invalid_point.isOnCurve());
}
