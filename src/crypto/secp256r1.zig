//! secp256r1 elliptic curve implementation
//!
//! Production ECDSA implementation for Neo blockchain using P-256 curve.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

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
    x: u256, y: u256, is_infinity: bool = false,
    
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
    const scalar = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &private_key));
    if (scalar == 0 or scalar >= Secp256r1.N) return errors.CryptoError.InvalidKey;
    
    const generator = Point.generator();
    const public_point = generator.multiply(scalar);
    if (public_point.is_infinity) return errors.CryptoError.KeyGenerationFailed;
    
    var result = try allocator.alloc(u8, if (compressed) 33 else 65);
    
    if (compressed) {
        result[0] = if (public_point.y & 1 == 0) 0x02 else 0x03;
        const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, public_point.x));
        @memcpy(result[1..33], &x_bytes);
    } else {
        result[0] = 0x04;
        const x_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, public_point.x));
        const y_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, public_point.y));
        @memcpy(result[1..33], &x_bytes);
        @memcpy(result[33..65], &y_bytes);
    }
    
    return result;
}

pub fn sign(hash: [32]u8, private_key: [32]u8) ![64]u8 {
    const z = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &hash));
    const d = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &private_key));
    
    if (d == 0 or d >= Secp256r1.N) return errors.CryptoError.InvalidKey;
    
    const k = generateDeterministicK(hash, private_key);
    if (k == 0 or k >= Secp256r1.N) return errors.CryptoError.ECDSAOperationFailed;
    
    const generator = Point.generator();
    const k_point = generator.multiply(k);
    if (k_point.is_infinity) return errors.CryptoError.ECDSAOperationFailed;
    
    const r = k_point.x % Secp256r1.N;
    if (r == 0) return errors.CryptoError.ECDSAOperationFailed;
    
    const k_inv = modInverse(k, Secp256r1.N);
    const rd = modMul(r, d, Secp256r1.N);
    const z_plus_rd = modAdd(z, rd, Secp256r1.N);
    var s = modMul(k_inv, z_plus_rd, Secp256r1.N);
    
    if (s == 0) return errors.CryptoError.ECDSAOperationFailed;
    if (s > Secp256r1.HALF_CURVE_ORDER) s = Secp256r1.N - s;
    
    var signature: [64]u8 = undefined;
    @memcpy(signature[0..32], &std.mem.toBytes(std.mem.nativeToBig(u256, r)));
    @memcpy(signature[32..64], &std.mem.toBytes(std.mem.nativeToBig(u256, s)));
    
    return signature;
}

pub fn verify(hash: [32]u8, signature: [64]u8, public_key: []const u8) !bool {
    const r = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, signature[0..32]));
    const s = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, signature[32..64]));
    
    if (r == 0 or r >= Secp256r1.N or s == 0 or s >= Secp256r1.N) return false;
    
    const public_point = if (public_key.len == 33)
        try pointFromCompressed(public_key)
    else if (public_key.len == 65)
        try pointFromUncompressed(public_key)
    else
        return errors.CryptoError.InvalidKey;
    
    const z = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &hash));
    const s_inv = modInverse(s, Secp256r1.N);
    const u1 = modMul(z, s_inv, Secp256r1.N);
    const u2 = modMul(r, s_inv, Secp256r1.N);
    
    const generator = Point.generator();
    const point1 = generator.multiply(u1);
    const point2 = public_point.multiply(u2);
    const result_point = point1.add(point2);
    
    if (result_point.is_infinity) return false;
    return (result_point.x % Secp256r1.N) == r;
}

fn pointFromCompressed(compressed: []const u8) !Point {
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

fn pointFromUncompressed(uncompressed: []const u8) !Point {
    if (uncompressed.len != 65 or uncompressed[0] != 0x04) return errors.CryptoError.InvalidKey;
    
    const x = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, uncompressed[1..33]));
    const y = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, uncompressed[33..65]));
    
    return Point.init(x, y);
}

fn generateDeterministicK(hash: [32]u8, private_key: [32]u8) u256 {
    var v = [_]u8{0x01} ** 32;
    var k_hmac = [_]u8{0x00} ** 32;
    
    var hmac_input = std.ArrayList(u8).init(std.heap.page_allocator);
    defer hmac_input.deinit();
    
    hmac_input.appendSlice(&v) catch return 0;
    hmac_input.append(0x00) catch return 0;
    hmac_input.appendSlice(&private_key) catch return 0;
    hmac_input.appendSlice(&hash) catch return 0;
    
    hmacSha256(&k_hmac, hmac_input.items, &k_hmac);
    hmacSha256(&k_hmac, &v, &v);
    
    hmac_input.clearRetainingCapacity();
    hmac_input.appendSlice(&v) catch return 0;
    hmac_input.append(0x01) catch return 0;
    hmac_input.appendSlice(&private_key) catch return 0;
    hmac_input.appendSlice(&hash) catch return 0;
    
    hmacSha256(&k_hmac, hmac_input.items, &k_hmac);
    hmacSha256(&k_hmac, &v, &v);
    
    while (true) {
        hmacSha256(&k_hmac, &v, &v);
        const candidate_k = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &v));
        if (candidate_k >= 1 and candidate_k < Secp256r1.N) return candidate_k;
        
        hmac_input.clearRetainingCapacity();
        hmac_input.appendSlice(&v) catch return 0;
        hmac_input.append(0x00) catch return 0;
        
        hmacSha256(&k_hmac, hmac_input.items, &k_hmac);
        hmacSha256(&k_hmac, &v, &v);
    }
}

fn hmacSha256(key: []const u8, message: []const u8, output: []u8) void {
    const block_size = 64;
    var actual_key: [block_size]u8 = undefined;
    
    if (key.len > block_size) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(key);
        hasher.final(actual_key[0..32]);
        @memset(actual_key[32..], 0);
    } else {
        @memcpy(actual_key[0..key.len], key);
        @memset(actual_key[key.len..], 0);
    }
    
    var i_pad: [block_size]u8 = undefined;
    var o_pad: [block_size]u8 = undefined;
    
    for (actual_key, 0..) |byte, i| {
        i_pad[i] = byte ^ 0x36;
        o_pad[i] = byte ^ 0x5C;
    }
    
    var inner_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inner_hasher.update(&i_pad);
    inner_hasher.update(message);
    var inner_hash: [32]u8 = undefined;
    inner_hasher.final(&inner_hash);
    
    var outer_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    outer_hasher.update(&o_pad);
    outer_hasher.update(&inner_hash);
    outer_hasher.final(output[0..32]);
}

fn modAdd(a: u256, b: u256, modulus: u256) u256 {
    const sum = a +% b;
    return if (sum >= modulus) sum - modulus else sum;
}

fn modSub(a: u256, b: u256, modulus: u256) u256 {
    return if (a >= b) a - b else a + modulus - b;
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