//! Advanced hashing functions for Neo blockchain (Production Implementation)

const std = @import("std");

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");
const secure = @import("../utils/secure.zig");

/// Computes SHA256 hash of input data
pub fn sha256(data: []const u8) Hash256 {
    return Hash256.sha256(data);
}

/// Computes double SHA256 hash (SHA256 of SHA256)
pub fn doubleSha256(data: []const u8) Hash256 {
    return Hash256.doubleSha256(data);
}

/// Computes RIPEMD160 hash of input data
pub fn ripemd160(data: []const u8) !Hash160 {
    const ripemd160_impl = @import("ripemd160.zig");
    const hash_bytes = ripemd160_impl.ripemd160(data);
    return Hash160.fromArray(hash_bytes);
}

/// Computes Hash160 (RIPEMD160 of SHA256)
pub fn hash160(data: []const u8) !Hash160 {
    const sha_hash = sha256(data);
    return try ripemd160(sha_hash.toSlice());
}

/// HMAC-SHA256 implementation
pub fn hmacSha256(key: []const u8, message: []const u8, allocator: std.mem.Allocator) !Hash256 {
    _ = allocator;
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, message, key);
    return Hash256{ .bytes = out };
}

/// PBKDF2 with HMAC-SHA256
pub fn pbkdf2(password: []const u8, salt: []const u8, iterations: u32, dk_len: usize, allocator: std.mem.Allocator) ![]u8 {
    if (dk_len == 0) return errors.CryptoError.InvalidKey;
    if (iterations == 0) return errors.CryptoError.InvalidKey;

    const derived_key = try allocator.alloc(u8, dk_len);
    errdefer {
        secure.secureZeroBytes(derived_key);
        allocator.free(derived_key);
    }

    std.crypto.pwhash.pbkdf2(derived_key, password, salt, iterations, std.crypto.auth.hmac.sha2.HmacSha256) catch {
        return errors.CryptoError.InvalidKey;
    };

    return derived_key;
}

/// PBKDF2 with HMAC-SHA512 (RFC 2898) - used by BIP-39 seed derivation.
pub fn pbkdf2HmacSha512(password: []const u8, salt: []const u8, iterations: u32, dk_len: usize, allocator: std.mem.Allocator) ![]u8 {
    if (dk_len == 0) return errors.CryptoError.InvalidKey;
    if (iterations == 0) return errors.CryptoError.InvalidKey;

    const derived_key = try allocator.alloc(u8, dk_len);
    errdefer {
        secure.secureZeroBytes(derived_key);
        allocator.free(derived_key);
    }

    std.crypto.pwhash.pbkdf2(derived_key, password, salt, iterations, std.crypto.auth.hmac.sha2.HmacSha512) catch {
        return errors.CryptoError.InvalidKey;
    };

    return derived_key;
}

/// Scrypt key derivation (RFC 7914)
pub fn scrypt(password: []const u8, salt: []const u8, n: u32, r: u32, p: u32, dk_len: usize, allocator: std.mem.Allocator) ![]u8 {
    if (n == 0 or (n & (n - 1)) != 0) return errors.CryptoError.InvalidKey;
    if (r == 0 or p == 0) return errors.CryptoError.InvalidKey;
    if (r > std.math.maxInt(u30) or p > std.math.maxInt(u30)) return errors.CryptoError.InvalidKey;

    // Zig stdlib scrypt uses log2(N) as `ln`.
    const ln: u6 = @intCast(@ctz(n));
    const params = std.crypto.pwhash.scrypt.Params{
        .ln = ln,
        .r = @intCast(r),
        .p = @intCast(p),
    };

    const derived_key = try allocator.alloc(u8, dk_len);
    errdefer {
        secure.secureZeroBytes(derived_key);
        allocator.free(derived_key);
    }

    std.crypto.pwhash.scrypt.kdf(allocator, derived_key, password, salt, params) catch {
        return errors.CryptoError.InvalidKey;
    };

    return derived_key;
}

test "scrypt RFC 7914 vector (N=16,r=1,p=1)" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const derived = try scrypt("", "", 16, 1, 1, 64, allocator);
    defer allocator.free(derived);

    const expected_hex = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906";
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, derived);
}
