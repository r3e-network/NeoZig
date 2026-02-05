//! Base58 and Base58Check encoding implementation.
//!
//! This is the single production codec used across the SDK (addresses, WIF, NEP-2).
//! It performs no allocation beyond caller-provided allocator and returns
//! `ValidationError.InvalidParameter` for bad characters and `ValidationError.InvalidChecksum`
//! for Base58Check failures.

const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const secure = @import("secure.zig");
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DECODE_MAP = blk: {
    var map = [_]u8{0xFF} ** 256;
    for (ALPHABET, 0..) |char, i| {
        map[char] = @intCast(i);
    }
    break :blk map;
};

pub fn encode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (data.len == 0) return try allocator.alloc(u8, 0);

    var leading_zeros: usize = 0;
    while (leading_zeros < data.len and data[leading_zeros] == 0) {
        leading_zeros += 1;
    }

    var digits = ArrayList(u8).init(allocator);
    defer digits.deinit();

    const bytes_iter = data[leading_zeros..];
    for (bytes_iter) |byte| {
        var carry: u32 = byte;
        var i: usize = 0;
        while (i < digits.items.len) : (i += 1) {
            const value = (@as(u32, digits.items[i]) << 8) + carry;
            digits.items[i] = @intCast(value % 58);
            carry = value / 58;
        }
        while (carry > 0) {
            try digits.append(@intCast(carry % 58));
            carry /= 58;
        }
    }

    // Build the string: leading zeros become '1', digits are in little-endian order.
    const output_len = leading_zeros + digits.items.len;
    var encoded = try allocator.alloc(u8, output_len);
    var idx: usize = 0;
    while (idx < leading_zeros) : (idx += 1) {
        encoded[idx] = '1';
    }

    var digit_idx: usize = 0;
    while (digit_idx < digits.items.len) : (digit_idx += 1) {
        const source_index = digits.items.len - 1 - digit_idx;
        encoded[leading_zeros + digit_idx] = ALPHABET[digits.items[source_index]];
    }

    return encoded;
}

pub fn decode(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (encoded.len == 0) return try allocator.alloc(u8, 0);

    var leading_ones: usize = 0;
    while (leading_ones < encoded.len and encoded[leading_ones] == '1') {
        leading_ones += 1;
    }

    var bytes = ArrayList(u8).init(allocator);
    defer bytes.deinit();

    for (encoded[leading_ones..]) |char| {
        const digit_value = DECODE_MAP[char];
        if (digit_value == 0xFF) return errors.ValidationError.InvalidParameter;

        var carry: u32 = digit_value;
        var i: usize = 0;
        while (i < bytes.items.len) : (i += 1) {
            const value = @as(u32, bytes.items[i]) * 58 + carry;
            bytes.items[i] = @intCast(value & 0xFF);
            carry = value >> 8;
        }
        while (carry > 0) {
            try bytes.append(@intCast(carry & 0xFF));
            carry >>= 8;
        }
    }

    const output_len = leading_ones + bytes.items.len;
    var decoded = try allocator.alloc(u8, output_len);
    @memset(decoded[0..leading_ones], 0);

    var j: usize = 0;
    while (j < bytes.items.len) : (j += 1) {
        decoded[leading_ones + (bytes.items.len - 1 - j)] = bytes.items[j];
    }

    return decoded;
}

pub fn encodeCheck(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(data);
    var hash1: [32]u8 = undefined;
    hasher1.final(&hash1);

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    var hash2: [32]u8 = undefined;
    hasher2.final(&hash2);

    var payload = try allocator.alloc(u8, data.len + 4);
    defer {
        secure.secureZeroBytes(payload);
        allocator.free(payload);
    }
    @memcpy(payload[0..data.len], data);
    @memcpy(payload[data.len..], hash2[0..4]);

    return try encode(payload, allocator);
}

pub fn decodeCheck(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const decoded = try decode(encoded, allocator);
    defer {
        secure.secureZeroBytes(decoded);
        allocator.free(decoded);
    }

    if (decoded.len < 4) return errors.ValidationError.InvalidChecksum;

    const data_len = decoded.len - 4;
    const data = decoded[0..data_len];
    const checksum = decoded[data_len..];

    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(data);
    var hash1: [32]u8 = undefined;
    hasher1.final(&hash1);

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    var hash2: [32]u8 = undefined;
    hasher2.final(&hash2);

    if (!std.mem.eql(u8, checksum, hash2[0..4])) {
        return errors.ValidationError.InvalidChecksum;
    }

    return try allocator.dupe(u8, data);
}

test "base58 encode/decode roundtrip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const payload = [_]u8{ 0x35, 0x93, 0xad, 0x15, 0x72, 0xa4, 0xb3, 0x5c, 0x4b, 0x92, 0x54, 0x83, 0xce, 0x17, 0x01, 0xb7, 0x87, 0x42, 0xdc, 0x46, 0x0f };
    const encoded = try encode(&payload, allocator);
    defer allocator.free(encoded);

    const decoded = try decode(encoded, allocator);
    defer allocator.free(decoded);

    try testing.expectEqualSlices(u8, &payload, decoded);
}

test "base58check address vectors" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const script_hash = "75715e89bbba44a25dc9ca8d4951f104c25c253d";
    var buffer: [21]u8 = undefined;
    buffer[0] = 0x35;
    _ = try std.fmt.hexToBytes(buffer[1..], script_hash);

    const encoded = try encodeCheck(&buffer, allocator);
    defer allocator.free(encoded);

    try testing.expectEqualStrings("NWcx4EfYdfqn5jNjDz8AHE6hWtWdUGDdmy", encoded);

    const decoded = try decodeCheck(encoded, allocator);
    defer allocator.free(decoded);
    try testing.expectEqualSlices(u8, &buffer, decoded);
}
