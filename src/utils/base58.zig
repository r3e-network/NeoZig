//! Base58 and Base58Check encoding implementation
//!
//! Production-ready Base58 implementation for Neo addresses and WIF encoding.

const std = @import("std");
const errors = @import("../core/errors.zig");

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
    for (data) |byte| {
        if (byte == 0) leading_zeros += 1 else break;
    }
    
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();
    
    while (result.items.len < leading_zeros) {
        try result.append('1');
    }
    
    if (data.len > leading_zeros) {
        var big_num = try allocator.dupe(u8, data[leading_zeros..]);
        defer allocator.free(big_num);
        
        var digits = std.ArrayList(u8).init(allocator);
        defer digits.deinit();
        
        while (!isZero(big_num)) {
            const remainder = divideBy58(big_num);
            try digits.append(ALPHABET[remainder]);
        }
        
        std.mem.reverse(u8, digits.items);
        try result.appendSlice(digits.items);
    }
    
    return try result.toOwnedSlice();
}

pub fn decode(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (encoded.len == 0) return try allocator.alloc(u8, 0);
    
    var leading_ones: usize = 0;
    for (encoded) |char| {
        if (char == '1') leading_ones += 1 else break;
    }
    
    var big_num = std.ArrayList(u8).init(allocator);
    defer big_num.deinit();
    
    for (encoded[leading_ones..]) |char| {
        const digit_value = DECODE_MAP[char];
        if (digit_value == 0xFF) return errors.ValidationError.InvalidParameter;
        multiplyBy58(&big_num, digit_value);
    }
    
    var result = try allocator.alloc(u8, leading_ones + big_num.items.len);
    @memset(result[0..leading_ones], 0);
    @memcpy(result[leading_ones..], big_num.items);
    
    return result;
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
    defer allocator.free(payload);
    @memcpy(payload[0..data.len], data);
    @memcpy(payload[data.len..], hash2[0..4]);
    
    return try encode(payload, allocator);
}

pub fn decodeCheck(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const decoded = try decode(encoded, allocator);
    defer allocator.free(decoded);
    
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

fn isZero(big_num: []const u8) bool {
    for (big_num) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn divideBy58(big_num: []u8) u8 {
    var remainder: u32 = 0;
    for (big_num) |*byte| {
        const temp = remainder * 256 + byte.*;
        byte.* = @intCast(temp / 58);
        remainder = temp % 58;
    }
    return @intCast(remainder);
}

fn multiplyBy58(big_num: *std.ArrayList(u8), digit: u8) void {
    var carry: u32 = digit;
    for (big_num.items) |*byte| {
        const temp = @as(u32, byte.*) * 58 + carry;
        byte.* = @intCast(temp & 0xFF);
        carry = temp >> 8;
    }
    while (carry > 0) {
        big_num.append(@intCast(carry & 0xFF)) catch break;
        carry >>= 8;
    }
}